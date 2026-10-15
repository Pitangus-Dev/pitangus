"""A secret's identity: the HMAC of its value, the same whichever engine found it and wherever it is.

The engines never hand over the value (Betterleaks runs with `--redact`, Trivy masks it), but both say where it is and
something about it: scanning/secret_location.py reads the value from the snapshot only where all of that holds for one
value, turns it into an HMAC with a key derived from the master key (HKDF, context CONTEXT) and forgets it. Neither the
value nor the HMAC is ever stored, logged or returned: only a hash of the HMAC prefixed by the key's id (`identity`), so
a rotated master key gives every secret a new identity (see below).

The identity is the VALUE's, never the text around it: Betterleaks' match carries the key, the separator and the quotes
(`API_KEY = "…"`), so the value is read where its redacted `Match` puts REDACTED, out to the edges of the token it is
(`_whole`), and `KEY = "v"`, `KEY="v"`, `other_key: v` or Trivy's mask over `v` all give the identity of `v`.

When the value can't be read for sure, the secret is unlinkable (`unlinkable`): named by its rule, its file and the
content of its lines, never by a value, never by another's name: two engines' reports are then never joined by guess.

Only the value names a secret. Its former names (`value_formers`, findings/identity.py) are this same value's identity
as something else computed it, never what surrounds it (the rule, the file, the text before it on its line: those are
the same for two different values, so they never link a value to another):

* **A master key rotation.** With `PITANGUS_PREVIOUS_MASTER_KEY` set to the key before, every scan also computes each
  value's identity with it, as a former name: an entry stored under the old key moves to the new identity on the first
  scan that reads the value, triage and issue included (findings/registry._rekey). Without it, a scan can't tell an
  old identity's value from another (a run records the keys it computed with: `key_ids`), so what it doesn't see again
  stays open, unverified, never fixed.
* **A formula that changes.** The values are never stored, so an identity can't be recomputed afterwards: the formula is
  versioned (`FORMULAS`), and for one release the scans compute the formulas in `EARLIER` from the value next to the
  current one, as former names; an entry moves on the first scan that reads its value again. The formula before the
  value's span (the whole match, read where the value was verified: engines._betterleaks_identities) is kept as a former
  name until 0.15.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from collections.abc import Callable, Iterable
from functools import cache, lru_cache
from pathlib import Path
from typing import Any, NamedTuple

from pitangus.shared.masking import plain, random_looking

CONTEXT = "pitangus/secret-identity/v1"
VALUE_MAX = 16_384      # characters of one secret read (a private key fits)
QUOTES = "\"'`"


def _formula_2(kid: str, mac: str) -> str:
    return kid + hashlib.sha256(f"secret/2|{kid}|{mac}".encode()).hexdigest()[: 64 - len(kid)]


# Each version of the formula, from the key's id and the value's HMAC. CURRENT names a secret; EARLIER are still
# computed as former names for one release after a change, so entries stored under them move (see the docstring).
FORMULAS: dict[int, Callable[[str, str], str]] = {2: _formula_2}
CURRENT = 2
EARLIER: tuple[int, ...] = ()


class Names(NamedTuple):
    """A value's identity, and the names the same value had (another key, an earlier formula), every one computed from
    the value."""
    identity: str
    formers: list[str]


@cache
def _key() -> tuple[str, bytes] | None:
    """The key identities are computed with. With no master key and nowhere to keep one (a CLI scan in a read-only
    container, as in CI), one for this process alone: its scans name the same value the same and the same content the
    same (scanning a commit twice changes nothing), and nothing named under it ever links to another process's names,
    since its id is the run's own (`key_ids`: what it names is never fixed by a run under another key)."""
    from pitangus.shared import vault
    try:
        return vault.derived_key(CONTEXT)
    except (vault.VaultError, OSError):
        return vault.derived_key(CONTEXT, os.urandom(32))


@lru_cache(maxsize=4)
def _previous(configured: str) -> tuple[str, bytes] | None:
    from pitangus.shared import vault
    try:
        return vault.derived_key(CONTEXT, vault.decoded_key(configured)) if configured else None
    except vault.VaultError:
        return None


def _keys() -> list[tuple[str, bytes]]:
    """The current key, then the one before a master key rotation (PITANGUS_PREVIOUS_MASTER_KEY), when there is one."""
    from pitangus.shared import settings
    current = _key()
    if current is None:
        return []
    previous = _previous(settings.text("PITANGUS_PREVIOUS_MASTER_KEY"))
    return [current, *([previous] if previous and previous[0] != current[0] else [])]


def key_ids() -> list[str]:
    """The ids of the keys a scan computes identities with: a run records them (scanning/rule_set), and only a run that
    knew an identity's key can tell its value is gone (findings/registry.configuration_cause)."""
    return [kid for kid, _ in _keys()]


def names(value: str | None) -> Names | None:
    """`value`'s identity (64 hex characters: the key id, then the hash of its HMAC) and its former names (`Names`), or
    None without a key or a value."""
    keys = _keys()
    text = str(value or "").strip().strip(QUOTES).strip()
    if not keys or not text or len(text) > VALUE_MAX:
        return None
    raw = text.encode("utf-8", "surrogateescape")
    macs = [(kid, hmac.new(secret, raw, hashlib.sha256).hexdigest()) for kid, secret in keys]
    found = [FORMULAS[version](kid, mac) for version in (CURRENT, *EARLIER) for kid, mac in macs]
    return Names(found[0], list(dict.fromkeys(item for item in found[1:] if item != found[0])))


def identity(value: str | None) -> str | None:
    """`value`'s identity (`names`), or None without a key or a value."""
    found = names(value)
    return found.identity if found else None


def assign(finding: Any, found: Names | None) -> None:
    """`finding` named by its value: its `identity`, and `value_formers` (a list, empty or not), which says the identity
    is a value's and holds the only names it was known by before (findings/identity.py)."""
    if found is None:
        return
    finding["identity"] = found.identity
    finding["value_formers"] = list(dict.fromkeys([*(finding.get("value_formers") or []), *found.formers]))


UNLINKABLE = "secret-unlinkable/1"


def unlinkable(rule: str, path: str, content: bytes | None) -> str:
    """The name of a secret whose value couldn't be read for sure (scanning/secret_location.py): the keyed HMAC of its
    rule, its file and `content` (the lines it was reported on, line endings normalized; or what else holds them), so
    the same content always gives the same name and any change another; prefixed by the key's id, as a value's identity.
    Never a value's identity, never a former name (findings/identity.unlinkable). Without a content, a name no other
    report will have."""
    keys = _keys()
    if not keys or content is None:
        return "u" + os.urandom(31).hex() + "0"
    kid, secret = keys[0]
    mac = hmac.new(secret, b"\0".join([UNLINKABLE.encode(), rule.encode(), path.encode("utf-8", "surrogateescape"), content]),
                   hashlib.sha256).hexdigest()
    return kid + hashlib.sha256(f"{UNLINKABLE}|{kid}|{mac}".encode()).hexdigest()[: 64 - len(kid)]


def assign_unlinkable(finding: Any, identity: str) -> None:
    """`finding` named by `identity`, unlinkable: no value's names, no former names of any kind (findings/identity.py)."""
    finding["identity"] = identity
    finding["unlinkable"] = True
    for name in ("value_formers", "previous_fingerprint", "previous_fingerprints"):
        finding.pop(name, None)


def _inside(root: Path, relative: str) -> Path | None:
    try:
        base = root.resolve()
        target = (root / relative).resolve()
        target.relative_to(base)
    except (OSError, ValueError):
        return None
    return target if target.is_file() else None


# Characters a token is made of: a secret runs on through them, whatever part of it an engine marked. Backwards, `=`
# ends it (`key=value`); forwards it may be padding (`…==`).
TOKEN = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_+/.~")


def _whole(line: str, start: int, end: int) -> str:
    """The whole token an engine pointed at on `line` with [start, end): engines mark different parts of one secret
    (Trivy masks only a Slack token's prefix and first ten digits, Betterleaks reports all of it), and a part of two secrets
    can be the same (two tokens of one Slack workspace). Out to the token's edges, both engines read one value, and two
    secrets never share one. Never further than VALUE_MAX characters each way: a token longer than that (a blob in a
    bundle) is longer than any value read, and names nothing (`names`)."""
    floor, ceiling = max(0, start - VALUE_MAX - 1), min(len(line), end + VALUE_MAX + 1)
    while start > floor and line[start - 1] in TOKEN:
        start -= 1
    while end < ceiling and (line[end] in TOKEN or line[end] == "="):
        end += 1
    return line[start:end]


def names_on_line(line: str, start: int, end: int) -> Names | None:
    """`names` of the secret at [start, end) on `line`: the whole token there (`_whole`), as both engines read it."""
    return names(_whole(line, start, end)) if 0 <= start < end <= len(line) else None


def _lines(root: Path, relative: str, wanted: set[int]) -> dict[int, str]:
    target = _inside(root, relative)
    found: dict[int, str] = {}
    if target is None or not wanted:
        return found
    try:
        with target.open("r", encoding="utf-8", errors="surrogateescape") as handle:
            for number, text in enumerate(handle, 1):
                if number in wanted:
                    found[number] = text.rstrip("\n")
                if number >= max(wanted):
                    break
    except OSError:
        return {}
    return found


PIECES = re.compile(r"""[\s"'`=,;:()\[\]{}<>]+""")
RUN_VALUE = re.compile(r"[A-Za-z0-9\-_+/.~=]{12,}")


def values(root: Path | None, findings: Iterable[dict]) -> dict[str, set[str]]:
    """The values of the secrets the engines detected, read from the snapshot where each one pointed (`span`: line,
    start, end line, end; the whole token, as its identity reads it), by file. Only for masking them wherever else they
    appear (shared/masking.py): never stored, logged or returned with a finding. A secret without a position masks
    every piece of its line that isn't words (`masking.plain`) and every random-looking run on it."""
    found: dict[str, set[str]] = {}
    if root is None:
        return found
    wanted: dict[str, set[int]] = {}
    secrets = [finding for finding in findings if finding.get("scanner") == "secrets" and finding.get("path")]
    for finding in secrets:
        span = finding.get("span")
        first, last = (int(span[0]), int(span[2])) if isinstance(span, list) and len(span) == 4 else (int(finding.get("line") or 0),) * 2
        if 0 < first <= last and last - first <= 200:
            wanted.setdefault(str(finding["path"]), set()).update(range(first, last + 1))
    lines = {path: _lines(root, path, numbers) for path, numbers in wanted.items()}
    for finding in secrets:
        path, span = str(finding["path"]), finding.get("span")
        text = lines.get(path, {})
        bucket = found.setdefault(path, set())
        if isinstance(span, list) and len(span) == 4 and all(isinstance(item, int) for item in span):
            first, start, last, end = span
            if first == last and first in text and 0 <= start < end <= len(text[first]):
                bucket.update({text[first][start:end].strip(QUOTES), _whole(text[first], start, end).strip(QUOTES)})
                continue
            if first < last and all(number in text for number in range(first, last + 1)):
                body = [text[first][start:], *(text[number] for number in range(first + 1, last)), text[last][:end]]
                bucket.update(piece.strip() for piece in body if len(piece.strip()) >= 16)
                bucket.add("\n".join(body))
                continue
        line = text.get(int(finding.get("line") or 0))
        if line is not None:
            bucket.update(piece for piece in PIECES.split(line) if len(piece) >= 6 and not plain(piece))
            bucket.update(match.group(0) for match in RUN_VALUE.finditer(line) if random_looking(match.group(0)))
    return {path: {value for value in items if value} for path, items in found.items() if items}
