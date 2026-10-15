"""What an engine's run must show before anything it didn't report can count as gone (docs/findings.md).

Every adapter hands its process result here instead of judging it itself: an exit code the engine never uses for a
clean run, empty output, output that isn't the JSON the engine always writes, or JSON without the mark it writes
whenever it read its input (`evidence`) makes the engine blind. The adapters only parse what passed and say which
units (files, manifests, URLs) they examined and which not, and why (`coverage`).

A run that didn't finish (killed, timed out, a wrong exit code, no output, output that isn't its JSON or lacks its mark)
neither opens nor closes findings, in every mode (`failed`): no findings, not completed, no coverage. `settled` applies
the same rule to whatever an adapter returns, so an engine added later inherits it. `PITANGUS_COVERAGE_MODE` decides
the rest: `on` (the default) judges fixes by the coverage each engine declares; `shadow` keeps the rules before it and
records the verdicts (`contract`), so a run shows what the contract would have changed.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from pitangus.shared import settings
from pitangus.shared.i18n import catalog, msg
from pitangus.shared.model import Message


@dataclass(frozen=True)
class Contract:
    engine: str                               # its name, for the messages
    ok_codes: frozenset[int]                  # exit codes of a run that read its input
    shape: tuple[type, ...]                   # what its JSON always is (dict, list)
    evidence: Callable[[Any], bool] = field(default=lambda payload: True)  # the mark it writes whenever it ran


def mode() -> str:
    return settings.text("PITANGUS_COVERAGE_MODE")


def enforced() -> bool:
    return mode() == "on"


def verdict(contract: Contract, code: int | None, text: str | None) -> tuple[Any, Message | None]:
    """The engine's payload, or why it can't be trusted (and the payload is None)."""
    if code not in contract.ok_codes:
        return None, msg("scanning.contract.exit_code", engine=contract.engine, code=code)
    if not (text or "").strip():
        return None, msg("scanning.contract.empty", engine=contract.engine)
    try:
        payload = json.loads(text or "")
    except ValueError:
        return None, msg("scanning.contract.invalid", engine=contract.engine)
    if not isinstance(payload, contract.shape) or not contract.evidence(payload):
        return None, msg("scanning.contract.unexpected", engine=contract.engine)
    return payload, None


def jsonl(contract: Contract, code: int | None, text: str | None) -> tuple[list[dict] | None, Message | None]:
    """The same for JSON lines (nuclei): every non-empty line a JSON object. No lines is valid here: the evidence
    that the engine ran comes from elsewhere (its statistics)."""
    if code not in contract.ok_codes:
        return None, msg("scanning.contract.exit_code", engine=contract.engine, code=code)
    entries = []
    for line in (text or "").splitlines():
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            return None, msg("scanning.contract.invalid", engine=contract.engine)
        if not isinstance(entry, dict):
            return None, msg("scanning.contract.unexpected", engine=contract.engine)
        entries.append(entry)
    return entries, None


def recorded(result: dict, failure: Message | None, *, finished: bool = False) -> dict:
    """The result with the contract's verdict on it (`summary.tools[].contract`). `finished`: the engine read its input
    and what it reports stands, but it can't vouch for what it didn't report (a rule that didn't load)."""
    return {**result, "contract": ({"blind": True, "cause": failure, **({"finished": True} if finished else {})}
                                   if failure else {"blind": False})}


# What a run that didn't finish can't hand over: anything it would open (findings, silenced or withheld ones, packages
# for the advisory watch, the dependency graph) or any unit it would vouch for (coverage).
UNFINISHED = ("findings", "silenced", "withheld", "packages", "system_packages", "graph", "coverage", "unexamined")


def failed(result: dict, cause: Message) -> dict:
    """The result of a run that didn't finish: inconclusive, blind, with nothing it would open or vouch for."""
    return {**{key: value for key, value in result.items() if key not in UNFINISHED}, "status": "inconclusive", "findings": [],
            "contract": {"blind": True, "cause": cause}}


def settled(result: dict) -> dict:
    """The rule above, whatever the adapter did: an inconclusive result that neither met the contract nor says it read
    its input (`recorded(..., finished=True)`) opens nothing and vouches for nothing."""
    contract = result.get("contract") or {}
    if result.get("status") != "inconclusive" or contract.get("blind") is False or contract.get("finished"):
        return result
    return failed(result, contract.get("cause") or result.get("detail") or msg("scanning.contract.empty", engine=result.get("name") or result.get("tool")))


def reason(value) -> str:
    """Why a unit went unexamined, as a language-neutral code (`parse_error`, `timeout`…) that `reason_message`
    renders: an engine's own wording, a string or a list like Opengrep's ["PartialParsing", [...]], becomes its code,
    never a Python repr."""
    while isinstance(value, (list, tuple)) and value:
        value = value[0]
    code = re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")[:40] if isinstance(value, str) else ""
    return code or "error"


def reason_message(code: str) -> Message:
    known = f"scanning.coverage.reason.{code}"
    if known in catalog("en"):
        return msg(known)
    if status := re.fullmatch(r"http_(\d{3}|none)", code):  # http_coverage: the answer that proved nothing
        return msg("scanning.coverage.reason.http", status=status.group(1))
    return msg("scanning.coverage.reason.other", code=code)




# `coverage` takes a `reason` argument of its own.
reason_code = reason


def coverage(examined: list[str] | str, unexamined: dict[str, str] | None = None, *,
             by_scanner: dict[str, dict[str, str]] | None = None, reason: str | None = None) -> dict:
    """What an engine looked at: `examined` the units it read ("*": every unit of its kind in the snapshot), and
    `unexamined` those it couldn't, each with why (a `reason` code). A finding outside it is never fixed by this engine's run.
    `by_scanner`: units only one of the engine's scanners couldn't examine ({"sca": {"pom.xml": "resolution_failed"}}),
    so the engine's other scanners still vouch for them. `reason`: why `examined` is empty, when it is."""
    found: dict[str, Any] = {"examined": examined if examined == "*" else sorted(set(examined)),
                             "unexamined": {unit: reason_code(why) for unit, why in sorted((unexamined or {}).items())}}
    if scoped := {scanner: {unit: reason_code(why) for unit, why in sorted(units.items())}
                  for scanner, units in sorted((by_scanner or {}).items()) if units}:
        found["by_scanner"] = scoped
    return {**found, "reason": reason} if reason else found


# HTTP evidence, for any engine that reads URLs (web and DAST): what an answer proves about the URL it came from. Only
# a status on this whitelist proves anything: a 2xx that the URL serves something, a 404 or a 410 that it doesn't. A
# redirect proves nothing about the URL, and isn't held against the site either: sites send plain HTTP to HTTPS and
# unknown paths to their login everywhere. Anything else (401, 403, 406, 418, 429, a 5xx, a 400, a code nobody
# defined, no status at all) is about the client or the server's mood, never the URL: a refusal, and a sign of a block.
PRESENT = range(200, 300)
ABSENT = frozenset({404, 410})
BLOCK_SHARE = 0.8         # refusals among a host's answers (to the whole run, or to one engine) that mean it turned it away
RATE_LIMIT_SHARE = 0.05   # 429s among them that mean it rate-limited the run: one request in twenty
ENGINE_ANSWERS_MIN = 10   # answers one engine needs before its share alone decides (one refused root isn't a block)


def _code(status: Any) -> int | None:
    return status if isinstance(status, int) and not isinstance(status, bool) else None


def present(status: Any) -> bool:
    """Whether an answer says the URL serves something (a 2xx)."""
    return _code(status) in PRESENT


def absent(status: Any) -> bool:
    """Whether an answer says the URL serves nothing: not found, or gone."""
    return _code(status) in ABSENT


def proves(status: Any) -> bool:
    """Whether an answer says anything about the URL: present or absent."""
    return present(status) or absent(status)


def redirect(status: Any) -> bool:
    return (code := _code(status)) is not None and 300 <= code < 400


def refused(status: Any) -> bool:
    """Whether an answer is a refusal: anything that neither proves something about the URL nor redirects."""
    return not proves(status) and not redirect(status)


def blocked_hosts(answers: dict[str, list[tuple[str, int]]]) -> list[str]:
    """The hosts that turned the run away, from every answer of every engine over the whole run ({engine: [(host,
    status), …]}, one item per answer): refusals are at least BLOCK_SHARE of the host's answers to the run or to any one
    engine with ENGINE_ANSWERS_MIN of them (a block that only one phase met, like a WAF that starts halfway), or 429s at
    least RATE_LIMIT_SHARE."""
    groups: dict[tuple[str, str], list[int]] = {}
    for engine, items in answers.items():
        for host, status in items:
            for group in ((host, ""), (host, engine)):
                tally = groups.setdefault(group, [0, 0, 0])
                tally[0] += refused(status)
                tally[1] += status == 429
                tally[2] += 1
    return sorted({host for (host, engine), (refusals, limited, total) in groups.items()
                   if total >= (ENGINE_ANSWERS_MIN if engine else 1)
                   and (refusals >= BLOCK_SHARE * total or limited >= RATE_LIMIT_SHARE * total)})


def http_coverage(answers: dict[str, list[int]], *, accept: Callable[[int], bool] = proves,
                  paths: Callable[[int], bool] | None = None, failed=(), blocked=()) -> dict:
    """`coverage` for an engine that read pages ({page: every status it got there in this run}): a page is examined
    only when each of its own answers was accepted (by default, one that proves something: `proves`), none of its
    requests failed (`failed`: pages with a request that got no answer) and its host didn't turn the run away
    (`blocked`). `paths`: what a page other than a root needs instead, for an engine whose findings there are about one
    path (nuclei's exposed files): only `absent` proves such a finding gone, never a page that still answers."""
    examined, unexamined = [], {}
    for page, statuses in answers.items():
        rule = accept if paths is None or urlsplit(page).path in ("", "/") else paths
        rejected = next((status for status in statuses if not rule(status)), None)
        if (urlsplit(page).hostname or "") in blocked:
            unexamined[page] = "blocked"
        elif page in failed:
            unexamined[page] = "no_answer"
        elif rejected is not None and present(rejected) and all(proves(status) for status in statuses):
            unexamined[page] = "present"
        elif rejected is not None or not statuses:
            unexamined[page] = f"http_{rejected}"
        else:
            examined.append(page)
    for page in failed:
        unexamined.setdefault(page, "no_answer")
    return coverage(examined, unexamined)
