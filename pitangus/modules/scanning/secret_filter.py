"""A second look at what the secret engines flag: a match that can't be a secret is set aside, counted and named.

The engines decide by shape, so a generic rule fires on interface text (`"password": "Contraseña"`), references
(`password: ${DB_PASSWORD}`), placeholders (`YOUR-ACCESS-TOKEN`, `XXXXXXXX`), test data and keys that are public by
design (a Supabase anon key ships in every frontend). Each match is judged here on its rule, path, line and value
alone, never on the other matches, and `verdict` says why it isn't a finding. Nothing is dropped silently: the engine
step counts what was set aside by reason (engines.run_betterleaks, engines.run_trivy).

`generic-password` gets the filter measured on the public corpus (1525 matches on 18 repositories: the 12 the
validation labeled real all kept, 23 left, 18 of them real or seed data): paths outside the code (tests, docs,
examples, translations), references and templates, prose (text with spaces), identifiers (not passphrases), placeholders
and weak values (short, or of one kind of character and shorter than LONG). Every other rule only loses what is public by design, a reference, a name standing in
for the value (`ACCESS_TOKEN`) or a placeholder by its shape (a password never by a counted run: people do pick
`Aa12345678`). Outside the code it is still a finding, with a lower priority (engines._base).

Files are read wherever they are (lockfiles, go.sum, tests, examples, vendored code, docs: scanning/secret_coverage), so
what each file holds that looks like a token is judged by what the value is and the syntax right around it, never by
the file's name: a digest written with its algorithm (`h1:…`, `sha512-…`, `sha256:…`) or under a checksum's name, of
exactly that algorithm's length; a version specifier (`4.0.23(@types/node@22.13.14)`, `^1.2.3`); the operand of an
expansion (`${VAR:+word}`), judged as the literal it is without the expansion's syntax; a PEM header with no key body
(`-----BEGIN PRIVATE KEY-----\\n...`); a service account's `type` marker whose object holds no key material; and the
download token of a Firebase Storage object link, a per-object read link Firebase hands out to be published. A secret
of any common shape placed in those same files is none of these, and stays a finding.

The value is read, judged and forgotten: it is never returned, stored or logged.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from pathlib import Path

from pitangus.modules.scanning.secret_identity import VALUE_MAX

GENERIC_PASSWORD = "generic-password"  # gitleaks:allow (a rule's id)
# Why a match isn't a finding: counted, and named in this order.
REASONS = ("public", "unsigned", "path", "reference", "prose", "identifier", "placeholder", "weak", "checksum", "version",
           "keyless", "link")

# Tests, docs, examples, samples and translations: by folder, by a test file's name, or by a documentation or template
# extension.
OUTSIDE_CODE = re.compile(
    r"(^|/)(i18n|intl|locales?|lang|translations?|tests?|spec|specs|__tests__|cypress|e2e|testdata|fixtures?|mocks?|docs?"
    r"|examples?|samples?|\.devcontainer|\.github|it)(/|$)"
    r"|(Tests?\.(java|kt|cs)|_test\.go|\.test\.[jt]sx?|\.spec\.[jt]sx?|_spec\.rb|(^|/)test_[^/]*\.py"
    r"|\.(md|mdx|rst|txt|adoc|html?|po|pot|xliff|strings)|\.(example|sample|template|dist|tmpl))$", re.I)
REFERENCE = ("${", "{{", "$(", "%(", "<", "process.env", "os.environ", "getenv")
PLACEHOLDERS = frozenset({"password", "passwd", "pass", "pwd", "secret", "changeme", "change_me", "changeit", "admin", "root",
                          "postgres", "mysql", "test", "test123", "example", "default", "dummy", "user", "username", "xxx",
                          "xxxx", "none", "null", "true", "false", "your_password"})
SLOT_WORDS = frozenset({"password", "passwd", "pass", "pwd", "secret", "changeme", "test", "example", "dummy", "sample", "fake"})
IDENTIFIER = (re.compile(r"[a-z]+([._-][a-z]+)+"), re.compile(r"[a-z]+([A-Z][a-z]+)+"))
# Words joined by one separator, four or more and 20 characters at least: how passphrase generators write
# (`correct-horse-battery-staple`). A name in code joins fewer words, or mixes separators (`message.no-match-password`).
PASSPHRASE = re.compile(r"[a-z]+(?P<sep>[-_])[a-z]+(?:(?P=sep)[a-z]+){2,}")
PASSPHRASE_MIN = 20
NAME = re.compile(r"[A-Z]+(_[A-Z]+)+")  # an environment variable's name standing in for its value (`ACCESS_TOKEN`)
STRONG = 8  # characters a password needs, with two character classes, to be worth reporting
# Characters a password of one class needs: 26^16 (2^75) beats any 8 of two classes (62^8, 2^48), and words, names and
# labels rarely reach it, while generated passwords of one class do (crAPI's 19 lowercase letters).
LONG = 16
# A token nobody would issue: a placeholder word, a run of one character (`XXXXXXXX`, `T00000000`, `******`) or a counted
# sequence (`12345678`, `abcdef`). Six is where random letters and digits stop producing them by chance (1 in 36^5 per
# position), but not random digits (1 in 10^5): a run of six sets aside only what a generic rule matched (GENERIC),
# which has nothing else to go on. A vendor's rule matched the token's own format (`ghp_…`, `xoxb-…`, `sk_live_…`,
# `AKIA…`): it loses a value only to a placeholder word or to a run of VENDOR_RUN, the length people type to fill one
# (a vendor's prefix and then ten zeros, `1234567890abcdef…`, or sixteen `X`) and random digits make once
# in 10^9 per position.
GENERIC = "generic-"
VENDOR_RUN = 10
PLACEHOLDER_WORD = re.compile(r"example|placeholder|change[-_]?me|replace[-_]?me|dummy|redacted|\.\.\.|…|(?:^|[^a-z0-9])(?:your|my)[-_]", re.I)
RUN = 6
JWT = re.compile(r"eyJ[A-Za-z0-9_-]+\.e[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
PUBLIC_PREFIXES = ("sb_publishable_",)
KEY = re.compile(r"[A-Za-z0-9_.-]+$")
ASSIGN = re.compile(r"""[\s"'`]*(?:=>|:=|=|:)?[\s"'`]*$""")
VALUE = re.compile(r"""(?:[:=]\s*|=>\s*)(?:"([^"]*)"|'([^']*)'|([^\s,;#'"]+))""")
LEAD = 256  # characters before a value read for its key, whatever the line's length
# A digest written with its algorithm, just before the value or at its start (`h1:` in go.sum, `sha512-` in npm and
# pnpm integrity, `sha256:` in an image digest or a pip hash), and the bytes each algorithm's digest has: the value must
# decode, as hex or base64, to exactly that many bytes. `h1` is Go's SHA-256 module hash.
DIGEST_BYTES = {"h1": 32, "md5": 16, "sha1": 20, "sha224": 28, "sha256": 32, "sha384": 48, "sha512": 64}
DIGEST_LABEL = re.compile(r"(?i)(?:^|[^a-z0-9])(h1|md5|sha-?(?:1|224|256|384|512))[:=-]$")
# The last word of a key that names a checksum (`checksum`, `integrity`, `shasum`, `apiKeySha256`, `etag`): a value there
# of exactly a digest's length is that digest.
CHECKSUM_WORDS = frozenset({"checksum", "integrity", "digest", "hash", "shasum", "sha", "sha1", "sha224", "sha256", "sha384",
                            "sha512", "md5", "etag"})
WORD = re.compile(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])")
# A version specifier: an optional range operator or package alias, a dotted version of two to four numbers, a
# pre-release and build, and pnpm's peer suffixes (`(@types/node@22.13.14)`, nested), read innermost first.
PACKAGE = r"@?[A-Za-z0-9][\w.-]*(?:/[\w.-]+)?"
VERSION = r"v?\d+(?:\.\d+){1,3}(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?"
VERSION_SPEC = re.compile(rf"(?:\^|~>?|[<>]=?|==?|!=)?(?:npm:{PACKAGE}@)?{VERSION}")
PEER = re.compile(rf"\({PACKAGE}@(?:\^|~|[<>]=?)?{VERSION}\)")
# Where an expansion opens and how it closes: what is inside is an operand, not the value of the key before it.
EXPANSIONS = (("${", "}"), ("#{", "}"), ("%{", "}"), ("{{", "}}"), ("<%", "%>"))
SHELL_OPERAND = re.compile(r"\$\{[#!]?[A-Za-z_][A-Za-z0-9_]*(?::?[-+=?])")
# A PEM block's header, and the base64 characters its body needs to hold any private key: the smallest, an Ed25519 or
# X25519 key in PKCS#8, is 48 bytes, 64 characters. Escaped line breaks (`\\n`) are layout, not body.
PEM_HEADER = re.compile(r"-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----")
PEM_BODY_MIN = 64
ESCAPE = re.compile(r"\\[nrt]")
# A JSON object's type marker (a service account's `type` field): it names what the object is, and holds no key itself.
MARKER = re.compile(r"""["']?type["']?\s*:\s*["']?[a-z_]+["']?""")
AROUND = 8192  # characters read either side of a marker for the object around it
# A Firebase Storage download link (`…/v0/b/<bucket>/o/<object>?alt=media&token=<uuid>`): the token Firebase issues
# for one object, to be put in public pages; it reads that object and nothing else.
DOWNLOAD_LINK = re.compile(r"https?://firebasestorage\.googleapis\.com/v0/b/[^/\s?#]+/o/[^\s?#]+\?(?:[^\s#]*&)?token=$")
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
TOKENISH = 16  # characters of a pre-release part mixing capitals, small letters and digits that read as a token
MATCH_MAX = 4096  # characters of a match read for its value: a longer one is a finding as it stands


def outside_code(path: str) -> bool:
    return bool(OUTSIDE_CODE.search(path or ""))


def value_span(match: str, raw: str) -> tuple[int, int] | None:
    """Where the value is inside an engine's redacted match (`password": "REDACTED"`), given the text at the match's
    columns: [start, end) of its last copy, the one after the key. The engine redacts every copy of the value, the key's
    own included (`REDACTED = "REDACTED"` for `password = "password"`): each copy must read the same. A match that is
    all value (`REDACTED`) is the whole text, up to VALUE_MAX characters (a private key)."""
    if not isinstance(match, str) or not isinstance(raw, str):
        return None
    if match == "REDACTED":
        return (0, len(raw)) if 0 < len(raw) <= VALUE_MAX else None
    if len(raw) > MATCH_MAX or not 1 <= match.count("REDACTED") <= 8:
        return None
    first, *rest = (re.escape(part) for part in match.split("REDACTED"))
    pattern = first + "(?P<v0>.+?)" + rest[0] + "".join(f"(?P<v{index}>(?P=v0)){part}" for index, part in enumerate(rest[1:], 1))
    found = re.fullmatch(pattern, raw, re.S)
    return found.span(f"v{len(rest) - 1}") if found else None


def value_from_match(match: str, raw: str) -> str | None:
    """The value inside an engine's redacted match (`value_span`), read from a match of at most MATCH_MAX characters."""
    found = value_span(match, raw) if isinstance(raw, str) and len(raw) <= MATCH_MAX else None
    return raw[found[0]:found[1]] if found else None


def assigned_value(line: str) -> str | None:
    """The last value assigned on a line (`key = "value"`, `key: value`), for a match whose columns aren't known."""
    found = VALUE.findall(line or "")
    return next((a or b or c for a, b, c in reversed(found) if a or b or c), None)


def key_of(line: str, value: str) -> str:
    """The name the value is assigned to on its line (`MYSQL_PASSWORD` in `- MYSQL_PASSWORD=…`), lowercased."""
    return _key(line, value).lower()


def _key(line: str, value: str) -> str:
    """`key_of` as written (`apiKeySha256`)."""
    at = (line or "").rfind(value)
    before = ASSIGN.sub("", (line or "")[max(0, at - LEAD):at] if at >= 0 else "")
    found = KEY.search(before)
    return found.group(0) if found else ""


def _classes(value: str) -> int:
    """Kinds of characters in `value`: lowercase, uppercase, digits, others. A letter is a letter in any script (`ñ` is
    lowercase, `中` too), and a capital first letter adds none (`Contraseña`, `Swordfish` are one kind, as people write
    words)."""
    body = value[1:] if value[:1].isupper() and value[1:2].isalpha() and not value[1:2].isupper() else value
    return len({"upper" if char.isupper() else "lower" if char.isalpha() else "digit" if char.isdecimal() else "other" for char in body})


def _reference(value: str) -> bool:
    return value.startswith("$") or any(marker in value for marker in REFERENCE)


def _jwt(value: str) -> tuple[dict, dict] | None:
    """The header and claims of the first JWT in `value`, or None."""
    found = JWT.search(value)
    if not found:
        return None
    try:
        header, claims = (json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))) for part in found.group(0).split(".")[:2])
    except (binascii.Error, ValueError):
        return None
    return (header, claims) if isinstance(header, dict) and isinstance(claims, dict) else None


def _public(value: str) -> bool:
    """A key that is public by design: a Supabase anon JWT (its claims say `"role": "anon"`) or a publishable key. A
    service_role key says `service_role`, and stays a secret."""
    token = _jwt(value)
    return value.startswith(PUBLIC_PREFIXES) or (token is not None and token[1].get("role") == "anon")


def _unsigned(value: str) -> bool:
    """A JWT with `"alg": "none"`: it carries no signature, so anyone can write it and it proves nothing."""
    token = _jwt(value)
    return token is not None and str(token[0].get("alg", "")).lower() == "none"


def _counted(value: str, run: int = RUN) -> bool:
    """A run of `run` identical characters (`XXXXXX`, `******`), or of `run` consecutive ones (`123456`, `abcdef`; for a
    run of VENDOR_RUN, `1234567890` too, as a keyboard's row goes)."""
    same = step = 1
    lowered = value.lower()
    for previous, current in zip(lowered, lowered[1:]):
        alike = current.isalnum() and previous.isalnum()
        follows = ord(current) - ord(previous) == 1 or (run >= VENDOR_RUN and (previous, current) == ("9", "0"))
        same = same + 1 if current == previous and not current.isspace() else 1
        step = step + 1 if alike and follows and current.isdigit() == previous.isdigit() else 1
        if run in (same, step):
            return True
    return False


def _run_placeholder(rule: str, value: str) -> bool:
    """A placeholder by a run (RUN, GENERIC, VENDOR_RUN): of six for a generic rule but a password's, of VENDOR_RUN for
    a vendor's."""
    if rule.startswith(GENERIC):
        return rule != GENERIC_PASSWORD and _counted(value)
    return _counted(value, VENDOR_RUN)


def _before(line: str, value: str) -> str:
    """What precedes `value` on its line (the line as the engine step passes it ends with the value; else its last copy)."""
    line = line or ""
    if line.endswith(value):
        return line[:len(line) - len(value)]
    at = line.rfind(value)
    return line[:at] if at >= 0 else ""


def _operand(before: str, value: str) -> str:
    """`value` without the syntax of an expansion it sits inside: an expansion opened before it and not closed holds an
    operand. A shell default or alternative (`${NAME:-word}`, `${NAME:+word}`, `=`, `?`, with or without `:`) is read
    whole from the expansion's own text, wherever the engine's value started (`+has-password}` in
    `${MVNW_PASSWORD:+has-password}` is the literal `has-password`; `${DB_PASSWORD:--S3cr3t!}` is `-S3cr3t!`), and
    judged as the literal it is. Inside any other expansion, what the engine read up to the closer. Outside one, `value`
    as it is."""
    found = max(((before.rfind(opener), opener, closer) for opener, closer in EXPANSIONS), default=(-1, "", ""))
    open_at, opener, closer = found
    if open_at < 0 or closer in before[open_at:]:
        return value
    text = before[open_at:] + value
    end = text.find(closer, len(opener))
    body = text[:end] if end >= 0 else text
    operator = SHELL_OPERAND.match(body) if opener == "${" else None
    literal = body[operator.end():] if operator else body[len(before) - open_at:]
    return _unquoted(literal.strip())


def _unquoted(text: str) -> str:
    """`text` without one pair of matching quotes around it, and nothing else."""
    return text[1:-1] if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'`" else text


def _decoded_size(text: str) -> int | None:
    """Bytes `text` holds as hex, or else as base64 (standard or URL-safe, padded or not); None when it is neither."""
    if re.fullmatch(r"[0-9a-fA-F]+", text) and len(text) % 2 == 0:
        return len(text) // 2
    if not re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", text):
        return None
    core = text.rstrip("=")
    try:
        return len(base64.b64decode((core + "=" * (-len(core) % 4)).replace("-", "+").replace("_", "/"), validate=True))
    except (binascii.Error, ValueError):
        return None


def _digest(before: str, key: str, value: str) -> bool:
    """A digest: written with its algorithm (`h1:`, `sha512-`, `sha256:`), just before the value or at its start, or
    assigned to a key whose last word names a checksum; and of exactly that algorithm's length (any digest's under a
    checksum's name). A secret written after `sha256:` and shaped as a SHA-256 digest is the only one this sets aside."""
    found = re.match(r"(?i)(h1|md5|sha-?(?:1|224|256|384|512))[:=-](.+)", value)
    label, payload = (found.group(1), found.group(2)) if found else (None, value)
    if label is None and (prefix := DIGEST_LABEL.search(before[-16:])):
        label = prefix.group(1)
    size = _decoded_size(payload)
    if size is None:
        return False
    if label is not None:
        return size == DIGEST_BYTES[label.lower().replace("-", "")]
    words = WORD.findall(key)
    return bool(words) and words[-1].lower() in CHECKSUM_WORDS and size in set(DIGEST_BYTES.values())


def _version(value: str) -> bool:
    """A version specifier (`4.0.23(@types/node@22.13.14)`, `^1.2.3`, `npm:@scope/pkg@2.0.0-rc.1`), peers removed
    innermost first; never one whose pre-release reads as a token (capitals, small letters and digits, TOKENISH long)."""
    while (stripped := PEER.sub("", value)) != value:
        value = stripped
    if not VERSION_SPEC.fullmatch(value):
        return False
    return not any(len(part) >= TOKENISH and _classes(part) >= 3 for part in re.split(r"[.+-]", value))


def _pem_without_body(value: str) -> bool:
    """A PEM private key header whose body, up to the next `-----`, holds fewer base64 characters than any private key
    (`-----BEGIN PRIVATE KEY-----\\n...\\n-----END`, `…\\nabc\\n…`, `<your key>`)."""
    header = PEM_HEADER.search(value)
    if not header:
        return False
    body = ESCAPE.sub("", value[header.end():].split("-----", 1)[0])
    return len(re.findall(r"[A-Za-z0-9+/=]", body)) < PEM_BODY_MIN


def _object_around(text: str, at: int) -> str | None:
    """The `{…}` object that holds position `at` of `text`, braces counted; None when it doesn't open and close inside
    `text`."""
    depth, start = 0, None
    for index in range(at - 1, -1, -1):
        depth += {"}": 1, "{": -1}.get(text[index], 0)
        if depth < 0:
            start = index
            break
    if start is None:
        return None
    depth = 0
    for index in range(start, len(text)):
        depth += {"{": 1, "}": -1}.get(text[index], 0)
        if depth == 0:
            return text[start:index + 1]
    return None


def _key_material(text: str) -> bool:
    """A private key with its body anywhere in `text`, or a `private_key` field holding PEM_BODY_MIN base64 characters."""
    for header in PEM_HEADER.finditer(text):
        if not _pem_without_body(text[header.start():]):
            return True
    found = re.search(r"""["']?private_key["']?\s*:\s*["']([^"']*)""", text)
    return found is not None and len(re.findall(r"[A-Za-z0-9+/=]", ESCAPE.sub("", found.group(1)))) >= PEM_BODY_MIN


def marker(value: str | None) -> bool:
    """`value` is a type marker (a service account's `type` field): judging it needs the text around it (`around`)."""
    return bool(value) and bool(MARKER.fullmatch(str(value).strip()))


def keyless_marker(value: str | None, around: tuple[str, int] | None) -> bool:
    """A type marker (a service account's `type` field) whose object, read in `around` (text of its file and where the marker
    is in it), holds no key material: a description of a credential, not one. Without the text, or without the object's
    braces inside it, the marker stays a finding."""
    if around is None or not marker(value):
        return False
    found = _object_around(*around)
    return found is not None and not _key_material(found)


def around(root: Path | None, relative: str, offset: object) -> tuple[str, int] | None:
    """AROUND bytes of a snapshot file either side of byte `offset`, and where `offset` falls in them, for a marker's
    object (`keyless_marker`)."""
    if root is None or not isinstance(offset, int) or offset < 0:
        return None
    try:
        base = root.resolve()
        target = (root / relative).resolve()
        target.relative_to(base)
        with target.open("rb") as handle:
            start = max(0, offset - AROUND)
            handle.seek(start)
            raw = handle.read(offset - start + AROUND)
    except (OSError, ValueError):
        return None
    before = raw[:offset - start].decode("utf-8", "replace")
    return before + raw[offset - start:].decode("utf-8", "replace"), len(before)


def _download_link(before: str, value: str) -> bool:
    """The token of a Firebase Storage download link (`…/o/<object>?alt=media&token=<uuid>`)."""
    return bool(UUID.fullmatch(value)) and bool(DOWNLOAD_LINK.search(before[-2048:]))


def _password(key: str, value: str) -> str | None:
    if _reference(value):
        return "reference"
    if re.search(r"\s", value):
        return "prose"
    if any(pattern.fullmatch(value) for pattern in IDENTIFIER) and not (len(value) >= PASSPHRASE_MIN and PASSPHRASE.fullmatch(value)):
        return "identifier"
    lowered = value.lower().strip("[]()")
    if lowered in PLACEHOLDERS or lowered in key.replace("-", "_") or set(lowered) <= set("x*.?") or lowered.startswith(("your", "my-", "<")):
        return "placeholder"
    # The name of the slot, or a word that says the value is fake, with a short number and marks around it (`secret123`,
    # `Password1!`, `test_2024`): what a person writes to fill the field. An account's name with a number (`admin321`,
    # `root2024`) is a weak password people do deploy, and stays one.
    stem = re.fullmatch(r"[^a-z0-9]*([a-z]+)[^a-z0-9]*\d{1,4}[^a-z0-9]*", lowered)
    if stem and stem.group(1) in SLOT_WORDS:
        return "placeholder"
    if len(value) < STRONG or (_classes(value) < 2 and len(value) < LONG):
        return "weak"
    return None


def verdict(rule: str, path: str, line: str, value: str | None, around: tuple[str, int] | None = None) -> str | None:
    """Why a match of `rule` at `path` (its `line`, its `value` when it could be read, and for a type marker the text
    `around` it) isn't a finding, one of REASONS; None when it is one. A value that couldn't be read is a finding:
    nothing is set aside unseen."""
    if rule == GENERIC_PASSWORD and outside_code(path):
        return "path"
    value = (value or "").strip().strip("\"'`")
    if not value:
        return None
    before = _before(line, value)
    value = _operand(before, value)
    if not value:
        return "reference"
    if _public(value):
        return "public"
    if _unsigned(value):
        return "unsigned"
    if _pem_without_body(value) or keyless_marker(value, around):
        return "keyless"
    if _digest(before, _key(line, value), value):
        return "checksum"
    if _version(value):
        return "version"
    if _download_link(before, value):
        return "link"
    if rule == GENERIC_PASSWORD:
        return _password(key_of(line, value), value)
    if "\n" in value:
        return None
    if _reference(value):
        return "reference"
    if NAME.fullmatch(value) or any(pattern.fullmatch(value) for pattern in IDENTIFIER):
        return "identifier"
    if PLACEHOLDER_WORD.search(value) or ("password" not in rule and _run_placeholder(rule, value)):
        return "placeholder"
    return None
