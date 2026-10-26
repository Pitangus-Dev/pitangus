"""The one way free text an engine wrote, and every URL, are stored or shown: their structure and their common words,
never their values.

Pitangus stores no code or configuration (docs/findings.md, "What is stored"): a finding keeps where it is, its rule,
structural metadata and hashes, and its code is read from the repository when someone opens it (runs/code_view.py).
What is still stored as text is what tools and engines said: a message, an error, a step's detail, a web scanner's
evidence and attack, an imported SARIF's rule texts. Those may quote what they read, so each goes through `prose`
before anything stores or shows it. Rendering never decides whether something is a credential, and never keeps a word
for where it stands (a key, an operand, an argument): position saves no value.

* A **word** (a maximal run of letters, digits and `_`, in any script) stays only if it is in the `lexicon` (the words
  of programming languages, the product's own vocabulary in English and Spanish, and the common terms of code in
  render_terms.txt), or if it splits entirely (at `_`, at changes of case and at digits) into lexicon words and numbers
  of up to three digits, with at least as much of it in words of three or more letters as in two-letter ones. Any
  other word is replaced with PLACEHOLDER, wherever it is; a lone letter too, unless it is a word (`a`, `i`, `y`…).
* **Punctuation and operators** stay; runs of replaced words separated only by spaces become one PLACEHOLDER.
* A **URL** (`url`) is read the same way after percent-decoding, and loses its user information and every query and
  fragment value as well.

So a value survives only if it is made entirely of common words and numbers of up to three digits (`admin123` does;
`Winter2024Corp`, `xK9#mP2` and any random token don't).

Every URL stored or shown is rendered by `url`, a web finding's location and a run's target too. `location` (the form
0.13 stored them in: host and path names kept, token-shaped path segments replaced) is never stored or shown: a web
finding's identity reads it, through the keys of shared/web_keys.py, which keep only digests of its path.

Rendering is deterministic and idempotent.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from urllib.parse import unquote

# What replaces a value: the same mark masking used before 0.14, so a web finding's identity (which reads its location
# as stored) is the same before and after.
PLACEHOLDER = "***"
TEXT_MAX = 50_000
DIGITS_MAX = 3   # a number this long or shorter is structure (a count, a version, a port of a test server)

# The words of programming, query, shell and data languages.
KEYWORDS = frozenset("""
abstract and any as assert async await base bool boolean break byte case catch char class const continue debugger def
default defer del delete do double dynamic elif else enum except export extends extern false final finally float fn for
foreach from func function global go goto if impl implements import in include instanceof int interface internal is
lambda let long loop map match mod module mut namespace native new nil none nonlocal not null object of on or out
override package pass private protected pub public raise readonly record ref require require_once return sealed select
self short signed sizeof static str string struct super switch synchronized template then this throw throws trait
transient true try type typeof uint undefined union unless unsafe unsigned until use using val var virtual void
volatile when where while with yield yes no off nan inf
integer number bigint symbol never unknown list dict tuple set bytes float32 float64 int32 int64 uint32 uint64 usize
isize i32 i64 u8 u32 u64 f32 f64 rune error println printf print echo exit
insert into values update delete from where join left right inner outer full cross on group by order having limit offset
union all distinct create alter drop table view index trigger procedure grant revoke to with
begin commit rollback declare exec execute cursor fetch primary foreign references constraint unique check default
asc desc between like ilike exists cast coalesce count sum avg min max
fi esac done elif then do local readonly unset shift source trap wait sudo cd ls cat cp mv rm mkdir chmod chown grep sed
awk curl wget git docker npm pnpm pip python node java go make bash sh pwsh powershell kubectl helm terraform env set
arg label expose workdir entrypoint cmd
""".split())

URL_IN_TEXT = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]{1,20}://[^\s'\"`<>]+")
URL_START = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]{1,20}://")
_WORD = re.compile(r"\w+(?:['’]\w+)*")              # a contraction is one word (`doesn't`)
_URL_WORD = re.compile(r"(?:%[0-9A-Fa-f]{2}|\w)+")      # in a URL, a word may be percent-encoded in part or whole
_RUN = re.compile(r"\d+|\D+")
_CLITICS = frozenset({"s", "t", "d", "m", "ll", "re", "ve"})   # what follows an apostrophe in English (`app's`, `can't`)
_REPLACED_RUN = re.compile(re.escape(PLACEHOLDER) + r"(?:[ \t]+" + re.escape(PLACEHOLDER) + r")+")
_URL_TAIL = ".,;:)]}!?"


@lru_cache(maxsize=1)
def vocabulary() -> frozenset[str]:
    """The words the product itself writes (its message catalogs, English and Spanish, and render_words.txt) and the
    words of programming languages, lowercase. Only letters: no number, identifier or example value is one."""
    words: set[str] = set(KEYWORDS)
    here = Path(__file__).resolve().parent
    root = here / "i18n" / "locales"
    for line in (here / "render_words.txt").read_text(encoding="utf-8").splitlines():
        if not line.startswith("#"):
            words.update(word.lower() for word in line.split() if word.isalpha())

    def walk(value) -> None:
        if isinstance(value, str):
            words.update(word.lower() for word in re.findall(r"[^\W\d_]+(?:['’-][^\W\d_]+)*", re.sub(r"\{\{[^}]*\}\}|<[^>]*>", " ", value)))
        elif isinstance(value, dict):
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    for path in sorted(root.glob("*/*.json")):
        walk(json.loads(path.read_text(encoding="utf-8")))
    # A lone letter is a word in a sentence only as an article or a conjunction.
    return frozenset(word for word in words if len(word) > 1 or word in ("a", "e", "i", "o", "u", "y"))


@lru_cache(maxsize=1)
def lexicon() -> frozenset[str]:
    """Every word a rendered text may keep (see the module's docstring): `vocabulary`, the pieces of its hyphenated
    words and contractions (`built`, `in`, `don`), and the terms of code in render_terms.txt."""
    words = set(vocabulary())
    for word in list(words):
        words.update(piece for piece in re.split(r"['’-]", word) if len(piece) > 1)
    for line in (Path(__file__).resolve().parent / "render_terms.txt").read_text(encoding="utf-8").splitlines():
        if not line.startswith("#"):
            words.update(word.lower() for word in line.split() if word.isalnum())
    return frozenset(words)


def _cased(run: str) -> list[str]:
    """A run of letters split where its case changes: `getConnection` → get, Connection; `HTTPServer` → HTTP, Server."""
    pieces, start = [], 0
    for index in range(1, len(run)):
        left, right = run[index - 1], run[index]
        if (right.isupper() and not left.isupper()) or (left.isupper() and right.isupper() and index + 1 < len(run) and run[index + 1].islower()):
            pieces.append(run[start:index])
            start = index
    pieces.append(run[start:])
    return pieces


def pieces(word: str) -> list[str]:
    """A word's pieces: split at `_`, at digits and where its case changes (`DB_PASSWORD2x` → DB, PASSWORD, 2, x)."""
    found: list[str] = []
    for part in word.split("_"):
        for run in _RUN.findall(part):
            found.extend([run] if run[0].isdigit() else _cased(run))
    return found


@lru_cache(maxsize=65_536)
def kept(word: str) -> bool:
    """Whether a word stays (see the module's docstring): a lexicon word, a number of up to three digits, or lexicon
    words and such numbers joined, with at least as much of it in words of three or more letters as in two-letter ones
    (a random run splits into one- and two-letter pieces)."""
    if word.lower() in lexicon():
        return True
    if "'" in word or "’" in word:
        head, _, tail = word.replace("’", "'").rpartition("'")
        return tail.lower() in _CLITICS and kept(head)
    if word.isdigit():
        return len(word) <= DIGITS_MAX
    words = lexicon()
    long_ = short = 0
    for piece in pieces(word):
        if piece.isdigit():
            if len(piece) > DIGITS_MAX:
                return False
        elif len(piece) < 2 or piece.lower() not in words:
            return False
        elif len(piece) == 2:
            short += 2
        else:
            long_ += len(piece)
    return long_ > 0 and short <= long_


def _decoded(token: str) -> str:
    for _ in range(3):
        decoded = unquote(token)
        if decoded == token:
            break
        token = decoded
    return token


def _url_word(found: re.Match) -> str:
    token = found.group(0)
    if "%" not in token:
        return token if kept(token) else PLACEHOLDER
    # Kept only if it reads as common words both as written and decoded (`%0aCd` is `0aCd` to whoever reads it).
    return token if all(kept(word) for text in (token, _decoded(token)) for word in _WORD.findall(text)) else PLACEHOLDER


def _words(text: str) -> str:
    return _WORD.sub(lambda found: found.group(0) if kept(found.group(0)) else PLACEHOLDER, text)


def _parameters_shown(part: str) -> str:
    """A query or a fragment: each name read as words, each value replaced."""
    shown = []
    for piece in re.split(r"([&;])", part):
        name, equals, value = piece.partition("=")
        shown.append(_URL_WORD.sub(_url_word, name) + (equals + (PLACEHOLDER if value else "") if equals else ""))
    return "".join(shown)


def url(value: str) -> str:
    """A URL in a text as it may be shown: its scheme, host, port and path read word by word like any text (after
    percent-decoding), its user information and every query and fragment value replaced. Idempotent; anything that
    isn't a URL unchanged."""
    if not isinstance(value, str) or not (head := URL_START.match(value)):
        return value
    start = head.end()
    authority_end = next((index for index in range(start, len(value)) if value[index] in "/?#"), len(value))
    at = value.rfind("@", start, authority_end)
    authority = (PLACEHOLDER + value[at:authority_end]) if at > start else value[start:authority_end]
    rest = value[authority_end:]
    fragment_at = rest.find("#")
    fragment = rest[fragment_at + 1:] if fragment_at >= 0 else None
    rest = rest[:fragment_at] if fragment_at >= 0 else rest
    query_at = rest.find("?")
    query = rest[query_at + 1:] if query_at >= 0 else None
    path = rest[:query_at] if query_at >= 0 else rest
    shown = _URL_WORD.sub(_url_word, value[:start] + authority + path)
    if query is not None:
        shown += "?" + _parameters_shown(query)
    if fragment is not None:
        shown += "#" + _parameters_shown(fragment)
    return shown


def _rendered(text: str) -> str:
    pieces_: list[str] = []
    last = 0
    for found in URL_IN_TEXT.finditer(text):
        link = found.group(0).rstrip(_URL_TAIL)
        pieces_.append(_words(text[last:found.start()]))
        pieces_.append(url(link))
        last = found.start() + len(link)
    pieces_.append(_words(text[last:]))
    return _REPLACED_RUN.sub(PLACEHOLDER, "".join(pieces_))


def prose(text: str) -> str:
    """Free text an engine or a tool wrote (a message, an error, a web scanner's evidence) as its structure and its
    common words (see the module's docstring)."""
    if not isinstance(text, str) or not text:
        return text
    head, tail = text[:TEXT_MAX], text[TEXT_MAX:]
    return _rendered(head) + (PLACEHOLDER if tail else "")


# --- Location form ---------------------------------------------------------------------------------------------
# What a web finding's identity reads of a URL (findings/canonical.py, through shared/web_keys.py): a path segment stays
# unless it is shaped like a token. Never stored or shown: every URL is, rendered by `url`.

_RUNS = re.compile(r"(?P<upper>[A-Z]+)|(?P<lower>[a-z]+)|\d+")
_PREFIXED = (r"(?:gh[pousr]_|github_pat_|glpat-|gldt-|glptt-|glrt-|xox[abposr]-|xapp-|sk_(?:live|test)_|rk_(?:live|test)_"
             r"|whsec_|sk-(?:proj-|ant-|svcacct-)?|hf_|shp(?:at|ss|ca|pa)_|dop_v1_|doo_v1_|sbp_|sb_secret_|ATATT|npm_|pypi-"
             r"|AIza|SG\.|figd_|lin_api_|pat-na1-|xkeysib-)")
_TOKEN_SHAPES = (re.compile(_PREFIXED + r"[A-Za-z0-9_.\-]{8,}"), re.compile(r"(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|ABIA|ACCA)[A-Z0-9]{16}"),
                 re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*"), re.compile(r"[0-9a-fA-F]{32,}"))
_TOKEN_RUN = re.compile(r"[A-Za-z0-9+/_~=-]{20,}")
_CONSONANTS = re.compile(r"[b-df-hj-np-tv-xz]{5,}", re.I)
_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_SHORT_HEX = re.compile(r"[0-9a-fA-F]{16,}")
_DIGEST_LEAD = re.compile(r"(?:sha(?:1|224|256|384|512)[:-]|md5[:-]|@|commit/|/blob/|/tree/|integrity\W{0,4})$", re.I)


def _identifier_words(text: str) -> list[str]:
    """The words an identifier is written with: lower, Capitalized, CAPS and numbers ("HTTPServer2" is HTTP, Server
    and 2). Built from runs of one kind of character, each read once: the capital right before lowercase letters
    starts the next word."""
    words: list[str] = []
    caps_end = -1
    for run in _RUNS.finditer(text):
        if run.lastgroup == "lower" and run.start() == caps_end:
            caps = words.pop()
            if len(caps) > 1:
                words.append(caps[:-1])
            words.append(caps[-1] + run.group())
        else:
            words.append(run.group())
        if run.lastgroup == "upper":
            caps_end = run.end()
    return words


def plain_share(text: str) -> float:
    """How much of `text` is words (lower, Capitalized, short CAPS) and short numbers, as identifiers, paths and names
    are written; a random run is mostly one- and two-letter pieces."""
    words = _identifier_words(text)
    shouting = not any(character.islower() for character in text)
    plain = sum(len(word) for word in words if not ((word.isdigit() and len(word) > 7) or (word.isupper() and len(word) > (40 if shouting else 4))
                                                    or (word[-1].islower() and sum(ch.islower() for ch in word) < 2)))
    return plain / max(1, sum(map(len, words)))


def _kind(character: str) -> str:
    return "u" if character.isupper() else "l" if character.islower() else "d" if character.isdigit() else "s"


def random_looking(token: str) -> bool:
    """A run of key characters that reads as random (a key, a base64 blob), not as words (an identifier, a path)."""
    body = token.rstrip("=")
    if len(body) < 20:
        return False
    kinds = [_kind(character) for character in body]
    if "d" not in kinds and not ("u" in kinds and "l" in kinds):
        return False
    transitions = sum(left != right for left, right in zip(kinds, kinds[1:])) / (len(body) - 1)
    letters = kinds.count("u") + kinds.count("l")
    if "d" in kinds and letters and 0.3 <= kinds.count("u") / letters <= 0.7 and transitions >= 0.4:
        return True
    if plain_share(body) >= 0.8:
        return False
    return transitions >= 0.3


def _reads_as_words(text: str) -> bool:
    if not any(character.islower() for character in text):
        return any(character in "-_" for character in text) or not any(character.isdigit() for character in text)
    words = _identifier_words(text)
    mixed = any(character.isupper() for character in text)
    return all(word.isdigit() or not (word.isupper() or (mixed and _CONSONANTS.search(word))) for word in words) and \
        sum(len(word) for word in words if len(word) >= 3) >= 0.7 * sum(map(len, words))


def token_shaped(text: str) -> bool:
    """Whether a URL's path segment or fragment is a token (a JWT, a provider token, a long hex or random run), not a
    name, a number or an identifier (a UUID is one)."""
    text = unquote(text)
    if len(text) < 16 or _UUID.fullmatch(text):
        return False
    if _TOKEN_SHAPES[1].fullmatch(text):   # an AWS key id: its fixed length and alphabet are the shape, letters only or not
        return True
    if any(shape.fullmatch(text) for shape in _TOKEN_SHAPES):
        return not text.isalpha() and not text.isdigit()
    return bool(_TOKEN_RUN.fullmatch(text)) and (random_looking(text) or not _reads_as_words(text))


def segment_kept(segment: str, after: str = "") -> bool:
    """Whether a URL's path segment is kept: a name (letters, digits and `._~%@:+-`) that isn't shaped like a token
    (`token_shaped`); a digest after `commit/`, `@`… is kept."""
    if segment == PLACEHOLDER or not segment:
        return True
    if not re.fullmatch(r"[\w.~%@:+-]+", segment):
        return False
    if "@" in segment:   # `name@host`, `@scope`: each side on its own (a token glued to a host isn't a name)
        return all(segment_kept(piece, after) for piece in segment.split("@"))
    if not token_shaped(segment):
        return True
    return bool(_SHORT_HEX.fullmatch(segment) and _DIGEST_LEAD.search(after[-12:]))


def _parameters(part: str) -> str:
    """A query or a fragment with every value replaced and its names kept; a piece without `=` (an anchor) is kept only
    when it is made of words of the vocabulary."""
    pieces = re.split(r"([&;])", part)
    out = []
    for piece in pieces:
        if piece in ("&", ";") or not piece:
            out.append(piece)
            continue
        key, equals, value = piece.partition("=")
        if equals:
            out.append(f"{key if _key_shaped(unquote(key)) else PLACEHOLDER}={PLACEHOLDER if value else ''}")
        else:
            out.append(piece if piece == PLACEHOLDER or all(part.lower() in vocabulary() for part in re.split(r"[-_]", piece))
                       else PLACEHOLDER)
    return "".join(out)


def _key_shaped(key: str) -> bool:
    return key == PLACEHOLDER or bool(re.fullmatch(r"[A-Za-z_][\w.\-\[\]]{0,63}", key))


def location(value: str) -> str:
    """A location with its user information, its query, fragment and matrix values and its path segments that aren't
    structure (`segment_kept`) replaced; scheme, host, port and the rest kept. Idempotent; anything else unchanged."""
    if not isinstance(value, str) or not URL_START.match(value):
        return value
    head = URL_START.match(value)
    assert head is not None
    start = head.end()
    authority_end = next((index for index in range(start, len(value)) if value[index] in "/?#"), len(value))
    # `user:password@host`: a password may hold `/`, `?` or `#` unencoded, so its user information runs to the last `@`.
    # Ambiguous too, and taken as user information: what reads as a port followed by an `@` later in the path
    # (`deploy:6/…@host`: a password that starts with digits), and an `@` in a path segment that isn't structure.
    colon = value.find(":", start, authority_end)
    port_like = colon >= 0 and bool(re.fullmatch(r"\d{0,5}", value[colon + 1:authority_end]))
    path_end = next((index for index in range(authority_end, len(value)) if value[index] in "?#"), len(value))
    last_at = value.rfind("@", authority_end, path_end)
    doubtful = last_at >= 0 and not all(segment_kept(segment.split(";")[0]) for segment in value[authority_end:path_end].split("/"))
    if colon >= 0 and not port_like and value.rfind("@") > authority_end:
        authority_end = next((index for index in range(value.rfind("@"), len(value)) if value[index] in "/?#"), len(value))
    elif last_at >= 0 and (port_like or doubtful):
        authority_end = next((index for index in range(last_at, len(value)) if value[index] in "/?#"), len(value))
    authority = value[start:authority_end]
    at = authority.rfind("@")
    if at >= 0:
        authority = (PLACEHOLDER if authority[:at] else "") + authority[at:]
    host = authority[authority.rfind("@") + 1:]
    _, has_port, port = host.rpartition(":") if not host.endswith("]") else (host, "", "")
    if has_port and not (port.isdigit() and len(port) <= 5) and port != PLACEHOLDER:
        authority = authority[:len(authority) - len(port)] + PLACEHOLDER
    rest = value[authority_end:]
    fragment_at = rest.find("#")
    fragment = rest[fragment_at + 1:] if fragment_at >= 0 else None
    rest = rest[:fragment_at] if fragment_at >= 0 else rest
    query_at = rest.find("?")
    query = rest[query_at + 1:] if query_at >= 0 else None
    path = rest[:query_at] if query_at >= 0 else rest
    segments, walked = [], value[:authority_end]
    for segment in path.split("/"):
        name_, *matrix = segment.split(";")
        rendered = name_ if segment_kept(name_, walked) else PLACEHOLDER
        for parameter in matrix:
            key, equals, item = parameter.partition("=")
            rendered += ";" + (f"{key if _key_shaped(key) else PLACEHOLDER}={PLACEHOLDER if item else ''}" if equals
                               else (parameter if parameter == PLACEHOLDER or all(part.lower() in vocabulary() for part in re.split(r"[-_]", parameter))
                                     else PLACEHOLDER))
        segments.append(rendered)
        walked += segment + "/"
    result = value[:start] + authority + "/".join(segments)
    if query is not None:
        result += "?" + _parameters(query)
    if fragment is not None:
        result += "#" + _parameters(fragment)
    return result
