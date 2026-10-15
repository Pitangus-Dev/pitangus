"""Where a secret's value is: verified against what its engine said, never assumed from where it pointed.

An engine says where a secret is (a line and columns, a byte offset) and things about it that don't depend on where:
its redacted match, how many bytes it has, its entropy, the text it masked around it. Each report is a `Claim`: the
lines it names and that evidence. Every spot of those lines that fits the evidence is a candidate (`Claim.spots`): the
whole line is searched, so nothing depends on a position being right. A position then picks among the candidates:

* an offset from the start of the file (Trivy's) that lands on a spot that fits pins it: the masked text around it,
  literal where the engine shows it, has to be there too;
* a column (Betterleaks') that lands on a spot that fits names it only in a file the engine reads in one piece
  (`Claim.column_reach`): past its first read it may count a column from wherever a later piece starts, even in the
  middle of a short line, without saying so;
* without a position, every place of the line where the evidence fits and no position names must hold one same value:
  a place's value is the one all its spots contain (a run of the same length shifted over a secret reads, out to the
  token's edges, as the secret and something around it), and only its exact spots are occurrences. A column past the
  engine's first piece still says the value starts there or later: the places from there on are enough when they
  hold one same value.

Reports one engine made alike (the same lines, the same evidence) can't be told apart, so they are resolved together:
one finding per place where the value is, never more (an engine that reported one secret twice reports it once), and
columns that name overlapping spots name one occurrence (of one value, or of none when they disagree).

A report over several lines (a private key) is read where it says, from its first to its last line, and kept only if
the evidence holds there (the same redacted match and entropy, the same masked text line by line); its value is that
text with its line endings normalized.

An UNLINKABLE report (no spot fits, the spots hold several values nothing tells apart, the file can't be read) gets no
value: it is named by its rule, its file and the content of the lines it names (`secret_identity.unlinkable`), so the
same content gives the same name and any change gives another. That name is never a former name and never another
report's (findings/identity.py): it links nothing and inherits nothing.
"""

from __future__ import annotations

import hashlib
import math
import re
import struct
from collections.abc import Callable, Sequence
from bisect import bisect_left
from contextvars import ContextVar
from itertools import accumulate
from pathlib import Path
from typing import NamedTuple

from pitangus.modules.scanning import secret_identity

MULTILINE = 200          # lines a report may span and still be read for its value (a private key fits)
FILE_MAX = 64 << 20      # bytes of a file read for the lines a report names


class Claim(NamedTuple):
    """What one engine reported about one secret."""
    rule: str
    path: str
    first: int                      # its first and last lines (1-based; lines end at "\n", as both engines count them)
    last: int
    evidence: tuple                 # everything it said about the secret but where: reports alike can't be told apart
    spots: Callable[[bytes], list[tuple[int, int, int, int]]] | None
    # ^ one line: every (match start, match end, value start, value end) of the line, in bytes, that fits the evidence
    block: Callable[[bytes, int | None], tuple[int, int, int, int] | None] | None
    # ^ several lines: (match start, match end, value start, value end) in the lines joined by "\n" where the evidence
    #   holds, or None; the second argument is `offset` on the first line
    column: int | None = None       # where it says the value starts on its first line (bytes)
    column_reach: int = 0           # in files up to this many bytes the engine certainly counts `column` from the line's start
    offset: int | None = None       # where it says the value starts in the file (bytes): pins it when the text agrees
    layer: str | None = None        # what names the content when there is no file to read (an image layer's digest)


class Read(NamedTuple):
    """What a claim resolved to: a value (its names, where it is), a report of a value another claim already holds
    (`duplicate`), or an unlinkable name."""
    names: secret_identity.Names | None = None
    value: str | None = None        # read to name and judge it, never stored
    span: list[int] | None = None   # line, start, end line, end of the value (characters, 0-based)
    match: str | None = None        # the whole match there, line endings normalized: the formula before (a former name)
    unlinkable: str | None = None
    duplicate: bool = False


class Lines(NamedTuple):
    raw: dict[int, bytes]           # the lines wanted, without their "\n" (a "\r" stays)
    starts: dict[int, int]          # where each starts in the file (bytes)
    digest: str                     # the whole file's content, line endings normalized
    size: int                       # bytes of the file


def normalized(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _lines(root: Path, path: str, wanted: set[int]) -> Lines | None:
    target = secret_identity._inside(root, path)
    if target is None:
        return None
    raw: dict[int, bytes] = {}
    starts: dict[int, int] = {}
    content = hashlib.sha256()
    offset = 0
    try:
        if target.stat().st_size > FILE_MAX:
            return None
        with target.open("rb") as handle:
            for number, line in enumerate(handle, 1):
                if number in wanted:
                    raw[number], starts[number] = line[:-1] if line.endswith(b"\n") else line, offset
                content.update(line.replace(b"\r\n", b"\n").replace(b"\r", b"\n"))
                offset += len(line)
    except OSError:
        return None
    return Lines(raw, starts, content.hexdigest(), offset)


def _text(data: bytes) -> str:
    return data.decode("utf-8", "surrogateescape")


def _unlinkable(claim: Claim, lines: Lines | None) -> Read:
    """The claim's unlinkable name: from the content of the lines it names, else of its whole file, else of the layer
    it is in; with none of them, a name no other report will ever have."""
    content = None
    if lines is not None:
        block = [lines.raw[number] for number in range(claim.first, claim.last + 1) if number in lines.raw]
        content = normalized(_text(b"\n".join(block))).encode("utf-8", "surrogateescape") \
            if claim.first >= 1 and len(block) == claim.last - claim.first + 1 else ("file:" + lines.digest).encode()
    elif claim.layer:
        content = ("layer:" + claim.layer).encode()
    return Read(unlinkable=secret_identity.unlinkable(claim.rule, claim.path, content))


def _value(tokens: "_Tokens", chars: "_Columns", number: int, spot: tuple[int, int, int, int]) -> Read | None:
    match_start, match_end, start, end = (chars(item) for item in spot)
    value = tokens.whole(start, end)
    names = secret_identity.names(value)
    if names is None:
        return None
    return Read(names=names, value=value, span=[number, start, number, end], match=tokens.whole(match_start, match_end))


def _clusters(spots: list[tuple[int, int, int, int]]) -> list[list[tuple[int, int, int, int]]]:
    """`spots` grouped into places: spots that overlap (a run of the same length shifted over one secret keeps its
    entropy) are one place."""
    places: list[list[tuple[int, int, int, int]]] = []
    reach = -1
    for spot in sorted(spots):
        if places and spot[0] < reach:
            places[-1].append(spot)
        else:
            places.append([spot])
        reach = max(reach, spot[1]) if len(places[-1]) > 1 else spot[1]
    return places


def _outside(spots: list[tuple[int, int, int, int]], others: list[tuple[int, int, int, int]]) -> list[tuple[int, int, int, int]]:
    """The spots of `spots` that overlap none of `others`."""
    others = sorted(others)
    starts = [item[0] for item in others]
    reach, running = [], -1
    for item in others:
        running = max(running, item[1])
        reach.append(running)
    return [spot for spot in spots if (at := bisect_left(starts, spot[1]) - 1) < 0 or reach[at] <= spot[0]]


class _Tokens:
    """`secret_identity._whole` over one line, read once: where each run of token characters starts and ends, so a
    line full of candidates (a blob in a bundle) is walked once, not once per candidate."""

    def __init__(self, text: str):
        self.text = text
        back = "".join(sorted(secret_identity.TOKEN))
        self.back = [(found.start(), found.end()) for found in re.finditer(f"[{re.escape(back)}]+", text)]
        self.forth = [(found.start(), found.end()) for found in re.finditer(f"[{re.escape(back + '=')}]+", text)]
        self.back_starts = [run[0] for run in self.back]
        self.forth_starts = [run[0] for run in self.forth]

    def whole(self, start: int, end: int) -> str:
        limit = secret_identity.VALUE_MAX + 1
        if start > 0:
            at = bisect_left(self.back_starts, start) - 1     # the run holding start - 1, if any
            if at >= 0 and self.back[at][1] >= start:
                start = max(self.back[at][0], start - limit, 0)
        if end < len(self.text):
            at = bisect_left(self.forth_starts, end + 1) - 1   # the run holding end, if any
            if at >= 0 and self.forth[at][0] <= end < self.forth[at][1]:
                end = min(self.forth[at][1], end + limit, len(self.text))
        return self.text[start:end]


class _Columns:
    """Byte offsets of one line as character offsets."""

    def __init__(self, line: bytes):
        self.ascii = line.isascii()
        if not self.ascii:
            text = _text(line)
            self.starts = list(accumulate((len(char.encode("utf-8", "surrogateescape")) for char in text), initial=0))

    def __call__(self, offset: int) -> int:
        return offset if self.ascii else bisect_left(self.starts, offset)


class _Group(NamedTuple):
    members: list[int]
    spots: list[tuple[int, int, int, int]]
    pinned: dict[int, tuple[int, int, int, int]]     # by an offset from the file's start
    anchored: dict[int, tuple[int, int, int, int]]   # by a column
    loose: list[int]


def _group(claims: Sequence[Claim], members: list[int], line: bytes, start: int, size: int) -> _Group:
    claim = claims[members[0]]
    spots = sorted(set(claim.spots(line))) if claim.spots else []
    at_value: dict[int, tuple[int, int, int, int]] = {}
    for spot in spots:
        at_value.setdefault(spot[2], spot)
    offsets = {index: offset - start for index in members if (offset := claims[index].offset) is not None}
    pinned = {index: at_value[here] for index, here in offsets.items() if here in at_value}
    taken = set(pinned.values())
    columns = {index: column for index in members if index not in pinned and (column := claims[index].column) is not None
               and size <= claims[index].column_reach}
    anchored = {index: at_value[column] for index, column in columns.items() if column in at_value and at_value[column] not in taken}
    return _Group(members, spots, pinned, anchored, [index for index in members if index not in pinned and index not in anchored])


def _core(values: list[str]) -> str | None:
    """The value a place holds: one of its spots' values that every other one contains (a run of the same length
    shifted over a secret reads, out to the token's edges, as the secret and something around it); None when no value
    is in all of them (the place could be several things)."""
    shortest = min(values, key=len)
    return shortest if all(shortest in value for value in values) else None


def _one_line(claims: Sequence[Claim], groups: list[_Group], lines: Lines, number: int, results: list[Read | None]) -> None:
    """The claims of one line, by group of claims alike (see the module's docstring). An offset from the file's start
    or a column the engine certainly counts from the line's start, landing on a spot that fits, names it (overlapping
    spots named that way are one occurrence: of one value, or unlinkable when they disagree). The rest are read without
    positions: every place of the line where the evidence fits and nobody named must hold one same value. Claims beyond
    the places they can be are duplicates."""
    line = lines.raw[number]
    text, chars = _text(line), _Columns(line)
    tokens = _Tokens(text)
    named: dict[object, list[tuple[int, int, int, int]]] = {}
    for group in groups:
        named.setdefault(claims[group.members[0]].evidence[:1], []).extend([*group.pinned.values(), *group.anchored.values()])

    def value_of(spot: tuple[int, int, int, int]) -> str:
        return tokens.whole(chars(spot[2]), chars(spot[3]))

    for group in groups:
        taken: set[tuple] = set()

        def give(index: int, spot: tuple[int, int, int, int], taken: set[tuple] = taken) -> None:
            if spot in taken:
                results[index] = Read(duplicate=True)
            else:
                taken.add(spot)
                results[index] = _value(tokens, chars, number, spot) or _unlinkable(claims[index], lines)

        for index, spot in group.pinned.items():
            give(index, spot)
        for occurrence in _clusters(list(set(group.anchored.values()))):
            claimed = [index for index, spot in group.anchored.items() if spot in occurrence]
            if len({value_of(spot) for spot in occurrence}) == 1:
                give(claimed[0], group.anchored[claimed[0]])
            else:
                results[claimed[0]] = _unlinkable(claims[claimed[0]], lines)
            for index in claimed[1:]:
                results[index] = Read(duplicate=True)
        if not group.loose:
            continue
        places = _clusters(_outside([spot for spot in group.spots if spot not in taken], named[claims[group.members[0]].evidence[:1]]))
        if not places:
            # Every place that fits is named: these said one of them again. With none at all, nothing is read.
            for index in group.loose:
                results[index] = Read(duplicate=True) if group.spots else _unlinkable(claims[index], lines)
            continue
        cores = [_core([value_of(spot) for spot in place]) for place in places]
        if None not in cores and len(set(cores)) == 1:
            # One value everywhere: its occurrences are the spots that read as exactly it (copies side by side can
            # share a place).
            found = [spot for place in places for spot in place if value_of(spot) == cores[0]]
            for count, index in enumerate(group.loose):
                if count >= len(found):
                    results[index] = Read(duplicate=True)      # no more secrets than places where one fits
                else:
                    give(index, found[count])
            continue
        # Several values: a report is read only when every place it can be holds one same value (a column past the
        # engine's first piece still says the value starts there or later: it counts from a later cut of the line,
        # test_secret_location.RealEnginesTests.test_columns_count_from_the_line). How many reports there are says
        # nothing about which places they are: one engine may report one secret twice (its pieces overlap).
        exact = [[spot for spot in place if core is not None and value_of(spot) == core] for place, core in zip(places, cores)]
        ambiguous, given = [], 0
        for index in group.loose:
            claim = claims[index]
            bound = claim.column if claim.column is not None and lines.size > claim.column_reach else -1
            held, here = set(), []
            for place, core, spots in zip(places, cores, exact):
                if max(spot[2] for spot in place) >= bound:
                    after = [spot for spot in spots if spot[2] >= bound]
                    held.add(core if after else None)
                    here += after
            if len(held) != 1 or None in held:
                ambiguous.append(index)
            elif (free := next((spot for spot in here if spot not in taken), None)) is None:
                results[index] = Read(duplicate=True)      # every place of its value is read already
            else:
                give(index, free)
                given += 1
        for count, index in enumerate(ambiguous):
            # No more secrets than places where one fits.
            results[index] = _unlinkable(claims[index], lines) if given + count < len(places) else Read(duplicate=True)


def _several_lines(claim: Claim, lines: Lines) -> Read:
    block = b"\n".join(lines.raw[number] for number in range(claim.first, claim.last + 1))
    offset = claim.offset - lines.starts[claim.first] if claim.offset is not None else None
    found = claim.block(block, offset) if claim.block else None
    if found is None:
        return _unlinkable(claim, lines)
    match_start, match_end, start, end = found
    value = normalized(_text(block[start:end]))
    names = secret_identity.names(value)
    if names is None:
        return _unlinkable(claim, lines)

    def place(position: int) -> tuple[int, int]:
        breaks = block.count(b"\n", 0, position)
        begin = block.rfind(b"\n", 0, position) + 1
        return claim.first + breaks, len(_text(block[begin:position]))
    (line, column), (end_line, end_column) = place(start), place(end)
    return Read(names=names, value=value, span=[line, column, end_line, end_column], match=normalized(_text(block[match_start:match_end])))


def resolve(root: Path | None, claims: Sequence[Claim]) -> list[Read]:
    """What each claim's value is, or that it is unlinkable or a duplicate (see the module's docstring)."""
    token = _budget.set({"left": WINDOW_BUDGET, "seen": {}})
    try:
        return _resolve(root, claims)
    finally:
        _budget.reset(token)


def _resolve(root: Path | None, claims: Sequence[Claim]) -> list[Read]:
    wanted: dict[str, set[int]] = {}
    for claim in claims:
        if 1 <= claim.first <= claim.last <= claim.first + MULTILINE:
            wanted.setdefault(claim.path, set()).update(range(claim.first, claim.last + 1))
    files = {path: _lines(root, path, numbers) for path, numbers in wanted.items()} if root is not None else {}
    results: list[Read | None] = [None] * len(claims)
    groups: dict[tuple, list[int]] = {}
    for index, claim in enumerate(claims):
        lines = files.get(claim.path)
        if lines is None or not 1 <= claim.first <= claim.last <= claim.first + MULTILINE \
                or any(number not in lines.raw for number in range(claim.first, claim.last + 1)):
            results[index] = _unlinkable(claim, lines if root is not None else None)
        elif claim.first == claim.last:
            groups.setdefault((claim.path, claim.first, claim.evidence), []).append(index)
        else:
            results[index] = _several_lines(claim, lines)
    by_line: dict[tuple[str, int], list[_Group]] = {}
    for (path, number, _), members in groups.items():
        read = files[path]
        assert read is not None    # only claims whose lines were read are grouped
        by_line.setdefault((path, number), []).append(_group(claims, members, read.raw[number], read.starts[number], read.size))
    for (path, number), line_groups in by_line.items():
        read = files[path]
        assert read is not None
        _one_line(claims, line_groups, read, number, results)
    # One engine reporting the same lines twice over the same span reads them once.
    seen: set[tuple] = set()
    for index, result in enumerate(results):
        if result is not None and result.span is not None and claims[index].first != claims[index].last:
            key = (claims[index].evidence, claims[index].path, tuple(result.span))
            if key in seen:
                results[index] = Read(duplicate=True)
            seen.add(key)
    return [result if result is not None else _unlinkable(claim, None) for result, claim in zip(results, claims)]


# --- the evidence --------------------------------------------------------------------------------------------------

def entropy(value: str) -> float:
    """Shannon entropy as Gitleaks and Betterleaks compute it for a secret: by character, over its length in bytes."""
    size = len(value.encode("utf-8", "surrogateescape"))
    if not size:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    return -sum(count / size * math.log2(count / size) for count in counts.values())


def _single(value: float) -> float:
    return struct.unpack("f", struct.pack("f", value))[0]


def same_entropy(value: str, reported: float | None) -> bool:
    """Whether `value` has the entropy an engine reported (a 32-bit float, its sum in any order)."""
    return reported is None or abs(_single(entropy(value)) - _single(reported)) <= 2e-6 * max(1.0, abs(reported))


def _windows(line: bytes, size: int) -> dict[int, list[int]]:
    """Every run of `size` bytes of `line` by its entropy in thousandths (where it starts, in bytes): read once per line
    and length, however many matches of that length the line has."""
    text = _text(line)
    widths = None if text.isascii() else [len(char.encode("utf-8", "surrogateescape")) for char in text]
    found: dict[int, list[int]] = {}
    xlog = [count * math.log2(count) if count else 0.0 for count in range(size + 2)]
    log_size = math.log2(size)
    counts: dict[str, int] = {}
    total = 0.0
    chars = start = width = byte_start = 0
    for end, char in enumerate(text):
        count = counts.get(char, 0)
        total += xlog[count + 1] - xlog[count]
        counts[char] = count + 1
        chars += 1
        width += widths[end] if widths else 1
        while width > size:
            out = text[start]
            count = counts[out]
            total += xlog[count - 1] - xlog[count]
            counts[out] = count - 1
            chars -= 1
            step = widths[start] if widths else 1
            width -= step
            byte_start += step
            start += 1
        if width == size:
            found.setdefault(round((chars * log_size - total) / size * 1000), []).append(byte_start)
    return found


# Characters the runs of a match that is all value (`REDACTED`) are looked for in, per call of `resolve`: one run per
# length over every long line holding one costs that much, so past it what is left can't be verified (unlinkable).
WINDOW_BUDGET = 16_000_000
_budget: ContextVar[dict | None] = ContextVar("secret_location_budget", default=None)


def _redacted_windows(line: bytes, size: int, reported: float) -> list[int]:
    """Where every run of `size` bytes of `line` whose entropy is `reported` starts (a match that is all value), or
    none when the budget of this resolution is spent."""
    if size < 1 or size > len(line):
        return []
    state = _budget.get()
    seen = state["seen"] if state is not None else {}
    buckets = seen.get((line, size))
    if buckets is None:
        if state is not None:
            if state["left"] < len(line):
                return []
            state["left"] -= len(line)
            if len(seen) >= 4:
                seen.clear()
        buckets = seen[(line, size)] = _windows(line, size)
    near = round(reported * 1000)
    return sorted(start for bucket in (near - 1, near, near + 1) for start in buckets.get(bucket, ())
                  if same_entropy(_text(line[start:start + size]), reported))


def betterleaks_spots(match: str, size: int, reported: float | None, line: bytes,
                      value_span: Callable[[str, str], tuple[int, int] | None]) -> list[tuple[int, int, int, int]]:
    """Where on `line` a Betterleaks match fits: `size` bytes that read as its redacted `match` (the same text around
    REDACTED, every copy of the value alike: `value_span`), with the value's entropy `reported`."""
    if "REDACTED" not in match or not 0 < size <= len(line):
        return []
    pieces = match.split("REDACTED")
    lead, tail = pieces[0].encode("utf-8", "surrogateescape"), pieces[-1].encode("utf-8", "surrogateescape")
    if lead:
        starts = [found.start() for found in re.finditer(re.escape(lead), line)]
    elif tail:
        starts = [found.end() - size for found in re.finditer(re.escape(tail), line) if found.end() >= size]
    elif reported is not None:
        starts = _redacted_windows(line, size, reported)
    else:
        return []    # nothing but its length: every run of that length fits
    spots = []
    for start in starts:
        window = _text(line[start:start + size])
        found = value_span(match, window)
        if len(line) < start + size or found is None or not same_entropy(window[found[0]:found[1]], reported):
            continue
        spots.append((start, start + size, start + len(window[:found[0]].encode("utf-8", "surrogateescape")),
                      start + len(window[:found[1]].encode("utf-8", "surrogateescape"))))
    return spots


def betterleaks_block(match: str, reported: float | None, start: int, end: int,
                      value_span: Callable[[str, str], tuple[int, int] | None], block: bytes, _offset: int | None):
    """A Betterleaks match over several lines (`block`, joined by "\\n"): from byte `start` of the first line to byte
    `end` of the last, read as its redacted `match` with the value's entropy `reported`."""
    last = block.rfind(b"\n") + 1
    if start < 0 or end < 1 or last + end > len(block) or start >= last + end:
        return None
    window = _text(block[start:last + end])
    found = value_span(match, window)
    if found is None or not same_entropy(window[found[0]:found[1]], reported):
        return None
    return (start, last + end, start + len(window[:found[0]].encode("utf-8", "surrogateescape")),
            start + len(window[:found[1]].encode("utf-8", "surrogateescape")))


def _masked_pattern(masked: bytes) -> tuple[re.Pattern[bytes], list[tuple[int, int]]] | None:
    """`masked` (text with one `*` per byte of a secret) as a pattern of the text it masks, and its runs of `*`."""
    runs = [(found.start(), found.end()) for found in re.finditer(rb"\*+", masked)]
    if not runs:
        return None
    parts, at = [], 0
    for start, end in runs:
        parts += [re.escape(masked[at:start]), b"[\\s\\S]{%d}" % (end - start)]
        at = end
    parts.append(re.escape(masked[at:]))
    return re.compile(b"(?=(" + b"".join(parts) + b"))"), runs


def _variants(line: bytes) -> list[tuple[bytes, list[int] | None]]:
    """`line` as written and, when it has carriage returns, without them (Trivy drops the ones it doesn't mask), with
    where each byte left was."""
    if b"\r" not in line:
        return [(line, None)]
    return [(line, None), (line.replace(b"\r", b""), [index for index, byte in enumerate(line) if byte != 13])]


def trivy_spots(masked: bytes, line: bytes) -> list[tuple[int, int, int, int]]:
    """Where on `line` Trivy's masked text fits (its literal text where it shows it, a byte under each `*`), as written
    or without carriage returns: each masked run there is a spot."""
    pattern = _masked_pattern(masked)
    if pattern is None:
        return []
    compiled, runs = pattern
    spots = set()
    for text, where in _variants(line):
        for found in compiled.finditer(text):
            for start, end in runs:
                begin, finish = found.start() + start, found.start() + end
                if where is not None:
                    begin, finish = where[begin], where[finish - 1] + 1
                spots.add((begin, finish, begin, finish))
    return sorted(spots)


def _fits(masked: bytes, line: bytes, at: int) -> bool:
    for text, where in _variants(line):
        position = at if where is None else next((index for index, raw in enumerate(where) if raw >= at), len(text))
        if position >= 0 and len(text) >= position + len(masked) and all(
                mark == 42 or mark == byte for mark, byte in zip(masked, text[position:position + len(masked)])):
            return True
    return False


def trivy_block(masked: bytes, code: dict[int, bytes], first: int, block: bytes, offset: int | None):
    """A Trivy secret over several lines (`block`, joined by "\\n"): its masked first line (`masked`) fits there with a
    run starting at `offset`, each masked line it shows (`code`, by number) fits its line, and the value runs from
    `offset` to the last masked byte of its last line."""
    lines = block.split(b"\n")
    if offset is None or not any(_fits(masked, lines[0], offset - start) for start, _ in
                                 [(found.start(), found.end()) for found in re.finditer(rb"\*+", masked)]):
        return None
    for number, content in code.items():
        position = number - first
        if 0 < position < len(lines) and not _fits(content, lines[position], 0):
            return None
    last = len(block) - len(lines[-1])
    shown = code.get(first + len(lines) - 1)
    end = last + (shown.rfind(b"*") + 1 if shown and b"*" in shown else len(lines[-1].rstrip(b"\r")))
    return (offset, end, offset, end) if offset < end else None
