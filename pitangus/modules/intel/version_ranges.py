"""Whether a version satisfies a declared dependency range, in each package manager's syntax.

It answers "does the package that requires this dependency allow its fixed version?". Anything it doesn't
understand (git URLs, tags, workspaces, odd syntax) is None: unknown, never a guess.
"""

from __future__ import annotations

import re

from pitangus.modules.intel.advisories import compare_versions

# The range syntax of each package manager whose lockfile or manifest keeps declared ranges (scanning/declared_ranges.py).
SYNTAX = {"poetry": "pep440", "uv": "pep440", "pip": "pep440", "npm": "npm", "yarn": "npm", "pnpm": "npm", "bundler": "gem"}
# A declared range comes from the scanned repository and is stored on every finding it explains: only text shaped like
# a range (versions, operators, `||`, pre-release letters, `npm:` aliases) and short enough to read is kept.
MAX_RANGE = 200
RANGE = re.compile(r"[0-9A-Za-z .,|^~<>=!*+_:@/-]{1,%d}" % MAX_RANGE)


def bounded(requirement) -> str | None:
    """The requirement, stripped, when it is shaped like a range; None (unknown) otherwise."""
    if not isinstance(requirement, str):
        return None
    requirement = requirement.strip()
    return requirement if RANGE.fullmatch(requirement) else None


def allows(syntax: str | None, requirement: str | None, version: str) -> bool | None:
    if requirement is None or len(requirement) > MAX_RANGE or not version or syntax not in ("pep440", "npm", "gem"):
        return None
    try:
        return {"pep440": _pep440, "npm": _npm, "gem": _gem}[syntax](requirement.strip(), version.strip().lstrip("vV"))
    except (ValueError, IndexError):
        return None


def _numbers(text: str) -> tuple[list[int | None], str]:
    """`1.2.x-beta` → ([1, 2, None], "-beta"): the release parts (None for a wildcard) and what follows."""
    match = re.fullmatch(r"v?((?:\d+|[xX*])(?:\.(?:\d+|[xX*]))*)(.*)", text)
    if not match:
        raise ValueError(text)
    parts: list[int | None] = [None if part in ("x", "X", "*") else int(part) for part in match[1].split(".")]
    if None in parts:
        parts = parts[:parts.index(None)]
    return (parts + [None] * 3)[:max(3, len(parts))], match[2]


def _join(parts: list[int | None], suffix: str = "") -> str:
    return ".".join(str(part or 0) for part in parts[:max(3, len(parts))]) + suffix


def _bump(parts: list[int | None], index: int) -> str:
    """The first version past the `index` part: (1, 2, 3) bumped at 1 → 1.3.0."""
    values = [part or 0 for part in parts]
    values = values[:index + 1] + [0] * (len(values) - index - 1)
    values[index] += 1
    return ".".join(str(value) for value in values)


def _check(operator: str, bound: str, version: str) -> bool:
    order = compare_versions(version, bound)
    return {">=": order >= 0, ">": order > 0, "<=": order <= 0, "<": order < 0, "==": order == 0, "!=": order != 0}[operator]


def _caret(parts: list[int | None], suffix: str) -> list[tuple[str, str]]:
    major, minor, patch = parts[0], parts[1], parts[2]
    low = (">=", _join(parts, suffix))
    if major is None:
        return []
    if major > 0 or minor is None:
        return [low, ("<", _bump(parts, 0))]
    if minor > 0 or patch is None:
        return [low, ("<", _bump(parts, 1))]
    return [low, ("<", _bump(parts, 2))]


def _tilde(parts: list[int | None], suffix: str) -> list[tuple[str, str]]:
    if parts[0] is None:
        return []
    return [(">=", _join(parts, suffix)), ("<", _bump(parts, 0 if parts[1] is None else 1))]


def _partial(operator: str, parts: list[int | None], suffix: str) -> list[tuple[str, str]]:
    """A comparator whose version may be partial (`>1.2`, `<=1`, `1.x`)."""
    known = [part for part in parts if part is not None]
    if not known:
        return [] if operator in ("", "=", ">=", "<=") else [("<", "0.0.0")]
    full = len(known) >= 3
    if operator in ("", "=", "=="):
        return [("==", _join(parts, suffix))] if full else [(">=", _join(parts)), ("<", _bump(parts, len(known) - 1))]
    if operator == ">" and not full:
        return [(">=", _bump(parts, len(known) - 1))]
    if operator == "<=" and not full:
        return [("<", _bump(parts, len(known) - 1))]
    return [(operator, _join(parts, suffix))]


def _npm(requirement: str, version: str) -> bool | None:
    if requirement.startswith("npm:"):
        requirement = requirement[4:]
        if "@" in requirement[1:]:
            requirement = requirement[requirement.rindex("@") + 1:]
    if requirement in ("", "*", "x", "X", "latest"):
        return True if requirement != "latest" else None
    if re.search(r"[:/]|^[a-zA-Z]", requirement):
        return None  # git, file:, workspace:, a tag
    for alternative in requirement.split("||"):
        alternative = alternative.strip()
        constraints: list[tuple[str, str]] = []
        hyphen = re.fullmatch(r"(\S+)\s+-\s+(\S+)", alternative)
        if hyphen:
            low, _ = _numbers(hyphen[1])
            high, high_suffix = _numbers(hyphen[2])
            constraints += _partial(">=", low, "") + _partial("<=", high, high_suffix)
        else:
            alternative = re.sub(r"(>=|<=|>|<|=|\^|~)\s+", r"\1", alternative)
            for comparator in alternative.split():
                match = re.fullmatch(r"(>=|<=|>|<|=|\^|~>?)?(.+)", comparator)
                if not match:
                    return None
                operator, (parts, suffix) = match[1] or "", _numbers(match[2])
                constraints += (_caret(parts, suffix) if operator == "^" else _tilde(parts, suffix) if operator.startswith("~")
                                else _partial(operator, parts, suffix))
        if all(_check(operator, bound, version) for operator, bound in constraints):
            return True
    return False


def _pep440(requirement: str, version: str) -> bool | None:
    if requirement in ("", "*"):
        return True
    if "||" in requirement:  # Poetry writes unions in its lockfile
        results = [_pep440(part.strip(), version) for part in requirement.split("||")]
        return True if True in results else None if None in results else False
    for clause in requirement.split(","):
        clause = clause.strip()
        match = re.fullmatch(r"(~=|===|==|!=|<=|>=|<|>|\^|~)?\s*([0-9][0-9A-Za-z.*+!_-]*)", clause)
        if not match:
            return None
        operator, bound = match[1] or "==", match[2]
        if operator == "===":
            ok = bound == version
        elif operator in ("==", "!=") and bound.endswith(".*"):
            prefix = [int(part) for part in bound[:-2].split(".")]
            current, _ = _numbers(version)
            ok = [part or 0 for part in current[:len(prefix)]] == prefix
            ok = ok if operator == "==" else not ok
        elif operator == "~=":
            parts, suffix = _numbers(bound)
            known = len([part for part in parts if part is not None])
            if known < 2:
                return None
            ok = _check(">=", bound, version) and _check("<", _bump(parts, known - 2), version)
        elif operator in ("^", "~"):
            parts, suffix = _numbers(bound)
            ok = all(_check(op, value, version) for op, value in (_caret if operator == "^" else _tilde)(parts, suffix))
        else:
            ok = _check(operator, bound, version)
        if not ok:
            return False
    return True


def _gem(requirement: str, version: str) -> bool | None:
    for clause in requirement.split(","):
        match = re.fullmatch(r"\s*(~>|>=|<=|!=|>|<|=)?\s*([0-9][0-9A-Za-z.]*)\s*", clause)
        if not match:
            return None
        operator, bound = match[1] or "=", match[2]
        if operator == "~>":
            segments = [int(part) for part in re.findall(r"\d+", bound)]
            prefix = segments[:-1] if len(segments) > 1 else segments
            ceiling = prefix[:-1] + [prefix[-1] + 1]
            ok = _check(">=", bound, version) and _check("<", ".".join(map(str, ceiling)), version)
        else:
            ok = _check("==" if operator == "=" else operator, bound, version)
        if not ok:
            return False
    return True
