"""The identity of a finding that is about code or configuration: its rule, its file and what it matched, without
comments or formatting (findings/canonical.py for the whole formula). Here, below every context, so that whoever masks
a finding's text (shared/masking.py) can pin the identity its original text had first."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any

CODE_MAX = 20_000       # characters of matched code an identity reads

# How each language writes comments, by file extension: what a comment says (a suppression, a note) is no part of the code.
_C_LIKE = ("//", ("/*", "*/"))
_HASH = ("#", None)
COMMENTS: dict[str, tuple[str | None, tuple[str, str] | None]] = {
    **dict.fromkeys(("js", "mjs", "cjs", "jsx", "ts", "tsx", "java", "kt", "kts", "go", "c", "h", "cc", "cpp", "hpp", "cs",
                     "swift", "rs", "scala", "dart", "groovy", "gradle", "php", "m", "mm", "proto", "rules"), _C_LIKE),
    **dict.fromkeys(("py", "rb", "sh", "bash", "zsh", "yaml", "yml", "tf", "hcl", "r", "pl", "toml", "ex", "exs", "nix",
                     "dockerfile", "cfg", "conf", "ini", "env", "ps1", "mk", "makefile"), _HASH),
    **dict.fromkeys(("sql", "lua", "hs"), ("--", ("/*", "*/"))),
    **dict.fromkeys(("html", "htm", "xml", "vue", "svelte", "svg"), (None, ("<!--", "-->"))),
    "css": (None, ("/*", "*/")), "scss": _C_LIKE, "less": _C_LIKE,
}
QUOTES = ("\"", "'", "`")
WORD = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$")


def digest(*parts: str) -> str:
    # Length-prefixed parts: no value can pass for two (`a|b` + `c` vs `a` + `b|c`).
    return hashlib.sha256("".join(f"{len(part)}:{part}" for part in parts).encode()).hexdigest()


def _syntax(path: str) -> tuple[str | None, tuple[str, str] | None]:
    name = path.rsplit("/", 1)[-1].lower()
    extension = name.rsplit(".", 1)[-1] if "." in name else name
    return COMMENTS.get(extension, (None, None))


def normalized_code(code: str, path: str) -> str:
    """The code without its comments (as the file's language writes them; strings are left alone) and without
    formatting: whitespace stays only where it separates two words (`return x`), so a reformat is the same code."""
    line, block = _syntax(path)
    text, kept, index, quote = str(code or "")[:CODE_MAX], [], 0, None
    while index < len(text):
        character = text[index]
        if quote:
            kept.append(character)
            if character == "\\" and index + 1 < len(text):
                kept.append(text[index + 1])
                index += 2
                continue
            if character == quote:
                quote = None
            index += 1
            continue
        if block and text.startswith(block[0], index):
            end = text.find(block[1], index + len(block[0]))
            index = len(text) if end < 0 else end + len(block[1])
            kept.append(" ")
            continue
        if line and text.startswith(line, index):
            end = text.find("\n", index)
            index = len(text) if end < 0 else end
            continue
        if character in QUOTES:
            quote = character
        kept.append(character)
        index += 1
    tokens = "".join(kept).split()
    result: list[str] = []
    for token in tokens:
        if result and result[-1][-1] in WORD and token[0] in WORD:
            result.append(" ")
        result.append(token)
    return "".join(result)


def address(value: Any) -> str:
    """A resource's address, or "" when the engine gave none: a position (`template.yaml:12`) is not an address."""
    text = str(value or "").strip()
    head, _, tail = text.rpartition(":")
    return "" if not text or (head and tail.isdecimal()) else text


def content_identity(finding: Mapping[str, Any]) -> str | None:
    """The identity of a code or configuration finding (`code` and `config` in findings/canonical.py), None for any
    other kind (a dependency, a web finding, a secret without code: their identities read no text)."""
    scanner = str(finding.get("scanner") or "")
    if scanner == "dast" or (scanner == "sca" and (finding.get("package") or {}).get("name")):
        return None
    tool, rule, path = str(finding.get("tool") or "").lower(), str(finding.get("rule_id") or ""), str(finding.get("path") or "")
    if scanner in ("iac", "cicd"):
        return digest("config", tool, rule, path, address(finding.get("resource")) or normalized_code(str(finding.get("snippet") or ""), path))
    if finding.get("snippet") is not None or scanner == "sast":
        return digest("code", tool, rule, path, normalized_code(str(finding.get("snippet") or ""), path))
    return None


def anywhere_identity(finding: Mapping[str, Any]) -> str | None:
    """What a code or configuration finding is wherever it sits in the repository: its identity with the file reduced
    to its kind (its extension, which decides how comments are written), for the PR gate. None for anything whose
    identity reads no code (a dependency, a secret, a web finding, a rule that matched no text nor resource: two of
    those in different files may be different problems). Pinned as `anywhere` before a finding's code is rendered."""
    if "anywhere" in finding:
        pinned = finding["anywhere"]
        return str(pinned) if pinned else None
    scanner, path = finding.get("scanner"), str(finding.get("path") or "")
    if scanner in ("secrets", "dast") or not (normalized_code(str(finding.get("snippet") or ""), path).strip()
                                              or (scanner in ("iac", "cicd") and address(finding.get("resource")))):
        return None
    name = path.rsplit("/", 1)[-1]
    return content_identity({**finding, "path": f"*.{name.rsplit('.', 1)[-1]}" if "." in name else name})
