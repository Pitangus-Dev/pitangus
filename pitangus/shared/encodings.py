"""What an engine that reads bytes can read in a file: decided by the bytes themselves, never by the file's name.

The engines match their patterns on the bytes as they are. Text they can read is text that decodes as UTF-8 and holds no
zero byte: then every character of a token is where a pattern looks for it. Anything else (UTF-16 or UTF-32, an EBCDIC
code page, bytes that decode as nothing) they can't read, whatever they say they did. A file whose bytes are a consistent
UTF-16 or UTF-32 text (its BOM, or the zero bytes beside every ASCII one, give it away, and it decodes strictly to
printable text) is rewritten as UTF-8 before any engine reads it (`as_utf8`); one still unreadable after that is
declared unexamined by the engines that read bytes (scanning/engines.secret_gaps).
"""

from __future__ import annotations

import codecs
import unicodedata

# UTF-32 first: its little-endian BOM starts with UTF-16's.
BOMS = ((codecs.BOM_UTF32_LE, "utf-32"), (codecs.BOM_UTF32_BE, "utf-32"), (codecs.BOM_UTF8, "utf-8-sig"),
        (codecs.BOM_UTF16_LE, "utf-16"), (codecs.BOM_UTF16_BE, "utf-16"))
SAMPLE = 4096
_WHITESPACE = {"\t", "\n", "\r", "\f", "\v"}


def codec(data: bytes) -> str | None:
    """The codec of a file's bytes: "utf-8"/"utf-8-sig" for text the engines read as is, a UTF-16/32 codec when its BOM
    or its zero bytes give it away, None when it decodes as nothing."""
    for bom, name in BOMS:
        if data.startswith(bom):
            return name
    sample = data[:SAMPLE]
    if sample and sample.count(0) * 3 >= len(sample):   # no BOM: a zero byte beside every ASCII one
        if sample[2::4].count(0) + sample[3::4].count(0) >= len(sample) // 2 and sample[0::4].count(0) * 4 < len(sample):
            return "utf-32-le"
        if sample[0::4].count(0) + sample[1::4].count(0) >= len(sample) // 2 and sample[3::4].count(0) * 4 < len(sample):
            return "utf-32-be"
        return "utf-16-le" if sample[1::2].count(0) >= sample[0::2].count(0) else "utf-16-be"
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return "utf-8"


def readable(data: bytes) -> bool:
    """Whether an engine that matches bytes reads this as the text it is: UTF-8 (a BOM allowed) without a zero byte."""
    if b"\0" in data:
        return False
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def _printable(text: str) -> bool:
    """Text, not bytes that happened to decode: no control character but whitespace, nothing unassigned."""
    return all(char in _WHITESPACE or unicodedata.category(char) not in ("Cc", "Cn", "Cs") for char in text)


def as_utf8(data: bytes) -> bytes | None:
    """The same text as UTF-8, for bytes an engine can't read that are a consistent UTF-16 or UTF-32 text; None for
    anything else (readable already, or not one of those: then nothing is rewritten and it stays declared)."""
    if readable(data):
        return None
    found = codec(data)
    if found is None or found.startswith("utf-8"):
        return None
    try:
        text = data.decode(found)
    except UnicodeDecodeError:
        return None
    text = text.removeprefix("\ufeff")
    if "\0" in text or not _printable(text):
        return None
    return text.encode("utf-8")
