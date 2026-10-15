"""Problems found while reading a threat model: every one at once, each pointing at its place in the JSON.

An **error** stops the import (the model would be broken: missing or repeated ids, references to ids that don't
exist, wrong types). A **warning** means Pitangus changed or couldn't use something that matters (text cut to its
limit, an unknown value replaced, a protocol it can't reason about). An **info** is a harmless normalization: a
synonym read as our field, a field kept as written that Pitangus doesn't use, "true" written as text. Paths are JSON
Pointers (RFC 6901) into the document as the person wrote it; `code` is the same for identical problems, so the
panel can group them.

Our lists are suggestions and the person's data is never thrown away: a field Pitangus doesn't know becomes a custom
property of its object (`custom_properties`), shown in the editor and the reports and exported back in the same place;
a value outside one of our lists becomes the team's own option.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import re

from pitangus.shared.i18n import msg

LIMIT = 200  # problems returned at most; the rest are counted
TAGS = re.compile(r"</?[A-Za-z!][^<>]*>")
# Control characters and the bidirectional overrides that make a label read differently from what it holds.
INVISIBLE = re.compile(r"[\x00-\x1f\x7f‎‏‪-‮⁦-⁩]")
ORDER = ("error", "warning", "info")
KEPT = "custom_properties"
KEPT_NAME = re.compile(r"[^\x00-\x1f\x7f]{1,60}")
KEPT_LIMIT = 8000  # characters of JSON in an object's custom properties (the model's own: 5×)


def pointer(*parts) -> str:
    return "".join("/" + str(part).replace("~", "~0").replace("/", "~1") for part in parts)


def normal(key: str) -> str:
    """A field name as compared: case, spaces and hyphens don't matter («Component-ID» is component_id)."""
    return "_".join(key.strip().lower().replace("-", "_").split())


def _code(message) -> str:
    """Identical problems (same message and parameters) share a code, whatever object they belong to."""
    raw = json.dumps(message, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


class Item:
    """One object of the document read through its synonyms: values under our field names, each with its real path,
    and the fields Pitangus doesn't use, kept as written."""

    def __init__(self, path: str, values: dict, keys: dict, kept: dict):
        self.path, self.values, self.keys, self.kept = path, values, keys, kept

    def get(self, field: str, default=None):
        return self.values.get(field, default)

    def at(self, field: str) -> str:
        return self.path + pointer(self.keys.get(field, field))

    def keep(self, entry: dict) -> dict:
        """`entry` with the kept fields attached (only when there are some)."""
        return {**entry, KEPT: self.kept} if self.kept else entry


class Problems:
    """Collects errors, warnings and infos under a base path (``/model`` when the document wraps the model)."""

    def __init__(self, base: str = ""):
        self.base = base
        self.items: list[dict] = []

    def add(self, severity: str, path: str, message, identifier=None) -> None:
        self.items.append({"severity": severity, "path": self.base + path, "id": identifier if isinstance(identifier, str) else None,
                           "code": _code(message), "message": message})

    def error(self, path: str, message, identifier=None) -> None:
        self.add("error", path, message, identifier)

    def warning(self, path: str, message, identifier=None) -> None:
        self.add("warning", path, message, identifier)

    def info(self, path: str, message, identifier=None) -> None:
        self.add("info", path, message, identifier)

    def escalate(self, path: str, message, identifier=None) -> None:
        """A note that turned out to matter: what was said about `path` gives way to this warning."""
        full = self.base + path
        self.items = [item for item in self.items if not (item["path"] == full and item["severity"] != "error")]
        self.warning(path, message, identifier)

    @property
    def errors(self) -> list[dict]:
        return [item for item in self.items if item["severity"] == "error"]

    def listing(self) -> list[dict]:
        """Errors first, then warnings, then infos, each in document order; capped."""
        ordered = [item for severity in ORDER for item in self.items if item["severity"] == severity]
        if len(ordered) <= LIMIT:
            return ordered
        rest = len(ordered) - LIMIT + 1
        message = msg("threats.problems.more", count=rest)
        return [*ordered[:LIMIT - 1], {"severity": ordered[LIMIT - 1]["severity"], "path": "", "id": None, "code": _code(message), "message": message}]

    def read(self, raw: dict, known: set[str], path: str, identifier=None, *, aliases: dict[str, str] | None = None,
             merge: dict[str, str] | None = None, limit: int = KEPT_LIMIT) -> Item:
        """Reads an object's fields: ours by name (case and hyphens don't matter), the synonyms in `aliases` as ours
        (info), and any other field kept as written (info; a likely typo of ours, warning). When a field comes twice
        (ours and a synonym), ours wins and the synonym is kept; for the fields in `merge` both texts are joined with
        that separator instead, so nothing the person wrote is lost."""
        aliases, merge = aliases or {}, merge or {}
        values: dict = {}
        keys: dict = {}
        kept: dict = {}
        ours_first = sorted(raw, key=lambda key: not (isinstance(key, str) and normal(key) in known))
        for key in ours_first:
            value = raw[key]
            if key == KEPT and isinstance(value, dict):  # the panel's custom properties, or a file that groups them
                kept.update({name: item for name, item in value.items() if isinstance(name, str) and name not in kept})
                continue
            name = normal(key) if isinstance(key, str) else ""
            field = name if name in known else aliases.get(name)
            where = path + pointer(key)
            if field is None:
                kept[key] = value
                close = difflib.get_close_matches(name, [*known, *aliases], n=1, cutoff=0.8)
                if close:
                    self.warning(where, msg("threats.problems.kept_typo", field=str(key)[:40], suggestion=aliases.get(close[0], close[0])), identifier)
                else:
                    self.info(where, msg("threats.problems.kept_field", field=str(key)[:40]), identifier)
                continue
            current = values.get(field)
            if field in values and (value in (None, "", []) or value == current):
                continue
            if current in (None, "", []):
                values[field], keys[field] = value, key
                if name != field:
                    self.info(where, msg("threats.problems.alias", alias=str(key)[:40], field=field), identifier)
                continue
            if field in merge and isinstance(value, str) and isinstance(current, str):
                values[field] = value.strip() + merge[field] + current.strip()
                self.info(where, msg("threats.problems.alias_joined", alias=str(key)[:40], field=field), identifier)
                continue
            kept[key] = value
            self.warning(where, msg("threats.problems.alias_conflict", alias=str(key)[:40], field=field), identifier)
        return Item(path, values, keys, self._bounded(kept, path, identifier, limit))

    def _bounded(self, kept: dict, path: str, identifier, limit: int) -> dict:
        """Custom properties with sensible names and a bounded size (a few kilobytes per object): beyond that it's an
        error, never a silent drop."""
        result, used = {}, 2
        for key, value in kept.items():
            size = len(json.dumps({key: value}, ensure_ascii=False, default=str))
            if not KEPT_NAME.fullmatch(str(key)) or used + size > limit:
                self.error(path + pointer(key), msg("threats.problems.kept_too_large", field=str(key)[:40], limit=limit), identifier)
                continue
            result[key], used = value, used + size
        return result

    def own_choice(self, value, allowed, path: str, field, identifier=None, *, aliases: dict | None = None, limit: int = 40):
        """A value of a list the team can extend (severity, likelihood, a mapping's status…): ours by name or synonym,
        any other short text kept as the team's own option (info). None when absent."""
        if value in (None, ""):
            return None
        if not isinstance(value, str):
            self.error(path, msg("threats.problems.not_text", field=field), identifier)
            return None
        key = normal(value)
        if key in allowed:
            return key
        aliased = (aliases or {}).get(key, (aliases or {}).get(value.strip().lower()))
        if aliased in allowed:
            self.info(path, msg("threats.problems.value_alias", field=field, value=value[:40], used=aliased), identifier)
            return aliased
        label = self.text(value, limit, path, field, identifier=identifier)
        if label:
            self.info(path, msg("threats.problems.own_value", field=field, value=label), identifier)
        return label or None

    def text(self, value, limit: int, path: str, field, *, required: bool = False, multiline: bool = False, identifier=None) -> str:
        """Text the person wrote. Wrong type or missing when required: error. Markup in a single-line label or too
        long: cleaned and warned. Prose (multiline) keeps `<…>` as typed: it is escaped wherever it is shown, and a
        scenario may well talk about a `<script>` tag; a list of strings there is read as one item per line."""
        if value is None or value == "":
            if required:
                self.error(path, msg("threats.errors.field_required", field=field), identifier)
            return ""
        if multiline and isinstance(value, list) and value and all(isinstance(item, str) for item in value):
            self.info(path, msg("threats.problems.list_joined", field=field), identifier)
            value = "\n".join(f"- {item.strip()}" for item in value if item.strip())
        if not isinstance(value, str):
            self.error(path, msg("threats.problems.not_text", field=field), identifier)
            return ""
        if multiline:
            cleaned = "\n".join(line.rstrip() for line in value.strip().replace("\r\n", "\n").split("\n"))
            safe = "".join(character for character in cleaned if character in "\n\t" or not INVISIBLE.match(character))
        else:
            cleaned = " ".join(value.split())
            safe = " ".join(TAGS.sub("", INVISIBLE.sub("", cleaned)).split())
        if safe != cleaned:
            self.warning(path, msg("threats.problems.cleaned", field=field), identifier)
        if len(safe) > limit:
            self.warning(path, msg("threats.problems.truncated", field=field, limit=limit), identifier)
            safe = safe[:limit].rstrip()
        if required and not safe:
            self.error(path, msg("threats.errors.field_required", field=field), identifier)
        return safe

    def flag(self, value, path: str, field, identifier=None) -> bool:
        """A yes/no field. "true"/"false" (or yes/no) as text is understood, with an info; anything else is an error."""
        if value is None or isinstance(value, bool):
            return bool(value)
        if isinstance(value, str) and value.strip().lower() in ("true", "false", "yes", "no"):
            self.info(path, msg("threats.problems.flag_text", field=field), identifier)
            return value.strip().lower() in ("true", "yes")
        self.error(path, msg("threats.problems.not_flag", field=field), identifier)
        return False

    def choice(self, value, allowed, default, path: str, field, identifier=None, *, aliases: dict | None = None):
        """One value of a closed list. Case, spaces and hyphens don't matter and a known synonym is read as ours (info);
        an unknown one falls back to `default`, warned; absent is `default` silently; a non-text value is an error."""
        if value in (None, ""):
            return default
        if not isinstance(value, str):
            self.error(path, msg("threats.problems.not_text", field=field), identifier)
            return default
        key = normal(value)
        if key in allowed:
            return key
        aliased = (aliases or {}).get(key, (aliases or {}).get(value.strip().lower()))
        if aliased in allowed:
            self.info(path, msg("threats.problems.value_alias", field=field, value=value[:40], used=aliased), identifier)
            return aliased
        self.warning(path, msg("threats.problems.unknown_value", field=field, value=value[:40], allowed=", ".join(a for a in allowed if a),
                               fallback=default if default is not None else "—"), identifier)
        return default

    def keys(self, raw: dict, known: set[str], path: str, identifier=None) -> None:
        """Fields of the envelope (outside the model): anything else there is ignored."""
        for key in raw:
            if key not in known:
                self.warning(f"{path}{pointer(key)}", msg("threats.problems.unknown_field", field=str(key)[:40]), identifier)
