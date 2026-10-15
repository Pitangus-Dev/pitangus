"""The description of a Jira issue, written for the developer who has to fix it.

Security must not be a burden: the first lines are enough to do the work. What to change, exactly; where (repository,
file and line, linked to the code when the commit is known); the command that does it; how to verify it. Then why, in
a few lines (severity, deadline, KEV and EPSS when they matter, the vulnerabilities in one line), and the details last
(the remaining steps, a before/after example, every advisory, references).

The fix itself comes from the fix guide (`findings/fix_guide.py`: steps, commands, example); this module only lays it
out, whatever the guide says. No internal jargon (engine names, rule ids, priority factors, CVSS vectors) and never a
secret's value. Built as structured blocks (`jira.adf_document`, Jira Cloud's native format), never from Markdown, with
a plain text version for text fields and templates.
"""

from __future__ import annotations

from typing import Any, cast

from pitangus.modules.findings import fix_guide, sla
from pitangus.modules.intel.advisories import compare_versions
from pitangus.modules.sources.permalinks import code_url
from pitangus.shared.i18n import localize, t, text
from pitangus.shared.model import Finding

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
REFERENCES_MAX = 8
ADVISORIES_MAX = 20
IDENTIFIERS_SHOWN = 10
EPSS_RELEVANT = 0.1  # a 10% chance of exploitation in 30 days: worth saying (the dashboard uses the same bar)
OS_MANAGERS = frozenset(fix_guide.OS_DATABASES.values())  # apt, apk, dnf: a package of an image's system


def _t(key: str, locale: str, **params) -> str:
    return t(f"integrations.jira.brief.{key}", locale, **params)


def severity_label(level: str, locale: str) -> str:
    label = t(f"scanning.severity.{level}", locale) if level in SEVERITY_ORDER else level
    return label[:1].upper() + label[1:]


def _reference_url(identifier: str) -> str | None:
    if identifier.startswith("CVE-"):
        return f"https://nvd.nist.gov/vuln/detail/{identifier}"
    if identifier.startswith("GHSA-"):
        return f"https://github.com/advisories/{identifier}"
    return None


# Steps that speak to the panel (a "Verify again" button, "this advisory") or that "How to verify it" already says.
NOT_FOR_JIRA = (*sorted(fix_guide.PANEL_STEPS), "findings.fix.closes_all")
EVIDENCE_MAX = 300


def _fix(members: list[dict], locale: str) -> dict:
    """The fix guide of the group: for a package, the version that closes every advisory (same as the panel)."""
    attached = fix_guide.attach([cast(Finding, dict(item)) for item in members])
    found = next((item.get("fix") for item in attached if item.get("fix")), None)
    guide: dict = dict(found) if found else {}
    if not guide:
        return {}
    guide["steps"] = [step for step in guide.get("steps") or [] if not (isinstance(step, dict) and step.get("$t") in NOT_FOR_JIRA)]
    return localize(guide, locale)


def _sentence(value: str) -> str:
    value = value.strip()
    return value if not value or value[-1] in ".!?:…" else value + "."


def _kind(members: list[dict], guide: dict) -> str:
    """What "fixed" means for this issue: secret, image (an OS package), dependency, dependency without a fix, code."""
    lead = members[0]
    package = lead.get("package") or {}
    if lead.get("scanner") == "secrets":
        return "secret"
    if lead.get("scanner") == "dast":
        return "web"
    if package.get("name"):
        if fix_guide.manager(str(lead.get("path") or ""), str(package.get("ecosystem") or "")) in OS_MANAGERS:
            return "image"
        return "dependency" if guide.get("commands") or any((item.get("package") or {}).get("fixed_version") for item in members) else "no_fix"
    return "code"


def _target(members: list[dict]) -> str | None:
    """The version that fixes every advisory of the group that has a fix: the highest of their fixed versions."""
    target = None
    for version in filter(None, ((item.get("package") or {}).get("fixed_version") for item in members)):
        target = version if target is None or compare_versions(version, target) > 0 else target
    return target


def _action(kind: str, members: list[dict], guide: dict, target: str | None, locale: str) -> str:
    """The first line: what to change, exactly, in one sentence."""
    if guide.get("action"):  # the guide knows better: what blocks the update has to move first
        return _sentence(guide["action"])
    lead = members[0]
    package = lead.get("package") or {}
    names = {"package": str(package.get("name") or ""), "version": str(package.get("version") or "?"), "target": target or ""}
    if kind in ("dependency", "image") and target:
        fixed = sum(1 for item in members if (item.get("package") or {}).get("fixed_version"))
        if kind == "image":
            return _t("action.image", locale, **names)
        if fixed < len(members):
            return _t("action.dependency_some", locale, fixed=fixed, count=len(members), **names)
        return _t("action.dependency", locale, **names)
    if package.get("name"):
        return _t("action.no_fix", locale, **names)
    if kind == "secret":
        return _t("action.secret", locale)
    first = next((step for step in guide.get("steps") or [] if isinstance(step, str) and step.strip()), None)
    remediation = first or text(lead.get("remediation"), locale)
    return _sentence(remediation) if remediation else _t("action.generic", locale, title=text(lead.get("title"), locale).rstrip("."))


def _apply(guide: dict, locale: str) -> list[dict]:
    """Right after the action: the command that applies it or, without one, the snippet to add (an override, a
    pinned version). A before/after example of code is a pattern to adapt: it goes with the details."""
    commands = [command for command in guide.get("commands") or [] if command.get("code")]
    applying = [command for command in commands if command.get("action") != "check"]
    blocks: list[dict] = []
    for command in commands:
        # A lone command that applies the fix is just "Run:"; several, or one that checks the result, say what each does.
        alone = len(applying) == 1 and command.get("action") != "check"
        label = _t("run", locale) if alone else f"{command.get('label') or _t('run', locale)}:"
        blocks += [{"paragraph": [label]}, {"code": command["code"], "language": "bash"}]
    example = guide.get("example") or {}
    if not example.get("before") and example.get("after"):
        # The guide names the file the snippet goes in (package.json, pom.xml, Dockerfile…), not the finding's path.
        blocks[0:0] = [{"paragraph": [_t("add_snippet", locale, file=example["file"]) if example.get("file") else _t("add_snippet_nowhere", locale)]},
                       {"code": example["after"], "language": example.get("language")}]
        if example.get("note"):
            blocks.insert(2, {"paragraph": [example["note"]]})
    return blocks


def _steps(guide: dict, action: str, locale: str) -> list[dict]:
    """The guide's steps (the first one is the action already said), then a before/after example."""
    steps = [_sentence(step) for step in (guide.get("steps") or []) if isinstance(step, str) and step.strip()]
    steps = [step for step in steps if step != action]
    blocks: list[dict] = [{"ordered": [[step] for step in steps]}] if len(steps) > 0 else []
    example = guide.get("example") or {}
    language = example.get("language")
    if example.get("before"):
        blocks += [{"paragraph": [{"strong": _t("before", locale)}]}, {"code": example["before"], "language": language},
                   {"paragraph": [{"strong": _t("after", locale)}]}, {"code": example.get("after") or "", "language": language}]
        if example.get("note"):
            blocks.append({"paragraph": [example["note"]]})
    return blocks


def _identifiers(members: list[dict]) -> list[str]:
    return list(dict.fromkeys(item for member in members for item in [*(member.get("cve") or []), *(member.get("ghsa") or [])]))


def _primary(members: list[dict]) -> list[str]:
    """One identifier per advisory (its CVE, else its GHSA), so the count is of vulnerabilities, not of aliases."""
    return list(dict.fromkeys(found for member in members if (found := next(iter([*(member.get("cve") or []), *(member.get("ghsa") or [])]), None))))


def brief(group: list[dict], findings: dict, *, asset: str, source: dict | None, first_seen: dict, days: dict,
          panel_url: str | None, locale: str) -> dict[str, Any]:
    """{"blocks": [...], "text": "..."} for one issue: a group of tickets (one finding, or one package's advisories).

    The first lines are what a developer acts on: what to change, where, the command and how to verify it. Then why
    (severity, deadline, KEV and EPSS when they matter, the vulnerabilities in one line), then the details."""
    source = source or {}
    members = [findings.get(ticket["fingerprint"]) or {} for ticket in group]
    first, lead = group[0], members[0]
    severity = min((ticket["severity"] for ticket in group), key=lambda item: SEVERITY_ORDER.index(item) if item in SEVERITY_ORDER else 9)
    package = lead.get("package") or {}
    guide = _fix(members, locale)
    kind = _kind(members, guide)
    target = _target(members)
    image = source.get("provider") == "registry" or kind == "image"
    path, line = str(lead.get("path") or ""), lead.get("line") if isinstance(lead.get("line"), int) else None
    web = lead.get("web") or {}

    # What to change, where, the command, how to verify
    action = _action(kind, members, guide, target, locale)
    blocks: list[dict] = [{"paragraph": [{"strong": action}]}]
    if kind == "web":
        where: list[list] = [[_t("site", locale), {"strong": asset}]]
        if path:
            where.append([_t("url", locale), {"code": f"{web['method']} {path}" if web.get("method") else path}])
        if web.get("parameter"):
            where.append([_t("parameter", locale), {"code": str(web["parameter"])}])
    else:
        where = [[_t("image" if image else "repository", locale), {"strong": asset}]
                 + ([f" ({_t('branch', locale, branch=source['branch'])})"] if source.get("branch") and not image else [])]
    if path and kind != "web":
        label = path if package.get("name") or not line else f"{path}:{line}"
        url = code_url(source, path, None if package.get("name") else line)
        where.append([_t("in_image" if image else "manifest" if package.get("name") else "file", locale)]
                     + [{"link": label, "url": url} if url else {"code": label}])
    blocks.append({"bullets": where})
    blocks += _apply(guide, locale)
    blocks.append({"paragraph": [{"strong": _t("verify_label", locale)}, " " + _t(f"verify_{kind}", locale)]})

    # Why
    blocks.append({"heading": _t("why", locale)})
    facts: list = [_t("severity", locale), {"strong": severity_label(severity, locale)}]
    deadlines = sorted(filter(None, ((sla.deadline(ticket["severity"], first_seen.get(ticket["fingerprint"]), days) or {}).get("due")
                                     for ticket in group)))
    if deadlines:
        facts += [" · " + _t("due", locale), {"strong": deadlines[0]}]
    seen = sorted(filter(None, (first_seen.get(ticket["fingerprint"]) for ticket in group)))
    if seen:
        facts.append(" · " + _t("detected", locale, date=str(seen[0])[:10]))
    blocks.append({"paragraph": facts})
    kev = next((item["kev"] for item in members if item.get("kev")), None)
    if kev:
        blocks.append({"paragraph": [{"strong": _t("kev_ransomware" if kev.get("ransomware") else "kev", locale, date=kev.get("date_added") or "?")}]})
    epss = max((score for item in members if isinstance(score := (item.get("epss") or {}).get("score"), (int, float))), default=None)
    if epss is not None and epss >= EPSS_RELEVANT:
        blocks.append({"paragraph": [_t("epss", locale, probability=f"{epss:.0%}")]})
    identifiers, primary = _identifiers(members), _primary(members)
    if primary:
        shown: list = []
        for index, item in enumerate(primary[:IDENTIFIERS_SHOWN]):
            url = _reference_url(item)
            shown += ([", "] if index else []) + [{"link": item, "url": url} if url else {"code": item}]
        rest = len(primary) - IDENTIFIERS_SHOWN
        blocks.append({"paragraph": [_t("advisories", locale, count=len(primary))] + shown
                       + ([" " + _t("and_more", locale, count=rest)] if rest > 0 else [])})
    if not package.get("name"):
        title = text(lead.get("title"), locale) or text(first.get("summary"), locale)
        reason = text(lead.get("reason"), locale)
        blocks.append({"paragraph": [{"strong": _sentence(title)}] + ([" " + _sentence(reason)] if reason else [])})
        description = str(web.get("description") or "")
        if description:  # the scanner's own text, attributed
            blocks.append({"paragraph": [{"strong": _t("according_to", locale, tool=str(lead.get("tool") or "?"))}, " " + description]})
        if web.get("evidence"):
            blocks.append({"paragraph": [_t("evidence", locale), {"code": str(web["evidence"])[:EVIDENCE_MAX]}]})
        if lead.get("scanner") == "secrets":
            blocks.append({"paragraph": [_t("secret_value", locale)]})
    cwes = list(dict.fromkeys(item for member in members for item in member.get("cwe") or []))
    if cwes:
        blocks.append({"paragraph": [_t("weakness", locale)] + [
            part for index, cwe in enumerate(cwes[:3]) for part in ([", "] if index else [])
            + [{"link": f"CWE-{cwe}", "url": f"https://cwe.mitre.org/data/definitions/{cwe}.html"}]]})

    # Details
    details = _steps(guide, action, locale)
    if package.get("name"):
        rows = []
        for member, ticket in list(zip(members, group))[:ADVISORIES_MAX]:
            identifier = next(iter(member.get("cve") or member.get("ghsa") or [member.get("rule_id") or ""]), "")
            url = _reference_url(identifier)
            summary = text((member.get("advisory") or {}).get("summary"), locale) or text(member.get("title"), locale)
            fixed = (member.get("package") or {}).get("fixed_version")
            rows.append([{"link": identifier, "url": url} if url else {"code": identifier},
                         f" · {severity_label(ticket['severity'], locale)} · {summary}"
                         + (f" · {_t('fixed_in', locale, version=fixed)}" if fixed else f" · {_t('no_fix_yet', locale)}")])
        details.append({"bullets": rows})
    scores: list[float] = [score for item in members if isinstance(score := (item.get("advisory") or {}).get("cvss_score"), (int, float))]
    if scores:
        details.append({"paragraph": [_t("cvss", locale, score=f"{max(scores):.1f}")]})
    references = [[{"link": item, "url": url}] for item in identifiers if (url := _reference_url(item))]
    extra = [url for member in members for url in [*((member.get("advisory") or {}).get("references") or []),
                                                    *((member.get("web") or {}).get("references") or [])] if isinstance(url, str)]
    references += [[{"link": url, "url": url}] for url in dict.fromkeys(extra) if url.startswith("https://")]
    if references:
        details += [{"paragraph": [{"strong": _t("references", locale)}]}, {"bullets": references[:REFERENCES_MAX]}]
    if details:
        blocks += [{"heading": _t("details", locale)}, *details]

    footer: list = []
    if panel_url:
        footer.append({"link": _t("open_in_pitangus", locale), "url": panel_url})
    footer.append(("  ·  " if footer else "") + _t("finding_id", locale, id=str(first.get("finding_id") or first["fingerprint"][:16])))
    blocks.append({"paragraph": footer})
    return {"blocks": blocks, "text": plain(blocks)}


def plain(blocks: list[dict]) -> str:
    """The same content as plain text (text fields and templates)."""
    def inline(items) -> str:
        parts = []
        for item in items if isinstance(items, list) else [items]:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                parts.append(str(item.get("strong") or item.get("code") or item.get("link") or ""))
        return "".join(parts)
    lines: list[str] = []
    for block in blocks:
        if "heading" in block:
            lines += ["", str(block["heading"])]
        elif "paragraph" in block:
            if block is blocks[-1]:
                lines.append("")  # the footer, apart
            lines.append(inline(block["paragraph"]))
        elif "bullets" in block:
            lines += [f"- {inline(item)}" for item in block["bullets"]]
        elif "ordered" in block:
            lines += [f"{index}. {inline(item)}" for index, item in enumerate(block["ordered"], 1)]
        elif "code" in block:
            lines += [f"    {row}" for row in str(block["code"]).splitlines()]
    return "\n".join(lines).strip()
