"""Technical findings report (PDF) for a scan or for the accumulated state of a repository or image.

For the team doing the fixes, in this order: a cover; a short executive summary; what to do first (one action per
package or per code finding, each with an ID that the rest of the report reuses); dependencies grouped with the
version that closes all their advisories; one sheet per critical or high code finding (what happens, how to fix it,
how to verify it); the rest in a table; the team's decisions; and, at the end, what this report is and isn't. The
full vulnerability index goes in an appendix; the full text of each advisory remains in the JSON, the SARIF and the
panel.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import cast

from reportlab.lib.units import mm
from reportlab.platypus import KeepTogether, Paragraph, Spacer, Table, TableStyle

from pitangus.modules.reporting.audit import status_label, status_of
from pitangus.modules.intel.data_sources import attribution
from pitangus.modules.findings.fix_guide import guide
from pitangus.modules.findings.remediation import action, counts_text, fix_groups
from pitangus.modules.reporting.design import (ATTENTION, BRAND, CODE_BG, DANGER, INK, LINE, MONO, MUTED, ORDER, SEVERITY_INK, STYLE, SUCCESS,
                            WIDTH, GAP_STATES, build, built_from, bullets, chip, count, cover, coverage_gaps, day, disclaimer, h2,
                            hexval, kpis, listing, location, path, percent, plain, rich, severity_label, step_status,
                            t as _t, table)
from pitangus.shared import i18n
from pitangus.shared.i18n import default_locale, localize, msg
from pitangus.shared.model import Finding

KINDS = ("repository_scan", "image_scan", "pr_review", "sarif_import", "asset_state")
ACTIVE = ("open", "in_progress")
ANNEX_LIMIT = 600
DETAIL_LIMIT = 150   # sheets for critical or high code findings
TABLE_LIMIT = 500    # medium and low rows
FIRST_LIMIT = 15


def _severity_counts(counts: dict[str, int], locale: str) -> str:
    """«5 critical, 15 high and 51 medium»: counted as findings (in Spanish they agree with «hallazgos»)."""
    parts = [msg(f"reports.count.{level}", count=counts[level]) for level in ("critical", "high", "medium") if counts[level]]
    if counts["low"] + counts["info"]:
        parts.append(msg("reports.count.low_info", count=counts["low"] + counts["info"]))
    return listing([i18n.text(part, locale) for part in parts], 10, locale=locale)


def revision(record: dict) -> str:
    """Branch and commit that were analyzed (a pull request's head); the snapshot hash goes apart."""
    source = record.get("source") or {}
    commit = (record.get("pull_request") or {}).get("head_sha") or source.get("commit") or ""
    return " · ".join(value for value in (source.get("branch"), commit[:12]) if value) or "—"


def _columns(locale: str, *names: str) -> list[str]:
    return [_t(i18n.t(f"reports.columns.{name}", locale)) for name in names]


CODE_COLUMNS = 96  # characters of IBM Plex Mono 7.8 pt that fit the page width inside a code block


def _id(value: str) -> str:
    return f'<font name="{MONO}" color="{hexval(BRAND)}">{value}</font>'


def _code(text: str, limit: int = 1500) -> str:
    """A code sample as monospaced markup, keeping its lines and indentation; a line longer than the block continues on
    the next one (spaces are hard, so the page can't wrap it anywhere else)."""
    rows = []
    for line in (str(text or "")[:limit].splitlines() or [""])[:30]:
        line = line.rstrip().replace("\t", "    ")
        rows += [line[start:start + CODE_COLUMNS] for start in range(0, max(len(line), 1), CODE_COLUMNS)]
    return "<br/>".join(_t(row, 200).replace(" ", "&nbsp;") if row.strip() else "&nbsp;" for row in rows)


def _sheet(item: dict, ident: str, locale: str) -> list:
    """One critical or high code finding: what it is, where, what happens, how to fix it and how to know it's fixed."""
    t = lambda key, **params: i18n.t(key, locale, **params)  # noqa: E731
    severity = item.get("severity", "info")
    head = Table([[Paragraph(_id(ident), STYLE["id"]),
                   Paragraph(f'<font color="{hexval(SEVERITY_INK.get(severity, MUTED))}">{_t(severity_label(severity, locale).upper())}</font>',
                             STYLE["chip"])]], colWidths=[22 * mm, WIDTH - 22 * mm], hAlign="LEFT")
    head.setStyle(TableStyle([("LEFTPADDING", (0, 0), (-1, -1), 0), ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]))
    rows = [(t("reports.technical.sheet.status"), _t(status_label(status_of(item), locale))),
            (t("reports.technical.sheet.location"), f'<font name="{MONO}">{path(location(item), 70)}</font>')]
    classification = ", ".join(f"CWE-{value}" for value in (item.get("cwe") or [])[:3])
    if classification:
        rows.append((t("reports.technical.sheet.classification"), _t(classification)))
    if item.get("rule_id"):
        rows.append((t("reports.technical.sheet.rule"), f'<font name="{MONO}">{_t(item["rule_id"], 120)}</font>'))
    facts = Table([[Paragraph(_t(label), STYLE["cellmuted"]), Paragraph(value, STYLE["cell"])] for label, value in rows],
                  colWidths=[34 * mm, WIDTH - 34 * mm], hAlign="LEFT")
    facts.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0), ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                               ("LINEABOVE", (0, 0), (-1, 0), 1.2, INK), ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE)]))
    story = [head, Paragraph(_t(item.get("title"), 200), STYLE["sheet_title"]), facts]
    if item.get("reason"):
        story += [Paragraph(_t(t("reports.technical.sheet.what_happens")), STYLE["h4"]), Paragraph(rich(item["reason"], 600), STYLE["body"])]
    story += [Paragraph(_t(t("reports.technical.sheet.how_to_fix")), STYLE["h4"]),
              Paragraph(rich(item.get("remediation") or t("reports.technical.fallback_fix"), 600), STYLE["body"])]
    fix = localize(item.get("fix") or guide(cast(Finding, item)), locale) or {}
    example = fix.get("example") or {}
    if example.get("after"):
        # Before over after, full width: code lines are long and a column each would push them off the page.
        for key, colour, code in (("before", DANGER, example.get("before")), ("after", SUCCESS, example["after"])):
            if not code:
                continue
            block = Table([[Paragraph(f'<font color="{hexval(colour)}">{_t(t(f"reports.technical.sheet.{key}"))}</font>', STYLE["label"])],
                           [Paragraph(_code(code), STYLE["code"])]], colWidths=[WIDTH], hAlign="LEFT")
            block.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), CODE_BG), ("LEFTPADDING", (0, 0), (-1, -1), 8),
                                       ("RIGHTPADDING", (0, 0), (-1, -1), 8), ("TOPPADDING", (0, 0), (-1, 0), 6),
                                       ("BOTTOMPADDING", (0, -1), (-1, -1), 8)]))
            story += [Spacer(1, 4), block]
    story += [Paragraph(_t(t("reports.technical.sheet.how_to_verify")), STYLE["h4"]),
              Paragraph(_t(t("reports.technical.sheet.verify_text")), STYLE["body"])]
    references = [url for url in ((item.get("advisory") or {}).get("references") or [])[:3] if str(url).startswith("https://")]
    if references:
        story.append(Paragraph(_t(i18n.t("reports.common.references", locale, list=" · ".join(references)), 400), STYLE["note"]))
    # The heading and the facts never part; the rest may flow onto the next page.
    return [KeepTogether(story[:3]), *story[3:], Spacer(1, 16)]


def render_technical_pdf(record: dict, *, version: str, locale: str | None = None) -> bytes:
    locale = locale or default_locale()
    record = localize(record, locale)
    t = lambda key, **params: i18n.t(key, locale, **params)  # noqa: E731
    kev_mark = f'<br/><font color="{hexval(DANGER)}">{_t(t("reports.common.kev_mark"))}</font>'
    malicious_mark = f'<br/><font color="{hexval(DANGER)}">{_t(t("reports.common.malicious_mark"))}</font>'
    findings = [item for item in record.get("findings") or [] if status_of(item) != "excluded"]
    active = [item for item in findings if status_of(item) in ACTIVE]
    decided = [item for item in findings if status_of(item) in ("accepted", "false_positive")]
    fixed = [item for item in findings if status_of(item) == "fixed"]
    source = record.get("source") or {}
    name = source.get("name") or source.get("id") or "—"
    when = day(record.get("created_at") or record.get("scanned_at"))
    kind = t(f"reports.technical.kind.{record.get('type')}") if record.get("type") in KINDS else t("reports.technical.kind.default")
    counts = {level: sum(1 for item in active if item.get("severity") == level) for level in ORDER}
    groups = fix_groups(active)
    # One ID per action, in the order of the report: the summary, the tables and the sheets all say PIT-00N.
    ids = {id(entry): f"PIT-{index:03d}" for index, entry in enumerate(groups, 1)}
    by_finding = {item.get("fingerprint"): ids[id(entry)] for entry in groups for item in entry["items"]}
    packages = [entry for entry in groups if entry["kind"] == "package"]
    code = sorted([item for item in active if not (item.get("scanner") == "sca" and (item.get("package") or {}).get("name"))],
                  key=lambda item: (ORDER.get(item.get("severity"), 9), str(item.get("path")), item.get("line") or 0))
    kev = sum(1 for item in active if item.get("kev"))
    fixable = sum(1 for entry in packages if entry["target"])
    engines = [step for step in record.get("steps") or [] if (step.get("tool") or {}).get("version")]

    fields = [(t("reports.technical.meta.date"), when), (t("reports.technical.meta.type"), kind),
              (t("reports.technical.meta.revision"), revision(record), "mono"),
              (t("reports.technical.meta.engines"), ", ".join(step["name"] for step in engines) or "—"),
              (t("reports.technical.meta.reference"), str(record.get("id") or "—"), "mono")]
    if source.get("sha256"):
        fields.append((t("reports.technical.meta.snapshot"), str(source["sha256"]), "mono"))
    if built_from(record):
        fields.append((t("reports.technical.meta.built_from"), built_from(record, locale), "mono"))
    story = cover(t("reports.technical.cover_kind"), name,
                  t("reports.technical.subtitle_state" if record.get("type") == "asset_state" else "reports.technical.subtitle_scan", date=when),
                  fields, note=t("reports.design.cover_note", version=version))

    # 1. Executive summary: a few sentences a person would write, then the figures.
    story.append(h2(t("reports.technical.exec_heading")))
    urgent = [entry for entry in groups if entry["severity"] == "critical" or entry["kev"] or entry.get("malicious")]
    sentences = [t("reports.technical.summary", pending=msg("reports.count.pending_findings", count=len(active)),
                   counts=_severity_counts(counts, locale) or msg("reports.common.none"),
                   actions=msg("reports.count.actions", count=len(groups)), packages=msg("reports.count.packages_to_update", count=len(packages)),
                   fixable=fixable, code=msg("reports.count.findings", count=len(code)))]
    if urgent:
        sentences.insert(0, t("reports.technical.exec_urgent", count=len(urgent), first=ids[id(urgent[0])],
                              last=ids[id(urgent[-1])]) if len(urgent) > 1 else t("reports.technical.exec_urgent", count=1, first=ids[id(urgent[0])]))
    if decided:
        sentences.append(t("reports.technical.decided", count=len(decided)))
    story.append(Paragraph(_t(" ".join(sentences), 1200), STYLE["body"]))
    gaps = coverage_gaps(record.get("steps") or [], locale=locale)
    if gaps:
        story.append(Paragraph(_t(t("reports.technical.incomplete", gaps=", ".join(gaps)), 600), STYLE["body"]))
    figures = [(t("reports.audit.kpi.open_critical"), counts["critical"], SEVERITY_INK["critical"], None),
               (t("reports.audit.kpi.open_high"), counts["high"], ATTENTION, None),
               (t("reports.technical.kpi.medium_low"), counts["medium"] + counts["low"] + counts["info"], INK, None),
               (t("reports.technical.kpi.actions"), len(groups), INK, None)]
    if kev:
        figures.insert(2, (t("reports.technical.kpi.kev"), kev, DANGER, None))
    # A single scan only knows what it found: «fixed» comes from the repository's history (or a triage decision).
    if record.get("type") == "asset_state" or fixed:
        figures.append((t("reports.audit.kpi.fixed"), len(fixed), SUCCESS, None))
    story += [Spacer(1, 8), kpis(figures)]

    # 2. What to do first.
    if groups:
        story.append(h2(t("reports.common.what_first")))
        body = []
        for entry in groups[:FIRST_LIMIT]:
            item = entry["items"][0]
            what = (f"{_t(entry['name'], 60)} {_t(entry['version'], 30)} · {_t(count('advisories', len(entry['items']), locale))}" if entry["kind"] == "package"
                    else _t(item.get("title"), 120))
            where = path(entry["path"] if entry["kind"] == "package" else location(item), 60)
            body.append([Paragraph(_id(ids[id(entry)]), STYLE["id"]), chip(entry["severity"], locale=locale),
                         f"<b>{plain(action(entry, short=True, locale=locale), 200)}</b><br/><font color=\"{hexval(MUTED)}\">{what} · {where}</font>"
                         + (malicious_mark if entry.get("malicious") else "") + (kev_mark if entry["kev"] else "")])
        story.append(table(_columns(locale, "id", "severity", "action"), body, [22 * mm, 18 * mm, WIDTH - 40 * mm]))
        if len(groups) > FIRST_LIMIT:
            story.append(Paragraph(_t(t("reports.technical.first_truncated", shown=FIRST_LIMIT, total=len(groups)), 400), STYLE["note"]))

    # 3. Dependencies, one row per package.
    if packages:
        total = sum(len(entry["items"]) for entry in packages)
        story.append(h2(t("reports.technical.dependencies", packages=msg("reports.count.packages", count=len(packages)),
                           vulnerabilities=msg("reports.count.vulnerabilities", count=total))))
        body = []
        for entry in packages:
            body.append([Paragraph(_id(ids[id(entry)]), STYLE["id"]), chip(entry["severity"], locale=locale),
                         f"<b>{_t(entry['name'], 60)}</b> {_t(entry['version'], 30)}<br/><font color=\"{hexval(MUTED)}\">{_t(entry['ecosystem'], 20)} · {path(entry['path'], 40)}</font>",
                         _t(counts_text(entry["counts"], locale=locale), 80) + f'<br/><font color="{hexval(MUTED)}">{_t(listing(entry["ids"], 4, locale=locale), 160)}</font>'
                         + (kev_mark if entry["kev"] else ""),
                         f"<b>{_t(entry['target'], 40)}</b>" + ("" if entry["complete"] else f'<br/><font color="{hexval(MUTED)}">{_t(t("reports.technical.partial_fix"))}</font>')
                         if entry["target"] else f'<font color="{hexval(DANGER)}">{_t(t("reports.technical.no_fixed_version"))}</font>'])
        story.append(table(_columns(locale, "id", "severity", "package", "vulnerabilities", "update_to"), body,
                           [22 * mm, 18 * mm, 52 * mm, WIDTH - 130 * mm, 38 * mm]))
        story.append(Paragraph(_t(t("reports.technical.update_note"), 400), STYLE["note"]))

    # 4. Code, secrets and infrastructure: a sheet for each critical or high, a table for the rest.
    if code:
        serious = [item for item in code if item.get("severity") in ("critical", "high")]
        rest = [item for item in code if item.get("severity") not in ("critical", "high")]
        story.append(h2(t("reports.common.code_heading", count=len(code))))
        for item in serious[:DETAIL_LIMIT]:
            story += _sheet(item, by_finding.get(item.get("fingerprint"), "—"), locale)
        if len(serious) > DETAIL_LIMIT:
            story.append(Paragraph(_t(t("reports.technical.detail_truncated", shown=DETAIL_LIMIT, total=len(serious)), 400), STYLE["note"]))
        if rest:
            story.append(Paragraph(_t(t("reports.common.medium_low", count=len(rest))), STYLE["h3"]))
            story.append(table(_columns(locale, "id", "severity", "finding", "location", "fix"),
                               [[Paragraph(_id(by_finding.get(item.get("fingerprint"), "—")), STYLE["id"]), chip(item.get("severity", "info"), locale=locale),
                                 _t(item.get("title"), 120), path(location(item), 26),
                                 plain(action({"kind": "finding", "items": [item]}, short=True, locale=locale), 160)] for item in rest[:TABLE_LIMIT]],
                               [22 * mm, 16 * mm, 46 * mm, 42 * mm, WIDTH - 126 * mm]))
            if len(rest) > TABLE_LIMIT:
                story.append(Paragraph(_t(t("reports.technical.table_truncated", shown=TABLE_LIMIT, total=len(rest)), 400), STYLE["note"]))

    # 5. The team's decisions.
    if decided:
        story.append(h2(t("reports.technical.decisions", count=len(decided))))
        story.append(table(_columns(locale, "finding", "decision", "reason", "by", "expires"),
                           [[_t(item.get("title"), 110), _t(status_label(status_of(item), locale)), _t((item.get("triage") or {}).get("reason") or "—", 220),
                             _t((item.get("triage") or {}).get("by") or "—", 40), day((item.get("triage") or {}).get("expires_at"))] for item in decided[:400]],
                           [52 * mm, 24 * mm, WIDTH - 130 * mm, 30 * mm, 24 * mm]))
        if len(decided) > 400:
            story.append(Paragraph(_t(t("reports.technical.decisions_truncated", shown=400, total=len(decided)), 400), STYLE["note"]))

    # 6. About this report: how it was made, what it didn't cover, where the data comes from, what it is not.
    story.append(h2(t("reports.technical.about_heading")))
    lines = []
    if record.get("type") == "asset_state":
        lines.append(_t(t("reports.technical.state_note"), 600))
    for step in record.get("steps") or []:
        status = step_status(step.get("status"), locale)
        colour = hexval(DANGER) if step.get("status") in GAP_STATES else hexval(MUTED)
        lines.append(f"<b>{_t(step.get('name'), 60)}</b> · <font color=\"{colour}\">{_t(status, 30)}</font>"
                     + (f" · {_t(step['detail'], 260)}" if step.get("detail") else ""))
    about = bullets(lines or [_t(t("reports.technical.no_engines"))], "text")
    if record.get("limitations"):
        about += [Paragraph(_t(t("reports.common.limitations")), STYLE["h3"]), *bullets([_t(item, 300) for item in record["limitations"]], "note")]
    sources = attribution(active, locale=locale)
    if sources:
        about += [Paragraph(_t(t("reports.common.sources")), STYLE["h3"]), *bullets([_t(line, 300) for line in sources], "note")]
    about += [Spacer(1, 6), Paragraph(_t(t("reports.technical.closing") + " " + disclaimer(locale), 800), STYLE["note"])]
    story.append(KeepTogether(about))  # the closing note never lands alone on a page

    # Appendix: one row per dependency advisory, to trace every identifier without dumping its description.
    advisories = sorted([item for item in active if item.get("scanner") == "sca"],
                        key=lambda item: (ORDER.get(item.get("severity"), 9), str((item.get("package") or {}).get("name")), str(item.get("rule_id"))))
    if advisories:
        story.append(h2(t("reports.common.annex", count=len(advisories)), number=False))
        body = []
        for item in advisories[:ANNEX_LIMIT]:
            package = item.get("package") or {}
            advisory = item.get("advisory") or {}
            epss = (item.get("epss") or {}).get("score")
            body.append([f'<font name="{MONO}">{_t(((item.get("cve") or [])[:1] or (item.get("ghsa") or [])[:1] or [item.get("rule_id")])[0], 40)}</font>',
                         _t(f"{package.get('name', '')} {package.get('version', '')}", 70),
                         _t(severity_label(item.get("severity"), locale)) if item.get("severity") in ORDER else "—",
                         f"{advisory['cvss_score']:.1f}" if isinstance(advisory.get("cvss_score"), (int, float)) else "—",
                         percent(epss, locale) if isinstance(epss, (int, float)) else "—",
                         f'<font color="{hexval(DANGER)}"><b>{_t(t("reports.common.yes"))}</b></font>' if item.get("kev") else "—",
                         _t(package.get("fixed_version") or "—", 40),
                         _t((item.get("source") or {}).get("short") or (item.get("source") or {}).get("name") or "—", 20)])
        story.append(table(_columns(locale, "identifier", "package", "severity", "cvss", "epss", "kev", "fixed_in", "source"), body,
                           [34 * mm, WIDTH - 142 * mm, 16 * mm, 11 * mm, 14 * mm, 10 * mm, 36 * mm, 21 * mm]))
        if len(advisories) > ANNEX_LIMIT:
            story.append(Paragraph(_t(t("reports.technical.annex_truncated", shown=ANNEX_LIMIT, total=len(advisories)), 400), STYLE["note"]))
    issued = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return build(story, title=t("reports.technical.title", name=name), footer=t("reports.technical.footer", name=name[:70], date=issued),
                 version=version, subject=kind, locale=locale, reference=str(record.get("id") or ""))
