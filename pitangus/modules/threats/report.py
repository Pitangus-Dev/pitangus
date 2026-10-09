"""Threat model report for the development team (PDF and Markdown).

What a team needs to act, in this order: how much there is and what to handle first; the diagram;
the threats the team wrote (the most concrete ones); those with evidence in the scans; and the
rule-based ones grouped by pattern (one measure fixes the pattern in all its components, instead of
repeating the same threat twenty times). The exhaustive parts (flows, components, PASTA, trees, ATT&CK) go
in annexes. The diagram and the flow table share the numbering.
"""

from __future__ import annotations

import html

from reportlab.lib.units import mm
from reportlab.platypus import KeepTogether, Paragraph, Spacer

from pitangus.modules.threats import diagram as threat_diagram
from pitangus.modules.threats import methods as threat_methods
from pitangus.modules.reporting.design import (ATTENTION, ATTENTION_BG, DANGER, DANGER_BG, INK, MUTED, SEVERITY, SOFT, STYLE, SUCCESS,
                            SUCCESS_BG, WIDTH, build, bullets, chip, disclaimer, h2, header, kpis, listing, meta, severity_label,
                            table, wide_page, wide_size)
from pitangus.modules.reporting.design import t as esc
from pitangus.shared.i18n import default_locale, localize, t, text

ORDER = ("critical", "high", "medium", "low")
PENDING = ("evidenced", "open")


def _status(status: str, locale: str) -> str:
    return t(f"threats.report.status.{status}", locale)


def _worst(items: list[dict]) -> str:
    return min((item["severity"] for item in items), key=ORDER.index)


def _families(model: dict) -> list[str]:
    """The rule sets that generate threats for this approach (none for ATT&CK, attack trees or team-only)."""
    method = model.get("methodology") or "stride"
    if method in threat_methods.RULE_BASED:
        return [threat_methods.RULE_BASED[method]]
    return [item for item in ("stride", "linddun") if item in model.get("custom_modules", [])] if method == "custom" else []


def _counts(items: list[dict], locale: str) -> str:
    return ", ".join(t(f"threats.report.count_{level}", locale, count=value) for level in ORDER
                     if (value := sum(1 for item in items if item["severity"] == level)))


def digest(model: dict, rows: list[dict], *, locale: str | None = None) -> dict:
    """Everything the PDF and the Markdown show, already grouped, sorted and in the `locale` language."""
    from pitangus.modules.threats import model as tm
    locale = locale or default_locale()
    rows = localize(rows, locale)
    components = {item["id"]: item for item in model.get("components", [])}
    flows = model.get("flows", [])
    number = {flow["id"]: index for index, flow in enumerate(flows, start=1)}
    pending = [row for row in rows if row["status"] in PENDING]
    team = [row for row in rows if row.get("framework") == "manual"]
    evidenced = [row for row in rows if row["status"] == "evidenced"]
    patterns: dict[tuple, list[dict]] = {}
    for row in pending:
        if row.get("framework") != "manual":
            patterns.setdefault((row["framework"], row["rule"]), []).append(row)

    def where(items: list[dict], limit: int = 8) -> str:
        flows_hit = sorted(number[item["element"]] for item in items if item["element_type"] == "flow" and item["element"] in number)
        names = [item["element_name"] for item in items if item["element_type"] != "flow"]
        parts = []
        if names:
            parts.append(listing(list(dict.fromkeys(names)), limit, locale=locale))
        if flows_hit:
            parts.append(t("threats.report.flows_list", locale, count=len(flows_hit),
                           list=listing([str(value) for value in flows_hit], limit + 2, locale=locale)))
        return "; ".join(parts)

    grouped = []
    for (family, rule), items in patterns.items():
        first = items[0]
        # Where the pattern is still open without evidence: the ones with evidence are already listed on their own.
        unproven = [item for item in items if item["status"] != "evidenced"]
        grouped.append({"rule": rule, "family": family, "title": first["title"], "category": first["category"], "cwe": first["cwe"],
                        "why": first["why"], "mitigations": first["mitigations"], "severity": _worst(items), "count": len(items),
                        "counts": _counts(items, locale), "where": where(items), "where_short": where(items, 3),
                        "evidenced": sum(1 for item in items if item["status"] == "evidenced"),
                        "unproven": len(unproven), "unproven_where": where(unproven, 3) if unproven else "",
                        "unproven_severity": _worst(unproven) if unproven else None})
    grouped.sort(key=lambda entry: (ORDER.index(entry["severity"]), -entry["evidenced"], -entry["count"], entry["title"]))
    team.sort(key=lambda row: (row["status"] not in PENDING, ORDER.index(row["severity"]), row["element_name"]))
    evidenced.sort(key=lambda row: (ORDER.index(row["severity"]), -row["evidence_count"], row["element_name"]))
    # What to handle first: the concrete (evidence, what the team wrote) before the generic patterns.
    first = [("evidence", row) for row in evidenced if row["severity"] in ("critical", "high")]
    first += [("team", row) for row in team if row["status"] in PENDING and row["severity"] in ("critical", "high")]
    # The critical patterns; with none, the high ones. Only where they aren't already listed with evidence.
    worst = "critical" if any(entry["unproven_severity"] == "critical" for entry in grouped) else "high"
    first += [("pattern", {**entry, "severity": entry["unproven_severity"]}) for entry in grouped if entry["unproven_severity"] == worst]
    first.sort(key=lambda pair: ORDER.index(pair[1]["severity"]))
    by_component = []
    for component in model.get("components", []):
        own = [row for row in pending if row["element"] == component["id"]]
        by_component.append({"component": component, "counts": {level: sum(1 for row in own if row["severity"] == level) for level in ORDER},
                             "total": len(own)})
    by_component.sort(key=lambda entry: tuple(-entry["counts"][level] for level in ORDER) + (entry["component"]["name"],))
    member_of = {member: boundary["name"] for boundary in model.get("boundaries", []) for member in boundary["components"]}
    decided = [row for row in rows if row["status"] not in PENDING]
    method = model.get("methodology") or "stride"
    linked = [item for item in model.get("components", []) if item.get("asset")]
    trees = model.get("attack_trees") or []
    paths = [threat_methods.open_paths(tree) for tree in trees]
    mappings = model.get("attack_mappings") or []
    return {"method": method, "families": _families(model), "trees": trees, "open_paths": paths, "mappings": mappings,
            "mapping_counts": {status: sum(1 for item in mappings if item["status"] == status) for status in ("relevant", "mitigated", "not_applicable")},
            "open_rules": sum(entry["count"] for entry in grouped),
            "locale": locale, "rows": rows, "linked": linked, "components": components, "flows": flows, "number": number, "pending": pending,
            "team": team, "evidenced": evidenced, "patterns": grouped, "first": first[:8], "by_component": by_component,
            "member_of": member_of, "decided": decided,
            "method_label": text(threat_methods.METHODOLOGIES.get(method, method), locale), "kinds": localize(tm.KINDS, locale),
            "labels": localize(tm.CLASSIFICATION_LABELS, locale),
            "severity": {level: sum(1 for row in pending if row["severity"] == level) for level in ORDER},
            "rule_based": sum(1 for row in rows if row.get("framework") != "manual")}


def coverage(model: dict, data: dict) -> list[str]:
    """How threats are derived and what couldn't be verified: without repositories, "no evidence" isn't "no flaws"."""
    locale = data["locale"]
    total, linked = len(data["components"]), len(data["linked"])
    if data["families"]:
        lines = [t("threats.report.coverage_method", locale, method=data["method_label"], count=len(data["team"]))]
    elif data["method"] == "attack":
        lines = [t("threats.report.coverage_method_attack", locale, techniques=len(data["mappings"]), count=len(data["team"]))]
    elif data["method"] == "attack_trees":
        lines = [t("threats.report.coverage_method_attack_trees", locale, goals=len(data["trees"]), count=len(data["team"]))]
    else:
        lines = [t("threats.report.coverage_method_manual", locale, method=data["method_label"], count=len(data["team"]))]
    if linked:
        lines.append(t("threats.report.coverage_linked", locale, linked=linked, total=total))
    else:
        lines.append(t("threats.report.coverage_unlinked", locale))
    if model.get("repository_refs"):
        lines.append(t("threats.report.coverage_refs", locale, refs=listing(list(model["repository_refs"]), 6, locale=locale)))
    return lines


def _kind(entry: dict, kinds: dict) -> str:
    return entry.get("custom_kind") or kinds.get(entry["kind"], entry["kind"])


def _element_name(model: dict, data: dict, element: str) -> str:
    if element in data["components"]:
        return data["components"][element]["name"]
    for flow in data["flows"]:
        if flow["id"] == element:
            return t("threats.report.flow_element", data["locale"], number=data["number"][element],
                     source=data["components"][flow["source"]]["name"], target=data["components"][flow["target"]]["name"])
    return t("threats.report.whole_system", data["locale"])


def _extras(row: dict, locale: str) -> list[str]:
    return [t(f"threats.report.likelihood.{row['likelihood']}", locale) if row.get("likelihood") else "",
            t(f"threats.report.impact.{row['impact']}", locale) if row.get("impact") else ""]


def _node_extras(model: dict, data: dict, node: dict) -> list[str]:
    locale = data["locale"]
    return [t(f"threats.report.difficulty.{node['difficulty']}", locale) if node.get("difficulty") else "",
            t("threats.report.on_element", locale, element=_element_name(model, data, node["element"])) if node.get("element") else "",
            t("threats.report.mitigated", locale) if node.get("mitigated") else ""]


def _summary(data: dict) -> tuple[str, list]:
    """The summary sentence and the key figures, which depend on how the approach finds threats."""
    locale, rows, counts = data["locale"], data["rows"], data["severity"]
    r = lambda key, **params: t(f"threats.report.{key}", locale, **params)  # noqa: E731
    team_open = sum(1 for row in data["team"] if row["status"] in PENDING)
    decided = r("summary_decided", count=len(data["decided"]))
    if data["method"] == "attack":
        mapped = data["mapping_counts"]
        sentence = " ".join((r("attack_summary", count=len(data["mappings"]), relevant=mapped["relevant"], mitigated=mapped["mitigated"],
                                 na=mapped["not_applicable"]), r("summary_team_only", count=len(data["team"])), decided))
        return sentence, [(r("kpi_techniques"), len(data["mappings"]), INK, SOFT), (r("kpi_relevant"), mapped["relevant"], ATTENTION, ATTENTION_BG),
                          (r("kpi_mitigated"), mapped["mitigated"], SUCCESS, SUCCESS_BG), (r("kpi_not_applicable"), mapped["not_applicable"], INK, SOFT),
                          (r("kpi_team"), team_open, INK, SOFT), (r("kpi_decided"), len(data["decided"]), SUCCESS, SUCCESS_BG)]
    if data["method"] == "attack_trees":
        reachable = sum(1 for value in data["open_paths"] if value)
        empty = sum(1 for tree in data["trees"] if not tree.get("nodes"))  # no steps yet: neither reachable nor cut
        cut = len(data["trees"]) - reachable - empty
        steps = sum(len(tree.get("nodes") or []) for tree in data["trees"])
        sentence = " ".join((r("trees_summary", count=len(data["trees"]), steps=r("steps_count", count=steps), open=reachable, cut=cut),
                             r("summary_team_only", count=len(data["team"])), decided))
        return sentence, [(r("kpi_goals"), len(data["trees"]), INK, SOFT), (r("kpi_reachable"), reachable, DANGER, DANGER_BG),
                          (r("kpi_cut"), cut, SUCCESS, SUCCESS_BG), (r("kpi_steps"), steps, INK, SOFT),
                          (r("kpi_team"), team_open, INK, SOFT), (r("kpi_decided"), len(data["decided"]), SUCCESS, SUCCESS_BG)]
    if data["families"]:
        evidence = (r("summary_evidenced", count=len(data["evidenced"])) if data["evidenced"]
                    else r("summary_no_evidence") if data["linked"] else r("summary_not_searched"))
        total = r("summary_total", count=len(rows), rules=data["rule_based"], components=len(data["components"]), flows=len(data["flows"]),
                  open_rules=r("open_rules", count=data["open_rules"]), patterns=r("patterns_count", count=len(data["patterns"])), team=r("team_written", count=len(data["team"])))
        sentence = " ".join((total, evidence, decided))
    else:
        sentence = " ".join((r("summary_team_only", count=len(data["team"])), decided))
    return sentence, [(r("kpi_open"), len(data["pending"]), INK, SOFT), (r("kpi_critical"), counts["critical"], SEVERITY["critical"][1], DANGER_BG),
                      (r("kpi_high"), counts["high"], ATTENTION, ATTENTION_BG), (r("kpi_evidenced"), len(data["evidenced"]), ATTENTION, ATTENTION_BG),
                      (r("kpi_team"), team_open, INK, SOFT), (r("kpi_decided"), len(data["decided"]), SUCCESS, SUCCESS_BG)]


def _how_to_read(data: dict) -> str:
    method = data["method"]
    key = f"how_to_read_{method}" if method in ("attack", "attack_trees") else "how_to_read" if data["first"] else "how_to_read_no_first"
    return t(f"threats.report.{key}", data["locale"])


def _contradiction(row: dict, locale: str) -> str:
    decision = row.get("decision") or {}
    return t("threats.report.contradicted_note", locale, status=_status(decision.get("status", ""), locale).lower(), by=decision.get("by") or "—") \
        if row.get("contradicted") else ""


def _tree_state(tree: dict, paths: int, locale: str) -> tuple[str, object]:
    """Reachable, cut, or not broken down yet (an empty tree is not a mitigated one)."""
    roots = sum(1 for node in tree.get("nodes") or [] if node["parent"] is None)
    if not roots:
        return t("threats.report.tree_state_empty", locale), MUTED
    if paths:
        return t("threats.report.tree_state_open", locale, count=roots, open=paths), DANGER
    return t("threats.report.tree_state_cut", locale), SUCCESS


def _letters():
    """Appendix letters in the order they appear: A, B, C… (an approach without trees doesn't leave a gap)."""
    letters = iter("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    return lambda title, locale: t("threats.report.appendix", locale, letter=next(letters), title=title)


def _yes(value, locale: str) -> str:
    return t("threats.report.yes" if value else "threats.report.no", locale)


# ------------------------------------------------------------------ PDF

def render_pdf(model: dict, rows: list[dict], *, version: str, locale: str | None = None) -> bytes:
    data = digest(model, rows, locale=locale)
    locale, rows = data["locale"], data["rows"]
    r = lambda key, **params: t(f"threats.report.{key}", locale, **params)  # noqa: E731
    appendix = _letters()
    story = header(r("title"), model["name"], model.get("description") or "")
    linked, refs = len(model.get("repositories") or []), len(model.get("repository_refs") or [])
    story.append(meta([(r("meta_method"), data["method_label"]),
                       (r("meta_updated"), f"{str(model.get('updated_at') or '')[:10] or '—'} · {model.get('updated_by') or '—'}"),
                       (r("meta_scope"), r("scope", components=len(data["components"]), flows=len(data["flows"]),
                                          boundaries=len(model.get("boundaries") or []))),
                       (r("meta_repositories"), r("repositories_value", linked=linked, pending=refs) if refs else str(linked) if linked else r("none")),
                       (r("meta_team"), str(len(data["team"]))), (r("meta_reference"), str(model.get("id") or "—"), "mono")]))
    sentence, figures = _summary(data)
    story += [Spacer(1, 10), h2(r("summary")), kpis(figures), Spacer(1, 6),
              Paragraph(esc(sentence, 900), STYLE["body"]), Paragraph(esc(_how_to_read(data), 400), STYLE["note"])]
    if data["first"]:
        story.append(h2(r("first")))
        body = []
        for source, item in data["first"]:
            if source == "pattern":
                body.append([chip(item["severity"], locale=locale),
                             f"<b>{esc(item['title'], 140)}</b><br/>{esc(item['category'], 80)} · {esc(r('pattern_in', count=item['unproven']), 60)}",
                             esc(item["unproven_where"], 200), esc("; ".join(item["mitigations"][:2]), 260)])
            else:
                label = _status("evidenced", locale) if source == "evidence" else r("from_team")
                body.append([chip(item["severity"], locale=locale),
                             f"<b>{esc(item['title'], 140)}</b><br/><font color=\"#636363\">{esc(label, 40)}</font>",
                             esc(_element_name(model, data, item["element"]) if item["element"] else item["element_name"], 160),
                             esc("; ".join(item["mitigations"][:2]) or "—", 260)])
        story.append(table([r("col_severity"), r("col_threat"), r("col_where"), r("col_action")], body,
                           [19 * mm, 55 * mm, 45 * mm, WIDTH - 119 * mm]))
    # ATT&CK and attack trees are the analysis itself for those approaches: in the body, not in an appendix.
    if data["method"] == "attack":
        story += _attack_pdf(model, data, r("attack_heading", count=len(data["mappings"])))
    if data["method"] == "attack_trees":
        story += _trees_pdf(model, data, lambda goal: r("tree_heading", goal=goal), r("trees_heading", count=len(data["trees"])))
    # The diagram, on a landscape page (A3 if large: it is still vector and can be zoomed in).
    if data["components"]:
        drawn = threat_diagram.scene(model, data["kinds"], locale=locale)
        _, _, width, height = drawn["bounds"]
        area = wide_size(None)
        size = "a3" if min(area[0] / width, area[1] / height) < 0.5 else None  # below that, text is unreadable in print
        area = wide_size(size)
        story += wide_page([Paragraph(esc(r("diagram")), STYLE["h3"]),
                            threat_diagram.to_drawing(model, area[0], area[1] - 12 * mm, data["kinds"], locale=locale)], size=size)
    if data["team"]:
        story.append(h2(r("team_heading", count=len(data["team"]))))
        body = []
        for row in data["team"]:
            extra = " · ".join(value for value in _extras(row, locale) if value)
            body.append([chip(row["severity"], locale=locale),
                         f"<b>{esc(row['title'], 160)}</b>" + (f'<br/><font color="#636363">{esc(row["why"], 320)}</font>' if row["why"] else ""),
                         esc(row["element_name"], 120) + (f'<br/><font color="#636363">{esc(extra, 80)}</font>' if extra else ""),
                         esc("; ".join(row["mitigations"]) or "—", 320),
                         esc(_status(row["status"], locale), 30) + (f'<br/><font color="#636363">{esc(row["owner"], 60)}</font>' if row.get("owner") else "")])
        story.append(table([r("col_severity"), r("col_threat_scenario"), r("col_where"), r("col_mitigation"), r("col_status")], body,
                           [19 * mm, 62 * mm, 32 * mm, WIDTH - 131 * mm, 18 * mm]))
    if data["evidenced"]:
        story.append(h2(r("evidenced_heading", count=len(data["evidenced"]))))
        body = []
        for row in data["evidenced"]:
            evidence = "<br/>".join(f"{esc(item['title'], 80)} · {esc(item['location'], 80)}" for item in row["evidence"][:3])
            more = row["evidence_count"] - min(3, len(row["evidence"]))
            warning = _contradiction(row, locale)
            body.append([chip(row["severity"], locale=locale),
                         f"<b>{esc(row['title'], 140)}</b>" + (f'<br/><font color="{DANGER.hexval().replace("0x", "#")}">{esc(warning, 200)}</font>' if warning else ""),
                         esc(row["element_name"], 120), evidence + (f"<br/>{esc(r('and_more', count=more), 40)}" if more > 0 else "")])
        story.append(table([r("col_severity"), r("col_threat"), r("col_where"), r("col_evidence")], body,
                           [19 * mm, 50 * mm, 38 * mm, WIDTH - 107 * mm]))
        story.append(Paragraph(esc(r("evidence_note"), 400), STYLE["note"]))
    if data["patterns"]:
        story.append(h2(r("patterns_heading", patterns=len(data["patterns"]), threats=data["open_rules"])))
        body = [[chip(entry["severity"], locale=locale),
                 f"<b>{esc(entry['title'], 140)}</b><br/><font color=\"#636363\">{esc(entry['category'], 60)}"
                 + (f" · CWE-{', CWE-'.join(str(value) for value in entry['cwe'][:3])}" if entry["cwe"] else "") + "</font>",
                 f"<b>{entry['count']}</b> · {esc(entry['counts'], 80)}<br/>{esc(entry['where'], 320)}",
                 esc("; ".join(entry["mitigations"][:3]), 300)] for entry in data["patterns"]]
        story.append(table([r("col_severity"), r("col_pattern"), r("col_affects"), r("col_measure")], body,
                           [19 * mm, 50 * mm, 55 * mm, WIDTH - 124 * mm]))
        story.append(Paragraph(esc(r("patterns_note"), 400), STYLE["note"]))
    story.append(h2(r("decisions_heading", count=len(data["decided"]))))
    if data["decided"]:
        body = [[esc(row["title"], 120), esc(row["element_name"], 100), esc(_status(row["status"], locale), 20),
                 esc((row.get("decision") or {}).get("reason") or "—", 240), esc((row.get("decision") or {}).get("by") or "—", 40),
                 esc(str((row.get("decision") or {}).get("at") or "")[:10] or "—", 10)]
                for row in data["decided"][:400]]
        story.append(table([r("col_threat"), r("col_where"), r("col_decision"), r("col_reason"), r("col_by"), r("col_date")], body,
                           [46 * mm, 32 * mm, 20 * mm, WIDTH - 136 * mm, 20 * mm, 18 * mm]))
        if len(data["decided"]) > 400:
            story.append(Paragraph(esc(r("decisions_truncated", shown=400, count=len(data["decided"]))), STYLE["note"]))
    else:
        story.append(Paragraph(esc(r("no_decisions"), 400), STYLE["body"]))
    # Annexes
    no = '<font color="#b71824">{}</font>'
    if data["flows"]:
        story.append(h2(appendix(r("appendix_flows"), locale)))
        body = [[str(data["number"][flow["id"]]), esc(f"{data['components'][flow['source']]['name']} → {data['components'][flow['target']]['name']}", 140),
                 flow["protocol"].upper(), esc(flow.get("name") or "—", 160) + (f'<br/><font color="#636363">{esc(", ".join(data["labels"][item] for item in flow["data"]), 80)}</font>' if flow.get("data") else ""),
                 esc(_yes(True, locale)) if flow.get("authenticated") else no.format(esc(_yes(False, locale))),
                 esc(_yes(True, locale)) if flow.get("encrypted") else no.format(esc(_yes(False, locale)))]
                for flow in data["flows"]]
        story.append(table([r("col_number"), r("col_source_target"), r("col_protocol"), r("col_carries"), r("col_auth_short"), r("col_encrypted")], body,
                           [10 * mm, 62 * mm, 18 * mm, WIDTH - 124 * mm, 17 * mm, 17 * mm]))
    story.append(h2(appendix(r("appendix_components"), locale)))
    body = []
    for entry in data["by_component"]:
        component = entry["component"]
        exposure = ", ".join(value for value in ("Internet" if component.get("internet_facing") else "",
                                                 ", ".join(data["labels"][item] for item in component.get("data") or [])) if value)
        body.append([f"<b>{esc(component['name'], 80)}</b><br/><font color=\"#636363\">{esc(_kind(component, data['kinds']), 50)}"
                     + (f" · {esc(component['technology'], 40)}" if component.get("technology") else "") + "</font>",
                     esc(data["member_of"].get(component["id"], "—"), 60), esc(exposure or "—", 90),
                     *[(f'<font color="{SEVERITY[level][1 if level == "critical" else 0].hexval().replace("0x", "#")}"><b>{entry["counts"][level]}</b></font>'
                        if entry["counts"][level] else '<font color="#636363">0</font>') for level in ORDER]])
    story.append(table([r("col_component"), r("col_boundary"), r("col_exposure"), r("col_critical_short"), r("col_high_short"),
                        r("col_medium_short"), r("col_low_short")], body,
                       [54 * mm, 36 * mm, WIDTH - 146 * mm, 14 * mm, 14 * mm, 14 * mm, 14 * mm]))
    story += _methods_pdf(model, data, appendix)
    # The method and the closing note stay together: a lone line on the last page reads as a mistake.
    story += [h2(r("method_heading")),
              KeepTogether([*bullets([esc(line, 600) for line in coverage(model, data)]), Spacer(1, 8),
                            Paragraph(esc(r("note"), 400) + " " + esc(disclaimer(locale), 400), STYLE["note"])])]
    return build(story, title=r("document_title", name=model["name"]), footer=r("document_title", name=model["name"][:80]), version=version,
                 author=str(model.get("updated_by") or "Pitangus"), subject=r("title"), locale=locale)


def _attack_pdf(model: dict, data: dict, heading: str) -> list:
    locale = data["locale"]
    r = lambda key, **params: t(f"threats.report.{key}", locale, **params)  # noqa: E731
    body = []
    for item in data["mappings"]:
        _, _, tactics = threat_methods.TECHNIQUES[item["technique"]]
        body.append([f"<b>{esc(item['technique'], 12)}</b> {esc(text(threat_methods.technique_label(item['technique']), locale), 80)}",
                     esc(", ".join(text(threat_methods.TACTICS[tactic], locale) for tactic in tactics), 80),
                     esc(_element_name(model, data, item["element"]) if item.get("element") else r("whole_system"), 100),
                     esc(r(f"mapping_status.{item['status']}")), esc(item.get("note") or "—", 200)])
    return [h2(heading), table([r("col_technique"), r("col_tactic"), r("col_element"), r("col_status"), r("col_note")], body,
                               [46 * mm, 30 * mm, 38 * mm, 18 * mm, WIDTH - 132 * mm]),
            Paragraph(html.escape(r("attack_trademark")), STYLE["note"])]


def _trees_pdf(model: dict, data: dict, title, heading: str) -> list:
    """Each tree with its steps and whether the goal is still reachable, under `heading`; `title(goal)` names each tree."""
    locale = data["locale"]
    r = lambda key, **params: t(f"threats.report.{key}", locale, **params)  # noqa: E731
    story = [h2(heading)]
    for tree, paths in zip(data["trees"], data["open_paths"]):
        story.append(Paragraph(esc(title(tree["goal"]), 120), STYLE["h3"]))
        state, colour = _tree_state(tree, paths, locale)
        story.append(Paragraph(f'<font color="{colour.hexval().replace("0x", "#")}">{esc(state, 200)}</font>', STYLE["note"]))
        for depth, node in _walk(tree):
            extra = _node_extras(model, data, node)
            gate = " " + r("all_required") if node["gate"] == "and" and node["has_children"] else ""
            story.append(Paragraph("&nbsp;" * 6 * depth + "•&nbsp;&nbsp;" + esc(node["text"], 200) + esc(gate, 40)
                                   + (f' <font color="#636363">· {esc(", ".join(value for value in extra if value), 160)}</font>' if any(extra) else ""),
                                   STYLE["body"]))
    return story


def _methods_pdf(model: dict, data: dict, appendix) -> list:
    """The approach's own material that isn't the core of the report: PASTA notes, and the trees or techniques when the
    approach is another one."""
    locale = data["locale"]
    r = lambda key, **params: t(f"threats.report.{key}", locale, **params)  # noqa: E731
    story = []
    notes = model.get("pasta") or {}
    if any(notes.values()):
        story.append(h2(appendix(r("appendix_pasta"), locale)))
        for key, title in threat_methods.PASTA_STAGES:
            if notes.get(key):
                story += [Paragraph(esc(text(title, locale), 80), STYLE["h3"]), Paragraph(esc(notes[key], 3000), STYLE["body"])]
    if data["trees"] and data["method"] != "attack_trees":
        story += _trees_pdf(model, data, lambda goal: r("tree_heading", goal=goal), appendix(r("trees_heading", count=len(data["trees"])), locale))
    if data["mappings"] and data["method"] != "attack":
        story += _attack_pdf(model, data, appendix(r("appendix_attack"), locale))
    return story


def _walk(tree: dict):
    children: dict = {}
    for node in tree["nodes"]:
        children.setdefault(node["parent"], []).append(node)

    def walk(parent, depth):
        for node in children.get(parent, []):
            yield depth, {**node, "has_children": bool(children.get(node["id"]))}
            yield from walk(node["id"], depth + 1)
    return walk(None, 0)


# ------------------------------------------------------------------ Markdown

def _cell(value) -> str:
    return " ".join(str(value or "").split()).replace("|", "\\|")


def _row(*cells) -> str:
    return "| " + " | ".join(cells) + " |"


def _line(value) -> str:
    """Text from the model on one line: a title or a step can't open a new heading or list item."""
    return " ".join(str(value or "").split())


def to_markdown(model: dict, rows: list[dict], *, locale: str | None = None) -> str:
    """The same report in Markdown (for a wiki, a ticket or a pull request)."""
    data = digest(model, rows, locale=locale)
    locale = data["locale"]
    r = lambda key, **params: t(f"threats.report.{key}", locale, **params)  # noqa: E731
    appendix = _letters()
    names = {level: severity_label(level, locale) for level in ORDER}
    sentence, _ = _summary(data)
    lines = ["# " + r("document_title", name=_line(model["name"])), "", _line(model.get("description")), "",
             r("md_intro", method=data["method_label"], date=str(model.get("updated_at") or "")[:16].replace("T", " "),
               by=model.get("updated_by") or "—", components=len(data["components"]), flows=len(data["flows"]),
               boundaries=len(model.get("boundaries") or [])), "",
             "## " + r("summary"), ""]
    if data["families"]:
        lines += ["- " + r("md_open", count=len(data["pending"]), counts=_counts(data["pending"], locale) or r("none")),
                  "- " + r("md_rules", count=data["rule_based"], open_rules=r("open_rules", count=data["open_rules"]),
                           patterns=r("patterns_count", count=len(data["patterns"])), team=r("team_written", count=len(data["team"]))),
                  "- " + (r("md_evidence", evidenced=len(data["evidenced"]), decided=len(data["decided"])) if data["linked"]
                          else r("md_no_evidence", decided=len(data["decided"]))), ""]
    else:
        lines += [sentence, ""]
    if data["first"]:
        lines += ["## " + r("first"), "", _row(r("col_severity"), r("col_threat"), r("col_where"), r("col_action")), "|---|---|---|---|"]
        for source, item in data["first"]:
            where = item["unproven_where"] if source == "pattern" else (_element_name(model, data, item["element"]) if item["element"] else item["element_name"])
            title = f"{item['title']} ({r('pattern_in', count=item['unproven'])})" if source == "pattern" else item["title"]
            lines.append(_row(names[item["severity"]], _cell(title), _cell(where), _cell("; ".join(item["mitigations"][:2]) or "—")))
        lines.append("")
    if data["method"] == "attack":
        lines += _attack_md(model, data, r("attack_heading", count=len(data["mappings"])))
    if data["method"] == "attack_trees":
        lines += _trees_md(model, data, r("trees_heading", count=len(data["trees"])))
    if data["team"]:
        lines += ["## " + r("team_heading", count=len(data["team"])), ""]
        for row in data["team"]:
            details = [row["element_name"], row["category"], r("md_status", status=_status(row["status"], locale).lower())]
            details += [r("md_owner", owner=row["owner"])] if row.get("owner") else []
            details += [value for value in _extras(row, locale) if value]
            lines += [f"### {names[row['severity']]} · {_line(row['title'])}", "", _line(" · ".join(details)), ""]
            if row["why"]:
                lines += [_line(row["why"]), ""]
            if row["mitigations"]:
                lines += [_line(r("md_mitigation", text="; ".join(row["mitigations"]))), ""]
    if data["evidenced"]:
        lines += ["## " + r("evidenced_heading", count=len(data["evidenced"])), "",
                  _row(r("col_severity"), r("col_threat"), r("col_where"), r("col_evidence_short")), "|---|---|---|---|"]
        for row in data["evidenced"]:
            evidence = "; ".join(r("md_evidence_item", title=item["title"], location=item["location"]) for item in row["evidence"][:3])
            warning = _contradiction(row, locale)
            lines.append(_row(names[row["severity"]], _cell(row["title"] + (f" ({warning})" if warning else "")), _cell(row["element_name"]), _cell(evidence)))
        lines.append("")
    if data["patterns"]:
        lines += ["## " + r("md_patterns_heading", count=len(data["patterns"])), "", r("md_patterns_note"), "",
                  _row(r("col_severity"), r("col_pattern"), r("col_affects"), r("col_measure")), "|---|---|---|---|"]
        for entry in data["patterns"]:
            cwe = f" · CWE-{', CWE-'.join(str(value) for value in entry['cwe'][:3])}" if entry["cwe"] else ""
            lines.append(_row(names[entry["severity"]], f"{_cell(entry['title'])} ({_cell(entry['category'])}{cwe})",
                              f"{entry['count']} ({entry['counts']}): {_cell(entry['where'])}", _cell("; ".join(entry["mitigations"][:3]))))
        lines.append("")
    if data["decided"]:
        lines += ["## " + r("decisions_heading", count=len(data["decided"])), "",
                  _row(r("col_threat"), r("col_where"), r("col_decision"), r("col_reason"), r("col_by"), r("col_date")), "|---|---|---|---|---|---|"]
        for row in data["decided"]:
            decision = row.get("decision") or {}
            lines.append(_row(_cell(row["title"]), _cell(row["element_name"]), _status(row["status"], locale),
                              _cell(decision.get("reason") or "—"), _cell(decision.get("by") or "—"), str(decision.get("at") or "")[:10] or "—"))
        lines.append("")
    if data["flows"]:
        lines += ["## " + appendix(r("appendix_flows"), locale), "", _row(r("col_number"), r("col_source_target"), r("col_protocol"), r("col_carries"),
                                                                       r("col_authenticated"), r("col_encrypted")), "|---|---|---|---|---|---|"]
        for flow in data["flows"]:
            carries = ", ".join(data["labels"][item] for item in flow.get("data") or [])
            lines.append(_row(str(data["number"][flow["id"]]),
                              f"{_cell(data['components'][flow['source']]['name'])} → {_cell(data['components'][flow['target']]['name'])}",
                              flow["protocol"].upper(), _cell(" · ".join(value for value in (flow.get("name"), carries) if value) or "—"),
                              _yes(flow.get("authenticated"), locale), _yes(flow.get("encrypted"), locale)))
        lines.append("")
    lines += ["## " + appendix(r("appendix_components"), locale), "", _row(r("col_component"), r("col_type"), r("col_boundary"), r("col_data"),
                                                                        r("col_exposed"), r("col_open_by_severity")), "|---|---|---|---|---|---|"]
    for entry in data["by_component"]:
        component = entry["component"]
        lines.append(_row(_cell(component["name"]), _cell(_kind(component, data["kinds"])), _cell(data["member_of"].get(component["id"], "—")),
                          _cell(", ".join(data["labels"][item] for item in component.get("data") or []) or "—"),
                          _yes(component.get("internet_facing"), locale), "/".join(str(entry["counts"][level]) for level in ORDER)))
    lines.append("")
    notes = model.get("pasta") or {}
    if any(notes.values()):
        lines += ["## " + appendix(r("appendix_pasta"), locale), ""]
        for key, title in threat_methods.PASTA_STAGES:
            if notes.get(key):
                lines += [f"### {text(title, locale)}", "", notes[key], ""]
    if data["trees"] and data["method"] != "attack_trees":
        lines += _trees_md(model, data, appendix(r("trees_heading", count=len(data["trees"])), locale))
    if data["mappings"] and data["method"] != "attack":
        lines += _attack_md(model, data, appendix(r("appendix_attack"), locale))
    lines += ["## " + r("method_heading"), "", *(f"- {line}" for line in coverage(model, data)), "",
              f"> {r('note')} {disclaimer(locale)}", ""]
    return "\n".join(lines)


def _trees_md(model: dict, data: dict, heading: str) -> list[str]:
    locale = data["locale"]
    r = lambda key, **params: t(f"threats.report.{key}", locale, **params)  # noqa: E731
    lines = ["## " + heading, ""]
    for tree, paths in zip(data["trees"], data["open_paths"]):
        lines += ["### " + r("tree_heading", goal=_line(tree["goal"])), "", _tree_state(tree, paths, locale)[0], ""]
        for depth, node in _walk(tree):
            extra = _node_extras(model, data, node)
            gate = " " + r("all_required") if node["gate"] == "and" and node["has_children"] else ""
            lines.append(f"{'  ' * depth}- {_line(node['text'])}{gate}" + (f" · {', '.join(item for item in extra if item)}" if any(extra) else ""))
        lines.append("")
    return lines


def _attack_md(model: dict, data: dict, heading: str) -> list[str]:
    locale = data["locale"]
    r = lambda key, **params: t(f"threats.report.{key}", locale, **params)  # noqa: E731
    lines = ["## " + heading, "", _row(r("col_technique"), r("col_tactic"), r("col_element"), r("col_status"), r("col_note")), "|---|---|---|---|---|"]
    for item in data["mappings"]:
        _, _, tactics = threat_methods.TECHNIQUES[item["technique"]]
        element = _element_name(model, data, item["element"]) if item.get("element") else r("whole_system")
        lines.append(_row(f"{item['technique']} {_cell(text(threat_methods.technique_label(item['technique']), locale))}",
                          ", ".join(text(threat_methods.TACTICS[tactic], locale) for tactic in tactics),
                          _cell(element), r(f"mapping_status.{item['status']}"), _cell(item.get("note") or "")))
    return lines + ["", r("attack_trademark"), ""]
