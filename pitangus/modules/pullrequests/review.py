"""Pull request review: which findings a PR introduces and how to report it on GitHub.

A PR is judged not by everything in the repository but by what it adds.
The head commit is scanned with the same engines and cross-checked against two things:

* the **baseline**, the latest full scan of the repository (main branch):
  an instance of a family it already had is pre-existing, not the PR's fault (families and copies counted as the
  registry counts them, findings/canonical.py, across the whole repository and following renamed files);
* the **diff**: a code or secret finding counts if it falls on an added or
  modified line; a dependency finding, if the PR touches the manifest that declares it.

Without a baseline, only what falls on changed lines counts, and the review says so.
"""

from __future__ import annotations

import re

from pitangus.modules.findings.canonical import growth
from pitangus.shared.i18n import default_locale, msg, t, text
from pitangus.shared.model import Finding

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
GATES = ("critical", "high", "medium", "never")


def changed_lines(files: list[dict]) -> dict[str, set[int] | None]:
    """Added or modified lines per file. None: no patch (binary or huge), the whole file counts."""
    result: dict[str, set[int] | None] = {}
    for item in files:
        name = item.get("filename")
        if not isinstance(name, str) or item.get("status") == "removed":
            continue
        patch = item.get("patch")
        if not isinstance(patch, str):
            # A file only renamed has nothing changed in it (GitHub sends no patch for it).
            result[name] = set() if item.get("status") == "renamed" and item.get("changes") == 0 else None
            continue
        lines: set[int] = set()
        current = 0
        for raw in patch.splitlines():
            header = HUNK.match(raw)
            if header:
                current = int(header.group(1))
                continue
            if raw.startswith("+") and not raw.startswith("+++"):
                lines.add(current)
                current += 1
            elif raw.startswith("-") and not raw.startswith("---"):
                continue
            elif not raw.startswith("\\"):
                current += 1
        result[name] = lines
    return result


def renames(files: list[dict]) -> dict[str, str]:
    """{head path: base path} for each renamed file (GitHub's `previous_filename`, git's `rename from`)."""
    return {item["filename"]: item["previous_filename"] for item in files
            if item.get("status") == "renamed" and isinstance(item.get("filename"), str) and isinstance(item.get("previous_filename"), str)}


def _touches(finding: Finding, changed: dict[str, set[int] | None]) -> bool:
    path = finding.get("path")
    if path not in changed:
        return False
    if finding.get("scanner") == "sca":
        return True  # the manifest or the lockfile changed
    lines = changed[path]
    return lines is None or finding.get("line") in lines


def classify(findings: list[Finding], changed: dict[str, set[int] | None], baseline: list[Finding] | None,
             renamed: dict[str, str] | None = None) -> dict[str, list[Finding]]:
    """Separates what the PR introduces from what already existed in the code it touches. `baseline`: the base's
    findings (an engine's reports or a stored run), or None without one. `renamed`: the PR's renamed files (`renames`).
    The server's review and `pitangus scan --base` both decide here.

    Both sides are grouped into families by the registry's own identity and copies are counted across the whole
    repository (`canonical.growth`): the PR introduces as many instances as the head has more than the base, reported
    among those on the lines it changed. Pasting a vulnerable line, a secret or a workflow step above an identical one,
    or into another file, adds an instance; moving one (within its file or to another), renaming its file,
    reformatting it or commenting it adds none."""
    touching = [finding for finding in findings if _touches(finding, changed)]
    if baseline is None:
        return {"introduced": touching, "preexisting": []}
    identities, added = growth(baseline, findings, renamed)
    groups: dict[str, list[Finding]] = {}
    for finding, identity in zip(findings, identities):
        if _touches(finding, changed):
            groups.setdefault(identity, []).append(finding)
    introduced, preexisting = [], []
    for identity, group in groups.items():
        ordered = sorted(group, key=lambda finding: (str(finding.get("path") or ""), int(finding.get("line") or 0)))
        introduced += ordered[:added[identity]]
        preexisting += ordered[added[identity]:]
    return {"introduced": introduced, "preexisting": preexisting}


def verdict(introduced: list[Finding], gate: str = "high") -> dict:
    """Commit status: fails if the PR introduces something of the threshold severity or worse."""
    counts = {level: sum(1 for item in introduced if item["severity"] == level) for level in SEVERITY_ORDER}
    if gate == "never":
        blocking = 0
    else:
        limit = SEVERITY_ORDER.index(gate)
        blocking = sum(count for level, count in counts.items() if SEVERITY_ORDER.index(level) <= limit)
    if blocking:
        description = msg("pulls.verdict.blocking", count=blocking, gate=GATE_LABEL.get(gate, gate))
    elif introduced:
        description = msg("pulls.verdict.below", count=len(introduced))
    else:
        description = msg("pulls.verdict.clean")
    return {"state": "failure" if blocking else "success", "description": description, "counts": counts, "blocking": blocking}


def _cell(value, limit: int = 120) -> str:
    """Safe cell text: one line, no backticks or pipes that break the table or open Markdown."""
    text = " ".join(str(value or "").split()).replace("`", "'").replace("|", "/")
    if len(text) > limit:
        text = text[:limit].rsplit(" ", 1)[0].rstrip(",.;:") + "…"  # cut at a word, not mid-word
    return text


SEVERITY_LABEL = {"critical": msg("pulls.severity.critical"), "high": msg("pulls.severity.high"), "medium": msg("pulls.severity.medium"),
                  "low": msg("pulls.severity.low"), "info": msg("pulls.severity.info")}
GATE_LABEL = {"critical": msg("pulls.gate.critical"), "high": msg("pulls.gate.high"), "medium": msg("pulls.gate.medium"),
              "low": msg("pulls.gate.low"), "never": msg("pulls.gate.never")}


def markdown_rows(findings: list[Finding], locale: str | None = None, limit: int = 25, *, fix: bool = True,
                  more: str = "pulls.table.more") -> list[str]:
    """`fix=False`: without the fix column (findings already fixed). `more`: where the rows past `limit` are."""
    locale = locale or default_locale()
    lines = [t("pulls.table.header", locale), "|---|---|---|---|"] if fix else [t("pulls.table.header_resolved", locale), "|---|---|---|"]
    from pitangus.modules.findings.fix_guide import attach
    ordered = attach([Finding(**item) for item in sorted(findings, key=lambda item: SEVERITY_ORDER.index(item["severity"]) if item["severity"] in SEVERITY_ORDER else 9)])
    for finding in ordered[:limit]:
        package = finding.get("package") or {}
        line = finding.get("line") if isinstance(finding.get("line"), int) else 0
        where = (f"`{_cell(package.get('name'), 60)}` {_cell(package.get('version'), 30)}" if package.get("name")
                 else f"`{_cell(finding.get('path'), 80)}:{line}`")
        # Only a command that really upgrades (with its version); "reinstall" or "install -r" don't say to what.
        commands = [item for item in (finding.get("fix") or {}).get("commands") or [] if item.get("action") == "update"]
        remedy = (f"`{_cell(commands[0]['code'], 120)}`" if commands and "`" not in commands[0]["code"]
                  else t("pulls.table.update_to", locale, version=_cell(package["fixed_version"], 30)) if package.get("fixed_version")
                  else _cell(text(finding.get("remediation"), locale), 140))
        severity = text(SEVERITY_LABEL.get(finding["severity"], finding["severity"]), locale)
        row = f"| {severity} | {_cell(text(finding['title'], locale), 80)} | {where} |"
        lines.append(f"{row} {remedy} |" if fix else row)
    if len(ordered) > limit:
        lines.append(f"| | {t(more, locale, count=len(ordered) - limit)} | |" + (" |" if fix else ""))
    return lines


def render_comment(pull: dict, outcome: dict, *, run_id: str, baseline_run: str | None, panel_url: str | None,
                   gate: str = "high", tools: list[dict] | None = None, locale: str | None = None) -> str:
    """GitHub Markdown comment. Never includes secret values: only rule, file and line.

    A PR comment is read by the whole team: it speaks PITANGUS_DEFAULT_LOCALE unless told otherwise."""
    locale = locale or default_locale()
    introduced, preexisting, state = outcome["introduced"], outcome["preexisting"], outcome["verdict"]
    commit = f"`{pull['head_sha'][:7]}`"
    base = f"`{pull.get('base_ref') or '?'}`"
    gate_label = text(GATE_LABEL.get(gate, gate), locale)
    lines = [t("pulls.comment.heading", locale), ""]
    if state["blocking"]:
        lines += ["> [!CAUTION]", "> " + t("pulls.comment.blocking", locale, count=state["blocking"], gate=gate_label),
                  "> " + t("pulls.comment.blocking_hint", locale)]
    elif introduced:
        lines += ["> [!WARNING]", "> " + t("pulls.comment.below", locale, count=len(introduced)), "> " + t("pulls.comment.below_hint", locale)]
    else:
        lines += ["> [!TIP]", "> " + t("pulls.comment.clean", locale, commit=commit)]
    if introduced:
        lines += ["", t("pulls.comment.attention", locale, count=len(introduced)), "", *markdown_rows(introduced, locale)]
    if preexisting:
        lines += ["", "<details>", f"<summary>{t('pulls.comment.preexisting', locale, count=len(preexisting), branch=base)}</summary>", "",
                  *markdown_rows(preexisting, locale, 15), "", "</details>"]
    engines = ", ".join(f"{item['name'].capitalize()} {item['version']}" for item in (tools or []) if item.get("status") in ("completed", "partial"))
    basis = t("pulls.comment.basis_baseline" if baseline_run else "pulls.comment.basis_none", locale, branch=base)
    where = t("pulls.comment.where_link", locale, url=panel_url) if panel_url else t("pulls.comment.where_plain", locale)
    lines += ["", t("pulls.comment.footer", locale, commit=commit, basis=basis, gate=gate_label, engines=f" · {engines}" if engines else "",
                    where=where, run=run_id[:12])]
    return "\n".join(lines)


def render_unused_comment(new: list[dict], before: list[dict], ecosystems: list[str], locale: str | None = None) -> str:
    """Informational: declared dependencies the code doesn't use, singling out the ones the PR adds."""
    locale = locale or default_locale()

    def table(items: list[dict]) -> list[str]:
        rows = [t("pulls.unused.header", locale), "|---|---|---|"]
        rows += [f"| `{_cell(item['name'], 60)}` | {item['ecosystem']} | `{_cell(item['manifest'], 80)}:{int(item['line'])}` |" for item in items[:30]]
        if len(items) > 30:
            rows.append(f"| {t('pulls.unused.more', locale, count=len(items) - 30)} | | |")
        return rows
    lines = [t("pulls.unused.heading", locale), ""]
    if new:
        lines += ["> [!WARNING]", "> " + t("pulls.unused.new", locale, count=len(new)), "> " + t("pulls.unused.new_hint", locale), "",
                  t("pulls.unused.added", locale, count=len(new)), "", *table(new)]
    else:
        lines += ["> [!TIP]", "> " + t("pulls.unused.clean", locale)]
    if before:
        lines += ["", "<details>", f"<summary>{t('pulls.unused.before', locale, count=len(before))}</summary>", "", *table(before), "", "</details>"]
    projects = ", ".join(f"`{item}`" for item in ecosystems) or t("pulls.unused.no_manifests", locale)
    lines += ["", t("pulls.unused.footer", locale, projects=projects, count=len(new))]
    return "\n".join(lines)
