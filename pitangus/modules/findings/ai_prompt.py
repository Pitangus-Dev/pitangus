"""A finding as a prompt to paste into the developer's own AI assistant (Claude, Cursor, Copilot…): the rule, where it
is, why it matters, the matched fragment and the recommended fix. Pitangus calls no AI for this; the text is all.

What never goes into it: a value. A secret finding and a hard-coded credential carry no fragment at all, and the fragment
is the finding's code as stored, rendered again as its structure (shared/render.py: every literal, every value after
`=` or `:`, every argument after a flag replaced); the texts around it were rendered when the run was stored. Never
code beyond the fragment the engine matched, capped.
"""

from __future__ import annotations

import posixpath
from typing import cast

from pitangus.modules.findings.fix_guide import panel_step
from pitangus.shared.i18n import msg, text
from pitangus.shared import render
from pitangus.shared.masking import keeps_no_snippet, mask_url, sanitize_finding
from pitangus.shared.model import Finding

FRAGMENT_LINES = 30
FRAGMENT_MAX = 2_000
LANGUAGES = {"py": "python", "js": "javascript", "jsx": "jsx", "mjs": "javascript", "cjs": "javascript", "ts": "typescript", "tsx": "tsx",
             "java": "java", "kt": "kotlin", "go": "go", "rb": "ruby", "php": "php", "cs": "csharp", "rs": "rust", "scala": "scala",
             "swift": "swift", "sql": "sql", "tf": "hcl", "yml": "yaml", "yaml": "yaml", "json": "json", "rules": "", "dockerfile": "dockerfile"}


def safe_fragment(finding: Finding) -> str | None:
    """The matched fragment fit to leave Pitangus: none for a secret or a hard-coded credential, otherwise its
    structure (render.code, idempotent on what was stored), at most FRAGMENT_LINES lines."""
    if keeps_no_snippet(finding):
        return None
    fragment = str(finding.get("snippet") or "").strip("\n")
    if not fragment.strip():
        return None
    fragment = render.code(fragment)
    lines = fragment.splitlines()[:FRAGMENT_LINES]
    return "\n".join(lines)[:FRAGMENT_MAX]


def _language(path: str) -> str:
    name = posixpath.basename(path).lower()
    return LANGUAGES.get(name if "." not in name else name.rsplit(".", 1)[1], "")


def prompt(finding: Finding, locale: str) -> str:
    """The prompt for one finding, in `locale`. `finding` with its fix guide attached (fix_guide.attach) gives steps."""
    def say(message) -> str:
        return text(message, locale) if isinstance(message, dict) else str(message or "")

    # Whatever it was read from, the finding as it may be shown (idempotent on a stored one); its fix guide is ours.
    finding = cast(Finding, {**sanitize_finding({key: value for key, value in finding.items() if key != "fix"}),
                             **({"fix": finding["fix"]} if "fix" in finding else {})})

    where = finding["path"] if finding.get("scanner") in ("dast", "sca") or not finding.get("line") else f"{finding['path']}:{finding['line']}"
    lines = [say(msg("findings.prompt.intro")), "",
             say(msg("findings.prompt.finding", title=say(finding.get("title")), rule=finding.get("rule_id"),
                     severity=say(msg(f"findings.prompt.severity.{finding.get('severity', 'medium')}")))),
             say(msg("findings.prompt.where", where=where))]
    package = finding.get("package") or {}
    if package.get("name"):
        lines.append(say(msg("findings.prompt.package", name=package["name"], version=package.get("version") or "?")
                         if not package.get("fixed_version") else
                         msg("findings.prompt.package_fixed", name=package["name"], version=package.get("version") or "?",
                             fixed=package["fixed_version"])))
    if finding.get("reason"):
        lines.append(say(msg("findings.prompt.why", reason=say(finding["reason"]))))
    fragment = safe_fragment(finding)
    if fragment:
        lines += ["", say(msg("findings.prompt.code")), f"```{_language(finding['path'])}", fragment, "```"]
    lines += ["", say(msg("findings.prompt.fix", fix=say(finding.get("remediation"))))]
    guide = finding.get("fix") or {}
    # The panel's own steps (re-verify in Pitangus) mean nothing to an assistant editing the code.
    steps = [say(step) for step in guide.get("steps") or [] if say(step) and not panel_step(step)]
    if steps:
        lines += [say(msg("findings.prompt.steps"))] + [f"- {step}" for step in steps[:8]]
    commands = [str(command.get("code")) for command in guide.get("commands") or [] if isinstance(command, dict) and command.get("code")]
    if commands:
        lines += [say(msg("findings.prompt.commands"))] + [f"    {command}" for command in commands[:4]]
    if finding.get("scanner") == "secrets":
        lines += ["", say(msg("findings.prompt.secret"))]
    lines += ["", say(msg("findings.prompt.rules"))]
    return render.URL_IN_TEXT.sub(lambda found: mask_url(found.group(0)), "\n".join(lines)).strip() + "\n"
