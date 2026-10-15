"""A finding as a prompt to paste into the developer's own AI assistant (Claude, Cursor, Copilot…): the rule, where it
is, why it matters, its code and the recommended fix. Pitangus calls no AI for this; the text is all.

Pitangus stores no code, so the prompt it builds has none (`parts`): its code is added where the reader is, from what
they read when they opened the finding (the panel, from runs/code_view.py, secrets masked), or by the CLI from the
local file it scanned (`prompt` with `code`). A secret finding and a hard-coded credential never carry code.
"""

from __future__ import annotations

import posixpath
from typing import cast

from pitangus.modules.findings.fix_guide import panel_step
from pitangus.shared.i18n import msg, text
from pitangus.shared import render
from pitangus.shared.masking import code_withheld, mask_url, sanitize_finding
from pitangus.shared.model import Finding

LANGUAGES = {"py": "python", "js": "javascript", "jsx": "jsx", "mjs": "javascript", "cjs": "javascript", "ts": "typescript", "tsx": "tsx",
             "java": "java", "kt": "kotlin", "go": "go", "rb": "ruby", "php": "php", "cs": "csharp", "rs": "rust", "scala": "scala",
             "swift": "swift", "sql": "sql", "tf": "hcl", "yml": "yaml", "yaml": "yaml", "json": "json", "rules": "", "dockerfile": "dockerfile"}


def _language(path: str) -> str:
    name = posixpath.basename(path).lower()
    return LANGUAGES.get(name if "." not in name else name.rsplit(".", 1)[1], "")


def parts(finding: Finding, locale: str) -> dict[str, str]:
    """The prompt for one finding, in `locale`, around where its code goes: {before, heading, language, after}. With
    its fix guide attached (fix_guide.attach) it gives steps."""
    def say(message) -> str:
        return text(message, locale) if isinstance(message, dict) else str(message or "")

    # Whatever it was read from, the finding as it may be shown (idempotent on a stored one); its fix guide is ours.
    finding = cast(Finding, {**sanitize_finding({key: value for key, value in finding.items() if key != "fix"}),
                             **({"fix": finding["fix"]} if "fix" in finding else {})})

    where = finding["path"] if finding.get("scanner") in ("dast", "sca") or not finding.get("line") else f"{finding['path']}:{finding['line']}"
    before = [say(msg("findings.prompt.intro")), "",
              say(msg("findings.prompt.finding", title=say(finding.get("title")), rule=finding.get("rule_id"),
                      severity=say(msg(f"findings.prompt.severity.{finding.get('severity', 'medium')}")))),
              say(msg("findings.prompt.where", where=where))]
    package = finding.get("package") or {}
    if package.get("name"):
        before.append(say(msg("findings.prompt.package", name=package["name"], version=package.get("version") or "?")
                          if not package.get("fixed_version") else
                          msg("findings.prompt.package_fixed", name=package["name"], version=package.get("version") or "?",
                              fixed=package["fixed_version"])))
    if finding.get("reason"):
        before.append(say(msg("findings.prompt.why", reason=say(finding["reason"]))))
    after = [say(msg("findings.prompt.fix", fix=say(finding.get("remediation"))))]
    guide = finding.get("fix") or {}
    # The panel's own steps (re-verify in Pitangus) mean nothing to an assistant editing the code.
    steps = [say(step) for step in guide.get("steps") or [] if say(step) and not panel_step(step)]
    if steps:
        after += [say(msg("findings.prompt.steps"))] + [f"- {step}" for step in steps[:8]]
    commands = [str(command.get("code")) for command in guide.get("commands") or [] if isinstance(command, dict) and command.get("code")]
    if commands:
        after += [say(msg("findings.prompt.commands"))] + [f"    {command}" for command in commands[:4]]
    if finding.get("scanner") == "secrets":
        after += ["", say(msg("findings.prompt.secret"))]
    after += ["", say(msg("findings.prompt.rules"))]

    def urls(lines: list[str]) -> str:
        return render.URL_IN_TEXT.sub(lambda found: mask_url(found.group(0)), "\n".join(lines)).strip()
    return {"before": urls(before), "heading": say(msg("findings.prompt.code")), "language": _language(finding["path"]),
            "after": urls(after)}


def code_text(lines: list[dict], locale: str) -> str:
    """Lines read when the finding was opened (runs/code_view.py) as the prompt's code: a withheld line says so."""
    return "\n".join(text(msg("findings.prompt.masked_line"), locale) if line.get("masked") == "line" else str(line.get("text") or "")
                     for line in lines)


def prompt(finding: Finding, locale: str, code: str | None = None) -> str:
    """The prompt for one finding, with `code` (its lines as the reader has them, secrets masked) when there is any."""
    pieces = parts(finding, locale)
    block = f"\n\n{pieces['heading']}\n```{pieces['language']}\n{code}\n```" if code and code.strip() and not code_withheld(finding) else ""
    return f"{pieces['before']}{block}\n\n{pieces['after']}\n"
