"""How to read, fix and check a web finding, from what the scanner itself said.

Pitangus doesn't write its own remediation for web rules: the fix often lives outside the code (a WAF, a CDN, a load
balancer, platform settings), so the scanner's description, solution and references are shown as published. Added
here only what is derived from the finding, never invented:

- the fragment of the evidence the result is about (the `'unsafe-inline'` of the directive the message names, the
  cookie or header named as parameter, the version in a `Server` header);
- for rules about response headers or cookies, a `curl` command that shows that header for the finding's URL;
- the priority factor that fits a web finding (headers apply to everyone who opens the URL; informational ones
  describe the site) instead of the code-only "confirm reachability".

The URL and the evidence come from the scanned site: they reach the command only through `shlex.quote`, and whoever
renders the rest escapes it.
"""

from __future__ import annotations

import re
import shlex

from pitangus.shared.i18n import msg
from pitangus.shared.model import Finding

# ZAP passive rules about response headers (plugin id → headers that show whether it is fixed).
ZAP_HEADERS: dict[str, tuple[str, ...]] = {
    "10010": ("set-cookie",), "10011": ("set-cookie",), "10054": ("set-cookie",), "10029": ("set-cookie",), "90033": ("set-cookie",),
    "10015": ("cache-control",), "10019": ("content-type",), "10020": ("x-frame-options", "content-security-policy"),
    "10021": ("x-content-type-options",), "10035": ("strict-transport-security",), "10036": ("server",), "10037": ("x-powered-by",),
    "10038": ("content-security-policy",), "10039": ("x-backend-server",), "10052": ("x-chromelogger-data",), "10055": ("content-security-policy",),
    "10056": ("x-debug-token",), "10061": ("x-aspnet-version",), "10063": ("permissions-policy",), "10098": ("access-control-allow-origin",),
    "90004": ("cross-origin-opener-policy", "cross-origin-embedder-policy", "cross-origin-resource-policy"),
}
# Nuclei's header template names the missing header as its matcher (kept as the finding's parameter).
NUCLEI_HEADER_TEMPLATES = frozenset(("http-missing-security-headers",))
HEADER_NAME = re.compile(r"[a-z0-9][a-z0-9-]{1,60}")
URL = re.compile(r"https?://[^\s]+", re.IGNORECASE)
CSP_SOURCE = re.compile(r"\b([a-z-]+-src(?:-elem|-attr)?)\s+includes\s+(unsafe-[a-z]+)", re.IGNORECASE)
DIGITS = re.compile(r"\d+")
VERSION_REST = re.compile(r"[\w.-]+")
VERIFY_WEB = msg("findings.fix.verify_web")
WEB_FACTORS = ("findings.web.factor.header", "findings.web.factor.cookie", "findings.web.factor.info", "findings.web.factor.attack",
               "findings.web.factor.observed", "scanning.priority.confirm_reachability")


def headers(finding: Finding) -> tuple[str, ...]:
    """The response headers a web finding is about, when the rule is one of them."""
    rule = str(finding.get("rule_id") or "")
    if rule in ZAP_HEADERS and "zap" in str(finding.get("tool") or "zap").lower():
        return ZAP_HEADERS[rule]
    parameter = str((finding.get("web") or {}).get("parameter") or "").lower()
    if rule in NUCLEI_HEADER_TEMPLATES and HEADER_NAME.fullmatch(parameter):
        return (parameter,)
    return ()


def check(finding: Finding) -> str | None:
    """`curl` showing the headers the finding is about, for its URL; none for any other rule, nor when only another
    method (a form's POST) gets that response."""
    names, url = headers(finding), str(finding.get("path") or "")
    method = str((finding.get("web") or {}).get("method") or "GET").upper()
    if not names or not URL.fullmatch(url) or method not in ("GET", "HEAD"):
        return None
    pattern = "^(" + "|".join(names) + "):"
    return f"curl -sI {shlex.quote(url)} | grep -i -E {shlex.quote(pattern)}"


def version_span(evidence: str) -> tuple[int, int] | None:
    """Where the first version number is (`2.4.41`, `8.1.2-1ubuntu`): a whole run of digits followed by a dot and a
    digit, up to the end of the word. Each run of digits is looked at once, so it takes linear time."""
    for digits in DIGITS.finditer(evidence):
        end = digits.end()
        if evidence.startswith(".", end) and DIGITS.match(evidence, end + 1) and (rest := VERSION_REST.match(evidence, end)):
            return digits.start(), rest.end()
    return None


def _span(evidence: str, start: int, end: int) -> dict:
    return {"before": evidence[:start], "match": evidence[start:end], "after": evidence[end:]}


def highlight(finding: Finding, message: str) -> dict | None:
    """The evidence split around the fragment the result is about, when it can be told from the result itself."""
    web = finding.get("web") or {}
    evidence = str(web.get("evidence") or "")
    if not evidence:
        return None
    if source := CSP_SOURCE.search(message or ""):
        directive, keyword = source.group(1).lower(), source.group(2).lower()
        for found in re.finditer(r"(?:^|;)\s*([a-z-]+)([^;]*)", evidence, re.IGNORECASE):
            if found.group(1).lower() == directive:
                token = re.search(re.escape(f"'{keyword}'"), found.group(2), re.IGNORECASE)
                if token:
                    return _span(evidence, found.start(2) + token.start(), found.start(2) + token.end())
    rule = str(finding.get("rule_id") or "")
    if rule == "10035" and (fragment := re.search(r"max-age\s*=\s*0\b", evidence, re.IGNORECASE)):
        return _span(evidence, fragment.start(), fragment.end())
    if rule == "10036" and (version := version_span(evidence)):
        return _span(evidence, *version)
    parameter = str(web.get("parameter") or "")
    if len(parameter) >= 2 and parameter != evidence and (index := evidence.find(parameter)) >= 0:
        return _span(evidence, index, index + len(parameter))
    return None


def factor(finding: Finding) -> dict:
    """What the finding's context means for its priority, from what is known of it."""
    names = headers(finding)
    if (finding.get("web") or {}).get("attack"):
        return msg("findings.web.factor.attack")
    if finding.get("severity") == "info":
        return msg("findings.web.factor.info")
    if names == ("set-cookie",):
        return msg("findings.web.factor.cookie")
    return msg("findings.web.factor.header") if names else msg("findings.web.factor.observed")


def guide(finding: Finding) -> dict:
    """The fix guide of a web finding: the scanner's solution as published (stored as the remediation), the check and
    the re-scan. The scanner's description and references stay in the finding's `web`."""
    reason = finding.get("reason")
    message = str(((reason or {}).get("params") or {}).get("message") or "") if isinstance(reason, dict) else str(reason or "")
    command = check(finding)
    return {"kind": "web", "steps": [finding.get("remediation") or "", VERIFY_WEB], "example": None,
            "commands": [{"label": msg("findings.fix.commands.check"), "action": "check", "code": command}] if command else [],
            "web": {"highlight": highlight(finding, message), "check": command}}


def prioritize(finding: Finding) -> None:
    """Replaces a code-only factor (or a web factor computed earlier) with the one for this web finding."""
    priority = finding.get("priority")
    if not isinstance(priority, dict):
        return
    factors = [item for item in priority.get("factors") or [] if not (isinstance(item, dict) and item.get("$t") in WEB_FACTORS)]
    finding["priority"] = {**priority, "factors": [*factors, factor(finding)]}  # a copy: callers may share the stored dict
