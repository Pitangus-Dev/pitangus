"""One finding when several web tools report the same problem at the same URL.

Two findings are the same only when an explicit row of `EQUIVALENT` puts their rules in one family and they are at
the same URL (scheme, host and path; a TLS check is about its host's root). Nothing is matched by title or by CWE
alone: a CWE covers many different checks. The first tool in `ORDER` keeps the finding (its fingerprint, title and
text); the others are listed in `also_detected_by`, their rules in `related_rules`, and what each saw stays in
`web.also` (tool, rule, title and evidence). The severity is the highest of them, and agreement adds confidence.
"""

from __future__ import annotations

from typing import Any

from pitangus.modules.scanning.engines import SEVERITY_NAME
from pitangus.shared.model import Finding

ORDER = ("zap", "nuclei", "testssl")
RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
NUCLEI_HEADERS = "http-missing-security-headers:"
# family → {tool: rule ids}. ZAP's are its alert ids (pluginId) as its SARIF names them.
EQUIVALENT: dict[str, dict[str, frozenset[str]]] = {
    "hsts-missing": {"zap": frozenset({"10035"}), "nuclei": frozenset({NUCLEI_HEADERS + "strict-transport-security"}),
                     "testssl": frozenset({"HSTS"})},
    "hsts-weak": {"nuclei": frozenset({"weak-hsts-detect", "weak-hsts-detect:hsts-header"}), "testssl": frozenset({"HSTS_time"})},
    "csp-missing": {"zap": frozenset({"10038"}), "nuclei": frozenset({NUCLEI_HEADERS + "content-security-policy"})},
    "clickjacking": {"zap": frozenset({"10020"}), "nuclei": frozenset({NUCLEI_HEADERS + "x-frame-options"})},
    "nosniff-missing": {"zap": frozenset({"10021"}), "nuclei": frozenset({NUCLEI_HEADERS + "x-content-type-options"})},
    "permissions-policy-missing": {"zap": frozenset({"10063"}), "nuclei": frozenset({NUCLEI_HEADERS + "permissions-policy"})},
    "cookie-samesite": {"zap": frozenset({"10054"}), "nuclei": frozenset({"missing-cookie-samesite-strict"})},
    # A server's version (ZAP 10036, 10037) has no twin: nuclei's version templates name technologies, not findings.
    # ZAP's Hidden File Finder (40035) and .env leak (40034) are active rules: they match an imported ZAP run only.
    "git-exposed": {"zap": frozenset({"40035"}), "nuclei": frozenset({"git-config"})},
    "env-exposed": {"zap": frozenset({"40034"}), "nuclei": frozenset({"laravel-env"})},
    "tls-deprecated": {"nuclei": frozenset({"deprecated-tls"}), "testssl": frozenset({"SSLv2", "SSLv3", "TLS1", "TLS1_1"})},
    "tls-weak-ciphers": {"nuclei": frozenset({"weak-cipher-suites", "insecure-cipher-suite-detect"}),
                         "testssl": frozenset({"cipherlist_NULL", "cipherlist_aNULL", "cipherlist_EXPORT", "cipherlist_LOW",
                                              "cipherlist_3DES_IDEA", "cipherlist_OBSOLETED"})},
    "certificate-expired": {"nuclei": frozenset({"expired-ssl"}), "testssl": frozenset({"cert_expirationStatus"})},
    "certificate-untrusted": {"nuclei": frozenset({"self-signed-ssl", "untrusted-root-certificate"}),
                              "testssl": frozenset({"cert_chain_of_trust"})},
    "certificate-name": {"nuclei": frozenset({"mismatched-ssl-certificate"}), "testssl": frozenset({"cert_trust"})},
}
_FAMILY = {(tool, rule): family for family, tools in EQUIVALENT.items() for tool, rules in tools.items() for rule in rules}


def _tool(finding: Finding) -> str:
    return str(finding.get("tool") or "").lower()  # ZAP's SARIF names itself "ZAP"


def family_of(finding: Finding) -> str | None:
    rule = str(finding.get("rule_id") or "")
    tool = _tool(finding)
    family = _FAMILY.get((tool, rule))
    if family is None and tool == "nuclei" and ":" in rule:
        family = _FAMILY.get((tool, rule.split(":", 1)[0]))
    if family is None and tool == "zap" and "-" in rule:  # an alert's variant (10035-1) of its rule
        family = _FAMILY.get((tool, rule.split("-", 1)[0]))
    return family


def _location(finding: Finding) -> str:
    path = str(finding.get("path") or "")
    return path if path.endswith("/") or "/" in path.split("://", 1)[-1] else path + "/"


def merge(findings: list[Finding]) -> tuple[list[Finding], int]:
    """The findings with cross-tool duplicates folded into one; and how many were folded."""
    ordered = sorted(findings, key=lambda item: ORDER.index(_tool(item)) if _tool(item) in ORDER else len(ORDER))
    kept: list[Finding] = []
    primary: dict[tuple[str, str], Finding] = {}
    folded = 0
    for finding in ordered:
        family = family_of(finding)
        key = (family, _location(finding)) if family else None
        twin = primary.get(key) if key else None
        if twin is None or _tool(twin) == _tool(finding):
            if key and twin is None:
                primary[key] = finding
            kept.append(finding)
            continue
        folded += 1
        tool = str(finding.get("tool"))
        if tool not in twin.setdefault("also_detected_by", []):
            twin["also_detected_by"].append(tool)
            twin["confidence"] = min(10, int(twin.get("confidence") or 6) + 1)
        if finding["rule_id"] not in twin.setdefault("related_rules", []):
            twin["related_rules"].append(finding["rule_id"])
        web: dict[str, Any] = twin.setdefault("web", {})
        seen = {"tool": tool, "rule_id": finding["rule_id"], "title": finding.get("title")}
        evidence = (finding.get("web") or {}).get("evidence")
        web.setdefault("also", []).append({**seen, **({"evidence": evidence} if evidence else {})})
        if RANK.get(finding["severity"], 4) < RANK.get(twin["severity"], 4):
            twin["severity"] = finding["severity"]
            twin["priority"]["action"] = "act" if finding["severity"] == "critical" else "attend" if finding["severity"] == "high" else "track"
            twin["priority"]["factors"] = [*twin["priority"].get("factors", []),
                                           *finding.get("priority", {}).get("factors", [])][:4] or [SEVERITY_NAME[finding["severity"]]]
    return kept, folded
