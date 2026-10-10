"""One finding when several web tools report the same problem at the same URL.

Two findings are the same only when an explicit row of `EQUIVALENT` puts their rules in one family and they are at
the same URL (scheme, host and path; a TLS check is about its host's root). Nothing is matched by title or by CWE
alone: a CWE covers many different checks. The first tool in `ORDER` keeps the finding (its fingerprint, title and
text); the others are listed in `also_detected_by`, their rules in `related_rules`, and what each saw stays in
`web.also` (tool, rule, title and evidence). The severity is the highest of them, and agreement adds confidence.

A rule may sit in several rows: testssl.sh's `security_headers` sums up every missing header, so it folds into the
first of ZAP's (or nuclei's) header findings at the same URL.
"""

from __future__ import annotations

from typing import Any

from pitangus.modules.scanning.engines import SEVERITY_NAME
from pitangus.shared.model import Finding

ORDER = ("zap", "nuclei", "testssl")
RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
NUCLEI_HEADERS = "http-missing-security-headers:"
TESTSSL_HEADERS = frozenset({"security_headers"})
# family → {tool: rule ids}. ZAP's are its alert ids (pluginId) as its SARIF names them.
EQUIVALENT: dict[str, dict[str, frozenset[str]]] = {
    "hsts-missing": {"zap": frozenset({"10035"}), "nuclei": frozenset({NUCLEI_HEADERS + "strict-transport-security"}),
                     "testssl": frozenset({"HSTS"})},
    "hsts-weak": {"nuclei": frozenset({"weak-hsts-detect", "weak-hsts-detect:hsts-header"}), "testssl": frozenset({"HSTS_time"})},
    "csp-missing": {"zap": frozenset({"10038"}), "nuclei": frozenset({NUCLEI_HEADERS + "content-security-policy"}), "testssl": TESTSSL_HEADERS},
    "clickjacking": {"zap": frozenset({"10020"}), "nuclei": frozenset({NUCLEI_HEADERS + "x-frame-options"}), "testssl": TESTSSL_HEADERS},
    "nosniff-missing": {"zap": frozenset({"10021"}), "nuclei": frozenset({NUCLEI_HEADERS + "x-content-type-options"}), "testssl": TESTSSL_HEADERS},
    "permissions-policy-missing": {"zap": frozenset({"10063"}), "nuclei": frozenset({NUCLEI_HEADERS + "permissions-policy"}),
                                   "testssl": TESTSSL_HEADERS},
    "cookie-samesite": {"zap": frozenset({"10054"}), "nuclei": frozenset({"missing-cookie-samesite-strict"})},
    # A server's version (ZAP 10036, 10037) has no twin: nuclei's version templates name technologies, not findings.
    # ZAP's Hidden File Finder (40035) and .env leak (40034) are active rules: they match an imported ZAP run only.
    "git-exposed": {"zap": frozenset({"40035"}), "nuclei": frozenset({"git-config"})},
    "env-exposed": {"zap": frozenset({"40034"}), "nuclei": frozenset({"laravel-env"})},
    "tls-deprecated": {"nuclei": frozenset({"deprecated-tls"}), "testssl": frozenset({"SSLv2", "SSLv3", "TLS1", "TLS1_1"})},
    "tls-weak-ciphers": {"nuclei": frozenset({"weak-cipher-suites", "insecure-cipher-suite-detect"}),
                         "testssl": frozenset({"cipherlist_NULL", "cipherlist_aNULL", "cipherlist_EXPORT", "cipherlist_LOW",
                                              "cipherlist_3DES_IDEA", "cipherlist_OBSOLETED"})},
    # testssl.sh's certificate checks are one finding per host (web_tools.parse_testssl), every check in its evidence.
    "certificate": {"nuclei": frozenset({"expired-ssl", "self-signed-ssl", "untrusted-root-certificate", "mismatched-ssl-certificate",
                                         "revoked-ssl-certificate"}),
                    "testssl": frozenset({"certificate"})},
}
_FAMILIES: dict[tuple[str, str], tuple[str, ...]] = {}
for _family, _tools in EQUIVALENT.items():
    for _name, _rules in _tools.items():
        for _rule in _rules:
            _FAMILIES[(_name, _rule)] = (*_FAMILIES.get((_name, _rule), ()), _family)


def _tool(finding: Finding) -> str:
    return str(finding.get("tool") or "").lower()  # ZAP's SARIF names itself "ZAP"


def families_of(finding: Finding) -> tuple[str, ...]:
    rule = str(finding.get("rule_id") or "")
    tool = _tool(finding)
    families = _FAMILIES.get((tool, rule), ())
    if not families and tool == "nuclei" and ":" in rule:
        families = _FAMILIES.get((tool, rule.split(":", 1)[0]), ())
    if not families and tool == "zap" and "-" in rule:  # an alert's variant (10035-1) of its rule
        families = _FAMILIES.get((tool, rule.split("-", 1)[0]), ())
    return families


def family_of(finding: Finding) -> str | None:
    families = families_of(finding)
    return families[0] if families else None


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
        keys = [(family, _location(finding)) for family in families_of(finding)]
        twin = next((primary[key] for key in keys if key in primary and _tool(primary[key]) != _tool(finding)), None)
        if twin is None:
            for key in keys:
                primary.setdefault(key, finding)
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
