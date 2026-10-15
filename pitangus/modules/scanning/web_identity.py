"""What a web finding is about, for its identity: the site, or one page.

A missing or misconfigured response header (CSP, HSTS, X-Frame-Options…) is a property of the site: reported once per
page, every new page of a blog added a finding, and fixing the header fixed dozens. Those alerts are one finding per
host and rule, at the host's root. A page's own finding keeps its URL, but a file name that carries a build hash
(`CSY8UEx1.js`, `index-BkL9x2a1.css`) changes on every deploy: its identity uses the name without the hash, so the
finding (and its triage) survives the next build. The URL people read stays the real one.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from pitangus.shared.model import Finding

# ZAP passive rules about response headers that every page of a site shares.
ZAP_SITE_RULES = frozenset({
    "10020",  # anti-clickjacking header
    "10021",  # X-Content-Type-Options
    "10035",  # Strict-Transport-Security
    "10036",  # Server header leaks its version
    "10037",  # X-Powered-By
    "10038",  # Content-Security-Policy not set
    "10055",  # CSP misconfigured
    "10063",  # Permissions-Policy
    "90004",  # site isolation headers (Spectre)
})
NUCLEI_SITE_TEMPLATES = ("http-missing-security-headers",)
# ZAP passive rules about what a page carries that usually comes from the site's shared template or server config: the
# same evidence on many pages is one finding per host and evidence (a different comment or header value stays apart).
ZAP_EVIDENCE_RULES = frozenset({
    "10015",  # Cache-Control directives to re-examine
    "10027",  # suspicious comments
    "10049",  # storable and cacheable content
})
# Rollup/Vite hashes are 8 characters of base64url (`-` and `_` included), webpack's 20 of hex.
FORMERS_MAX = 500   # former fingerprints one site-level finding remembers (one per page it was reported on)
HASH_PART = re.compile(r"[A-Za-z0-9_-]{8,32}")


def site_level(tool: str, rule: str) -> bool:
    """Whether a finding is about the site's response headers rather than one page."""
    tool, rule = str(tool or "").lower(), str(rule or "")
    if tool == "zap":
        return rule.split("-", 1)[0] in ZAP_SITE_RULES
    if tool == "nuclei":
        return rule.startswith(NUCLEI_SITE_TEMPLATES)
    return False


def shared_evidence(tool: str, rule: str) -> bool:
    """Whether a finding is about evidence the site's pages share (folded by host and evidence)."""
    return str(tool or "").lower() == "zap" and str(rule or "").split("-", 1)[0] in ZAP_EVIDENCE_RULES


def root_of(url: str) -> str:
    """The host's root, where a site-level finding lives."""
    parts = urlsplit(url)
    return f"{parts.scheme or 'https'}://{parts.netloc.lower()}/"


def _hashed(part: str) -> bool:
    # A build hash mixes letters and digits, the digits not only at the end (`bootstrap5`, `release20231001` aren't).
    if not HASH_PART.fullmatch(part):
        return False
    digits = sum(character.isdigit() for character in part)
    letters = sum(character.isalpha() for character in part)
    return digits >= 2 and letters >= 2 and not part.rstrip("0123456789").isalpha()


def _unhashed(segment: str) -> str:
    """One dot-separated piece of a file name with its hash replaced: the whole piece (`CCbp9-6k`) or its tail after a
    `-`/`_` (`index-BkL9x2a1`), the shortest tail first so the name before it stays."""
    cuts = [index + 1 for index, character in enumerate(segment) if character in "-_"]
    for cut in sorted(cuts, reverse=True):
        if _hashed(segment[cut:]):
            return f"{segment[:cut]}*"
    return "*" if _hashed(segment) else segment


def identity_path(url: str) -> str:
    """The URL as the finding's identity: the file name's build hash replaced (`/_astro/index.*.js`)."""
    head, _, name = url.rpartition("/")
    if not head or "." not in name:
        return url
    stem, _, extension = name.rpartition(".")
    return f"{head}/{'.'.join(_unhashed(segment) for segment in stem.split('.'))}.{extension}"


def remember_former(finding: Finding, former: str) -> None:
    """`former`: the fingerprint this report had before site-level folding and hash normalization (its page, its real
    file name). The registry moves the finding stored under it to the current one instead of marking it fixed."""
    if former == finding["fingerprint"]:
        return
    formers = finding.setdefault("previous_fingerprints", [])
    if former not in formers and len(formers) < FORMERS_MAX:
        formers.append(former)
