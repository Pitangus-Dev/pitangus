"""Run kinds, in one place so that no filter is left behind when one is added."""

# Full scans of an asset: whatever a new one no longer reports counts as remediated.
FULL_SCANS = ("repository_scan", "image_scan", "dast_scan")
# The full scans that store a package inventory: what an SBOM (and the VEX next to it) is built from. A web scan has
# none, so a domain has no SBOM.
INVENTORY_SCANS = ("repository_scan", "image_scan")
# Advisories published after the last scan, checked against its dependencies (advisory_watch). They only add:
# they are not a full scan and remediate nothing.
ADVISORY_RUNS = ("advisory_watch",)
# Findings another tool reported (SARIF). A full import remediates only what that same tool stopped reporting.
IMPORT_RUNS = ("sarif_import",)
# Everything that feeds the findings registry and accepts triage.
FINDING_RUNS = FULL_SCANS + ("pr_review",) + ADVISORY_RUNS + IMPORT_RUNS
