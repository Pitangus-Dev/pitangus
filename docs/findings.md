English · [Español](es/hallazgos.md)

# Findings, triage and remediation

Every scan, pull request review and import feeds one **register** per asset (a repository, an image or a verified
domain). The register keeps the current state of each finding, decides on its own what was fixed and what came back,
and records what your team decided about each one (**triage**: confirm it, dismiss it as a false positive, accept the
risk, mark it fixed). This page explains how to read the results, how to work through them and how to export them.
Terms such as fingerprint, triage, KEV or SARIF are explained in the [glossary](glossary.md).

## Prerequisites

- At least one finished scan: of code ([Scan your code](scanning-code.md)), of an image
  ([Scan container images](scanning-images.md)) or of a site ([Scan a website or API](scanning-web.md)), or a SARIF
  import from another tool ([Integrations](integrations.md)).
- Any user can read findings and triage them. Accepting a risk, excluded paths, deadlines and re-verifying a web
  finding are for administrators.

## The Overview dashboard

**Overview** (`#/overview`) summarizes every asset over the last 7, 30 or 90 days or the last year. Its figures have
explicit definitions:

- **Open**: what appears in the latest run of each asset.
- **Fixed**: a fingerprint that was in an earlier run of that asset and no longer appears (shown with the fix rate).
- **Time to fix**: from first detection until the finding is gone.
- **Overdue**: open findings past their [remediation deadline](#remediation-deadlines).
- **In CISA KEV**: open findings that are actively exploited somewhere.
- **Score**: a summary shown next to its formula, `100·e^(−risk/150)`, where risk weighs open findings by severity,
  KEV and EPSS. It drops with what's open, most with critical and KEV findings. It isn't a certification.

The panels show new findings per day by severity, open findings by severity, found versus fixed, the most common
weakness types (CWE), exploitability (findings in KEV or with EPSS ≥ 10 %), the most affected assets, the top
priority findings, recent runs and a year of scan activity. **Security news** lists the CVEs published in NVD in the
last 7 and 30 days and the latest additions to CISA KEV; a CVE is marked **affects you** when it names a package
from your open findings as the affected product, or one of their CVEs.

<!-- screenshot: overview | The Overview dashboard with the score, open and overdue findings, and charts of new and fixed findings over the last 30 days -->

## Read the findings

**Findings** (`#/findings`) opens one asset at a time: pick it at the top. You can look at its **Current state**
(scans, PRs and imports combined) or at one specific run. Tabs split **Open**, **Fixed** and **Excluded** findings.

- **Cards**: overdue, critical, high, in CISA KEV and fix available, counted over pending findings.
- **Filters**: search (package, CVE, file…), severity and **More filters**: status, priority, source (dependencies,
  code, infrastructure, CI/CD pipelines, secrets, web) and due date.
- **The detail** of a finding says what it is, where, how to fix it (with a before and after example when there is
  one), its priority and why, its lifecycle (when it was first and last seen, where it came from) and its triage
  history. Dependency findings add the fixed version, CVSS, EPSS and KEV
  ([Dependency findings](scanning-code.md#dependency-findings)).

<!-- screenshot: findings | The findings table of one asset, with severity, priority and due date columns, and a web problem grouped over several URLs -->

### Web findings are grouped by problem

In a site's findings, the same problem on several URLs is one row that opens to each URL, and the table says, for
example, "15 findings in 8 problems". Every URL is still its own finding, with its own triage and history, and the
figures count them one by one. The technical reports (PDF and Markdown) group them the same way; the audit evidence
keeps one row per URL. A web finding's detail also shows what the other tools that saw it reported (**Also reported
by**). See [Scan a website or API](scanning-web.md).

## How a finding lives and dies

Each finding has a **fingerprint**: a stable identifier built from what it is and where, so the same problem in the
next run is recognized as the same finding. The register updates itself from four sources:

| Source | What it does |
| --- | --- |
| **Full scan** of the asset | Whatever appears stays open, and is reopened if it had been fixed. Whatever was open and no longer appears is **fixed automatically**. |
| **PR review** | What the PR introduces stays open with origin "PR #n". A later commit in the PR that removes it fixes it; a PR closed without merging withdraws its findings; a merged PR leaves them for the next full scan. |
| **Import from another tool** (SARIF 2.1.0 from Semgrep, CodeQL, Snyk, Trivy, Strix, ZAP, Nuclei…) | Its findings open with the tool's name as origin, in an asset Pitangus already knows. A later **full** import of the **same tool** fixes what it no longer reports; a **partial** one only opens and updates. Pitangus's scans never fix an imported finding, and an import never fixes theirs. |
| **Triage** | What your team decides (next section). |

Fingerprints are built to survive normal changes:

- Secrets and Opengrep code findings keep their fingerprint when lines are added above them, so they don't look
  fixed and new at once.
- A secret is identified by its rule, its file and what precedes it on its line, never by its value.
- A dependency advisory has one fingerprint whichever engine reports it and whatever it calls it.
- Findings from versions that computed fingerprints differently keep their state, triage, Jira issue and pending
  verification on the next scan.

A repository's identity is its GitHub identity (its numeric ID): a renamed repository is still the same one. If
GitHub stops giving access to a repository (deleted, or removed from the App), the panel warns; if access doesn't
come back within 24 hours, its findings, triage and linked tickets are deleted.

A scan where an engine didn't run is **incomplete**: it doesn't mark anything as fixed, because "not seen" isn't
"gone".

## Triage

Select one or more findings (up to 500 at a time) and choose a status. Every change goes into the finding's history
with user, date and reason.

| Status | Action | What it means | Reason |
| --- | --- | --- | --- |
| Open | **Reopen** | Counts as pending again in the panel, tickets and SARIF. | Optional |
| In progress | **In progress** | Someone is working on the fix. Still counts as pending. | Optional |
| False positive | **False positive** | Stops counting as pending in this and future scans of the asset. | Required |
| Accepted risk | **Accept risk** | You take on the risk until an expiry date (one year at most); then it reopens on its own. **Administrators only.** | Required |
| Fixed | **Mark fixed** | Marks it fixed without waiting for the next scan. Say how (PR, patch, deploy). If a later scan finds it again, it reopens on its own. | Required |

A required reason has at least 10 characters. Decisions are tied to the fingerprint, not to a run, so they hold
across scans. Dismissed findings (false positives, accepted risks) don't count as open, don't go to Jira and are
reported as such in VEX ([Compliance evidence](compliance.md)).

## Verify a fix: Reverify and Verify again

Fixed something? Open the finding and click **Reverify**: Pitangus scans its asset again and tells you whether it's
still there. After a result, the button becomes **Verify again**. The result is one of:

- **Fixed**: the new full scan no longer finds it, and the register marks it fixed.
- **Still present**: it still shows up.
- **Incomplete**: an engine didn't run, so the scan proves nothing. Try again.
- **Failed**: the scan failed. Try again.

If a scan of that asset is already queued or running, the finding joins it instead of starting another one. Some
findings are verified differently:

- **Web findings**: Reverify runs the passive scan of the domain again (administrators only). Deploy the fix first.
- **From an open PR**: they're verified on every push to the PR.
- **Imported**: only the tool that reported it can say whether it's gone; import a new full SARIF from it.

## Excluded paths

Some folders aren't worth looking at: intentionally vulnerable examples, tests with fake data, generated code. An
**administrator** excludes them per repository in **Findings → Repository settings → Excluded paths**, one pattern
per line, with a mandatory reason kept in the history:

```text
fixtures
docs/*.md
**/testdata
```

Patterns work like `.gitignore`: a pattern that matches a folder excludes everything inside it (`fixtures` covers
`fixtures/a/b.py`), `*` doesn't cross folders and `**` does. Patterns that would exclude everything (`**`, `*/**`),
absolute paths and `..` are rejected.

- What falls under them doesn't count as open, isn't in the report or the SARIF and **doesn't block PRs**. It
  doesn't disappear: it stays in the **Excluded** tab, and every run states in its limitations how many findings were
  left out and by which pattern.
- Excluding isn't fixing: excluded findings never become fixed. Remove the exclusion and they're open again.
- Exclusions live on the server, **not in the repository**: a file in the repository would let a PR exclude itself.
  For the same reason, the repository's `.gitleaks.toml` isn't applied.

From the terminal, `make scan DIR=../my-repo ARGS="--exclude fixtures"` does the same for one run ([CLI](cli.md)).

## Remediation deadlines

Every pending finding has a due date based on its severity, counted from **first detection** (reopening it doesn't
restart the clock). By default: critical 7 days, high 30, medium 90 and low 180. An **administrator** changes them in
**Policies → Remediation deadlines** (a whole number of days from 1 to 3650, or empty so that severity never falls
due); they apply to every repository. Only open and in-progress findings fall due: fixed, excluded, false positives
and accepted risks that haven't expired never do.

They show up in **Findings** (the **Overdue** card, an "Overdue by N days" or "Due in N days" badge, and the
**More filters → Due date** filter), in the **Overview** (Overdue) and in the audit evidence report (the policy and
the overdue findings sorted by delay, which is what SOC 2 and ISO 27001 ask for as evidence of timely remediation).

## Several assets at once

The scope picker at the top of **Findings** (the same one as in **Compliance**) has four options: **One** asset (the
default, with its runs and settings), **An organization** (its repositories), **Choose several** (repositories and
images) or **All**. With a repository come the images built from it, unless you turn that off.

The scope stays in the address (`#/findings?scope=account&account=acme`), so a reload or a shared link opens the
same view. It combines each asset's current state:

- The cards add up the whole scope, and the table gains an **Asset** column.
- **By asset** lists each asset with its pending and critical findings, most critical first; click one to open it
  alone.
- Triage works per finding or on a selection across assets. It's saved asset by asset; if one fails, the panel says
  which and retries only those. Jira issues and the consolidated audit evidence (up to 500 assets) work the same way.
- Excluded paths, secret rules, picking a specific run and the per-asset files (PDF, SARIF, SBOM…) need one asset.
- A very large scope lists the 10,000 most urgent findings of the tab and says so; the counts always cover
  everything.

## OWASP coverage

**Coverage** (`#/coverage`) shows, for one asset's latest full scan, which OWASP Top 10 categories were checked:
how many Pitangus rules target each category (read from `rules/`), which engines covered it and how many findings it
produced. What a scan of that kind can't cover is declared with its reason, not with a generic sentence: for code,
insecure design, logging and alerting, and exceptional conditions need the running application; an image scan only
reads packages and configuration; a passive web scan sends no attacks.

<!-- screenshot: coverage | The OWASP coverage matrix of one run, with the categories checked, the engines and rule counts behind each, and the categories not covered with their reason -->

## OWASP guidance on each finding

Every finding links to the OWASP pages about its kind of problem, under **OWASP guidance** in its detail:

- the [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/) page that explains how to prevent it,
- its OWASP Top 10:2025 category,
- and, for code and web findings, the OWASP API Security Top 10 2023 risk and the Web Security Testing Guide (WSTG)
  test that fit.

The links come from a curated, versioned mapping in the repository
([`pitangus/modules/findings/references.yaml`](../pitangus/modules/findings/references.yaml)): by rule first
(security headers, cookie flags, CORS, HSTS, TLS, clickjacking, GitHub Actions audits, image checks…), then by
framework or file (Dockerfile, Kubernetes, Terraform, pipelines), then by CWE, then by scanner. A finding whose engine
gave no OWASP category gets the one OWASP's own CWE mapping assigns.

They're links only; the pages' text isn't copied. Pitangus doesn't write its own fix for third-party rules, since the
fix may live in a WAF, a CDN or the platform rather than the code: **the tool's own guidance and references come
first, as published**, and the OWASP links after them. The technical PDF and the Markdown report print them next to
each finding's references. The API serves them as `guidance` (`title`, `url`, `kind`: `cheatsheet`, `top10`,
`api_top10` or `wstg`), computed when the finding is read, so findings from older runs get them too.

<!-- screenshot: finding-web-detail | A web finding's detail: what it is, evidence, how to fix it, the OWASP guidance links and the other tools that reported it -->

## CVE tracker

**CVE tracker** (`#/cve-tracker`) searches a local copy of NVD kept in the database, cross-referenced with CISA KEV
and EPSS: free text, CVE by prefix, severity, KEV only, year, sorting by date, CVSS or EPSS. Each CVE shows its
severity and CVSS, EPSS, whether it's in KEV, its CWE, vector and references, and **which of your repositories and
images have it** among their findings. **Only those affecting me** limits the list to CVEs open in your assets
(leaving out what was dismissed in triage). The search stays in the address, so you can share or reload it.

The copy loads in the background from newest to oldest, resumes after a restart and then stays current every 2
hours. Without an NVD API key, NVD allows 5 requests every 30 seconds and the full load (about 400,000 CVEs) takes a
few hours; with `PITANGUS_NVD_API_KEY` it's about 8 times faster. `PITANGUS_CVE_SYNC=off` turns it off
([Configuration](configuration.md)). When NVD hasn't scored a CVE (since 2026 it only enriches some), the score comes
from **EUVD** (ENISA's database), queried on demand and cached, which also says whether it's actively exploited.

## Export findings

From a run or the current state of an asset: **PDF report**, and under **More formats**:

| Format | For |
| --- | --- |
| **Markdown report** | Pasting into a wiki, an issue or a PR. |
| **Full JSON** | Your own scripts. |
| **SARIF (code scanning)** | SARIF 2.1.0, the standard format for static analysis results, with `security-severity`, for GitHub code scanning and other tools. |
| **Jira tickets (JSON)** | One ticket per remediation task, in the shape the Jira connector uses. |
| **SBOM · CycloneDX 1.6** and **VEX · OpenVEX (from triage)** | See [Compliance evidence](compliance.md). |
| **Audit evidence (SOC 2, ISO, PCI…)** | A PDF with scope, method, findings, exceptions and sign-offs, mapped to the framework you choose. See [Compliance evidence](compliance.md). |

The current state exports its accumulated register through its own route, so it's never confused with a single run.
Excluded findings are left out. Reports come out in English or Spanish. The compliance profiles organize technical
evidence; they aren't an audit, a certification or an attestation.

**Jira.** **Create in Jira** turns a selection (up to 50 findings) into issues, one per remediation task, without
duplicating issues that already exist; routing rules can also create them automatically after a scan. Setup and
details are in [Integrations](integrations.md).

## Common errors

| What you see | Why | What to do |
| --- | --- | --- |
| "No findings in what was scanned" | The rules and dependencies covered raised nothing | Check the run's coverage and limitations: a clean result isn't proof. |
| A finding came back after you marked it fixed | A later scan found it again | Check the fix was deployed or merged into the scanned branch. |
| **Accept risk** is missing | Only administrators accept risks | Ask an administrator. |
| Reverify says the scan was incomplete | An engine didn't run | Fix the engine problem ([Troubleshooting](troubleshooting.md)) and verify again. |
| A warning says GitHub has had no access to the repository | The App lost access to it (deleted, or removed from the App) | Give the App access again within 24 hours to keep its findings. |

## Next steps

- [Compliance evidence: SBOM, VEX, audit reports and CRA](compliance.md).
- [Integrations](integrations.md): Jira, Slack, Teams and SARIF imports.
- [Threat modeling](threat-modeling.md): link threats to the evidence in your findings.
- [Concepts](concepts.md).
