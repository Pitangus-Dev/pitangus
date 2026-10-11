English · [Español](es/analisis-de-codigo.md)

# Scan your code and dependencies (SAST, SCA, secrets, IaC)

A code scan reads a repository without running it and looks for five kinds of problems: flaws in your own code
(**SAST**, static application security testing), dependencies with known vulnerabilities (**SCA**, software
composition analysis), secrets committed by mistake, risky infrastructure configuration (**IaC**, infrastructure as
code: Terraform, Kubernetes, Dockerfiles…) and risky CI/CD pipelines. Every result is a *finding*: a candidate you
confirm and fix, not proof of an exploitable flaw. A clean result doesn't prove there are no vulnerabilities. The
terms are explained in the [glossary](glossary.md).

Pitangus doesn't write its own engines: it runs well-known open-source ones, each pinned by digest, and puts their
results in one register with triage, deadlines and evidence (see [Findings, triage and remediation](findings.md)).

## Prerequisites

- Pitangus running ([installation](installation.md) or the [quickstart](quickstart.md)), with Docker available to the
  worker. Without Docker, only a reduced fallback runs (see [Common errors](#common-errors)).
- The engine images: `make up` builds the Opengrep image and pulls the missing engines; `make engines` pulls them on
  their own.
- For repositories on GitHub: the GitHub App installed on them ([Connecting GitHub](github-app.md)). Folders in the
  server's workspace can be scanned without it.
- For the terminal: only `make` and Docker, from the Pitangus folder.

## Launch a scan from the panel

1. Click **New scan** (or press `N`).
2. Choose **Code**.
3. In **Repositories**, pick one or more repositories, or **Whole organization**. Up to 100 can be picked by hand;
   a whole organization has no cap. Several repositories run as a batch, one after another, that you can follow and
   cancel in **Scans**.
4. Optionally, in **Context**, write what the application does and what worries you. It's shown in the report as
   your team's note.
5. In **Review and launch**, check what will run (the languages that have SAST rules, secrets, dependencies,
   infrastructure). Leave **Check dependencies online with OSV** off unless you want package names and versions sent
   out (see [Dependency findings](#dependency-findings)). Launch it.

<!-- screenshot: new-scan | The New scan flow on its first step, with Code, Container image and Web app or API as the scan types -->

The scan is queued and starts as soon as a worker is free. See [Background scans and progress](#background-scans-and-progress).

## Launch a scan from the terminal

`make scan` analyzes a local folder with the same engines as the panel. It never runs your code and never sends it
anywhere:

```bash
make scan DIR=../my-repo
```

With `--base`, only what your change introduces counts, which is what you want before a push or in CI:

```bash
make scan DIR=../my-repo ARGS="--base main"
```

The output looks like this (shortened):

```text
Pitangus · my-repo · changes since main (merge-base 73223791, 3 files)

CRITICAL app.py:8  Injection: eval exec non literal
HIGH     requirements.txt  urllib3 1.26.4: 9 advisories (5 high, 4 medium) → update to 2.7.0
HIGH     settings.py:1  Exposed GitHub personal access token

Engines: Opengrep 1.30.0, Gitleaks 8.30.1, Trivy 0.75.0, OSV-Scanner 2.6.0

BLOCKED · threshold: high or above · 7 new findings at severity high or above
```

Exit codes are `0` (pass), `1` (findings at or above the threshold), `2` (invalid input) and `3` (an engine didn't
run, so the analysis is incomplete). Every option, the GitHub Action and GitLab CI are in
[Scanning from the terminal and in CI](cli.md).

## Analysis engines

Each engine runs in its own container, pinned by digest, with no capabilities, no privilege escalation and the code
snapshot mounted read-only.

| Engine | What it covers | Network |
| --- | --- | --- |
| **Opengrep 1.30.0** | SAST with the Pitangus rules (`rules/`, MIT) for JavaScript, TypeScript, Python, Java, Go, PHP, Ruby and C# | None |
| **Gitleaks 8.30.1** | Secrets, values redacted | None |
| **Trivy 0.75.0** | Dependencies of any ecosystem, infrastructure configuration (Dockerfile, Kubernetes, Terraform) and secrets | Only to download its vulnerability database, cached in `data/trivy-cache/`; nothing from the repository is sent |
| **OSV-Scanner 2.6.0** | Dependencies, against the OSV database (which includes GitHub's advisory database); reads more formats, such as .NET `.csproj` and `Directory.Packages.props`, `gradle.lockfile`, `uv.lock`, `Pipfile.lock`, `pubspec.lock` | Only to download the OSV databases, cached in `data/osv-cache/`; matching is local |
| **Checkov 3.3.19** | IaC (Terraform, CloudFormation, Kubernetes, Helm, Kustomize, ARM, Bicep, Serverless, OpenAPI, Ansible, Dockerfile) and pipelines (GitHub Actions, GitLab CI, Bitbucket, Azure Pipelines, CircleCI, Argo) | None (`--skip-download`, no external modules) |
| **zizmor 1.30.1** | GitHub Actions in depth: template injection, dangerous triggers (`pull_request_target`), token permissions, actions not pinned by SHA or archived, credentials that persist after `checkout` | None (`--offline`) |

The Opengrep image is built locally by `make build` (or `make up`): it downloads the official binary and checks it
against its pinned SHA-256 (`docker/engines/opengrep/VERIFY.md` explains the Cosign check).

**The Pitangus rules.** The Semgrep registry rules can't be shipped in a product (their license has been
internal-use-only since December 2024), so Pitangus writes its own: 58 rules aimed at specific sinks (code
execution, SQL, deserialization, unescaped HTML, unverified TLS), 14 of them with taint tracking from request inputs.
They're validated against `fixtures/sast-samples/`, where all 58 fire on vulnerable code. Each run says which of the
repository's languages have rules and which don't.

Manifests and lockfiles enter the snapshot by name, without the 2 MB limit that applies to code files (a large
`package-lock.json` is normal), with a safety cap of 64 MB.

### Several engines, one finding

Trivy and Checkov review the same infrastructure and overlap on many rules, as do Checkov and zizmor on GitHub
Actions. When two engines see **the same problem in the same place** (same file, overlapping lines, an equivalent
rule), one finding remains: the primary engine's, marked "Detected by Trivy and Checkov", with the equivalent rules
in view and one extra point of confidence. What only one engine sees is added as is.

| Coverage | Primary | Adds |
| --- | --- | --- |
| Infrastructure as code | Trivy | Checkov |
| GitHub Actions and other pipelines | zizmor | Checkov |
| Image configuration | Pitangus rules | Trivy and Checkov |

Rule equivalence is a table measured on intentionally vulnerable reference repositories (TerraGoat, CfnGoat,
KubernetesGoat and CI/CD-Goat) and reviewed pair by pair; for a pair the table doesn't know, titles are compared.
On those repositories, Checkov adds between 39 % more issues (Kubernetes) and more than double (Terraform) on top
of Trivy:

| Repository | Trivy | Checkov | Merged | New from Checkov | zizmor |
| --- | --- | --- | --- | --- | --- |
| TerraGoat (Terraform) | 244 | 472 | 196 | 276 | 13 |
| KubernetesGoat (Kubernetes, Helm) | 321 | 349 | 225 | 124 | 0 |
| CfnGoat (CloudFormation) | 67 | 70 | 42 | 28 | 9 |
| CI/CD-Goat (pipelines) | 45 | 90 | 69 | 21 | 209 |

Checkov's free edition gives no severity. For rules paired with Trivy, Trivy's severity is used; for the rest, a
rule in the code (`checkov_severity`) raises public exposure, privileges, credentials or disabled TLS to high,
lowers tags, monitoring, backups or customer-managed keys to low, and leaves everything else at medium. zizmor gives
its own severity; "action not pinned by SHA" is lowered to medium, because exploiting it first requires compromising
the third-party action. Neither Checkov nor zizmor findings store code snippets, only rule, file and lines, because
a snippet might contain a secret.

Dependencies follow the same idea: an advisory that Trivy and OSV-Scanner both report, even when one calls it by its
CVE and the other by its GHSA, is **one finding** "detected by Trivy and OSV-Scanner", with the same fingerprint
either engine alone would give it, so triage and tickets follow it.

## Dependency findings

**Development dependencies** (`devDependencies`, development groups) are scanned too and marked
**Development dependency**: they don't reach production, but they run on developer machines and in CI, which is
where supply chain attacks land. They drop one priority level unless they're in CISA KEV.

Each dependency advisory arrives ready for a decision:

- **Details from the advisory.** Summary, CVE and GHSA aliases, CWE (the weakness type) and the CVSS vector; the
  CVSS score is computed from the vector with the 3.1 formula, not copied.
- **Fixed version.** Chosen from the range that contains the installed version: someone on `minimatch 9.0.5` reads
  "update to 9.0.6", not "to 10.2.3". The panel groups advisories by package and names the version that fixes all
  of them.
- **Exploitation signals.** Two public feeds downloaded in bulk once a day into `data/feeds/`: the **CISA KEV**
  catalog (vulnerabilities known to be exploited) and **EPSS** (the probability of exploitation in the next 30 days).
  Nobody receives a CVE-by-CVE lookup that would reveal which dependencies you have.
- **Priority with its reasons in view.** **Act now** if it's in KEV, or combines CVSS ≥ 9 with a high EPSS;
  otherwise **Attend** or **Track**. The finding says why.
- **A stable fingerprint**, independent of the lockfile's path, so the same advisory isn't a new finding (or a
  duplicate ticket) on every run.

Known malicious packages (OpenSSF `MAL-*` advisories, through OSV) are flagged **Malicious**, critical and Act now,
with the real fix: remove the package and rotate the secrets of every machine where it was installed.

### The OSV online lookup (opt-in)

By default the dependency list never leaves the server: Trivy and OSV-Scanner download their databases and match
locally. **Check dependencies online with OSV** in the panel, or `--allow-osv-upload` in the CLI, allows sending
**only package names and versions** (never code):

- With the engines available, it lets OSV-Scanner resolve transitive dependencies for manifests without a lockfile
  (it queries deps.dev). Without the permission, it compares only what manifests and lockfiles declare.
- Without Docker, it's the only way dependencies are checked at all (against `api.osv.dev`). Without the permission,
  the dependency step shows as **Not tested**, never as zero vulnerabilities.

```bash
make scan DIR=../my-repo ARGS="--allow-osv-upload"
```

What leaves the server and when is listed in [Security](security.md#what-leaves-your-machine).

## New advisories without rescanning

Every scan stores its dependencies and their versions. Once a day (`PITANGUS_ADVISORY_WATCH_HOURS`, `24` by default,
`0` turns it off) they're checked against the updated OSV database with OSV-Scanner **offline**: the advisories are
downloaded, the dependency list stays on the server. Anything the register didn't know about opens as a
**New advisories** run that only adds findings; the next full scan has the final say. Operating system packages in
container images are checked when the image is scanned again.

## Pull request review

With the GitHub App, Pitangus reviews each pull request (PR) for what it **introduces**, not for what was already
there. There are no webhooks, so the server doesn't need to be reachable from the internet.

### Turn it on

In **Pull requests**, an administrator sets, per repository:

- **Watching**: turn the repository on in **Watched repositories** (or **Watch all repositories**). A watcher polls
  every `PITANGUS_PR_POLL_SECONDS` (300 s by default, 60 minimum) and queues a review for each new head commit.
  Drafts are skipped. **Review now** reviews a PR by hand; **Re-scan** reviews its latest commit again.
- **Target branches**: only PRs into these branches are reviewed (the default branch if none is set; up to 10).
- **Comment and set the commit status on GitHub**: publish the result on the PR (on by default).
- **Blocking threshold**: **Critical**, **High and above** (default), **Medium and above** or **Never block**.
- **Rescan the target branches when they change**: after a merge, the branch is scanned again so the comparison
  doesn't go stale; at most once every `PITANGUS_BRANCH_MIN_MINUTES` (60 min) per branch, and only when the queue is
  nearly empty, so manual scans and PR reviews don't wait behind it.

The App needs **Pull requests: Read and write** and **Commit statuses: Read and write**, which the setup guide
already includes. If you change an existing App's permissions, accept the update in GitHub (*Settings →
Applications → Installed GitHub Apps*); until then the panel says which permission is missing.

### What counts as introduced

The review scans the PR's head commit with the same engines and then filters:

- A code or secret finding counts if it falls on a line the diff adds or modifies. A dependency finding counts if
  the PR touches the manifest or lockfile that declares it.
- If its fingerprint was already in the latest scan of the target branch, it's **pre-existing**: reported
  separately, not counted against the PR. Without an earlier scan, everything on changed lines counts, and the
  review says so.

The result is one more run in the panel, with triage shared with the main branch. On GitHub, Pitangus publishes a
**single comment** that's rewritten on every push (it only edits comments this App created) and a `pitangus`
**commit status** that fails if the PR introduces anything at or above the threshold. Secrets are cited by rule and
location; their value is never published.

Findings from a PR join the repository's register with origin "PR #n". A later commit that removes one marks it
fixed; a PR closed without merging withdraws its findings; a merged PR leaves them for the next full scan.

## Background scans and progress

Starting a scan returns immediately and queues it. One or more workers take scans from the queue, each one at a
time ([Scaling](scaling.md)). While it runs, the scan appears in **Scans** as queued or running, with a **Scan log**
written for people: which step started, which finished and with what count. The panel shows it live and folds it
once done. It never includes internal paths, raw tool output or stack traces; if something fails, it says in which
phase and gives the ID so an operator can check the logs. When the scan finishes, the panel shows a toast (and a
browser notification, if you granted permission).

Each engine is a step with a status: **Completed**, **Partial**, **Not tested**, **Inconclusive** or **Skipped**,
with the reason. An engine that didn't run is never shown as "zero findings": the run is marked incomplete.

## What it doesn't do

- **The SAST layer is the thinnest.** 58 rules for specific sinks, with no framework-specific knowledge beyond what
  they cover. A commercial engine finds logic flaws these rules can't.
- **No cross-file data flow.** Taint tracking stays inside one file. Each run states it in its limitations. For deep
  analysis, run CodeQL or Semgrep yourself and [bring their results in](integrations.md#bringing-results-from-other-scanners):
  they get the same lifecycle.
- **No reachability analysis.** A vulnerable dependency is reported whether your code calls the vulnerable function
  or not.
- The repository's own `.gitleaks.toml` isn't applied, so a PR can't weaken secret detection. Secret rules are set
  in **Policies** and per repository in **Findings**.

## Common errors

| What you see | Why | What to do |
| --- | --- | --- |
| "Docker isn't available: using the internal rules (Python only) and secret patterns." | The worker can't reach Docker | Give the worker access to Docker, or use the worker image that carries the engines ([Containers](containers.md)). Until then only Python SAST and secret patterns run, and the steps say so. |
| "The Opengrep image isn't built: run make build (or docker compose build)." | The locally built SAST image is missing | Run `make build` or `make up`. |
| The dependency step is **Not tested** | No engines, and the OSV lookup wasn't allowed | Make the engines available, or allow the OSV lookup for that scan. |
| OSV-Scanner exceeded the time limit | The first run downloads the advisory databases | Run the scan again once the download finishes. |
| `make scan` exits with `3` | An engine didn't run, so the result proves nothing | Check the "Not analyzed" lines; `--allow-incomplete` only if you accept that. |
| A PR shows no comment on GitHub | The App lacks write permissions | Grant **Pull requests** and **Commit statuses** write access and accept the update. |

More in [Troubleshooting](troubleshooting.md).

## Next steps

- [Findings, triage and remediation](findings.md): what to do with the results.
- [Scan container images](scanning-images.md).
- [Scanning from the terminal and in CI](cli.md).
- [Compliance evidence](compliance.md): SBOM and VEX from your scans.
- [Integrations](integrations.md): import other tools' SARIF, Jira, Slack and Teams.
