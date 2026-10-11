English · [Español](es/vista-general.md)

# What is Pitangus: self-hosted application security

Pitangus is a self-hosted application security tool. It analyzes your source code, its dependencies, your container
images and, passively, your websites and APIs, keeps every finding in one registry, and tells you when a fix really
landed. It is for small teams and the people who look after their security: you install it on your own machine or
server, and your code never leaves it.

New to the vocabulary? A **finding** is a possible problem a tool reported (a vulnerable package, a leaked secret, a
missing security header). The [glossary](glossary.md) defines every term used in these pages.

## How it works

Every scan of a repository, a container image or a verified domain follows the same path, from what you connect to
the evidence you hand over.

1. **Engines in containers.** Pitangus doesn't write its own scanners. It runs established open-source engines, each
   pinned to a version and image digest, in a hardened container with no privileges: Opengrep, Gitleaks, Trivy, OSV-Scanner, Grype, Checkov and zizmor for
   code and images; ZAP, katana, nuclei, testssl.sh and httpx for websites and APIs.
2. **Runs.** Every scan is a **run**: a record of what was analyzed, which steps ran, which didn't and why. A step
   that didn't run is reported as *not tested*, never as clean.
3. **Findings registry.** Each finding gets a stable **fingerprint**, so the same problem is recognized across runs.
   What a later full scan no longer reports is marked fixed on its own; what comes back is reopened.
4. **Triage and verification.** You decide what each finding is (in progress, false positive, accepted risk), and
   **Verify again** rescans to tell you whether a fix landed.
5. **Evidence.** Reports (PDF, Markdown, SARIF, JSON), an SBOM and VEX statements, ready for an audit or a customer.

[Key concepts](concepts.md) explains each of these in more detail.

## What Pitangus covers, and what it doesn't

Pitangus runs established open-source engines, pinned by digest, and adds what none of them has on its own: one
registry with triage, deadlines, evidence, pull request review and proof that a fix is real. That's also where it
stops. Compared with a commercial suite (Snyk, Checkmarx, Veracode…), this is where it stands:

| Area | What runs | Where it falls short |
| --- | --- | --- |
| Dependencies (SCA) | Trivy, OSV-Scanner and Grype over NVD, GHSA and OSV, with KEV and EPSS | No reachability analysis: a vulnerable function is reported whether your code calls it or not. |
| Secrets | Gitleaks, plus Pitangus rules with a verification step for some token types | Only the files of the scanned commit: a secret deleted in an earlier commit but still in Git history isn't seen. |
| Container images | Trivy and Grype on the layers, history and configuration, read from the registry | The image is never run, so nothing about its behavior at runtime is checked. |
| Infrastructure and pipelines | Checkov (Terraform, Kubernetes, Dockerfiles…) and zizmor (GitHub Actions) | Checkov's free edition gives no severity; Pitangus assigns one by rule. |
| Your own code (SAST) | Opengrep with the 58 Pitangus rules in `rules/`, 14 of them with taint tracking inside one file | **This is the thinnest layer.** No cross-file data flow, and no framework knowledge beyond those rules. For deep analysis, run CodeQL or Semgrep and [bring their results in](integrations.md#bringing-results-from-other-scanners): they get the same lifecycle. |
| Websites and APIs (DAST) | A passive scan of a verified domain: ZAP (spider, AJAX spider and passive rules, or the GET and HEAD operations of an OpenAPI definition), plus katana, nuclei (detection-only templates), testssl.sh and httpx. Optional saved headers and up to 3 test users per scan; on demand or on a schedule. Off unless the server sets `PITANGUS_DAST_ENABLED=1`. See [Scan a website or API](scanning-web.md). | **Passive only:** no injections or other attacks, no form submissions other than a test user's sign-in, no POST, PUT or DELETE. Crawls are capped in time, so a large site isn't covered whole. Only ZAP signs in as test users; whether saved headers authenticate isn't checked. One web scan at a time per installation. For active tests, run your own scanner and [import its results](integrations.md#bring-your-own-dast). |
| Scale | One scan per worker; as many workers as you need, on one machine or several | No parallel scans inside a worker, no autoscaling manifests, no published benchmark. See [Scaling](scaling.md). |

What a commercial suite can't offer is the other half of the table: it runs on your server, the code never leaves it,
there's no per-developer price, and the source is open (AGPL-3.0).

> [!NOTE]
> A clean result doesn't prove there are no vulnerabilities. Pitangus says what it didn't check (*not tested*,
> *partial coverage*) so that few findings are never read as "secure".

## In development

These appear greyed out in the panel, marked **In development**. Today they produce no results and can't be used:

| Feature | What it will do |
| --- | --- |
| Active web scans | Active tests only with an administrator's authorization recorded in the run. Passive web and API scans already work. |
| GitLab, Bitbucket, Azure DevOps | Connect repositories with read-only project tokens. Today, scan them in their own pipelines with [`scan`](cli.md). |
| AI assistance | Finding explanations and patch proposals with your own key, with consent on every run. AI plays no part in any scan today. |
| Public API | Scoped personal tokens and a documented `/api/v1`. |

## A short tour of the panel

The sidebar has three groups: **Risk** (Overview, Findings, Threats, Coverage, CVE tracker, Compliance), **Scanning**
(Scans, Repositories, Images, Domains & APIs, Pull requests) and **Settings** (Policies, Integrations and, for
administrators, Users). The header always has **New scan**.

### Overview

**Overview** (`#/overview`) summarizes the risk of everything you've scanned: open findings by severity, actively
exploited vulnerabilities (KEV), what's overdue, found versus fixed over time, and the latest CVEs. Every figure is
computed from runs with its definition in view. On a new installation it starts with **Getting started**, a checklist
that ticks itself off.

<!-- screenshot: overview | The Overview dashboard with key figures, findings by severity and the found versus fixed chart -->

### Findings

**Findings** (`#/findings`) is the registry: the current state of every finding for one asset, an organization or
several at once, with filters, triage, deadlines, a fix guide per finding and exports. See [Findings](findings.md).

### Scans

**Scans** (`#/analyses`) lists every run with its type, status and results. Open one to see its steps (completed,
partial, skipped, not tested) and its limitations.

### Domains & APIs

**Domains & APIs** (`#/domains`) holds the sites and APIs you control. An administrator adds a domain, proves control
of it once, and then can scan it passively. Each domain has tabs for **Overview**, **Findings**, **Scans**, **Scope**
and **Test users**. See [Scan a website or API](scanning-web.md).

### Integrations

**Integrations** (`#/integrations`) is a page of sections: **Code providers** (the GitHub App), **Container
registries**, **Notifications** (Slack, Teams, webhooks; administrators only), **Issue tracking** (Jira Cloud) and **AI
assistance** (coming soon). See [Integrations and automation](integrations.md).

<!-- screenshot: integrations | The Integrations page with its sections: code providers, container registries, notifications, issue tracking and AI assistance -->

## Command palette and keyboard shortcuts

Press `⌘K` on macOS or `Ctrl+K` elsewhere (or click **Search…** in the header) to open the palette. It searches pages,
scans, repositories, images and domains, and runs actions: **New scan**, **Import SARIF results**, **Add a domain**
(administrators), **Connect a code provider** and **Keyboard shortcuts**.

<!-- screenshot: command-palette | The command palette open, with actions, pages and recent scans -->

Single-key shortcuts work anywhere in the panel, except while you type in a field or a dialog is open:

| Keys | Does |
| --- | --- |
| `⌘K` / `Ctrl+K` | Open or close the palette |
| `N` | New scan |
| `?` | Show the shortcuts |
| `G` then `O` | Overview |
| `G` then `F` | Findings |
| `G` then `T` | Threats |
| `G` then `V` | Coverage |
| `G` then `C` | CVE tracker |
| `G` then `M` | Compliance |
| `G` then `A` | Scans |
| `G` then `R` | Repositories |
| `G` then `I` | Images |
| `G` then `D` | Domains & APIs |
| `G` then `P` | Pull requests |
| `G` then `L` | Policies |
| `G` then `E` | Integrations |
| `G` then `U` | Users (administrators) |

The letters are the same in every language.

## Languages

Everything a person reads exists in English and Spanish: the panel, findings, fix guides, reports, PR comments and
notifications. The panel follows your browser's language, and the language switch in the header (or on the sign-in
screen) changes it. Findings are stored as message codes, not sentences, so each person reads them in their own language and
switching never needs a rescan. Text nobody requests in person (PR comments, notifications, Jira issues, the CLI) uses
`PITANGUS_DEFAULT_LOCALE` (`en` by default, see [Configuration](configuration.md)). Third-party text, such as an NVD
or GHSA advisory summary, is shown as published.

## Next steps

- [Quickstart](quickstart.md): from zero to your first verified fix in about 15 minutes.
- [Key concepts](concepts.md): runs, findings, fingerprints, triage and roles.
- [Installation](installation.md): requirements and the details of the first start.
- [Frequently asked questions](faq.md).
