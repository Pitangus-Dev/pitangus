English · [Español](es/preguntas-frecuentes.md)

# Frequently asked questions about Pitangus

Short, honest answers to what people ask before and after installing Pitangus. Terms are defined in the
[glossary](glossary.md).

## Is Pitangus a pentest?

No. Pitangus performs analysis: it reads code, dependencies, configuration and images without running them, and reads
a website's responses without attacking it. A pentest tries to exploit flaws in a running system and demonstrates the
impact. A Pitangus report doesn't replace the pentest that SOC 2 or ISO 27001 may require. You can run a pentest tool
yourself and [import its results](integrations.md#bring-your-own-dast). See [Key concepts](concepts.md).

## Does my code leave my server?

No. Pitangus runs on your machine or server, and the engines read a read-only copy of your code there. Code is
downloaded from GitHub (through your own GitHub App); it isn't uploaded anywhere. Advisory databases are downloaded and
queried locally. The only optional exception for dependencies is OSV's online lookup, which sends package names and
versions (never code) to `api.osv.dev`, and only if you tick it for a scan. There's no telemetry.

## Exactly what is sent where?

The full list, destination by destination, is in [What leaves your machine](security.md#what-leaves-your-machine).
In short: requests to GitHub for your repositories, downloads of public advisory feeds (NVD, CISA KEV, EPSS, the Trivy
and OSV databases), image registries when you scan an image, your Jira site and notification channels if you connect
them, and, for web scans, requests to the domains you verified.

## What does it cost, and what is the license?

Pitangus is free software under the GNU Affero General Public License v3.0 ([`LICENSE`](../LICENSE), AGPL-3.0-only).
There's no price per developer or per scan. You can use, study, modify and redistribute it; if you offer a modified
version to other people over a network, you must make that version's source available to them under the same license.
The SAST rules in `rules/` are MIT, so you can reuse them in other tools. You pay only for the machine it runs on.

## Can it attack my website?

No. Web scans are passive: ordinary `GET` and `HEAD` requests, a browser that follows links, TLS handshakes. No injections, no fuzzing, no form submissions other than a test user's sign-in, no
POST, PUT or DELETE. They are off unless the server sets `PITANGUS_DAST_ENABLED=1`, only an administrator can launch
or schedule one, and only against a domain whose control was proved. A passive scan still makes real requests, so
launch it only against sites you're allowed to test. See [Scan a website or API](scanning-web.md).

## Few findings: does that mean I'm secure?

No. A clean result doesn't prove there are no vulnerabilities. Each engine only sees what it's built to see (Pitangus's
own code rules don't follow data across files, web scans don't attack), and a run tells you what it didn't check: steps
marked **Not tested**, **Partial** or **Skipped**, and its limitations. When a tool didn't run or didn't reach a host,
Pitangus doesn't call that part clean and doesn't mark earlier findings fixed. See [Key concepts](concepts.md).

## Does it support GitLab, Bitbucket or Azure DevOps?

Not as a connected provider yet: they appear as **In development**. Today you can scan those repositories in their own
pipelines with [`scan`](cli.md), which needs no Pitangus server, or send the results to a running Pitangus as SARIF.

## Does it use AI?

No. AI plays no part in any scan today, and there's no key to save. AI assistance (explanations and patch proposals
with your own OpenAI or Anthropic key, with consent on every run) is in development. See
[Integrations and automation](integrations.md#ai-assistance).

## How many workers do I need?

A worker runs one scan at a time and needs about 4 GB of memory and 2 CPUs. One is enough to start. If scans wait in
the queue (an organization batch, many pull requests), add workers on the same machine
(`docker compose up -d --scale worker=3`) or on others. See [Scaling](scaling.md).

## Can I bring results from other tools?

Yes, as SARIF 2.1.0: CodeQL, Semgrep, Snyk, Trivy, ZAP, Nuclei, Strix and others. Import it from **New scan → Import
SARIF**, with `pitangus import-sarif` on the server, or from CI with the GitHub Action. Imported findings get the same
triage, deadlines, Jira issues and notifications as Pitangus's own, and a later full import of the same tool marks fixed
what it no longer reports. See [Integrations and automation](integrations.md#bringing-results-from-other-scanners).

## Does it need internet access?

It needs outgoing access: to pull the images the first time, to download advisory databases and feeds, to reach
GitHub, and for web scans, the domains you scan. It doesn't need incoming access: there are no webhooks, and pull
requests are watched by polling GitHub. The panel listens on `127.0.0.1` by default; to open it to your network or the
internet, put it behind HTTPS ([Installation](installation.md)).

## Does it need Docker?

Yes. Pitangus and its engines run as containers: Docker Engine 24 or later with Compose v2.24 or later, plus `make`
and `git`. `make doctor` checks all of it. See [Installation](installation.md).

## Is it ready for production?

It's in beta (v0.13). It works and is tested, but the API and the data formats may still change between releases.
Each release lists anything to do before upgrading. Take backups (`make backup`) and read the
[upgrade guide](upgrading.md) before each upgrade.

## How do I upgrade?

Check out the new version and run `make update`: it takes a backup, pulls the images and restarts, and migrations run
on their own. See [Upgrade Pitangus](upgrading.md).

## Which languages does it speak?

English and Spanish, everywhere: the panel, findings, fix guides, reports, PR comments and notifications. The panel
follows your browser; text nobody requests in person (PR comments, notifications, Jira, the CLI) uses
`PITANGUS_DEFAULT_LOCALE`. See [Overview](overview.md#languages).

## Who can see and change what?

Every signed-in user sees the findings. **Members** run scans and triage; **administrators** also connect providers,
manage users, accept risks, add and verify domains and launch web scans. See
[Key concepts](concepts.md#roles-administrator-and-member).

## Something doesn't work. Where do I start?

Run `make doctor`, then see [Troubleshooting](troubleshooting.md). To report a vulnerability in Pitangus itself, follow
[SECURITY.md](../.github/SECURITY.md).
