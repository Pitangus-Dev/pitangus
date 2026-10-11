English · [Español](es/integraciones.md)

# Integrations and automation

Integrations connect Pitangus to the tools your team already uses: GitHub for code and pull requests, container
registries for private images, Slack, Teams or a webhook for notifications, Jira Cloud for issues, and your CI for
results from other scanners. All of them are optional; Pitangus works on its own with local folders and public images.
An administrator configures them. Tokens and webhook URLs are encrypted in PostgreSQL through the vault, and secret
values never return to the browser.

## The Integrations page

**Integrations** (`#/integrations`, or `G` then `E`) is a page of sections, each a list of rows with its status
(connected, not set up, in development) and its configuration folded below:

| Section | What you connect | Who |
| --- | --- | --- |
| **Code providers** | The GitHub App; GitLab, Bitbucket and Azure DevOps show as **In development** | Administrators connect; members see the status |
| **Container registries** | Read-only tokens for private registries | Administrators |
| **Notifications** | Slack, Microsoft Teams and generic webhooks | Administrators only (members don't see this section) |
| **Issue tracking** | Jira Cloud: the connection, destinations and routing rules | Administrators connect; members see the status |
| **AI assistance** | Nothing yet: coming soon | Administrators can remove a key saved by an earlier version |

<!-- screenshot: integrations | The Integrations page with its sections: code providers, container registries, notifications, issue tracking and AI assistance -->

Members see a note at the top saying connecting providers and saving keys is up to an administrator.

## GitHub repositories and pull requests

The supported repository connection is a **GitHub App**. It needs four repository permissions: Contents (read), Metadata (read), Pull requests (read and write), and Commit statuses (read and write). Pitangus uses one-hour installation tokens in memory and does not need webhooks or OAuth. The complete setup is in [Connect GitHub](github-app.md).

For each repository, an administrator can enable pull request watching, choose whether Pitangus comments and sets a commit status, select the blocking severity, and optionally rescan the main branch after it changes. Pitangus polls GitHub every `PITANGUS_PR_POLL_SECONDS` rather than exposing an inbound webhook. See [Scan your code](scanning-code.md) for how a pull request review counts findings.

GitLab, Bitbucket, and Azure DevOps connections are visible as **In development** and do not work yet. Repositories from those providers can still be analyzed in their own pipelines with the CLI.

## CI and SARIF

The repository includes an official composite [GitHub Action](../action.yml) and the `pitangus scan` command for CI. They scan the checked-out folder, can compare a change with a base branch, emit SARIF, and return documented exit codes. They do not need a running Pitangus server. See [Terminal and CI](cli.md) for inputs, output, exit codes, and examples grounded in `action.yml` and the CLI parser.

If you want findings from another scanner in the Pitangus registry, import SARIF 2.1.0 in the panel. A pipeline can upload SARIF to a running instance through `POST /api/ci/sarif` with `PITANGUS_IMPORT_TOKEN`; use HTTPS and keep the token in the CI secret store. The site generates the [automation API reference](../docs-site/README.md#generated-api-reference) from OpenAPI.

### Bringing results from other scanners

Pitangus doesn't run every engine there is, and says so in [What Pitangus covers](overview.md#what-pitangus-covers-and-what-it-doesnt).
What it doesn't run, it imports: any tool that writes SARIF 2.1.0 lands in the same registry, with the same
fingerprints, triage, deadlines, Jira issues and notifications as Pitangus's own findings, and is marked fixed the
same way when a later import no longer reports it. Three ways in: **New scan → Import SARIF** in the panel;
`python -m pitangus import-sarif` on the server; or from CI, the Action's `import-sarif` input, which sends the files
to `/api/ci/sarif` with `PITANGUS_IMPORT_TOKEN` ([cli.md](cli.md#import-other-tools-results-import-sarif)).

The two gaps people ask about most:

- **Deep data-flow analysis.** Pitangus's own rules track data inside one file. CodeQL and Semgrep go further. In
  GitHub Actions, keep CodeQL's SARIF instead of (or besides) uploading it to code scanning, and send it to Pitangus:

  ```yaml
        - uses: github/codeql-action/init@v4      # pin it to the tag's commit SHA, as with the other actions
          with:
            languages: javascript-typescript
        - uses: github/codeql-action/analyze@v4
          with:
            upload: never
            output: codeql
        - uses: Pitangus-Dev/pitangus@v0.13.1
          if: always()
          with:
            scan: false
            import-sarif: codeql/javascript.sarif   # one file per language in that folder
            server: https://pitangus.example.com
            token: ${{ secrets.PITANGUS_IMPORT_TOKEN }}
  ```

  CodeQL is free for public repositories and, through GitHub Advanced Security, for private ones; running its CLI
  elsewhere is governed by the GitHub CodeQL Terms. The same step with Semgrep is in
  [cli.md](cli.md#other-tools-results).
- **Dynamic testing.** Pitangus runs [passive web and API scans](scanning-web.md) with ZAP of a
  verified domain (crawl and read, or the GET and HEAD operations of an OpenAPI definition; never attack) when the
  server sets `PITANGUS_DAST_ENABLED=1`: on demand or on a schedule, over listed subdomains when the domain has a DNS proof,
  with request headers saved for the domain (API keys, bearer tokens, cookies) and signed in as up to 3 test users,
  alongside katana, nuclei (detection-only templates), testssl.sh and httpx. The domain can be proved with a DNS
  TXT record, a file under `/.well-known/` or a meta tag. For anything deeper (active scans, attack templates, an
  AI pentest such as Strix), run the scanner yourself, against systems you own, and import its SARIF against the
  verified domain: see [Bring your own DAST](#bring-your-own-dast) below.

### Bring your own DAST

Pitangus's own web scan is passive and runs from the panel ([Scan a website or API](scanning-web.md)): it stores ZAP's findings exactly as an import of ZAP's SARIF would, with the same fingerprints, so both can feed the same domain without duplicates. For active scans, or to keep the scanner in your pipeline: if it already runs **OWASP ZAP** or **Nuclei**, their SARIF goes into the registry like any other import, with a **verified domain** as the asset: the findings get the same triage, deadlines, Jira issues and notifications as code findings, and a later full import marks fixed whatever the scanner no longer reports.

1. In **Domains & APIs**, an administrator adds the domain (`https://app.example.com`) and publishes the TXT record the panel shows (`_pitangus.app.example.com` = `pitangus-verify=…`), then verifies it. The domain is now the asset `domain:app.example.com`. The record is looked up again every day; if it disappears, or 90 days go by without a check, the domain stops being an asset until someone verifies it again.
2. The pipeline writes SARIF and sends it with the Action's `import-sarif`, `server`, `token` and `asset` inputs (or `python -m pitangus import-sarif … --asset domain:app.example.com --server …`).

ZAP writes SARIF only through the reports add-on's `sarif-json` template, from a `report` job of the [Automation Framework](https://www.zaproxy.org/docs/desktop/addons/automation-framework/) plan ([report job](https://www.zaproxy.org/docs/desktop/addons/report-generation/automation/), [SARIF template](https://www.zaproxy.org/docs/desktop/addons/report-generation/report-sarif-json/)). A passive plan (spider plus passive scan, no attacks) from GitHub Actions:

```yaml
name: Dynamic analysis
on:
  schedule: [{ cron: '0 3 * * 1' }]
  workflow_dispatch:

permissions: {}

jobs:
  zap:
    runs-on: ubuntu-latest
    steps:
      - name: ZAP, passive, through the Automation Framework
        run: |
          cat > zap.yaml <<'EOF'
          env:
            contexts:
              - name: app
                urls: ["https://app.example.com"]
                includePaths: ["https://app.example.com/.*"]
            parameters:
              failOnError: true
              progressToStdout: true
          jobs:
            - type: spider
              parameters:
                maxDuration: 2
            - type: passiveScan-wait
            - type: report
              parameters:
                template: sarif-json
                reportDir: /zap/wrk
                reportFile: zap
          EOF
          # ZAP runs as its own user (zap): the folder must accept its writes
          chmod a+w .
          docker run --rm -v "$PWD:/zap/wrk:rw" ghcr.io/zaproxy/zaproxy:2.17.0@sha256:7aaa659b0d43078febd82e29bad112285c370727e86ab8340444220e17d9f0d2 \
            zap.sh -cmd -autorun /zap/wrk/zap.yaml
          # the sarif-json template writes zap.json
      - uses: Pitangus-Dev/pitangus@v0.13.1
        if: always()
        with:
          scan: false
          import-sarif: zap.json
          asset: domain:app.example.com
          server: https://pitangus.example.com
          token: ${{ secrets.PITANGUS_IMPORT_TOKEN }}
```

Nuclei writes SARIF with `-se` ([options](https://docs.projectdiscovery.io/tools/nuclei/running)). Keep the request rate low and leave out the templates that fuzz or could disrupt the target; pin the image:

```yaml
      - name: Nuclei
        run: |
          docker run --rm -v "$PWD:/out" projectdiscovery/nuclei:v3.3.5 \
            -u https://app.example.com -rl 20 -c 10 -severity low,medium,high,critical \
            -etags dos,fuzz,intrusive -se /out/nuclei.sarif
      - uses: Pitangus-Dev/pitangus@v0.13.1
        if: always()
        with:
          scan: false
          import-sarif: nuclei.sarif
          asset: domain:app.example.com
          server: https://pitangus.example.com
          token: ${{ secrets.PITANGUS_IMPORT_TOKEN }}
```

What Pitangus does with it: findings of a web scanner get `scanner: dast`; the location is the URL without its query string or fragment (a session token or a cache-buster in the URL must not turn the same alert into a new finding on every run); the fingerprint is rule, URL and parameter name, never the evidence; and only the method, the parameter and a bounded evidence are kept, never the request or response ZAP attaches (they carry cookies and authorization headers). Nuclei puts the template path where SARIF expects a file and the URL in the result's properties; Pitangus reads the URL. One run with both tools is fine: each tool only marks fixed what it reported itself.

**Strix** ([usestrix/strix](https://github.com/usestrix/strix), Apache-2.0: AI agents that try to exploit what they find) writes `findings.sarif` next to its other reports. Import it against the verified domain like any other SARIF (`import-sarif: strix_runs/<run>/findings.sarif`, `asset: domain:app.example.com`). A finding about an endpoint arrives anchored to `SECURITY.md`; Pitangus places it at the endpoint's URL instead (the run's target plus the route, `GET /api/users/{id}` → `https://app.example.com/api/users/{id}`, with the method kept), so it's a web finding. A finding with a code location stays a code finding at its file and line. Strix's own severity label is kept (its `info` doesn't become `low`), the CWE comes from its rule, the fingerprint from its partial fingerprints (a reworded title is the same finding), and the areas it records as covered or left for a follow-up aren't findings. Credentials retold in its descriptions are redacted like any web finding's; the proof-of-concept script never comes in the SARIF.

**Only against systems you own or are authorized to test.** The TXT record proves control of the DNS zone to Pitangus; it isn't an authorization to test anything, and Pitangus doesn't check that you have one. Active scanning (ZAP's active scan, Nuclei's `-dast` fuzzing) can damage data and trip defenses: run it only where you're allowed to, outside production unless you know what you're doing, and keep the plan passive otherwise. This stays an *analysis*, not a pentest.

## Jira Cloud

Pitangus turns findings into Jira Cloud issues, without duplicates across scans. It supports Jira Cloud sites under
`https://<site>.atlassian.net` only.

### Connect a site

An administrator connects Jira under **Integrations → Issue tracking** with the site, the account email and an
[Atlassian API token](https://id.atlassian.com/manage-profile/security/api-tokens), then clicks **Save and validate**:
Pitangus checks the account before saving. The token is stored encrypted in the vault and never goes back to the
browser: the panel shows the email and the token's last four characters.

Only `https://<site>.atlassian.net` sites are accepted and redirects aren't followed, so the panel can't be used to send
requests anywhere else. Jira Server and Data Center are deliberately out of scope: they would require accepting
arbitrary hosts on your network.

### Destinations

A destination says where issues go: a project and an issue type, picked from what Jira offers, and what goes in each
field of its create screen. Each field takes a Pitangus variable (title, severity, Jira priority, description, CWE,
CVE, package, fixed version, file, line, repository, link to the finding, first detection, due date, labels), a fixed
value among the ones Jira allows, or a template with `{{variables}}` (plain substitution, nothing is evaluated).
Pitangus checks the mapping against Jira when you save it: every required field mapped, types that fit and allowed
values. Summary and description are mapped by default, and the due date too when the screen has it.

### Routing rules

Routing rules pick the destination per repository: explicit repositories or patterns on the name (`org/payments-*`),
in order. **The first enabled rule that matches wins**, and a last default rule covers the rest (it can be disabled).

- A **manual** rule creates issues only when someone asks, from **Findings**.
- An **automatic** rule creates them on its own: when a full scan, a SARIF import or the daily advisory watch finds new
  findings at or above its minimum severity, their issues are queued and created by the worker, with retries if Jira
  is down. Pull request reviews don't create issues, nor do findings dismissed in triage or in excluded paths.
- An automatic rule with **backfill** also creates, spaced out, the issues of the findings already open when it's saved
  or enabled.

When a full scan or a full import verifies a linked finding as fixed, Pitangus **comments on the issue**; it never
closes it. An issue covering several findings gets the comment once all of them are fixed, and another one if any
reappears.

### Create issues from Findings

In the findings table, select findings and click **Create in Jira** (up to 50 at a time; whatever was dismissed in
triage isn't exported). Each goes to the destination its repository's rules pick. Pitangus creates **one issue per
remediation task**: advisories for the same package go together with the version that fixes them all, while code and
secret findings go one by one.

Each issue carries the `appsec-<fingerprint>` label of every finding it covers. Before creating, Pitangus searches by
those labels, and the link is remembered per repository and fingerprint, so exporting again, today or after the next
scan, links the existing issue instead of duplicating it. If the project doesn't allow setting the priority on
creation, Pitangus retries without it. Issues are written in `PITANGUS_DEFAULT_LOCALE`, since the whole team reads
them.

## Slack, Teams, and webhooks

Under **Integrations → Notifications**, an administrator can add:

- Slack incoming webhooks;
- Microsoft Teams Workflows webhooks;
- a generic HTTPS webhook.

Each channel chooses its events (new findings from a minimum severity, finished batches). Pitangus sends one message
per scan, grouped: the five most severe findings, the count, and a link to the panel when `PITANGUS_PUBLIC_URL` is set.
Messages leave from a PostgreSQL outbox with retries, so a restart does not discard queued messages. Generic webhook
requests carry an HMAC-SHA256 signature in `X-Pitangus-Signature`; the signing secret is shown only when the channel is
created. Pull request reviews don't notify here: they already comment on the PR.

Private network destinations are blocked by default to reduce SSRF risk. `PITANGUS_ALLOW_PRIVATE_WEBHOOKS=1` is an
explicit opt-in.

## Periodic automation

With `PITANGUS_PERIODIC=leader` (the default), one worker elected through PostgreSQL runs due tasks. These include pull request and main-branch watching, advisory-data updates, dependency advisory checks, and delivery of notification and Jira outboxes.

Platforms that provide their own scheduler can use `PITANGUS_PERIODIC=external`. One scheduler then runs `pitangus periodic`, or calls `GET /api/cron` with `PITANGUS_CRON_TOKEN` (or Vercel's `CRON_SECRET`). Do not run both modes: the cron route is unavailable unless external mode and a valid token are configured. See [Periodic tasks](deploy.md#periodic-tasks) and the generated automation API reference in the documentation site.

## AI assistance

AI **plays no part** in any scan today, and there's no key to save in the panel. AI assistance (an explanation of each
finding and a proposed patch, with your own OpenAI or Anthropic key) is in development; when it arrives it will ask
for consent on every run before anything is sent, with a per-run budget and secret redaction, and source code will
never be sent without that consent. If an earlier version saved a key, the **AI assistance** section lists it so an
administrator can remove it.

An operator can already declare `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` on the server. Nothing uses them; these
commands list which keys exist and check one against the provider's model catalog, without sending code or findings
and without spending tokens:

```bash
make cli ARGS="providers"
make cli ARGS="ai-check --provider openai"
```

## Security checklist

1. Give GitHub and registry credentials the narrowest repository and read permissions they need.
2. Keep CI, metrics, and cron tokens in the platform's secret store; never put them in a workflow file.
3. Use HTTPS for every externally reachable Pitangus instance and webhook.
4. Leave private webhook and registry access disabled unless the worker's network boundary is designed for it.
5. Test notification and Jira destinations from the panel before enabling automatic routing.

See [Security](security.md) for what leaves the machine, how credentials are stored, and the known trade-offs.

## Next steps

- [Connect GitHub](github-app.md): create and install the GitHub App.
- [Terminal and CI](cli.md): `scan` and the GitHub Action.
- [Findings](findings.md): triage, deadlines and exports, including Jira.
- [Scan a website or API](scanning-web.md): the passive web scan and domain verification.
- [What Pitangus covers](overview.md#what-pitangus-covers-and-what-it-doesnt), and what it imports instead.
