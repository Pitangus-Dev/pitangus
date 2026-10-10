English · [Español](es/integraciones.md)

# Integrations and automation

Pitangus can connect to GitHub and Jira, accept SARIF from CI, send grouped notifications, and run periodic work without making the panel a public API. Integrations are optional and configured by an administrator. Tokens and webhook URLs are encrypted in PostgreSQL through the vault; secret values never return to the browser.

## GitHub repositories and pull requests

The supported repository connection is a **GitHub App**. It needs four repository permissions: Contents (read), Metadata (read), Pull requests (read and write), and Commit statuses (read and write). Pitangus uses one-hour installation tokens in memory and does not need webhooks or OAuth. The complete setup is in [Connect GitHub](github-app.md).

For each repository, an administrator can enable pull request watching, choose whether Pitangus comments and sets a commit status, select the blocking severity, and optionally rescan the main branch after it changes. Pitangus polls GitHub every `PITANGUS_PR_POLL_SECONDS` rather than exposing an inbound webhook. See [Pull request review](features.md#pull-request-review) for the exact behavior.

GitLab, Bitbucket, and Azure DevOps connections are visible as **In development** and do not work yet. Repositories from those providers can still be analyzed in their own pipelines with the CLI.

## CI and SARIF

The repository includes an official composite [GitHub Action](../action.yml) and the `pitangus scan` command for CI. They scan the checked-out folder, can compare a change with a base branch, emit SARIF, and return documented exit codes. They do not need a running Pitangus server. See [Terminal and CI](cli.md) for inputs, output, exit codes, and examples grounded in `action.yml` and the CLI parser.

If you want findings from another scanner in the Pitangus registry, import SARIF 2.1.0 in the panel. A pipeline can upload SARIF to a running instance through `POST /api/ci/sarif` with `PITANGUS_IMPORT_TOKEN`; use HTTPS and keep the token in the CI secret store. The site generates the [automation API reference](../docs-site/README.md#generated-api-reference) from OpenAPI.

### Bringing results from other scanners

Pitangus doesn't run every engine there is, and says so in [features.md](features.md#what-pitangus-covers-and-what-it-doesnt).
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
        - uses: Pitangus-Dev/pitangus@v0.12.2
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
- **Dynamic testing.** Pitangus never runs or attacks your applications. Until it offers that, run ZAP or Nuclei
  yourself, against systems you own, and import their SARIF against a verified domain: see
  [Bring your own DAST](#bring-your-own-dast) below.

### Bring your own DAST

Pitangus doesn't run web scanners yet (that's listed under [in development](features.md#in-development)). If your pipeline already runs **OWASP ZAP** or **Nuclei**, their SARIF goes into the registry like any other import, with a **verified domain** as the asset: the findings get the same triage, deadlines, Jira issues and notifications as code findings, and a later full import marks fixed whatever the scanner no longer reports.

1. In **Scanning → Domains**, an administrator adds the domain (`https://app.example.com`) and publishes the TXT record the panel shows (`_pitangus.app.example.com` = `pitangus-verify=…`), then verifies it. The domain is now the asset `domain:app.example.com`. The record is looked up again every day; if it disappears, or 90 days go by without a check, the domain stops being an asset until someone verifies it again.
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
      - uses: Pitangus-Dev/pitangus@v0.12.2
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
      - uses: Pitangus-Dev/pitangus@v0.12.2
        if: always()
        with:
          scan: false
          import-sarif: nuclei.sarif
          asset: domain:app.example.com
          server: https://pitangus.example.com
          token: ${{ secrets.PITANGUS_IMPORT_TOKEN }}
```

What Pitangus does with it: findings of a web scanner get `scanner: dast`; the location is the URL without its query string or fragment (a session token or a cache-buster in the URL must not turn the same alert into a new finding on every run); the fingerprint is rule, URL and parameter name, never the evidence; and only the method, the parameter and a bounded evidence are kept, never the request or response ZAP attaches (they carry cookies and authorization headers). Nuclei puts the template path where SARIF expects a file and the URL in the result's properties; Pitangus reads the URL. One run with both tools is fine: each tool only marks fixed what it reported itself.

**Only against systems you own or are authorized to test.** The TXT record proves control of the DNS zone to Pitangus; it isn't an authorization to test anything, and Pitangus doesn't check that you have one. Active scanning (ZAP's active scan, Nuclei's `-dast` fuzzing) can damage data and trip defenses: run it only where you're allowed to, outside production unless you know what you're doing, and keep the plan passive otherwise. This stays an *analysis*, not a pentest.

## Jira Cloud

Pitangus supports Jira Cloud sites under `https://<site>.atlassian.net`. An administrator connects a site, email, and Atlassian API token, then maps Pitangus variables to the fields Jira exposes for a project and issue type.

Routing rules choose the destination by repository. A rule can be manual or automatic, set a minimum severity, and optionally backfill existing open findings. Automatic rules run after full scans, SARIF imports, and the daily advisory watch; pull request reviews do not create Jira issues. Pitangus deduplicates issues with labels derived from finding fingerprints and comments when every linked finding is verified as fixed. It never closes the issue automatically. The full behavior and constraints are in [Features → Jira](features.md#jira).

## Slack, Teams, and webhooks

Under **Integrations → Notifications**, an administrator can add:

- Slack incoming webhooks;
- Microsoft Teams Workflows webhooks;
- a generic HTTPS webhook.

Each channel chooses new-finding and completed-batch events plus its minimum severity. Notifications are grouped per scan and delivered from a PostgreSQL outbox with retries, so a restart does not discard queued messages. Generic webhook requests carry an HMAC-SHA256 signature in `X-Pitangus-Signature`; the signing secret is shown only when the channel is created.

Private network destinations are blocked by default to reduce SSRF risk. `PITANGUS_ALLOW_PRIVATE_WEBHOOKS=1` is an explicit opt-in. Configure `PITANGUS_PUBLIC_URL` if messages should link back to the panel.

## Periodic automation

With `PITANGUS_PERIODIC=leader` (the default), one worker elected through PostgreSQL runs due tasks. These include pull request and main-branch watching, advisory-data updates, dependency advisory checks, and delivery of notification and Jira outboxes.

Platforms that provide their own scheduler can use `PITANGUS_PERIODIC=external`. One scheduler then runs `pitangus periodic`, or calls `GET /api/cron` with `PITANGUS_CRON_TOKEN` (or Vercel's `CRON_SECRET`). Do not run both modes: the cron route is unavailable unless external mode and a valid token are configured. See [Periodic tasks](deploy.md#periodic-tasks) and the generated automation API reference in the documentation site.

## AI provider keys

The panel can validate and store OpenAI and Anthropic keys, but AI analysis is not implemented. Pitangus does not send code or findings to either provider. The keys exist only to prepare the integration and should not be presented as an active analysis capability.

## Security checklist

1. Give GitHub and registry credentials the narrowest repository and read permissions they need.
2. Keep CI, metrics, and cron tokens in the platform's secret store; never put them in a workflow file.
3. Use HTTPS for every externally reachable Pitangus instance and webhook.
4. Leave private webhook and registry access disabled unless the worker's network boundary is designed for it.
5. Test notification and Jira destinations from the panel before enabling automatic routing.

See [Security](security.md) for what leaves the machine, how credentials are stored, and the known trade-offs.
