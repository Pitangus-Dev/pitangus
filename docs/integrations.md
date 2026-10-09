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
