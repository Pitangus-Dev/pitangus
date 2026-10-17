English · [Español](es/configuracion.md)

# Configuration

Every variable is optional and goes in `.env` (a copy of `.env.example`). After changing any of them, run `docker compose up -d`. `python -m pitangus check-config` (or `make cli ARGS=check-config`) checks them all; the server and the worker do it on start and stop with a clear message if one is invalid. On other platforms, see [deploy.md](deploy.md).


| Variable | Default | Purpose |
| --- | --- | --- |
| `PITANGUS_HOST_BIND` / `PITANGUS_HOST_PORT` | `127.0.0.1` / `8766` | Where the panel is published on the host. |
| `PITANGUS_PUBLIC_URL` | `http://127.0.0.1:8766` | URL people use to open the panel; it determines `Secure` cookies, HSTS and the App's Setup URL. |
| `PITANGUS_ALLOWED_ORIGINS` | 127.0.0.1 and localhost | Accepted origins (Host header and CSRF). |
| `PITANGUS_DEFAULT_LOCALE` | `en` | `en` or `es`. Language for PR comments, notifications, Jira issues, reports and CLI output when no person asked for one. The panel doesn't use it: it follows the browser's language, and each person can change it from the sidebar or the sign-in screen. |
| `PITANGUS_MASTER_KEY` | generated in `config/` | Master key (`openssl rand -base64 32`): it encrypts every secret in the database. Required where there is no persistent disk; the same on the API and every worker. |
| `PITANGUS_PREVIOUS_MASTER_KEY` | — | The master key before you changed it, while secret findings move to the new one. A secret's identity is the HMAC of its value with a key derived from the master key: with this set, each scan also computes it with the key before, so every secret it reads keeps its entry, triage and Jira issue. Without it, after a change, the secrets found open again under the new key and their old entries stay open as unverified, never fixed. Remove it once a full scan of every repository has run. It doesn't decrypt the stored secrets (integrations, channels): those need the key they were saved with. |
| `PITANGUS_SESSION_KEY` | generated, sealed in the database | Key that signs session cookies (32 bytes in base64). Only to pin it from a secrets manager. |
| `PITANGUS_REQUIRE_TOTP` | `admins` | `admins`, `all` or `none`. |
| `PITANGUS_NVD_API_KEY` | — | NVD API key: faster CVE downloads. Sent in a header and never logged. |
| `PITANGUS_DB_PASSWORD` | (generated) | PostgreSQL password; `make setup` writes it to `.env`. |
| `PITANGUS_DATABASE_URL` | (compose) | PostgreSQL connection string. `compose.yaml` builds it from the password; outside compose, e.g. `postgresql://pitangus:…@localhost:5432/pitangus` (the `postgres://` URLs managed databases hand out work as they are). |
| `PITANGUS_DATA_DIR` | `data` (CLI) or a temporary folder (ASGI) | Rebuildable caches, working folders and optional file logs. Compose sets it to `/data`; application state still lives in PostgreSQL. |
| `PITANGUS_CONFIG_DIR` | the platform's user config folder | Folder for `master.key` when `PITANGUS_MASTER_KEY` is not set. Compose sets it to `/config`. |
| `PITANGUS_EMBEDDED_WORKER` | `1` | `1`: the server also runs the scans (a single process). In compose the API uses `0` and the `worker` service runs them. |
| `PITANGUS_BIND` | `127.0.0.1` | Interface used by `pitangus serve`. Compose overrides it inside the container; prefer `PITANGUS_HOST_BIND` to control host publishing. |
| `PITANGUS_CVE_SYNC` | `on` | `off` turns off the local NVD copy. |
| `PITANGUS_EUVD` | `on` | `off` stops querying EUVD (ENISA) when NVD hasn't scored a CVE. Only the CVE identifier is sent. |
| `PITANGUS_PR_POLL_SECONDS` | `300` | How often watched PRs are checked. |
| `PITANGUS_BRANCH_MIN_MINUTES` | `60` | Minimum gap between two automatic rescans of the same repository's main branch (minimum 10). |
| `PITANGUS_ADVISORY_WATCH_HOURS` | `24` | How many hours between offline checks of already-scanned dependencies against new advisories. `0` turns it off. |
| `PITANGUS_ALLOW_PRIVATE_WEBHOOKS` | empty | `1` allows alerts to webhooks on your internal network (blocked by default to prevent SSRF). |
| `PITANGUS_ALLOW_PRIVATE_REGISTRIES` | — | `1` allows scanning images from registries with a private IP (your internal network). Blocked by default to prevent SSRF. |
| `PITANGUS_<ENGINE>_ENABLED` | unset: the panel decides | Pins an analysis engine on (`1`) or off (`0`) for the whole server, over what an administrator chose in **Settings → Analysis engines**: see [Analysis engines](#analysis-engines). |
| `PITANGUS_COVERAGE_MODE` | `on` | How a scan proves it looked before marking anything fixed ([findings.md](findings.md#proof-before-fixing)). `on` fixes only what the engine that owns a finding proved gone where it looked, with the per-file coverage, unverified findings and the fix hold; `shadow` works them out, records what they would change and fixes as before 0.14; `off` doesn't work them out. An engine run that didn't finish opens and fixes nothing in every mode. Read by the worker and the API. |
| `PITANGUS_IDENTITY_MODE` | `v2` | How findings are identified: `v2` stores one finding per family of identical problems, by its canonical identity, with its count; `shadow` keeps the engines' fingerprints, also works out the canonical identity and records the differences; `v1` uses the engines' fingerprints only. If `pitangus identity-gate` doesn't give 0/0 on a repository scanned twice on one commit, set `shadow` until it does ([findings.md](findings.md#one-identity-per-problem)). |
| `PITANGUS_SECRET_VALIDATION` | off | Betterleaks asks each secret's provider whether it is still active: it sends the secret to that provider ([security.md](security.md#what-leaves-your-machine)). An active secret is acted on first, a revoked one is tracked; none is hidden. |
| `PITANGUS_IGNORE_REPO_SUPPRESSIONS` | off | What the scanned repository says to suppress results allows nothing: comments in the code (`gitleaks:allow`, `# zizmor: ignore[…]`, `trivy:ignore`, `checkov:skip=`, `nosemgrep`) and files an engine would load (`.gitleaksignore`, `.github/zizmor.yml`, `.trivyignore`, `.checkov.yaml`, `osv-scanner.toml`). Off, they are honoured and every result they suppress is listed under Excluded with its rule, file and line and what suppressed it ([scanning-code.md](scanning-code.md#what-the-repository-says-to-the-engines)). |
| `PITANGUS_SECRETS_IGNORE_INLINE_ALLOW` | off | Its name before 0.14.1 (secret engines only): still read, with the same meaning as `PITANGUS_IGNORE_REPO_SUPPRESSIONS`. |
| `PITANGUS_THIRD_PARTY_RULES` | off | Adds 259 of GitLab's sast-rules (MIT and Apache-2.0 only, provenance checked file by file: [third_party/gitlab-sast-rules/NOTICE](../third_party/gitlab-sast-rules/NOTICE)) to Opengrep, next to Pitangus' own rules: more Java, Scala, C#, Go and Python coverage, with English rule texts. Off by default because of their noise: measured on a public corpus of 18 intentionally vulnerable and real applications, no rule reached 85% precision with at least 3 hits. Turned on, a GitLab match on the same line as one of Pitangus' and for the same weakness (CWE) is folded into it: one finding, Pitangus' texts and severity, the GitLab rule listed among its related rules. |
| `PITANGUS_SAST_OPT_IN_RULES` | empty | Pitangus' Opengrep rules that are off by default, to turn on, comma-separated: `appsec.js.dom-xss-sink` (3 of 18 matches were XSS on the measured corpus, [scanning-code.md](scanning-code.md#analysis-engines)). While a rule is off it reports nothing, and what it found before shows as not checked, never fixed. |
| `PITANGUS_FIX_HOLD_PERCENT` / `PITANGUS_FIX_HOLD_MINIMUM` | `30` / `10` | With the coverage contract on, a scan that would fix at least this share of an asset's open findings, and at least this many, holds its fixes until the next complete scan confirms them. |
| `PITANGUS_UNSEEN_WARN_SCANS` | `3` | After this many scans without being able to check an open finding, the asset's page warns about it. |
| `PITANGUS_EGRESS_IPS` | empty | The public IP addresses or CIDR ranges web scans leave from (the worker's), comma-separated, at most 16: `203.0.113.10, 2001:db8::/48`. The review of a web scan shows them to whoever must allow them in a firewall or WAF. An invalid value stops the server at start-up. Empty, an administrator can detect the API's address once from the panel (one request to `api.ipify.org`, see [security.md](security.md#what-leaves-your-machine)); set it when the worker leaves from another address. |
| `PITANGUS_TLS_CERT` / `PITANGUS_TLS_KEY` | — | Certificate and private-key files for TLS without a proxy. Both are required together. |
| `PITANGUS_ALLOW_INSECURE_HTTP` | empty (off) | `1` lets the server start when `PITANGUS_PUBLIC_URL` is plain `http://` on an address other than `127.0.0.1`/`localhost`, which it otherwise refuses. Passwords, session cookies and tokens then cross the network in clear: only on a trusted network, at your own risk. Prefer HTTPS. |
| `PITANGUS_DOWNLOAD_TIMEOUT` | `900` | Seconds a repository archive may take to download from GitHub before the scan gives up (minimum 60). Raise it for very large repositories or slow links. |
| `PITANGUS_API_MEMORY`, `PITANGUS_WORKER_MEMORY` | `1g`, `2g` (`4g` for the worker in `deploy/compose.yaml`, where the engines run inside it) | Memory ceilings of the API and worker containers in Compose, so a runaway process can't starve the host and Postgres. The engines' own containers have theirs (3 GB, 2 CPUs). |
| `DOCKER_SOCKET_GID` | detected by `make` | Group that owns the Docker socket on Linux and WSL with native Docker (`stat -Lc %g /var/run/docker.sock`), so the worker can start the engines. Read by Compose, not by the app; set it only if you start with `docker compose` directly. Not needed on Docker Desktop or OrbStack (group `0`, always added). |
| `GITHUB_APP_ID` + `GITHUB_APP_SLUG` + `GITHUB_APP_PRIVATE_KEY_FILE` | — | Alternative to the form: mount the App as a deployment secret. Takes precedence over the secret store. |
| `GITHUB_TOKEN` / `GITLAB_TOKEN` | — | Deployment-provided tokens for code sources. GitHub token connections are supported; the GitLab provider is declared but deliberately disabled until it is tested, so `GITLAB_TOKEN` does not enable GitLab today. Prefer the GitHub App for GitHub repositories. |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` | — | Keys the operator can list and validate with the CLI. AI analysis is not implemented and these keys receive no code or findings. |
| `PITANGUS_HOST_CONFIG_DIR` | `./config` | Host folder for the master key, when `PITANGUS_MASTER_KEY` isn't set. |
| `PITANGUS_HOST_DATA_DIR` / `PITANGUS_HOST_RULES_DIR` | detected by Compose | Absolute host paths mounted into sibling engine containers. Set them only when automatic Docker mount discovery cannot resolve the bind mounts. |
| `PITANGUS_FORWARDED_ALLOW_IPS` | empty | Behind a reverse proxy that is the only way to reach the API: the proxy addresses whose `X-Forwarded-For` is believed (`*` = any peer). Without it, sign-in throttling and the logs see the proxy's address for everybody. `compose.prod.yaml` sets it for Caddy. |
| `PITANGUS_ENGINE_RUNNER` | `auto` | `docker`: each engine in a sibling container through the Docker socket. `local`: the engines installed in the worker image (`pitangus-worker`), no socket. `auto`: Docker if it answers, else the installed engines. |
| `PITANGUS_PERIODIC` | `leader` | `leader`: a worker runs the periodic tasks on its own clock. `external`: a scheduler triggers them with `pitangus periodic` or `GET /api/cron` ([deploy.md](deploy.md#periodic-tasks)). |
| `PITANGUS_CRON_TOKEN` / `CRON_SECRET` | empty (off) | Bearer token for `GET /api/cron`, only with `PITANGUS_PERIODIC=external`. At least 32 characters. `CRON_SECRET` is what Vercel Cron sends. |
| `PITANGUS_LOG_FORMAT` | `text` | `json`: one JSON object per line on the process output. |
| `PITANGUS_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING` or `ERROR`. Debug logs are still passed through the secret redactor. |
| `PITANGUS_LOG_FILE` | empty (Compose: `logs/app.log`) | Also write JSON logs to this file, rotated at 10 MB × 5; a relative path is under the data folder. |
| `PITANGUS_METRICS_TOKEN` | empty (off) | Turns on `/api/metrics` (Prometheus) for requests with `Authorization: Bearer <token>`. At least 32 characters: `openssl rand -hex 32`. |
| `PITANGUS_IMPORT_TOKEN` | empty (off) | Turns on `POST /api/ci/sarif`, which lets CI import another tool's SARIF 2.1.0 into an existing asset with `Authorization: Bearer <token>` (no session). At least 32 characters: `openssl rand -hex 32`. Also what `pitangus import-sarif --server` sends, read from the environment. |
| `PITANGUS_PUBLIC_DEMO` + `PITANGUS_PUBLIC_DEMO_USER` / `PITANGUS_PUBLIC_DEMO_PASSWORD` | off · `demo` / empty | Only for a public demo with made-up data ([deploy/demo](../deploy/demo/README.md)). The server refuses every change (all but signing in and out and the evidence PDFs), runs nothing in the background, opens no network connection and lets only that account sign in; the sign-in page shows its password. It refuses to start with integration credentials set or with `PITANGUS_EUVD`, `PITANGUS_CVE_SYNC`, `PITANGUS_SECRET_VALIDATION` or `PITANGUS_EMBEDDED_WORKER` on. |

## Analysis engines

An administrator turns each engine on or off in **Settings → Analysis engines**; the change applies from the next scan
and is kept with who made it and when. The rows are grouped by what they check: code and dependencies (Opengrep, Trivy,
OSV-Scanner), secrets (Betterleaks), infrastructure and CI (Checkov, zizmor), images (Grype) and web (httpx, testssl.sh,
nuclei, the full web scan and katana). Defaults: every engine on but Checkov, Grype and the full web scan.

Turning an engine off hides nothing. Its step in every scan says **not run (disabled)**, with where to turn it back on,
and what it found before stays open, never marked fixed (it didn't look). When every engine for a kind of check is off
(secrets, say), the panel warns about it and each scan says that kind of check wasn't made.

A variable set in the server's environment wins over the panel and locks that switch: the panel shows it **Set by the
server**, naming the variable, and the step of an engine it keeps off names it too. Set it for both the API and the
worker. Unset (or empty), the panel's choice applies.

| Variable | Engine |
| --- | --- |
| `PITANGUS_OPENGREP_ENABLED` | Opengrep (SAST with Pitangus rules) |
| `PITANGUS_TRIVY_ENABLED` | Trivy (dependencies, infrastructure as code, secrets and images) |
| `PITANGUS_OSV_SCANNER_ENABLED` | OSV-Scanner (dependencies against OSV; also the known vulnerabilities of the versions a web scan sees) |
| `PITANGUS_BETTERLEAKS_ENABLED` | Betterleaks (secrets) |
| `PITANGUS_CHECKOV_ENABLED` | Checkov, on code and images: more Terraform, CloudFormation and Dockerfile checks, and pipelines other than GitHub Actions. Off by default. |
| `PITANGUS_ZIZMOR_ENABLED` | zizmor (GitHub Actions) |
| `PITANGUS_GRYPE_ENABLED` | Grype, a second opinion on container image packages next to Trivy (they disagree mostly on backported fixes). Off by default. |
| `PITANGUS_HTTPX_ENABLED` / `PITANGUS_TESTSSL_ENABLED` / `PITANGUS_NUCLEI_ENABLED` | The exposure check's tools. With all three off the exposure check doesn't start, and says why. |
| `PITANGUS_DAST_ENABLED` | The full web scan (experimental, off by default): passive web and API scans of verified domains with ZAP (spider or an OpenAPI definition's GET and HEAD operations, and passive rules, never an attack), launched by an administrator from **New scan → Full web scan**, the scans administrators schedule (the periodic task looks for due ones every 5 minutes) and related-host discovery with subfinder. Needs the Docker runner. The light exposure check doesn't need it. See [Scan a website or API](scanning-web.md). |
| `PITANGUS_KATANA_ENABLED` | katana, the full web scan's crawler (it only runs with it). |

**Images.** Each row says whether the engine's images are on the worker's server. An analysis the server runs never
downloads a missing one on the fly: the engine is declared not run (being prepared, it runs in the next scan), and
what it found before stays open. A one-shot scan with no server behind it (`pitangus scan`, the GitHub Action, the
pre-commit hook) pulls a missing image by its digest as it starts, and says so only if the pull fails. Nobody has to remember to download it: turning an engine on in the panel queues its images at once, and every
5 minutes the worker queues those of every engine that is on (from the panel or the environment) whose pinned image
is missing, as after an upgrade that changed a digest. The worker pulls them by digest in a lane of its own, so the
analyses queued meanwhile keep running, one preparation per engine at a time; after a failure (offline, say) it waits an hour before trying again on its own, and **Prepare engine** retries
at once. `make engines` reads only the environment and `.env`; the worker prepares the rest. With the engines
installed in the worker image (`PITANGUS_ENGINE_RUNNER=local`) there is nothing to download.

**Server with a domain** ([deploy-vps.md](deploy-vps.md)). Read by Compose, not by the app; `make setup DOMAIN=… [PREBUILT=1] [SOCKET=1]` writes them (`make setup PREBUILT=1`, without a domain, only `COMPOSE_FILE` and `PITANGUS_IMAGE`).

| Variable | Default | Purpose |
| --- | --- | --- |
| `PITANGUS_DOMAIN` | — | Domain Caddy gets the certificate for (`compose.prod.yaml`). The public URL and allowed origins become `https://<domain>`. |
| `COMPOSE_FILE` | `compose.yaml` | Compose files every command uses, e.g. `compose.yaml:compose.prod.yaml:compose.no-socket.yaml:compose.images.yaml:compose.images.no-socket.yaml`. `make setup` keeps `compose.backup-age.yaml` if you added it. |
| `PITANGUS_IMAGE` | — | Published image to run instead of building (`compose.images.yaml`), e.g. `ghcr.io/pitangus-dev/pitangus`. |
| `PITANGUS_IMAGE_TAG` | the code's version | Tag of that image; accepts a digest (`0.15@sha256:…`). |
| `PITANGUS_WORKER_IMAGE_TAG` | the code's version | The same for `<PITANGUS_IMAGE>-worker`, the worker with the engines inside (without the socket). `make up` pins both to the digests it checked. |
| `COMPOSE_PROFILES` | — | `backup` turns on the scheduled backups service. |
| `PITANGUS_BACKUP_DIR` | `./backups` | Where the backup service writes. |
| `PITANGUS_BACKUP_INTERVAL_HOURS` / `_KEEP_DAYS` | `24` / `14` | How often it backs up, and for how long it keeps its own copies. |
| `PITANGUS_BACKUP_AGE_RECIPIENT` | — | age public keys (`age1…` or `ssh-ed25519 …`, comma-separated) to encrypt every backup with, master key included; also read by `make backup` (needs `age` on the host). The service needs `compose.backup-age.yaml` in `COMPOSE_FILE`. Empty: not encrypted, and without the master key. |

**Deliberate trade-off:** with the repository's `compose.yaml`, so you don't have to install anything but Docker, the worker launches the engines as sibling containers through the Docker socket, which is equivalent to root on the host. On a server, `make setup DOMAIN=…` (`compose.no-socket.yaml`) and [`deploy/compose.yaml`](../deploy/compose.yaml) use the worker image with the engines inside instead: no socket at all. [What each one isolates](deploy-vps.md#engines-and-the-docker-socket).
