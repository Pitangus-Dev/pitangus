English · [Español](es/seguridad.md)

# Security

Pitangus reads your repositories' code and stores GitHub and Jira credentials. This document explains how it protects that information, what leaves your machine and which trade-offs it makes. To report a vulnerability, see [SECURITY.md](../.github/SECURITY.md).

## Secrets

| Secret | Where it lives | Who can see it |
| --- | --- | --- |
| GitHub App private key | `vault_entries` table, encrypted | Only the server process. GitHub receives a signed JWT, never the key. |
| OpenAI / Anthropic keys | `vault_entries` table, encrypted | Only the server; they're validated against the provider before being saved. The panel shows the last 4 characters. |
| Jira token | `vault_entries` table, encrypted | Same as above. |
| Container registry tokens | `vault_entries` table, encrypted | Only the server. They reach Trivy and Grype as environment variables (`-e NAME` with no value on the command), never on the command line. |
| Domain request headers (API keys, bearer tokens, session cookies for web scans) | `vault_entries` table, encrypted, one entry per domain | Only the worker, right before a scan that asked for them; administrators see names and the last 4 characters of long values. They reach ZAP inside its plan, on the container's standard input, written only in its memory-only home: never on the command line, a host file, the run, its progress, the logs or the findings (scrubbed from what ZAP returns). Removing the domain removes them. |
| Domain test users (username, password and TOTP key web scans sign in with) | `domain_test_users` table, the three sealed together with the master key (AES-256-GCM, bound to the domain and the row) | Only the worker, right before a scan that picked them; administrators see the name, username, method, login page, notes and host, never the password or the key. They reach ZAP as environment variables the Docker client passes by name (`-e NAME` with no value on the command), which ZAP's plan refers to as `${…}`: never on a command line, a host file, the plan, the run, its progress, the logs or the findings (scrubbed from what ZAP returns). Removing the domain removes them. |
| GitHub installation tokens | Memory, 1 h | Renewed automatically; never written to disk. |
| Master key | `config/master.key` (0400) or `PITANGUS_MASTER_KEY` | Whoever administers the server. |
| User passwords | `users` table in PostgreSQL, scrypt hash only | Nobody: they can't be recovered. |
| Session cookies | `sessions` table, hash only; signed with a key sealed in the vault (or `PITANGUS_SESSION_KEY`) | A copy of the database doesn't grant access. |

**Encryption.** AES-256-GCM, a random nonce per secret, and the secret's name as associated data: an encrypted value can't be moved to another entry without decryption failing, and any tampering is detected. If the master key doesn't decrypt the vault, the server says so instead of using corrupted data.

**Separation.** The encrypted secrets live in the database, the master key apart from it (`PITANGUS_MASTER_KEY` or `config/master.key`), and `data/` only holds caches and logs, so it carries no secrets. A database dump without the master key reveals nothing. On any platform with a secrets manager, set `PITANGUS_MASTER_KEY` there: it's the one value that must never live next to the database backups. `make backup` and the backup service respect that: they leave the key out, or encrypt the whole backup, key included, with age to a public key whose private half stays off the server (`PITANGUS_BACKUP_AGE_RECIPIENT`).

**Logs.** Request bodies, headers, passwords, TOTP codes and cookies are never logged. On top of that, every message goes through a filter that redacts:

- known patterns: `ghp_`, `ghs_`, `github_pat_`, `sk-…`, `xox…`, `AKIA…`, `ATATT…`, JWTs, `Bearer …`, `Basic …` and `-----BEGIN … PRIVATE KEY-----` blocks;
- any value stored in the vault, matched literally, even if it follows no known pattern.

**Browser.** No secret is ever sent back to the browser. The `.pem` key is read in your browser and travels to the server once, when you connect it; the panel doesn't keep it.

## Panel access

- **First administrator** created with a one-time code that only appears in the server console: whoever opens the URL before you can't take over the instance.
- **Passwords** hashed with scrypt (N=2¹⁵, r=8, p=1), 12 characters minimum. A nonexistent user costs the same as a real one, so response times don't reveal which users exist.
- **Two-factor authentication** with TOTP (RFC 6238), required for administrators by default, with 8 single-use backup codes. A code that was already used doesn't work twice.
- **Server-side sessions**, with an `HttpOnly`, `SameSite=Strict` cookie that is also `Secure` over HTTPS. Changing your password, turning on TOTP or having an administrator reset your credentials signs out your other sessions.
- **Rate limiting** per user and per address: after 5 failures, a progressive lockout from 30 s to 15 min. It also applies to the initial setup and to the return from GitHub. Behind a reverse proxy, the address comes from `X-Forwarded-For` only when the request comes from a proxy listed in `PITANGUS_FORWARDED_ALLOW_IPS` (`compose.prod.yaml` sets it for Caddy); otherwise everybody would share the proxy's address.
- **CSRF**: every POST requires an allowed `Origin` and an action header specific to its route.
- **Roles**: `admin` connects integrations, manages users and accepts risks; `member` scans and triages.

## Transport

- By default, the port is published on `127.0.0.1` only.
- If `PITANGUS_PUBLIC_URL` points outside this machine and isn't HTTPS, **the server won't start**. Only `PITANGUS_ALLOW_INSECURE_HTTP=1` allows it, at your own risk.
- With HTTPS: HSTS (1 year) and `Secure` cookies. TLS 1.2 minimum when the server itself terminates TLS.
- Every response carries a strict `Content-Security-Policy` (no inline scripts or styles), `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` and `Permissions-Policy`.
- Outbound calls use HTTPS with certificate verification and **don't follow redirects**, so a credential never ends up somewhere other than intended.

## What leaves your machine

| Destination | What is sent | When |
| --- | --- | --- |
| `api.github.com` | Your App's JWT, repository and PR requests; comments and commit statuses on your PRs | When you connect, scan and review PRs. Code is **downloaded** from GitHub; it isn't uploaded anywhere else. |
| `services.nvd.nist.gov` | Index and date ranges | Local CVE copy, in the background. |
| `www.cisa.gov`, `epss.empiricalsecurity.com` | Nothing: full public feeds are downloaded | Once a day. They're downloaded whole so they don't reveal which CVEs you care about. |
| Image registry and Trivy database | Nothing of yours | At build time and when Trivy updates its database. |
| Container registries (Docker Hub, GHCR, ECR…) | A request for the image you asked to scan, with your token if you saved one | When scanning an image. Registries on private IPs are blocked unless `PITANGUS_ALLOW_PRIVATE_REGISTRIES=1`, so the form can't be used as a bridge into your internal network (SSRF). The check runs again when the scan starts, and the engine's container gets the checked address for the registry's name, so an answer that changes in between (DNS rebinding) isn't followed. |
| `api.osv.dev` | Your dependencies' names and versions | **Only if you allow it**, per scan. Not used by default. |
| Your Jira site | The fields you map for each issue (by default title, description, priority, labels and due date), and comments when a finding is verified fixed or reappears | Only if you connect Jira: when someone exports, or on its own for automatic routing rules. |
| `api.openai.com`, `api.anthropic.com` | The server's key, to check that it's valid | Only when an operator tests it (`ai-check`). AI isn't used yet: it receives no code and no findings. |
| Your domains | A DNS TXT lookup of `_pitangus.<host>`, or one HTTPS `GET` of `/.well-known/pitangus-verify.txt` or of the homepage (file and meta proofs), and one HTTPS `HEAD` to the domain when an administrator probes it before adding it | When an administrator verifies a domain, once a day for every verified domain (the same proof is asked again), right before each web scan, and when the Add domain form probes a URL. Every HTTPS request goes to the already-resolved address and only if every address is public, validates the certificate for the name, follows no redirects and reads 64 KB at most in 10 seconds. Nothing is scanned. |
| Passive sources of subfinder (certificate transparency logs, passive DNS and archive services) | The registered domain's name | When a domain is added and when an administrator searches again for related hosts, only with `PITANGUS_DAST_ENABLED=1`. No API keys are configured, so sources that need one are skipped; nothing is sent to the domain's own hosts. The names found are then resolved through the server's DNS resolver. |
| A verified domain you scan | ZAP's requests: the pages its spider reaches on the scan's hosts with ordinary `GET`s, or the GET and HEAD operations of the OpenAPI definition you gave (no attacks, no form submissions, no POST/PUT/PATCH/DELETE), with the domain's saved headers only if the scan asked for them; and, for a definition given by URL, one `GET` of it from a host of the scan (pinned, no redirects, 5 MB at most) | Only when an administrator launches a [passive web or API scan](features.md#passive-web-scan) or schedules one, with `PITANGUS_DAST_ENABLED=1`. ZAP's container is the one engine that reaches a site on purpose; it gets each host's checked public address pinned to its name, a DNS server that answers nothing, and a context with those hosts only. |

There's no telemetry.

## Code analysis

- Repository code **is never executed**: Pitangus analyzes a read-only snapshot.
- Engines run in ephemeral containers with a read-only filesystem (they write only to an in-memory `/tmp` of 1 GB and to the folders they're given), `--cap-drop ALL`, `no-new-privileges` and memory, CPU and process limits. Gitleaks, Opengrep, Checkov and zizmor have no network; Trivy and Grype use it only for their vulnerability database and, when scanning an image, to read it from the registry. subfinder (related hosts) uses it to ask public sources for names under a domain, with no keys, no config mounted and a 75-second limit; what it answers is checked again (a host under the domain, public addresses only) before it's listed, and listing grants nothing: a host reaches a scan only with the domain's DNS proof and an administrator's choice. ZAP (passive web scans) uses it to reach the verified domain, and runs as its image's own user (uid 1000) over a fresh work folder, never a repository snapshot; its plan arrives on standard input and only the pinned names resolve.
- Container images you scan **are neither run nor built**: the engines read the manifest and the layers.
- The Trivy, OSV-Scanner, Gitleaks, Grype, Checkov and zizmor images are pinned by digest. The Opengrep image is built from the official binary, checked against its SHA-256.
- Values of secrets found in your code are redacted: findings keep the location and the type, not the value.
- Findings are stored as message codes with parameters, not as frozen sentences, so the panel, reports and PR comments render them in English or Spanish for whoever reads them. Advisory text from NVD, OSV or GHSA is shown as published, never machine-translated.

## Known trade-offs

- **Docker socket.** Engines are launched through `/var/run/docker.sock`, which is equivalent to root on the host. Only the `worker` service mounts it, and it exposes no ports; the service that handles requests (`api`) doesn't have it. That's the price of installing nothing but Docker, and the default on a laptop. On a server, `make setup DOMAIN=…` and `deploy/compose.yaml` use the worker image with the engines inside instead (`PITANGUS_ENGINE_RUNNER=local`); the socket is then an opt-in (`SOCKET=1`).
- **Engines inside the worker** (`PITANGUS_ENGINE_RUNNER=local`). No Docker socket, but also no container per engine: each engine runs as a process of the worker, with a fresh home folder, only `PATH` from the worker's environment (the database URL and the master key aren't passed to it), no core dumps, and its whole process group killed when it times out. Engines that need no network (Gitleaks, Opengrep, Checkov, zizmor) run in an empty network namespace (`unshare --user --net`) where the platform allows it: on a server or a VM, yes; in a container with Docker's default seccomp profile, no, and the worker says so in its log (`local_engines_share_the_network`). Elsewhere they run with their offline options wherever they have them. The boundary is the worker's container, not the engine: an engine broken by a hostile repository runs as the worker's user and can read what the worker can (`/proc/1/environ`, `config/master.key`). It doesn't reach the host. The comparison with the socket is in [deploy-vps.md](deploy-vps.md#engines-and-the-docker-socket).
- **Job queue.** Pending scans live in PostgreSQL. The code tokens that go with a scan are sealed with the master key (AES-GCM): the database never stores them in plaintext.
- **TOTP seeds** are sealed with the master key too: a database dump alone can't produce codes. Losing the master key
  means resetting second factors (`make cli ARGS="user reset-totp --username <name>"`) as well as re-entering the vault's secrets.
- **Master key on the same server** if you don't set `PITANGUS_MASTER_KEY`. It protects against a stray copy of the database, not against someone with full access to the server.
- **A single workspace** per installation: every user sees every connected repository.
- **Registry token visible to root.** While a private image is being scanned, the token sits in the engine container's configuration: anyone with Docker access on the host (who is already root) can read it. Use read-only tokens.
- **Registry redirects aren't checked.** Registries serve image layers from other hosts (a CDN, a bucket), so Trivy and Grype follow their redirects. A registry you ask to scan could point them at an internal address. They only request, and what comes back isn't shown. Scan images from registries you trust, or run the engines on a network without access to your internal one.
- **ZAP's network isn't fenced in.** Docker can't limit where a bridge network goes without an egress proxy, so ZAP's container could in principle reach any address the host can, including your internal network or a cloud metadata endpoint. What keeps it on the domain is its plan and its resolver: a context holding the scan's hosts only, each name pinned to the public address checked right before the scan, a DNS server (`--dns 127.0.0.1`) where nothing answers, so no other name resolves (a wildcard in the scope widens the context, not what resolves), `-silent` (no update checks), no active scan. A redirect or a link to another host is outside the context and isn't followed; a page on the domain that redirects to the same host's name can't land elsewhere, because the name is pinned. What the plan can't rule out is a URL with a literal IP address: ZAP's OpenAPI import follows redirects, so an API that answers a GET with a redirect to `http://10.0.0.5/` or a metadata address would have that one GET followed. If your Docker host can reach sensitive internal services, run the worker on a network that can't, or keep `PITANGUS_DAST_ENABLED` off.
- **Signing in as a test user.** The login form is submitted by a headless Firefox that ZAP drives through geckodriver, which ZAP unpacks into its memory-only home and runs from there, so only scans with test users mount that home without `noexec`. While such a scan runs, the test users' secrets are in the container's configuration, as any `-e` variable is: whoever can run `docker inspect` on the host (root-equivalent already) can read them until the container ends (`--rm`). Use test accounts, never real ones: the crawl follows links as that user (log out, delete…).
- **An API definition is untrusted input.** Only its GET and HEAD operations reach ZAP; its `servers` are replaced by the scan's target; any `$ref` outside the document is refused (ZAP would fetch it); YAML is read with the safe loader and no aliases; 5 MB, 2000 operations and a bounded depth at most. It travels sealed with the master key in the queue and is dropped from the job as soon as the worker opens it; the run keeps only its SHA-256 and operation count.

## Recommendations

1. Keep the panel on `127.0.0.1` unless you need remote access, and then use HTTPS.
2. Require TOTP for everyone (`PITANGUS_REQUIRE_TOTP=all`) if several people use it.
3. Install the App only on the repositories you want to scan (**Only select repositories**).
4. Keep the master key apart from the backups, and encrypt the backups with age before they leave the server (`PITANGUS_BACKUP_AGE_RECIPIENT`).
5. If an App key leaks: revoke it on GitHub (*Private keys → Delete*), generate a new one and reconnect it in **Integrations**.

## Exclusions and suppressions

- Excluded paths are decided by an administrator in the panel and stored on the server with author, date and reason. A PR can't exclude its own code or change the rules: no `.pitangus-ignore`, no `.gitleaks.toml`, no engine configuration inside the repository is honored.
- Patterns work like `.gitignore`: a pattern that matches a folder excludes everything inside it, so `fixtures` also covers `fixtures/a/b.py`. Patterns that would exclude everything are rejected.
- Excluded findings are counted on every run and can be reviewed; they're never silently deleted.
- In-code suppressions (`# nosemgrep: <rule>`) do travel with the repository and show up in the PR review; add a justification next to them.
