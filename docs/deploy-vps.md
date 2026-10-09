English · [Español](es/despliegue-vps.md)

# Deploy on a VPS

This guide puts Pitangus on its own server (Hetzner, DigitalOcean, Hostinger, OVH, any VPS with Docker) under your domain, with HTTPS, backups and monitoring. For a laptop, `make up` is still all you need: see [installation.md](installation.md).

With a fresh server and a DNS record already pointing at it, it's four commands:

```bash
git clone https://github.com/Pitangus-Dev/pitangus.git && cd pitangus
git checkout v0.12.2                                   # the release you want (see Upgrades)
make setup DOMAIN=pitangus.example.com PREBUILT=1   # HTTPS with Caddy + published images
make up                                             # prints https://pitangus.example.com and the setup code
```

The rest of this page covers what to prepare before, and what to do after.

## How it's laid out

```
internet ──443/80──▶ caddy ──edge network──▶ api (panel + API, no published port)
                                               │
                                     default network ── postgres (no published port)
                                               │
                                             worker (the engines inside its image; no Docker socket)
```

- `compose.prod.yaml` adds **Caddy**: it gets and renews the certificate for your domain (Let's Encrypt, with ZeroSSL as fallback), redirects HTTP to HTTPS, and is the only thing that publishes ports. The api publishes none; `PITANGUS_PUBLIC_URL` and `PITANGUS_ALLOWED_ORIGINS` become `https://<domain>`.
- `compose.images.yaml` (with `PREBUILT`) runs the images published on GitHub's registry instead of building on the server. They're multi-architecture (amd64 and arm64), carry an SBOM and provenance, and are signed with cosign.
- `compose.no-socket.yaml` runs the worker from the image with the engines inside (`pitangus-worker`): **no container has the Docker socket**, so nothing in the stack can reach the host's Docker. See [Engines and the Docker socket](#engines-and-the-docker-socket).
- `make setup DOMAIN=…` writes the overlays into `COMPOSE_FILE` in `.env`, so every `make` command and every plain `docker compose` command uses them.

## 1. Choose the server

| | Minimum | Comfortable |
| --- | --- | --- |
| CPU | 2 vCPU | 4 vCPU |
| Memory | 4 GB (+2 GB swap) | 8 GB |
| Disk | 40 GB SSD | 80 GB SSD |
| Architecture | amd64 or arm64 (Hetzner CAX, Graviton, Ampere) | |

Where it goes: each scan runs one engine at a time, capped at 2 CPUs and 3 GB of memory; the app and PostgreSQL use about 400 MB at rest. On disk, the engine images take ~2 GB, Trivy's database ~1.3 GB, Grype's ~2.1 GB (only if you scan container images), the local NVD copy ~0.7 GB, and each scan keeps a snapshot of the repository while it runs. Add room for your backups if they stay on the same disk before going offsite. More repositories than one worker keeps up with: [scaling.md](scaling.md).

Use a **dedicated server** for Pitangus, not one shared with other applications or other people: see [Hardening](#hardening).

## 2. Prepare the operating system

On Ubuntu 24.04 (Debian works the same, with `debian` in the Docker URLs). As root, the first time only:

```bash
# A user for Pitangus, with your SSH key; after this, never log in as root again.
adduser --disabled-password --gecos "" pitangus
mkdir -p /home/pitangus/.ssh && cp ~/.ssh/authorized_keys /home/pitangus/.ssh/
chown -R pitangus:pitangus /home/pitangus/.ssh && chmod 700 /home/pitangus/.ssh
usermod -aG sudo pitangus && passwd pitangus   # a sudo password for maintenance

# SSH: keys only, no root. A drop-in that sorts first wins over the cloud image's own (50-cloud-init.conf).
printf 'PasswordAuthentication no\nPermitRootLogin no\n' > /etc/ssh/sshd_config.d/10-pitangus.conf
sshd -t && systemctl restart ssh

# Security updates on their own.
apt-get update && apt-get install -y unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades

# Firewall: SSH, HTTP and HTTPS only.
ufw default deny incoming && ufw default allow outgoing
ufw allow 22/tcp && ufw allow 80/tcp && ufw allow 443/tcp && ufw allow 443/udp
ufw enable
```

Docker Engine, from Docker's own repository (the distribution's `docker.io` package lags behind and has no Compose v2):

```bash
apt-get install -y ca-certificates curl make git
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" > /etc/apt/sources.list.d/docker.list
apt-get update && apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
usermod -aG docker pitangus
```

Membership in the `docker` group is equivalent to root on this machine: give it only to the people who administer the server.

**Docker and ufw.** Ports that Docker publishes skip ufw's rules. That's why Pitangus publishes only 80 and 443 (Caddy) and nothing else: PostgreSQL and the API are on internal networks. Don't add `ports:` to other services. If your provider offers a cloud firewall (Hetzner Cloud Firewall, DigitalOcean Cloud Firewalls, Hostinger's VPS firewall), apply the same rule there too: in 22, 80, 443; out, everything.

## 3. Point the domain

Create an **A** record (and **AAAA** if the server has IPv6) for the name you'll use, e.g. `pitangus.example.com`, pointing at the server's public IP. Check it before starting, because Caddy requests the certificate as soon as it starts:

```bash
dig +short pitangus.example.com     # must print the server's IP
```

Optionally, a CAA record `0 issue "letsencrypt.org"` limits who can issue certificates for that name. If you add it, also allow `sectigo.com` (ZeroSSL, Caddy's fallback) or Caddy will only have one option.

## 4. Configure

As the `pitangus` user:

```bash
git clone https://github.com/Pitangus-Dev/pitangus.git && cd pitangus
git checkout v0.12.2
make setup DOMAIN=pitangus.example.com PREBUILT=1
make doctor
```

`make setup` creates `.env` with your UID/GID and a random database password, and in server mode also writes:

| Variable | Value | Why |
| --- | --- | --- |
| `PITANGUS_DOMAIN` | your domain | Caddy's certificate and site. |
| `PITANGUS_PUBLIC_URL` / `PITANGUS_ALLOWED_ORIGINS` | `https://<domain>` | Secure cookies, HSTS, CSRF and allowed `Host`. The overlay derives them from the domain anyway. |
| `COMPOSE_FILE` | `compose.yaml:compose.prod.yaml:compose.no-socket.yaml[:compose.images.yaml:compose.images.no-socket.yaml]` | Every command uses the overlays. |
| `PITANGUS_IMAGE` | `ghcr.io/pitangus-dev/pitangus` | Only with `PREBUILT`. For a fork: `PREBUILT=ghcr.io/you/pitangus`. |
| `PITANGUS_METRICS_TOKEN` | 64 random characters | Turns on `/api/metrics` (see [Monitoring](#monitoring)). |

Without `PREBUILT`, the server builds the images from the code (a few minutes, and more memory while it builds). Both ways run the same code.

Worth reviewing in `.env` before the first start (all in [configuration.md](configuration.md)):

- `PITANGUS_REQUIRE_TOTP=all`: two-factor for everyone, not only admins. Recommended on the internet.
- `PITANGUS_DEFAULT_LOCALE=es` if your team reads Spanish (PR comments, notifications, reports).
- `PITANGUS_NVD_API_KEY`: the CVE copy downloads in minutes instead of hours.
- `PITANGUS_MASTER_KEY`: by default the vault key is generated in `config/master.key`. If you set it here (or from your secrets manager), keep a copy apart: backups never carry it in the clear.
- `COMPOSE_PROFILES=backup`: scheduled backups (see [Backups](#backups)).

Keep a copy of `.env` in your password manager: it holds the database password, the metrics token and, if you set it, the master key.

## 5. Start and create the administrator

With the published images, install [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) first: `make up` then checks their signatures before starting anything and pins the checked digest in `.env`, so every later start (`docker compose up` too) runs exactly that image. Without cosign it starts anyway and says so in one line. `make verify-images` runs the same check on its own.

```bash
make up    # Signature verified: ghcr.io/pitangus-dev/pitangus@sha256:…  Pinned in .env: PITANGUS_IMAGE_TAG=0.12@sha256:…
```

`make up` pulls (or builds), starts everything, waits until the panel answers, pulls the engines and prints the URL and the **setup code**. Open `https://<domain>`, enter the code and create your admin user; then turn on two-factor under **Account**. If the page doesn't load, `make logs SERVICE=caddy` shows whether the certificate was issued (the usual causes: the DNS record doesn't point here yet, or port 80 is closed).

The code is printed only on the server console: whoever opens the URL before you can't take over the instance. `make setup-code` prints it again while no administrator exists.

## 6. GitHub App on a public domain

Follow [github-app.md](github-app.md) with these values:

| Field | Value |
| --- | --- |
| Homepage URL | `https://<domain>` |
| Setup URL | `https://<domain>/oauth/callback`, with **Redirect on update** |
| Callback URL | empty |
| Webhook | inactive: Pitangus polls pull requests, GitHub never needs to reach your server |

## Backups

Three things make up an instance: the **database** (runs, findings, triage, users and the encrypted secrets), the **master key** (`config/master.key`, or `PITANGUS_MASTER_KEY` in `.env`) and **`.env`**. `data/` holds caches and logs: useful, but it all rebuilds.

**Scheduled, inside Compose.** Add `COMPOSE_PROFILES=backup` to `.env` and run `make up`. The `backup` service writes `backups/auto-<date>/` (database.dump, data.tgz) every `PITANGUS_BACKUP_INTERVAL_HOURS` (24) and deletes its own copies older than `PITANGUS_BACKUP_KEEP_DAYS` (14). It doesn't stop the app (`pg_dump` is consistent on its own), gets only the database password and mounts `config/` and `data/` read-only. Its healthcheck turns unhealthy if the last backup is older than two intervals. `PITANGUS_BACKUP_DIR` moves them elsewhere (e.g. a mounted volume).

**With cron, from the host.** `make backup` does the same, stopping the API for a few seconds so `data/` is consistent too; it refuses to run while scans are in progress (and then cron retries the next day):

```text
30 3 * * * cd /home/pitangus/pitangus && make backup >> backups/cron.log 2>&1
```

**The master key stays out.** A backup never holds the master key in the clear next to the secrets it opens: unencrypted backups leave it out and carry `master-key.sha256`, which tells which key they need. Keep `config/master.key` (or `PITANGUS_MASTER_KEY`) once in your password manager, never with the backups. It doesn't change, so one copy is enough.

**Encrypted with age.** So that a copy of the backups is useless to whoever gets it, encrypt them with [age](https://github.com/FiloSottile/age) to a public key whose private half never touches the server. Then the master key does go in (`config.tgz`), encrypted like the rest, and every backup restores on its own.

1. On your workstation: `age-keygen -o pitangus-backup.key`. Keep that file offline (password manager, a USB key in a drawer); it prints the public key, `age1…`.
2. In `.env`: `PITANGUS_BACKUP_AGE_RECIPIENT=age1…` (several, comma-separated: a second administrator, a recovery key; `ssh-ed25519 …` keys work too).
3. `make backup` needs age on the host: `apt install age` (Debian, Ubuntu 22.04+), `dnf install age` or `brew install age`.
4. The service's default image has no age: add `:compose.backup-age.yaml` at the end of `COMPOSE_FILE` in `.env` and run `make up`, which builds it once. `make setup` keeps it there.

Each backup then holds `database.dump.age`, `data.tgz.age` and `config.tgz.age`. If the variable is set but age is missing, the backup fails with a clear message (the service exits and says why in `make logs SERVICE=backup`) instead of writing unencrypted files. Without the variable, backups work as before and print a warning.

**Offsite, always.** A backup on the same disk doesn't survive the server. Encrypted with age, any copy will do (`rsync`, `rclone`, a bucket). Without age, the offsite copy must be encrypted by the tool that sends it, e.g. [restic](https://restic.net) to any S3-compatible bucket (Backblaze B2, Hetzner Object Storage, R2…):

```text
0 4 * * * cd /home/pitangus/pitangus && restic backup backups/ --tag pitangus && restic forget --keep-daily 14 --keep-weekly 8 --prune
```

(`RESTIC_REPOSITORY`, `RESTIC_PASSWORD_FILE` and the bucket credentials in the crontab environment; keep the restic password outside the server.) Keep old copies locally only for a few days: `find backups -maxdepth 1 -name '20*' -mtime +7 -exec rm -rf {} +`.

**Restore.** Tested, on the same server or on a new one:

```bash
make restore FROM=backups/<date> CONFIRM=restore
make up
```

It checks the backup before touching anything, saves the current state in `backups/pre-restore-<date>/` (so `make restore FROM=backups/pre-restore-<date> CONFIRM=restore` undoes it), drops and recreates the database from `database.dump`, replaces `config/` when the backup carries `config.tgz` (otherwise it keeps the current one) and extracts `data/`. Each archive may hold only its own folder, with plain files and folders: an absolute path, `..`, a link or a device makes it refuse the backup before stopping anything. On a **new server**: prepare it as above, restore your `.env`, clone the same version, `make setup`, copy the backup folder into `backups/` and run the two commands. Restore on the same Pitangus version as the backup or a newer one: the app migrates data forward when it starts, never backwards. It assumes `config/` in the repository (the default `PITANGUS_HOST_CONFIG_DIR`).

- **Unencrypted backup on a new server:** put the master key back first, in `config/master.key` (or `PITANGUS_MASTER_KEY` in `.env`). `tr -d ' \r\n' < config/master.key | sha256sum` must print what the backup's `master-key.sha256` holds.
- **Encrypted backup:** decrypt it first, where the age private key is (your workstation, then copy the folder to the server; or bring the key to the server only for this):

  ```bash
  cd backups/<date>
  for f in *.age; do age -d -i ~/pitangus-backup.key -o "${f%.age}" "$f"; done
  cd ../.. && make restore FROM=backups/<date> CONFIRM=restore
  rm backups/<date>/database.dump backups/<date>/*.tgz   # the plaintext copy; the .age files stay
  ```

  If you brought the private key to the server, delete it too.

If `config/master.key` is lost (or `PITANGUS_MASTER_KEY` changes), the secrets can't be decrypted: you'd reconnect the GitHub App and re-enter the Jira token. Nothing else is lost.

## Upgrades

```bash
git fetch --tags && git checkout v0.12.2   # or stay on main and let make update pull it
make update
```

`make update` pulls the code (`git pull --ff-only` when you're on a branch; on a tag it keeps the version you checked out), takes a backup with `make backup` (it stops if scans are running: try again later), pulls the new images, restarts, and the app migrates the database on start. Read the release notes before a minor version jump. To roll back: check out the previous tag and `make restore FROM=backups/<the backup make update took> CONFIRM=restore`, then `make up`.

With `PREBUILT`, the image tag follows the checked-out code (`pitangus/version.py`), so compose files, rules and images always match. `make up` pins that tag to the digest it checked (`PITANGUS_IMAGE_TAG=0.12@sha256:…`) and keeps it while the version doesn't change; `make update` checks the newest image of the version and pins it again (by hand: `make verify-images REPIN=1`). A `PITANGUS_IMAGE_TAG` of your own (`0.12.1`, `0.12.1@sha256:…`) is checked but never replaced. Without the socket the worker image is checked and pinned the same way (`PITANGUS_WORKER_IMAGE_TAG`); with it, the Opengrep image is checked by its tag.

## Monitoring

**Health checks.** Docker watches every service: `api` (`/api/health`), `worker` (its heartbeat in the database) and `backup`. `make status` shows them; restart on failure is automatic. From outside, point an uptime monitor at `https://<domain>/api/health`: it answers `200 {"status": "ok"}` while the API is up. For a signed-in person it also says `"status": "degraded"` when no worker has sent a heartbeat (nothing would get scanned), with the number of workers and whether they reach Docker.

**Metrics.** `GET /api/metrics` in Prometheus format, with `Authorization: Bearer <PITANGUS_METRICS_TOKEN>` (off while the variable is empty; answers 404 then). Only aggregates: no repository names, identifiers or findings.

| Metric | Meaning |
| --- | --- |
| `pitangus_jobs{status}` | Jobs in the queue by status (`queued`, `running`, `done`, `failed`). |
| `pitangus_jobs_oldest_queued_age_seconds` | How long the oldest queued job has waited. |
| `pitangus_jobs_failed_24h` | Jobs that failed in the last 24 hours. |
| `pitangus_workers_alive` / `pitangus_workers_docker` | Workers with a recent heartbeat / that can start the engines. |
| `pitangus_worker_last_heartbeat_age_seconds` | Seconds since the latest heartbeat. |
| `pitangus_runs_24h{type,status}` | Runs created in the last 24 hours. |
| `pitangus_run_duration_seconds_24h{type,status,quantile}` | Duration of those that finished: p50, p95 and the maximum (`quantile="1"`). |
| `pitangus_info{version}` | Version serving the endpoint. |

```yaml
# prometheus.yml
scrape_configs:
  - job_name: pitangus
    scheme: https
    metrics_path: /api/metrics
    authorization: { credentials_file: /etc/prometheus/pitangus-token }
    static_configs: [{ targets: ["pitangus.example.com"] }]
```

Scrape through the domain (the API only accepts its public `Host`). Alerts worth having:

```yaml
- alert: PitangusNoWorker
  expr: pitangus_workers_alive == 0 or pitangus_workers_docker == 0
  for: 5m
- alert: PitangusQueueStuck
  expr: pitangus_jobs_oldest_queued_age_seconds > 3600
- alert: PitangusJobsFailing
  expr: pitangus_jobs_failed_24h > 5
```

**Logs.** `make logs` (API) and `make logs SERVICE=worker|caddy|backup`. Docker rotates them (10 MB × 5 per service). Caddy's access log is JSON and redacts cookies and `Authorization`.

## Engines and the Docker socket

On a server, `make setup DOMAIN=…` runs the engines **inside the worker's own image** (Trivy, OSV-Scanner, Gitleaks, Grype, Checkov, zizmor and Opengrep, the same pinned versions). No container mounts the Docker socket, which is equivalent to root on the host.

The other way, engines as sibling containers started through the socket, is an explicit opt-in: `make setup DOMAIN=… SOCKET=1`. What each one isolates:

| | Without the socket (default on a server) | With the socket (`SOCKET=1`, the default on a laptop) |
| --- | --- | --- |
| Someone who takes over the worker | Has the worker's container: the database and the stored secrets, not the host | Controls the host's Docker: root on the server |
| An engine broken by a hostile repository | Runs as the worker's user, in its container: it gets what the worker has (database, master key, stored tokens), not the host | Is alone in a throwaway container: read-only, no network for offline steps, only the code it scans |
| Image scans of a non-Docker-Hub registry | The registry's name is resolved by the engine (checked first) | The name is pinned to the address checked first (no DNS rebinding) |
| Resources | The engines share the worker's ceiling (`PITANGUS_WORKER_MEMORY`, 4 GB) | Each engine has its own (3 GB, 2 CPUs) |

The default trades the second row for the first: breaking out of an engine takes a flaw in that engine's parser, while the socket hands the host to anything that runs code in the worker. Neither removes the need for a dedicated machine with nothing else on it.

Existing servers keep what they had: `make setup DOMAIN=… SOCKET=0` switches one over (then `make up`), `SOCKET=1` goes back.

## Hardening

- **No Docker socket by default.** See [above](#engines-and-the-docker-socket). With `SOCKET=1`, the socket is root: anyone who takes over the worker controls the server. The API never has it, but then the right boundary is the machine: a **dedicated VM**, no other applications, no other tenants, and only administrators in the `docker` group.
- **PostgreSQL with the minimum.** Its container keeps only the capabilities its entrypoint needs to own the data folder and switch to the `postgres` user (`CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `SETGID`, `SETUID`), with `no-new-privileges`.
- **Two-factor for everyone** (`PITANGUS_REQUIRE_TOTP=all`), and remove users who leave.
- **Narrow the audience** if your team has fixed addresses: allow 443 only from them in the cloud firewall.
- **The real client address.** Behind Caddy, the API believes `X-Forwarded-For` (`PITANGUS_FORWARDED_ALLOW_IPS`, set by the overlay) because only Caddy, the worker and PostgreSQL can reach it, and Caddy replaces any `X-Forwarded-For` a client sends. Sign-in throttling and the audit log then see each person's address instead of the proxy's.
- **What the proxy adds.** HTTP→HTTPS redirect, HTTP/2 and HTTP/3, a 2 MB request limit (the app's own is 1 MB), header and body timeouts, compression only for the panel's static files, and no `Server`/`Via` headers. The security headers (CSP, HSTS, nosniff, frame, referrer) stay the app's, so there's a single, consistent set.
- **Images.** Everything third-party is pinned by digest; the published images are signed and carry an SBOM and SLSA provenance (`docker buildx imagetools inspect ghcr.io/pitangus-dev/pitangus:0.9 --format '{{json .SBOM}}'`).

## Coolify and Dokploy

Both platforms put their own proxy (Traefik) and certificates in front, so Caddy isn't used: deploy **`compose.yaml` alone** as a Docker Compose application from the Git repository, and let the platform route your domain to the **`api` service, port 8766**. These notes follow each platform's documented behavior; we haven't run Pitangus on them ourselves yet.

Variables to set in the platform (it writes them to `.env`, which the services read):

```bash
PITANGUS_DB_PASSWORD=<openssl rand -hex 24>
PITANGUS_PUBLIC_URL=https://pitangus.example.com
PITANGUS_ALLOWED_ORIGINS=https://pitangus.example.com
PITANGUS_FORWARDED_ALLOW_IPS=*              # only the platform's proxy reaches the api
PITANGUS_METRICS_TOKEN=<openssl rand -hex 32>
PITANGUS_UID=1000
PITANGUS_GID=1000
DOCKER_SOCKET_GID=<stat -c %g /var/run/docker.sock, on the server>
```

What to keep in mind on both:

- The worker mounts `/var/run/docker.sock` and starts sibling containers that mount folders by their **host** path. The worker finds those paths by inspecting itself, so bind mounts must be real host folders (not named volumes).
- `config/` must survive redeploys: set `PITANGUS_HOST_CONFIG_DIR` to an absolute path on the server (e.g. `/srv/pitangus/config`, owned by `PITANGUS_UID`). Losing it means re-entering every secret. `data/` only holds caches and logs.
- The `opengrep` service builds the engine image and exits: that's expected, not a failed deploy.
- The platform builds the images from the repository (there's no `compose.images.yaml` there). The first deploy takes a few minutes.
- **Coolify:** resource type *Docker Compose*, compose location `/compose.yaml`. Coolify keeps `./data` bind mounts in the application's folder across deploys.
- **Dokploy:** service type *Compose*, path `./compose.yaml`. Each deploy clones the code again, so point `PITANGUS_HOST_CONFIG_DIR` outside the clone (Dokploy suggests `../files/`).
- The hardening advice above still applies: a PaaS that also runs other people's applications on the same server is exactly what the Docker socket makes risky.

If something fails, [troubleshooting.md](troubleshooting.md) covers the usual causes; for proxy issues, `make logs SERVICE=caddy`.
