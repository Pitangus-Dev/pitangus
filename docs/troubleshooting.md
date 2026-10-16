English · [Español](es/solucion-problemas.md)

# Troubleshooting Pitangus

Common problems, grouped by where they show up, each with its likely cause and the fix. If yours isn't here, the
commands below usually point at it.

## Start here

```bash
make doctor     # requirements, permissions, port and engines
make status     # containers and engine images
make logs       # follow the app's logs (Ctrl+C to exit)
```

`make doctor` prints one line per check and a summary:

```text
Pitangus · environment check

Tools
  ✓ docker installed (27.3.1)
  ✓ Docker daemon running (27.3.1)
  ✓ docker compose 2.29.7
...
Result: 14 passed, 0 warnings, 0 errors
```

A `✗` line says what's wrong and, on the line below, what to do. The app's logs contain no passwords, tokens or keys,
so you can share them when asking for help. Still, read them first in case they include repository names or domains
you'd rather keep private.

## Install and Docker

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `make doctor`: *the Docker daemon is not responding* | Docker isn't running, or your user can't reach it. | Start Docker Desktop or OrbStack; on Linux, `sudo systemctl start docker` and add your user to the `docker` group. |
| `make doctor`: *docker compose … is too old* or *Docker Engine … is too old* | Pitangus needs Docker Engine 24+ and Compose v2.24+. | Upgrade Docker. |
| `opengrep` shows as *Exited* | That's expected: it only builds the engine image and checks that it starts. | Nothing to do. |
| The build fails at `sha256sum -c` | The downloaded Opengrep binary doesn't match the pinned hash. | Stop there: try again later and, if it keeps happening, open an issue. Never remove the check. |
| `make up` builds the images (`Building`, `pnpm install`, `pip install`) although you wanted the published ones | `.env` doesn't include `compose.images.yaml` in `COMPOSE_FILE` (for example, `make up` was run once before `make setup PREBUILT=1`). | `make setup PREBUILT=1`, then `make up`. `grep COMPOSE_FILE .env` should show `compose.images.yaml`. |
| The panel doesn't open at `127.0.0.1:8766` | Another service is using the port, or the container didn't start. | Change `PITANGUS_HOST_PORT`, along with `PITANGUS_PUBLIC_URL` and `PITANGUS_ALLOWED_ORIGINS`, in `.env`. `make logs` shows why the container stopped. |
| *Host not allowed* (403) | You're opening the panel with a URL that isn't in `PITANGUS_ALLOWED_ORIGINS`. | Add it in `.env` and restart: `docker compose up -d`. |
| The container stops with *serves the panel over plain HTTP* | `PITANGUS_PUBLIC_URL` points outside this machine without HTTPS. | Put HTTPS in front ([Deploy on a VPS](deploy-vps.md)) or go back to `http://127.0.0.1:8766`. |
| `Permission denied` on `data/` or `config/` | Docker created the folders as root. | `sudo chown -R $(id -u):$(id -g) data config`; if your `.env` has a different UID/GID, delete it and run `make setup`. |
| A secret can't be decrypted | `PITANGUS_MASTER_KEY` changed or `config/master.key` was lost. | Restore the key; if that's not possible, use *Forget the App* and reconnect GitHub and Jira. |
| A scan is *Failed* after a restart | On start-up, any scan left halfway is marked as failed. | Launch it again. |
| The CVE tracker is slow at first | The local NVD copy is still downloading (progress is shown at the top). | Wait, or add `PITANGUS_NVD_API_KEY`. |

## Windows and WSL

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Everything is very slow under WSL2 | The repository is on the Windows drive (`/mnt/c/...`), which WSL2 reads far more slowly. | Clone it inside Linux: `cd ~ && git clone --branch v0.15.0 https://github.com/Pitangus-Dev/pitangus.git`. |
| `Permission denied` on `data/` under WSL2 | The folders were created from Windows or by Docker as root. | Clone inside Linux as above and run `make setup` there before `make up`. |

## VPN and proxy

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| The first `make up` takes far longer than a few minutes | The ~800 MB of images go through a corporate VPN or proxy that slows down or inspects the container registry (`ghcr.io`, whose layers come from `pkg-containers.githubusercontent.com`). Measured: 25+ minutes behind a corporate VPN, 3 without it. | Run the first `make up` off the VPN, or ask your network team to exempt those two domains from inspection. It only happens once: later starts reuse the images. |
| `make engines` stops with *Pulling … failed* | The registry (Docker Hub or `ghcr.io`) isn't reachable through your network. | Check the connection or the proxy and run `make engines` again: it resumes with what's missing. |

## Engines not pulled or not tested

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| An engine shows as *Not tested* in a run | Docker isn't reachable from the worker, or the engine's image is missing. | `make status` lists the missing images: `make build` for Opengrep, `make engines` for the rest. Then scan again. |
| `make doctor`: *missing …* under *Analysis engines* | The images aren't pulled yet. | `make engines` (they are also pulled on the first scan). |
| Dependencies show as *Not tested*, mentioning OSV | The dependency engines (Trivy, OSV-Scanner) didn't run, usually because Docker isn't reachable, and the online fallback is off: it sends package names and versions to `api.osv.dev` only if you allow it. | Get the engines running (`make status`, `make engines`) and scan again. Or, if the code's owner allows it, tick **Check dependencies online with OSV** in the scan's review. |
| Linux: scans with suspiciously few findings, or new `trivy-cache-<uid>` caches | Before 23 Sep 2026 the engines ran as root with no capabilities, which on Linux can't read the app's private folders and silently returned zero findings. They now run with the app's UID; if root created an old cache, a new one is used next to it. | Rerun any scans done on Linux before you upgraded. The old caches (`data/trivy-cache`, `data/grype-cache`) can be removed with `sudo rm -rf` once the suffixed version exists. |

## Web scans

See [Scan a website or API](scanning-web.md) for how web scans work.

### Full web scan is greyed out in New scan

**Symptom.** In **New scan**, **Full web scan** says *Not enabled on this server*, or a run fails with "Web scans
are turned off on this server".

**Cause.** The full web scan is experimental and off unless the server sets `PITANGUS_DAST_ENABLED=1`. The API and
the worker both read it. The **Exposure check** needs nothing and stays available.

**Fix.**

```bash
echo 'PITANGUS_DAST_ENABLED=1' >> .env
make up          # restarts and pulls the web engines
```

### The run says web scans need the Docker runner

**Cause.** The worker runs without a Docker socket (the server image used by `deploy/compose.yaml` and the platform
targets). That image doesn't carry ZAP or the other web tools.

**Fix.** Run the worker that scans websites with the Docker runner (the laptop setup, or a worker with the socket
mounted). See [Where to deploy](deploy.md).

### A tool's step is Skipped: "The … image isn't on this server"

**Cause.** The image of katana, nuclei, testssl.sh, httpx, subfinder or ZAP wasn't pulled: its pull failed, or (for
ZAP, katana and subfinder) `PITANGUS_DAST_ENABLED` was turned on after the last `make up`.

**Fix.**

```bash
make engines
```

```text
Engines: 5 images missing; the first time can take a while depending on your connection.
→ projectdiscovery/katana
...
Engines: ready.
```

### Domain verification fails: "The verification TXT record wasn't found"

**Cause.** The record's name or value doesn't match, or it hasn't propagated yet. Pitangus asks the zone's own
nameservers first, so propagation is usually quick.

**Fix.** The record is `_pitangus.<host>` with the value `pitangus-verify=<token>`, both shown in the panel with copy
buttons. Check what the world sees:

```bash
dig +short TXT _pitangus.app.example.com
```

```text
"pitangus-verify=…"
```

If it answers nothing, fix the record at your DNS provider and click **Verify** again. Repeated attempts are rate
limited: "Too many attempts for this domain" means wait the seconds it says.

### File or meta proof: "answered with a redirect"

**Cause.** The file (`https://<host>/.well-known/pitangus-verify.txt`) or the homepage with the meta tag is fetched
once, with no redirects. A redirect (to `www.`, to `/en/`, to a login page) fails the check.

**Fix.** Serve the proof from that exact host and path, answering 200:

```bash
curl -sI https://app.example.com/.well-known/pitangus-verify.txt
```

```text
HTTP/2 200
```

For the meta proof, the tag must be in the HTML of `https://<host>/` itself. If your homepage always redirects, use
the DNS or the file proof. Only a DNS proof covers subdomains.

### "The domain resolves to a private or reserved address"

**Cause.** Pitangus only probes and scans public addresses. A name that resolves to a private, loopback, link-local or
cloud metadata address (an intranet site, a staging host behind a VPN) is refused, and nothing is sent to it.

**Fix.** There is no switch to allow private addresses for web scans. Scan a publicly reachable deployment, or run
your own scanner inside that network and [import its SARIF](integrations.md#bring-your-own-dast) against a verified
domain.

### A test user couldn't sign in

**Symptom.** The run says "Couldn't sign in as «name»" with a reason, the **Sign-in as test users** step is partial,
and the run's coverage is partial.

**Cause.** ZAP signs in through a headless browser, then requests the user's check page. Anything but a 200 there
(a redirect to the login, a 401, a 403) counts as a failed sign-in. Common reasons: a wrong password or TOTP key, a
login URL that isn't the page with the form, a check page that public visitors also see or that redirects, a login or
check page outside the scan's scope, or a sign-in step a browser can't complete alone (a CAPTCHA, a code sent by email).

**Fix.** In the domain's **Test users** tab, check the username, password and TOTP key (the base32 key the authenticator
app shows), set the login page to the page that holds the form, and set a check page only a signed-in user sees (such
as `/account`). Make sure both are on a host in the scope. Then scan again. What that user would see is reported as not
analyzed until a sign-in succeeds.

### Tool steps are partial or skipped

**Cause.** Each tool's step says why. "couldn't check … (no answer, or the address was refused)" means the tool got no
answer from that host; "didn't finish" or "Stopped after N minutes" means it failed or hit its time limit; a skipped
step names the reason (no image, no Docker runner).

**Fix.** Fix the reason the step names and scan again. Until a scan reaches that host with that tool, its earlier
findings there aren't marked fixed and the run's coverage stays partial: few findings there prove nothing.

### A firewall or WAF blocks the scan

**Symptom.** ZAP's findings are mostly about a block page, tools can't reach the host, or every request gets a 403.

**Cause.** The site filters by IP or blocks automated traffic, and the server's address isn't allowed.

**Fix.** Allow the scan's outgoing address. The review step of a web scan shows it under "If your site filters by IP,
allow:", with a copy button. Set it explicitly when the worker leaves from another address than the API:

```bash
echo 'PITANGUS_EGRESS_IPS=203.0.113.10' >> .env
docker compose up -d
```

Without the variable, an administrator can click **Detect** once in that step: the server asks `api.ipify.org` which
address it's seen from.

### "A web scan is already queued or running"

**Cause.** One web scan runs at a time per installation.

**Fix.** Wait for it to finish in **Scans**. Scheduled scans that hit this are tried again at the next round.

## Accounts and access

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| I can't find the setup code | It was printed when `make up` finished, and in the logs on first start. | `make setup-code`. If a user already exists, there's no code: sign in with that user. |
| Nothing opens until two-factor authentication is on | TOTP is mandatory for administrators (`PITANGUS_REQUIRE_TOTP`). | Turn it on with your authenticator app and keep the backup codes. |
| I lost my two-factor device | — | Another admin removes it under **Users**, or from the CLI: `make cli ARGS="user reset-totp --username your-user"`. |
| I forgot my password | — | **Users → Send password link**, or `make cli ARGS="user reset-password --username your-user"`. |
| A button says only an administrator can do it | Members can't connect providers, accept risks, manage domains or launch web scans. | Ask an administrator, or have one change your role under **Users**. |

## Upgrade issues

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `make update` stops with "N scans are running" | The backup refuses to run while scans are queued or running. | Wait for them in **Scans**, then `make update` again. |
| `make update` says "a fixed version: not pulling" | You installed a release and didn't check out the new one. | `git fetch --tags && git checkout v<new> && make update`. |
| Web scans skip tools after upgrading to 0.13 | The new web engine images weren't pulled. | `make engines` with `PITANGUS_DAST_ENABLED=1` in `.env`. |

The full list for each release is in [Upgrade Pitangus](upgrading.md#upgrade-issues).

## Language

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| The panel, a report or a PR comment is in the wrong language | The panel follows the browser; everything else uses `PITANGUS_DEFAULT_LOCALE`. | Use the language switch in the header (or on the sign-in screen); for reports, PR comments, notifications, Jira and the CLI, set `PITANGUS_DEFAULT_LOCALE=en` or `es` in `.env` and run `docker compose up -d`. |
| An advisory's summary stays in English in the Spanish panel | Third-party text (NVD, OSV, GHSA) is shown as published, never machine-translated. | Expected. |

## Next steps

- [Installation](installation.md): requirements and first start.
- [Upgrade Pitangus](upgrading.md).
- [Frequently asked questions](faq.md).
