English · [Español](README.es.md)

# Public demo

A read-only Pitangus anyone can open, with made-up data: **Lapis Labs**, the fictional organization that
`pitangus demo --full` builds offline from engine outputs recorded in this repository (five repositories with a month of
scans, a pull request review, an image, two domains, members, a threat model). Visitors browse findings, evidence, fix
guides, threat models and reports; they can't change anything, and the server makes no outbound connection.

## How it is kept read-only

Everything is enforced by the server with `PITANGUS_PUBLIC_DEMO=1` ([docs/configuration.md](../../docs/configuration.md)),
not by hiding buttons:

- Every request other than a read is refused (403, `code: public_demo`, a message in the reader's language) before any
  route, session check or body is read, for every account and role. Allowed: signing in and out, and the two audit
  evidence PDFs (rendered for the reader, nothing saved). Refused reads: the cron and metrics endpoints and GitHub's
  return addresses.
- Only the demo account can sign in; any other session counts for nothing. Its password is public, so failed sign-ins
  lock out the visitor's address, never the account, and it keeps at most 500 sessions.
- No worker, no periodic tasks; `pitangus worker` and `pitangus periodic` refuse to run. The API process can't open
  network connections or resolve any name but the database's. It refuses to start with integration credentials or with
  EUVD, the NVD sync, secret validation or the embedded worker on.
- In this compose file the API, the seed job and PostgreSQL sit on an internal network with no route to the internet;
  only `cloudflared` reaches out, to Cloudflare. No port is published on the server.

## What you need

- A small Linux server with Docker Engine and Compose v2: 1 vCPU, 2 GB of RAM and 10 GB of disk are enough (the demo
  uses about 1.3 GB at most). Any provider works, since nothing reaches it from outside but the tunnel.
- A Cloudflare account with the domain (here `pitangus.dev`), and Cloudflare Tunnel (free).

## Stand it up

1. On the server, open only SSH in the firewall (the tunnel needs no inbound port) and clone a release:
   `git clone --branch v0.16.0 https://github.com/Pitangus-Dev/pitangus /opt/pitangus` (the first release with the demo
   mode; until then, this branch).
2. In Cloudflare: Zero Trust → Networks → Tunnels → Create a tunnel → Cloudflared, name it `pitangus-demo`, and copy the
   token from the install command (don't run that command: the compose file runs cloudflared). Add a public hostname:
   `demo.pitangus.dev` → service `HTTP` → `api:8766`. Cloudflare creates the proxied DNS record itself.
3. `cp deploy/demo/demo.env.example deploy/demo/.env`, fill in `PITANGUS_DEMO_DOMAIN` and `CLOUDFLARE_TUNNEL_TOKEN`, and
   `chmod 600 deploy/demo/.env`.
4. `sh deploy/demo/reset.sh`. The first run builds the image (a few minutes); then it seeds and starts the demo and waits
   until the panel answers.
5. Reset it daily from the operator's crontab (`crontab -e`):
   `15 4 * * * sh /opt/pitangus/deploy/demo/reset.sh >> $HOME/pitangus-demo.log 2>&1`
   Each reset generates a new demo password and master key and rebuilds the database from scratch (PostgreSQL lives in
   memory), so the scan dates stay recent. Visitors signed in at that moment are signed out; it takes about a minute.

### Cloudflare settings

- SSL/TLS: *Always Use HTTPS* on, minimum TLS 1.2. The panel already sends its own security headers (CSP, HSTS,
  `X-Frame-Options`, `nosniff`, `Referrer-Policy`, `Permissions-Policy`, `Cache-Control: no-store`), the same as any
  other install: don't add them again with Transform Rules.
- Security → WAF → Rate limiting rules (the free plan has one rule, 10-second period): match
  `http.request.uri.path in {"/api/auth/login" "/api/reports/audit" "/api/evidence/portfolio"} or ends_with(http.request.uri.path, ".pdf")`,
  5 requests per 10 seconds per IP, action *Block* (if your plan rejects the `ends_with` part, keep the three paths).
  Signing in and rendering PDFs are what costs CPU.
- Caching: nothing to do (every response says `no-store`).

### Check it

```sh
curl -sI https://demo.pitangus.dev/ | grep -i -E 'content-security-policy|strict-transport|x-frame'
curl -s -X POST https://demo.pitangus.dev/api/repositories/scans -H 'Origin: https://demo.pitangus.dev' \
  -H 'X-Pitangus-Action: scan-repository' -H 'Content-Type: application/json' -d '{}'
# → 403 {"error": "This is a public read-only demo …", "code": "public_demo"}
```

## Credentials

- The visitor's account is `demo` (role *member*). Its password is generated on every reset, shown on the sign-in page
  and already filled in there: it is public on purpose, so link to the demo and say "the sign-in page has the
  credentials" instead of copying a password that changes daily. It is never a real person's password.
- The build also creates an administrator, `operator`, with a random password nobody sees. It exists so nobody can claim
  the server with a setup code; in demo mode it can't sign in.
- `deploy/demo/generated.env` (written by `reset.sh`, owner-only) holds the demo password, the master key and the
  database password. They protect only made-up data and change every day. There are no real tokens anywhere.

## Update

`git -C /opt/pitangus fetch --tags && git -C /opt/pitangus checkout v<new>`, then
`docker compose -f deploy/demo/compose.yaml --env-file deploy/demo/.env --env-file deploy/demo/generated.env build`
and `sh deploy/demo/reset.sh`. With a released image that has the demo mode, set `PITANGUS_DEMO_IMAGE` in `.env`
instead of building.

## On Render

It fits, with differences; a small VPS is simpler and cheaper. A web service from the published image
(`ghcr.io/pitangus-dev/pitangus:<version>`, Starter, about 7 USD/month) with the environment of the `api` service above
(`PITANGUS_PUBLIC_DEMO=1`, `PITANGUS_EUVD=0`, `PITANGUS_CVE_SYNC=0`, `PITANGUS_EMBEDDED_WORKER=0`, `PITANGUS_BIND=0.0.0.0`,
`PITANGUS_FORWARDED_ALLOW_IPS=*`, `PITANGUS_PUBLIC_DEMO_PASSWORD` and `PITANGUS_MASTER_KEY` generated) and a Render
PostgreSQL (about 6–7 USD/month), with the domain proxied by Cloudflare. What changes: Render has no internal-only
network, so the code-level guard (no connections from the API process) is the only network control; the image doesn't
carry the recordings, so seeding needs an image that adds `fixtures/`, `tests/fixtures`, `tests/engine-outputs` and
`web/src/examples/threat-models`; and the daily reset is a Render Cron Job (from 1 USD/month) that empties the database,
runs `seed.sh` and then calls the web service's deploy hook so the API starts again.
