#!/bin/sh
# Starts the public demo, or resets it: a new demo password, a new master key and a clean in-memory database rebuilt
# from the recordings. Run it once to start and then daily from cron, e.g.
#   15 4 * * * sh /opt/pitangus/deploy/demo/reset.sh >> /var/log/pitangus-demo.log 2>&1
# SKIP_TUNNEL=1 starts everything but cloudflared (to try it on a machine without a tunnel).
set -eu
cd "$(dirname "$0")"
[ -f .env ] || { echo "Missing deploy/demo/.env: copy demo.env.example and fill it in." >&2; exit 2; }
token=$(sed -n 's/^CLOUDFLARE_TUNNEL_TOKEN=//p' .env | tail -n1)
[ -n "$token" ] || [ -n "${SKIP_TUNNEL:-}" ] || { echo "Set CLOUDFLARE_TUNNEL_TOKEN in deploy/demo/.env." >&2; exit 2; }

random() { LC_ALL=C tr -dc "$1" </dev/urandom | head -c "$2"; }
# Readable on the sign-in page (four groups of five), never containing the username (the server would refuse it).
while :; do
  password="$(random a-z2-9 5)-$(random a-z2-9 5)-$(random a-z2-9 5)-$(random a-z2-9 5)"
  case "$password" in *demo*) ;; *) break ;; esac
done
umask 077
{
  echo "# Written by reset.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ); replaced on every reset."
  echo "PITANGUS_PUBLIC_DEMO_PASSWORD=$password"
  echo "PITANGUS_MASTER_KEY=$(head -c 32 /dev/urandom | base64 | tr -d '\n')"
  echo "PITANGUS_DB_PASSWORD=$(random a-f0-9 48)"
} > generated.env.tmp
mv generated.env.tmp generated.env

compose() { docker compose --env-file .env --env-file generated.env -f compose.yaml "$@"; }
if [ -n "${SKIP_TUNNEL:-}" ]; then compose up -d --force-recreate api; else compose up -d --force-recreate; fi
i=0
until [ "$(docker inspect -f '{{.State.Health.Status}}' "$(compose ps -q api)" 2>/dev/null)" = healthy ]; do
  i=$((i + 1)); [ "$i" -le 90 ] || { echo "The demo did not start within 3 minutes: docker compose -f deploy/demo/compose.yaml logs seed api" >&2; exit 1; }
  sleep 2
done
echo "Public demo ready ($(date -u +%Y-%m-%dT%H:%M:%SZ)). The sign-in page shows today's password."
