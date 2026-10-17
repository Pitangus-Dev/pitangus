#!/bin/sh
# Builds the public demo in an empty database (the `seed` service, once per start). Offline: no engines, no network.
set -eu
pitangus() { python -m pitangus --data-dir /data "$@"; }

: "${PITANGUS_PUBLIC_DEMO_PASSWORD:?missing: run deploy/demo/reset.sh}"
pitangus check-config >/dev/null

# The administrator exists so nobody can claim the server with a setup code; its password is random, never shown, and
# the demo lets no account but the demo one sign in.
python -c 'import secrets; print(secrets.token_urlsafe(32))' | pitangus user create --username operator --admin --password-stdin >/dev/null
printf '%s\n' "$PITANGUS_PUBLIC_DEMO_PASSWORD" | pitangus user create --username "${PITANGUS_PUBLIC_DEMO_USER:-demo}" \
  --display-name "Demo" --password-stdin >/dev/null

pitangus demo --recorded-only --full --fixtures /demo/fixtures --models /demo/models --recordings /demo/recordings
