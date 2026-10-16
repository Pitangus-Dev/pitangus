#!/bin/sh
# The engine images `make engines` pulls, one per line: the published ones (pinned by digest) of IMAGES in
# pitangus/modules/scanning/engines.py, read from the code with no Python, less those this server doesn't run, as
# engines.pulled_images() decides. Grype and Checkov only with PITANGUS_GRYPE_ENABLED / PITANGUS_CHECKOV_ENABLED; ZAP,
# katana and subfinder only with PITANGUS_DAST_ENABLED; every other engine unless its PITANGUS_<ENGINE>_ENABLED pins it
# off. Each setting comes from the environment or, when empty there, from the env file (ENV_FILE, .env by default). An
# engine turned on in the panel (Settings → Analysis engines) is prepared by the worker: this reads no database.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
env_file=${ENV_FILE:-.env}

setting() {
  value=$(printenv "$1" || true)
  [ -n "$value" ] || value=$(sed -n "s/^$1=//p" "$env_file" 2>/dev/null | tail -n1)
  printf '%s' "$value" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]'
}
on() { case $(setting "$1") in 1|true|yes|on) return 0 ;; *) return 1 ;; esac; }
# A core engine runs unless its variable is set to anything but on (what engine_switches.resolve does).
not_pinned_off() { value=$(setting "$1"); [ -z "$value" ] && return 0; case $value in 1|true|yes|on) return 0 ;; *) return 1 ;; esac; }

awk '/^IMAGES = \{/ { inside = 1; next } inside && /^\}/ { exit }
     inside && match($0, /^    "[a-z0-9-]+": \{/) { key = substr($0, 6, RLENGTH - 9) }
     inside && match($0, /"image": "[^"]*@sha256:[0-9a-f]+"/) { print key, substr($0, RSTART + 10, RLENGTH - 11) }' \
  "$root/pitangus/modules/scanning/engines.py" |
while read -r key image; do
  case $key in
    grype) on PITANGUS_GRYPE_ENABLED || continue ;;
    checkov) on PITANGUS_CHECKOV_ENABLED || continue ;;
    zap|subfinder) on PITANGUS_DAST_ENABLED || continue ;;
    katana) { on PITANGUS_DAST_ENABLED && not_pinned_off PITANGUS_KATANA_ENABLED; } || continue ;;
    *) not_pinned_off "PITANGUS_$(printf '%s' "$key" | tr '[:lower:]-' '[:upper:]_')_ENABLED" || continue ;;
  esac
  echo "$image"
done
