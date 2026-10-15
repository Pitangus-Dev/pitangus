#!/bin/sh
# The engine images `make engines` pulls, one per line: the published ones (pinned by digest) of IMAGES in
# pitangus/modules/scanning/engines.py, read from the code with no Python, less those this server doesn't run, as
# engines.pulled_images() decides. Grype and Checkov only with PITANGUS_GRYPE_ENABLED / PITANGUS_CHECKOV_ENABLED; ZAP,
# katana and subfinder only with PITANGUS_DAST_ENABLED; the exposure check's httpx, testssl.sh and nuclei always. Each
# setting comes from the environment or, when empty there, from the env file (ENV_FILE, .env by default).
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
env_file=${ENV_FILE:-.env}

on() {
  value=$(printenv "$1" || true)
  [ -n "$value" ] || value=$(sed -n "s/^$1=//p" "$env_file" 2>/dev/null | tail -n1)
  case $(printf '%s' "$value" | tr '[:upper:]' '[:lower:]') in 1|true|yes|on) return 0 ;; *) return 1 ;; esac
}

awk '/^IMAGES = \{/ { inside = 1; next } inside && /^\}/ { exit }
     inside && match($0, /^    "[a-z0-9-]+": \{/) { key = substr($0, 6, RLENGTH - 9) }
     inside && match($0, /"image": "[^"]*@sha256:[0-9a-f]+"/) { print key, substr($0, RSTART + 10, RLENGTH - 11) }' \
  "$root/pitangus/modules/scanning/engines.py" |
while read -r key image; do
  case $key in
    grype) on PITANGUS_GRYPE_ENABLED || continue ;;
    checkov) on PITANGUS_CHECKOV_ENABLED || continue ;;
    zap|katana|subfinder) on PITANGUS_DAST_ENABLED || continue ;;
  esac
  echo "$image"
done
