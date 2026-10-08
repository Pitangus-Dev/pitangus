#!/bin/sh
# Creates .env from .env.example with your UID/GID, and the data/, config/ and backups/ folders (yours, not root's).
# Leaves an existing .env alone, except for what you ask for:
#   make setup [PREBUILT=1]                           local use (http://127.0.0.1:8766)
#   make setup DOMAIN=pitangus.example.com [PREBUILT=1 | PREBUILT=ghcr.io/you/pitangus]
#     server: HTTPS with Caddy for that domain (compose.prod.yaml).
#     The worker runs the engines inside its own image, without the Docker socket (compose.no-socket.yaml).
#     SOCKET=1: engines as sibling containers through the socket instead; SOCKET=0 switches an existing server over.
#     A server set up before keeps what it had unless SOCKET says otherwise.
#   PREBUILT runs the published images instead of building (compose.images.yaml), locally or on a server.
#   Writes COMPOSE_FILE so every make and docker compose command uses them (compose.backup-age.yaml stays if present).
set -eu

DOMAIN=${DOMAIN:-}
PREBUILT=${PREBUILT:-}
SOCKET=${SOCKET:-}

# Replaces NAME=… in .env, or appends it.
set_var() {
  if grep -q "^$1=" .env; then
    sed -i.bak "s|^$1=.*|$1=$2|" .env && rm -f .env.bak
  else
    printf '%s=%s\n' "$1" "$2" >> .env
  fi
}
random_hex() { od -An -N"$1" -tx1 /dev/urandom | tr -d ' \n'; }

if [ -n "$DOMAIN" ] && ! printf '%s' "$DOMAIN" | grep -Eq '^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$'; then
  echo "DOMAIN must be a host name like pitangus.example.com (no scheme, port or path)." >&2
  exit 2
fi
case "$PREBUILT" in
  ''|0) image= ;;
  1) image=ghcr.io/pitangus-dev/pitangus ;;
  *) image=$PREBUILT ;;
esac
# A registry may carry a port (registry.example.com:5000/pitangus); the name itself, no tag or digest.
if [ -n "$image" ] && { ! printf '%s' "$image" | grep -Eq '^[a-z0-9][a-z0-9._:/-]*[a-z0-9]$' || case "${image##*/}" in *:*) true ;; *) false ;; esac; }; then
  echo "PREBUILT must be 1 or an image name without tag, like ghcr.io/you/pitangus." >&2
  exit 2
fi
case "$SOCKET" in
  ''|0|1) ;;
  *) echo "SOCKET must be 1 (engines through the Docker socket) or 0 (engines inside the worker)." >&2; exit 2 ;;
esac
# What COMPOSE_FILE already had: server mode, the socket-less worker, the encrypted backup service.
current=$(sed -n 's/^COMPOSE_FILE=//p' .env 2>/dev/null | tail -n1)
has() { case ":$current:" in *":$1:"*) true ;; *) false ;; esac; }
# Published images stay unless PREBUILT says otherwise (PREBUILT=0 goes back to building).
[ -n "$PREBUILT" ] || ! has compose.images.yaml || image=$(sed -n 's/^PITANGUS_IMAGE=//p' .env | tail -n1)
if [ "$SOCKET" = 0 ] || { [ -z "$SOCKET" ] && { has compose.no-socket.yaml || { [ -n "$DOMAIN" ] && ! has compose.prod.yaml; }; }; }; then
  no_socket=1
else
  no_socket=
fi
# compose.yaml, then the overlays in the order they apply.
compose_files() {
  files=compose.yaml
  [ -z "$1" ] || files=$files:compose.prod.yaml
  [ -z "$no_socket" ] || files=$files:compose.no-socket.yaml
  [ -z "$2" ] || files=$files:compose.images.yaml
  [ -z "$2" ] || [ -z "$no_socket" ] || files=$files:compose.images.no-socket.yaml
  ! has compose.backup-age.yaml || files=$files:compose.backup-age.yaml
  printf '%s' "$files"
}
if [ ! -f .env ]; then
  sed -e "s/^PITANGUS_UID=.*/PITANGUS_UID=$(id -u)/" -e "s/^PITANGUS_GID=.*/PITANGUS_GID=$(id -g)/" .env.example > .env
  chmod 600 .env
  echo "Created .env with your user ($(id -u):$(id -g)). Review it to change the port, URL or TLS."
else
  echo ".env already exists: left unchanged."
fi
# PostgreSQL password: random and only in .env. An .env from before PostgreSQL gets it appended, nothing else changes.
if ! grep -q '^PITANGUS_DB_PASSWORD=.' .env; then
  password=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')
  if grep -q '^PITANGUS_DB_PASSWORD=' .env; then
    sed -i.bak "s/^PITANGUS_DB_PASSWORD=.*/PITANGUS_DB_PASSWORD=$password/" .env && rm -f .env.bak
  else
    printf '\n# Database password (generated; do not share it).\nPITANGUS_DB_PASSWORD=%s\n' "$password" >> .env
  fi
  echo "Generated the PostgreSQL password in .env."
fi
if [ -n "$DOMAIN" ]; then
  files=$(compose_files server "$image")
  set_var PITANGUS_DOMAIN "$DOMAIN"
  set_var PITANGUS_PUBLIC_URL "https://$DOMAIN"
  set_var PITANGUS_ALLOWED_ORIGINS "https://$DOMAIN"
  set_var COMPOSE_FILE "$files"
  [ -n "$image" ] && set_var PITANGUS_IMAGE "$image"
  grep -q '^PITANGUS_METRICS_TOKEN=.' .env || set_var PITANGUS_METRICS_TOKEN "$(random_hex 32)"
  echo "Server mode: https://$DOMAIN behind Caddy ($files)."
  [ -n "$no_socket" ] && echo "Engines inside the worker: no Docker socket in any container (SOCKET=1 to use it)."
elif [ -n "$PREBUILT" ] || [ -n "$SOCKET" ]; then
  # Same local setup (127.0.0.1, plain HTTP), only without building or without the socket. An .env already in server
  # mode keeps Caddy.
  files=$(compose_files "$(has compose.prod.yaml && echo server)" "$image")
  set_var COMPOSE_FILE "$files"
  [ -z "$image" ] || set_var PITANGUS_IMAGE "$image"
  echo "Compose files: $files."
fi
# Back to building (PREBUILT=0): the published image and its pins go, so nothing checks or pulls them.
if [ -z "$image" ] && has compose.images.yaml; then
  sed -i.bak '/^PITANGUS_IMAGE=/d; /^PITANGUS_IMAGE_TAG=/d; /^PITANGUS_WORKER_IMAGE_TAG=/d' .env && rm -f .env.bak
fi
mkdir -p data config backups
chmod 700 config backups
