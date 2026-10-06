#!/bin/sh
# Backup into backups/<date>/: database.dump and data.tgz (without rebuildable caches).
# The master key never sits unencrypted next to the secrets it opens: without TAMANDUA_BACKUP_AGE_RECIPIENT (.env or
# the environment) it stays out (master-key.sha256 names the key the backup needs: keep config/master.key apart);
# with it (age1… or ssh-ed25519 …, comma-separated), every file is encrypted with age (*.age) and config.tgz, with the
# key, goes in too.
# For a consistent copy the app stops for a few seconds. Usage: make backup
set -eu

dotenv() { sed -n "s/^$1=//p" .env 2>/dev/null | tail -n1 | sed "s/^[\"']//; s/[\"']\$//"; }
sha256() { if command -v sha256sum >/dev/null; then sha256sum; else shasum -a 256; fi | cut -d' ' -f1; }

recipients=${TAMANDUA_BACKUP_AGE_RECIPIENT:-$(dotenv TAMANDUA_BACKUP_AGE_RECIPIENT)}
set --
if [ -n "$recipients" ]; then
  command -v age >/dev/null || { echo "TAMANDUA_BACKUP_AGE_RECIPIENT is set but age isn't installed: apt install age, dnf install age or brew install age (https://github.com/FiloSottile/age)." >&2; exit 2; }
  set -f; old_ifs=$IFS; IFS=,
  for recipient in $recipients; do
    recipient=$(printf '%s' "$recipient" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
    [ -z "$recipient" ] || set -- "$@" -r "$recipient"
  done
  IFS=$old_ifs; set +f
  [ $# -gt 0 ] && printf '' | age "$@" >/dev/null || { echo "TAMANDUA_BACKUP_AGE_RECIPIENT has no valid age recipient (age1… or ssh-ed25519 …, comma-separated)." >&2; exit 2; }
fi

stamp=$(date +%Y%m%d-%H%M%S)
target="backups/$stamp"
partial="backups/.$stamp.partial"
running=$(docker compose ps --status running --services 2>/dev/null | grep -x api || true)

if [ -n "$running" ]; then
  active=$(docker compose exec -T api python -c "from pathlib import Path; from tamandua.modules.runs.store import list_runs; print(sum(1 for r in list_runs(Path('/data')) if r.get('status') in ('queued', 'running')))" 2>/dev/null || echo 0)
  if [ "${active:-0}" != "0" ] && [ "${FORCE:-}" != "1" ]; then
    echo "$active scans are running. Wait for them to finish or use FORCE=1 (they will be marked as failed)." >&2
    exit 1
  fi
  docker compose stop api >/dev/null
fi
# Whatever happens next, the API comes back and no half-written backup is left.
trap 'rm -rf "$partial"; [ -z "$running" ] || docker compose start api >/dev/null' EXIT

umask 077
mkdir -p backups
chmod 700 backups
rm -rf "$partial" && mkdir "$partial"
# Runs, findings, triage and the encrypted secrets: PostgreSQL dump (pg_restore custom format).
docker compose exec -T postgres pg_dump -U tamandua -d tamandua -Fc > "$partial/database.dump"
tar czf "$partial/data.tgz" --exclude=data/feeds --exclude=data/trivy-cache --exclude=data/grype-cache --exclude=data/work --exclude=data/tmp data
if [ $# -gt 0 ]; then
  [ ! -d config ] || tar czf "$partial/config.tgz" config
  for file in "$partial"/*; do
    age "$@" -o "$file.age" "$file"
    rm -f "$file"
  done
else
  key=$(dotenv TAMANDUA_MASTER_KEY)
  if [ -n "$key" ]; then
    printf '%s' "$key" | tr -d ' \r\n' | sha256 > "$partial/master-key.sha256"
    keyfrom="TAMANDUA_MASTER_KEY in .env"
  elif [ -r config/master.key ]; then
    tr -d ' \r\n' < config/master.key | sha256 > "$partial/master-key.sha256"
    keyfrom="config/master.key"
  fi
fi
chmod 600 "$partial"/*
mv "$partial" "$target"

echo "Backup in $target/"
if [ $# -gt 0 ]; then
  echo "  Encrypted with age: database.dump.age, data.tgz.age and config.tgz.age (with the master key)."
  echo "  To restore, decrypt them with your age identity, then make restore (docs/deploy-vps.md#backups)."
else
  echo "  Restore with: make restore FROM=$target CONFIRM=restore"
  echo "  database.dump  users, settings, runs, findings, triage and the secrets, encrypted with the master key"
  echo "  data.tgz       data/ without the caches: logs and the session signing key (no secrets)"
  if [ -n "${keyfrom:-}" ]; then
    echo "  The master key is NOT in the backup: keep a copy of $keyfrom apart (a password manager),"
    echo "  never with the backups. master-key.sha256 tells which key this backup needs."
  fi
  echo "Warning: this backup is NOT encrypted; set TAMANDUA_BACKUP_AGE_RECIPIENT before copying backups offsite." >&2
fi
