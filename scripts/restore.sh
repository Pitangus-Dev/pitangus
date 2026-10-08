#!/bin/sh
# Restores a backup from `make backup` or the backup service: the database (replaced whole), config/ and data/.
# Usage: make restore FROM=backups/<date> CONFIRM=restore
#
# Before touching anything it checks the backup and saves the current state in backups/pre-restore-<date>/ (it's
# a normal backup: `make restore FROM=backups/pre-restore-<date>` undoes the restore). Restore on the same Pitangus
# version as the backup or a newer one: the app migrates the data forward when it starts, never backwards.
set -eu

from=${1:-}
from=${from%/}
if [ -n "$from" ] && [ ! -f "$from/database.dump" ] && [ -f "$from/database.dump.age" ]; then
  echo "$from is encrypted with age: decrypt it first with your identity, then restore." >&2
  echo "  for f in $from/*.age; do age -d -i <your-identity-file> -o \"\${f%.age}\" \"\$f\"; done" >&2
  exit 2
fi
if [ -z "$from" ] || [ ! -f "$from/database.dump" ]; then
  echo "Give a backup folder with a database.dump: make restore FROM=backups/<date> CONFIRM=restore" >&2
  exit 2
fi
if [ "${CONFIRM:-}" != "restore" ]; then
  echo "This replaces the database, config/ and data/ with the ones in $from (the current ones are saved first)."
  echo "Run again with: make restore FROM=$from CONFIRM=restore"
  exit 1
fi

# Each archive holds only its own folder (config/ or data/): plain files and folders, no absolute paths, no `..`,
# no links or devices. A tampered backup must not write anywhere else (compose.yaml, scripts/).
check_archive() {
  names=$(tar tzf "$1") && kinds=$(tar tvzf "$1" | cut -c1) || return 1
  ! printf '%s\n' "$names" | grep -Ev "^$2(/|\$)" >/dev/null || return 1
  ! printf '%s\n' "$names" | grep -E '(^|/)\.\.(/|$)' >/dev/null || return 1
  ! printf '%s\n' "$kinds" | grep -v '^[-d]$' >/dev/null
}

# Extracts into a fresh folder and checks the result again before it is used.
unpack() {
  rm -rf "$2.restoring" && mkdir "$2.restoring"
  tar xzf "$1" -C "$2.restoring"
  [ -d "$2.restoring/$2" ] && [ -z "$(find "$2.restoring" ! -type f ! -type d)" ] || {
    rm -rf "$2.restoring"; echo "$1 has something other than files and folders under $2/." >&2; exit 1; }
}

# 1. The backup is readable (before stopping anything).
[ "$(head -c 5 "$from/database.dump")" = "PGDMP" ] || { echo "$from/database.dump is not a pg_dump custom-format file." >&2; exit 1; }
for archive in config data; do
  if [ -f "$from/$archive.tgz" ]; then
    gzip -t "$from/$archive.tgz" || { echo "$from/$archive.tgz is damaged." >&2; exit 1; }
    check_archive "$from/$archive.tgz" "$archive" || {
      echo "$from/$archive.tgz holds something other than files and folders under $archive/: refused." >&2; exit 1; }
  fi
done
# Without config.tgz the current master key stays: it must be the one the backup's secrets were encrypted with.
if [ ! -f "$from/config.tgz" ]; then
  if [ -f "$from/master-key.sha256" ]; then
    sha256() { if command -v sha256sum >/dev/null; then sha256sum; else shasum -a 256; fi | cut -d' ' -f1; }
    key=$(sed -n 's/^PITANGUS_MASTER_KEY=//p' .env 2>/dev/null | tail -n1 | sed "s/^[\"']//; s/[\"']\$//")
    if [ -n "$key" ]; then current=$(printf '%s' "$key" | tr -d ' \r\n' | sha256)
    elif [ -r config/master.key ]; then current=$(tr -d ' \r\n' < config/master.key | sha256)
    else current=; fi
    if [ "$current" != "$(tr -d ' \r\n' < "$from/master-key.sha256")" ] && [ "${FORCE:-}" != "1" ]; then
      echo "The current master key is not the one $from needs (master-key.sha256): its secrets would not open." >&2
      echo "Put that key back (PITANGUS_MASTER_KEY in .env or config/master.key), or FORCE=1 to restore anyway." >&2
      exit 1
    fi
  fi
  echo "Note: $from has no config.tgz; the current master key is kept."
fi

# 2. Stop what writes, keep PostgreSQL up.
docker compose stop api worker backup >/dev/null 2>&1 || docker compose stop api worker >/dev/null
docker compose up -d --wait postgres >/dev/null 2>&1

# 3. Save the current state (a normal backup folder).
stamp=$(date +%Y%m%d-%H%M%S)
safety="backups/pre-restore-$stamp"
mkdir -p "$safety"
chmod 700 backups "$safety"
docker compose exec -T postgres pg_dump -U pitangus -d pitangus -Fc > "$safety/database.dump"
# config/ (the master key) is only copied when the backup replaces it: otherwise it stays in place, and a plain
# copy of the key next to the secrets it opens is what backups avoid.
[ -d config ] && [ -f "$from/config.tgz" ] && tar czf "$safety/config.tgz" config
[ -d data ] && tar czf "$safety/data.tgz" --exclude=data/feeds --exclude=data/trivy-cache --exclude=data/grype-cache \
  --exclude=data/work --exclude=data/tmp data
chmod 600 "$safety"/*
echo "Current state saved in $safety/"

# 4. The database, whole: dropped and recreated, so no table from a newer schema survives.
docker compose exec -T postgres psql -q -U pitangus -d postgres -v ON_ERROR_STOP=1 \
  -c 'DROP DATABASE IF EXISTS pitangus WITH (FORCE)' -c 'CREATE DATABASE pitangus OWNER pitangus'
docker compose exec -T postgres pg_restore -U pitangus -d pitangus --no-owner --exit-on-error < "$from/database.dump"
echo "Database restored."

# 5. Secrets (replaced, not merged: a stale key must not survive) and data (the caches are downloaded again).
if [ -f "$from/config.tgz" ]; then
  unpack "$from/config.tgz" config
  rm -rf config && mv config.restoring/config config && rmdir config.restoring
  chmod 700 config
  echo "config/ restored."
fi
if [ -f "$from/data.tgz" ]; then
  unpack "$from/data.tgz" data
  mkdir -p data && cp -Rp data.restoring/data/. data/ && rm -rf data.restoring
  echo "data/ restored."
fi
echo "Done. Start it with: make up"
