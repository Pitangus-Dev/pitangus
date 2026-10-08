#!/bin/sh
# Scheduled backups inside the `backup` service (compose profile `backup`); not meant to be run on the host.
# Every BACKUP_INTERVAL_HOURS: /backups/auto-<date>/ with database.dump (pg_dump -Fc) and data.tgz (the same layout as
# `make backup`), written to a hidden folder first and renamed when complete. Deletes its own auto-* folders older
# than BACKUP_KEEP_DAYS; manual backups are never touched.
# The master key never sits unencrypted next to the secrets it opens: without BACKUP_AGE_RECIPIENT it stays out
# (master-key.sha256 names the key the backup needs); with it (age1… or ssh-ed25519 …, comma-separated), every file
# is encrypted with age (*.age) and config.tgz, with the key, goes in too. Needs an image with age
# (compose.backup-age.yaml).
#   --check   exit 0 if the newest complete backup is younger than two intervals (the container healthcheck)
set -eu

interval=${BACKUP_INTERVAL_HOURS:-24}
keep=${BACKUP_KEEP_DAYS:-14}
case "$interval$keep" in *[!0-9]*|'') echo "BACKUP_INTERVAL_HOURS and BACKUP_KEEP_DAYS must be whole numbers" >&2; exit 2 ;; esac
[ "$interval" -ge 1 ] || { echo "BACKUP_INTERVAL_HOURS must be at least 1" >&2; exit 2; }

if [ "${1:-}" = "--check" ]; then
  recent=$(find /backups -mindepth 1 -maxdepth 1 -type d -name 'auto-*' -mmin -$((interval * 120)) | head -n1)
  [ -n "$recent" ]
  exit $?
fi

# The age arguments (-r <recipient>…) become the positional parameters passed to backup().
set --
if [ -n "${BACKUP_AGE_RECIPIENT:-}" ]; then
  command -v age >/dev/null || { echo "PITANGUS_BACKUP_AGE_RECIPIENT is set but this image has no age: add compose.backup-age.yaml to COMPOSE_FILE in .env and run make up." >&2; exit 2; }
  set -f; old_ifs=$IFS; IFS=,
  for recipient in $BACKUP_AGE_RECIPIENT; do
    recipient=$(printf '%s' "$recipient" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
    [ -z "$recipient" ] || set -- "$@" -r "$recipient"
  done
  IFS=$old_ifs; set +f
  [ $# -gt 0 ] && printf '' | age "$@" >/dev/null || { echo "PITANGUS_BACKUP_AGE_RECIPIENT has no valid age recipient (age1… or ssh-ed25519 …, comma-separated)." >&2; exit 2; }
  echo "Backups encrypted with age for $(($# / 2)) recipient(s), the master key included."
else
  echo "Warning: backups are NOT encrypted; set PITANGUS_BACKUP_AGE_RECIPIENT before copying them offsite (docs/deploy-vps.md#backups)." >&2
fi

# `set -e` doesn't apply inside `if ! backup`: every step stops the backup on its own.
backup() {
  stamp=$(date -u +%Y%m%d-%H%M%S)
  partial="/backups/.auto-$stamp.partial"
  rm -rf "$partial" && mkdir -m 700 "$partial" || return 1
  pg_dump -Fc -f "$partial/database.dump" || return 1
  tar czf "$partial/data.tgz" -C /source --exclude=data/feeds --exclude=data/trivy-cache --exclude=data/grype-cache \
    --exclude=data/work --exclude=data/tmp data || return 1
  if [ $# -gt 0 ]; then
    if [ -d /source/config ]; then tar czf "$partial/config.tgz" -C /source config || return 1; fi
    for file in "$partial"/*; do
      age "$@" -o "$file.age" "$file" && rm -f "$file" || return 1
    done
  elif [ -r /source/config/master.key ]; then
    tr -d ' \r\n' < /source/config/master.key | sha256sum | cut -d' ' -f1 > "$partial/master-key.sha256" || return 1
  fi
  chmod 600 "$partial"/* && mv "$partial" "/backups/auto-$stamp" || return 1
  echo "$(date -u +%FT%TZ) backup: auto-$stamp"
  find /backups -mindepth 1 -maxdepth 1 -type d -name 'auto-*' -mtime +"$keep" -print -exec rm -rf {} + | sed 's/^/pruned: /'
}

trap 'exit 0' TERM INT
umask 077
while :; do
  if ! backup "$@"; then
    echo "$(date -u +%FT%TZ) backup FAILED: see the lines above; retrying in 1 hour" >&2
    rm -rf /backups/.auto-*.partial
    sleep 3600 & wait $!
    continue
  fi
  sleep $((interval * 3600)) & wait $!
done
