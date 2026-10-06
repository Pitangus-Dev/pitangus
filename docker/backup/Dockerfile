# The backup service's image with age, to encrypt backups for TAMANDUA_BACKUP_AGE_RECIPIENT (compose.backup-age.yaml).
# The same PostgreSQL base as compose.yaml's postgres and backup services (pg_dump must match the server's major
# version); age comes from Alpine's signed repository.
FROM postgres:18-alpine@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873
RUN apk add --no-cache age && age --version
