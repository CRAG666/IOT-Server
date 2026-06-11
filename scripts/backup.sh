#!/bin/sh
# Nightly backup: pg_dump + mongodump to /backups, prune files older than BACKUP_KEEP_DAYS.
set -e

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
KEEP_DAYS="${BACKUP_KEEP_DAYS:-7}"

echo "[backup] Starting at $TIMESTAMP"

# PostgreSQL
PG_FILE="/backups/pg_${POSTGRES_DB}_${TIMESTAMP}.sql.gz"
pg_dump -h "$POSTGRES_HOST" -U "$POSTGRES_USER" "$POSTGRES_DB" | gzip > "$PG_FILE"
echo "[backup] PostgreSQL → $PG_FILE"

# MongoDB
MONGO_DIR="/backups/mongo_${TIMESTAMP}"
mongodump --host "$MONGO_HOST" --username "$MONGO_USER" --password "$MONGO_PASSWORD" \
  --authenticationDatabase admin --out "$MONGO_DIR" --gzip
echo "[backup] MongoDB → $MONGO_DIR"

# Prune old backups
find /backups -name "pg_*.sql.gz" -mtime "+${KEEP_DAYS}" -delete
find /backups -type d -name "mongo_*" -mtime "+${KEEP_DAYS}" -exec rm -rf {} + 2>/dev/null || true

echo "[backup] Done. Kept last ${KEEP_DAYS} days."
