#!/usr/bin/env bash
# Full E2E test suite for the IoTmx API.
#
# Usage:
#   cd /path/to/IOT-Server
#   bash http/tests/run_all.sh [--url http://host:port]
#
# Prerequisites:
#   • Server is running (default: http://localhost:8000)
#   • DB has a master_admin account (seeded by conftest or manually)
#   • Python venv with `cryptography` installed (the project venv works)
#
# The script:
#   1. Optionally seeds TicketStatus records for SQLite environments
#   2. Runs all .http test files in order via e2e.py, sharing variables
#   3. Reports pass/fail counts

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
E2E_PY="$REPO_ROOT/http/e2e.py"

URL="${IOTMX_URL:-http://localhost:8000}"

# Honour --url flag
for arg in "$@"; do
  case "$arg" in
    --url=*) URL="${arg#*=}" ;;
  esac
done
for i in "$@"; do
  if [[ "$i" == "--url" ]]; then
    shift; URL="$1"
  fi
done

export IOTMX_URL="$URL"

# ── Optional: seed TicketStatus for SQLite ───────────────────────────────────
# Seed ticket_status into a SQLite db if present.
# dev_server.py already handles this; this block is a fallback for other setups.
# Prefer http_test.db (dev server), fall back to test_run.db.
for _candidate in "$REPO_ROOT/http_test.db" "$REPO_ROOT/test_run.db"; do
  if command -v sqlite3 &>/dev/null && [[ -f "$_candidate" ]]; then
    if sqlite3 "$_candidate" "SELECT 1 FROM ticket_status LIMIT 1;" &>/dev/null; then
      sqlite3 "$_candidate" <<'SQL'
INSERT OR IGNORE INTO ticket_status (id, name, description)
VALUES
  (1, 'Open',        'Ticket is open and awaiting assignment'),
  (2, 'In Progress', 'Ticket is being worked on'),
  (3, 'Resolved',    'Ticket has been resolved'),
  (4, 'Closed',      'Ticket is closed');
SQL
    fi
    break
  fi
done

# ── Run test files ────────────────────────────────────────────────────────────
cd "$REPO_ROOT"

exec python "$E2E_PY" run \
  http/tests/00_login.http \
  http/tests/01_ops.http \
  http/tests/02_auth.http \
  http/tests/03_administrators.http \
  http/tests/04_managers.http \
  http/tests/05_users.http \
  http/tests/06_devices.http \
  http/tests/07_applications.http \
  http/tests/08_services.http \
  http/tests/09_roles.http \
  http/tests/10_tickets_service.http \
  http/tests/11_tickets_ecosystem.http \
  http/tests/12_payments.http \
  http/tests/13_telemetry.http \
  http/tests/14_webhooks.http \
  http/tests/15_policies.http \
  http/tests/99_cleanup.http
