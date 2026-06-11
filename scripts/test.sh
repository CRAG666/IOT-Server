#!/usr/bin/env bash
# Run Python tests and/or HTTP E2E tests.
#
# Usage:
#   bash scripts/test.sh [OPTIONS] [PYTEST_ARGS...]
#
# Options:
#   --url URL     Base URL of a running server (default: \$IOTMX_URL or http://localhost:8000)
#   --no-http     Skip HTTP tests even if a server is reachable
#   --http-only   Skip Python tests; run HTTP tests only
#   Any extra arguments are forwarded to pytest.
#
# Requirements for Python tests:
#   uv installed; no external services needed (uses SQLite + fakeredis).
#
# Requirements for HTTP tests:
#   A server running at URL with all services (Valkey, MongoDB, DB with master_admin seeded).
#   Server auto-detection: the script pings /health before attempting the suite.
#
# Exit codes:
#   0  all selected suites passed
#   1  one or more suites failed

set -uo pipefail
cd "$(dirname "$0")/.."          # always run from repo root

# ── Colours ──────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    BOLD='\033[1m'; GREEN='\033[32m'; RED='\033[31m'; YELLOW='\033[33m'; RESET='\033[0m'
else
    BOLD=''; GREEN=''; RED=''; YELLOW=''; RESET=''
fi

# ── Argument parsing ─────────────────────────────────────────────────────────
URL="${IOTMX_URL:-http://localhost:8000}"
RUN_PYTHON=1
RUN_HTTP=1
PYTEST_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --url)       URL="$2"; shift 2 ;;
        --url=*)     URL="${1#*=}"; shift ;;
        --no-http)   RUN_HTTP=0; shift ;;
        --http-only) RUN_PYTHON=0; shift ;;
        *)           PYTEST_ARGS+=("$1"); shift ;;
    esac
done

export IOTMX_URL="$URL"

# ── Helpers ───────────────────────────────────────────────────────────────────
section() { echo; echo -e "${BOLD}══ $* ══${RESET}"; }
pass()    { echo -e "  ${GREEN}PASS${RESET}  $*"; }
fail()    { echo -e "  ${RED}FAIL${RESET}  $*"; }
info()    { echo -e "  ${YELLOW}INFO${RESET}  $*"; }

server_reachable() {
    curl -sf --max-time 3 "$URL/health" > /dev/null 2>&1
}

# ── Track overall exit code ───────────────────────────────────────────────────
EXIT=0

# ─────────────────────────────────────────────────────────────────────────────
# 1. Python tests (pytest via uv)
# ─────────────────────────────────────────────────────────────────────────────
if [[ $RUN_PYTHON -eq 1 ]]; then
    section "Python tests (pytest)"
    if uv run pytest "${PYTEST_ARGS[@]+"${PYTEST_ARGS[@]}"}"; then
        pass "pytest"
    else
        fail "pytest"
        EXIT=1
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# 2. HTTP E2E tests
# ─────────────────────────────────────────────────────────────────────────────
if [[ $RUN_HTTP -eq 1 ]]; then
    section "HTTP E2E tests ($URL)"

    if ! server_reachable; then
        info "Server not reachable at $URL — skipping HTTP tests."
        info "Start the server first:"
        info "  uv run uvicorn app.main:app --reload"
        info "Then re-run with the same URL or set IOTMX_URL."
    else
        if bash http/tests/run_all.sh --url "$URL"; then
            pass "HTTP E2E suite"
        else
            fail "HTTP E2E suite"
            EXIT=1
        fi
    fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────
section "Result"
if [[ $EXIT -eq 0 ]]; then
    echo -e "  ${GREEN}${BOLD}All tests passed.${RESET}"
else
    echo -e "  ${RED}${BOLD}One or more suites failed.${RESET}"
fi

exit $EXIT
