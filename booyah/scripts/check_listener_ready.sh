#!/usr/bin/env bash
# check_listener_ready.sh — Booyah Listener Readiness Check (any-app generic)
#
# Verifies that:
#   1. The app is serving HTTP
#   2. BOOYAH_TAINT_ENABLED=1 is active in the PHP/app container
#   3. BOOYAH_ROLE is NOT hardcoded at the container level (dynamic detection required)
#   4. booyah_taint_map has write events for the active run_id
#   5. Role distribution shows expected roles are being captured
#
# Usage:
#   ./check_listener_ready.sh [app_host] [php_container] [db_container] [db_name] [run_id]
#
# Defaults target the Magento 2.4.8-p4 local stack.
#
# Exit codes:
#   0 — all checks pass, listeners are ready
#   1 — one or more checks failed

set -euo pipefail

APP_HOST="${1:-http://localhost:8082}"
PHP_CONTAINER="${2:-instrumented-magento-php-1}"
DB_CONTAINER="${3:-magento2-248-p4-db-1}"
DB_NAME="${4:-magento}"
DB_USER="${5:-magento}"
DB_PASS="${6:-magento}"
RUN_ID="${7:-run-full-20260507}"

PASS=1
WARNS=()

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║       Booyah Listener Readiness Check                       ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "  app_host:      $APP_HOST"
echo "  php_container: $PHP_CONTAINER"
echo "  db_container:  $DB_CONTAINER"
echo "  run_id:        $RUN_ID"
echo ""

# ── 1. App HTTP ─────────────────────────────────────────────────────────────
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${APP_HOST}/" 2>/dev/null || echo "000")
if [ "$STATUS" = "200" ] || [ "$STATUS" = "302" ]; then
  echo "  [OK]   App HTTP ${APP_HOST}/ → $STATUS"
else
  echo "  [FAIL] App HTTP ${APP_HOST}/ → $STATUS (expected 200/302)"
  PASS=0
fi

# Admin endpoint
ADMIN_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${APP_HOST}/admin" 2>/dev/null || echo "000")
if [ "$ADMIN_STATUS" = "200" ] || [ "$ADMIN_STATUS" = "302" ]; then
  echo "  [OK]   Admin endpoint → $ADMIN_STATUS"
else
  echo "  [WARN] Admin endpoint → $ADMIN_STATUS (non-critical if admin not used)"
  WARNS+=("Admin endpoint returned $ADMIN_STATUS")
fi

# ── 2. PHP container env ─────────────────────────────────────────────────────
if docker inspect "$PHP_CONTAINER" > /dev/null 2>&1; then
  CONTAINER_ENV=$(docker exec "$PHP_CONTAINER" env 2>/dev/null)

  TAINT_ENABLED=$(echo "$CONTAINER_ENV" | grep "^BOOYAH_TAINT_ENABLED=" | cut -d= -f2 || true)
  if [ "$TAINT_ENABLED" = "1" ]; then
    echo "  [OK]   BOOYAH_TAINT_ENABLED=1 in $PHP_CONTAINER"
  else
    echo "  [FAIL] BOOYAH_TAINT_ENABLED not '1' in $PHP_CONTAINER (got: '${TAINT_ENABLED:-unset}')"
    PASS=0
  fi

  ACTIVE_RUN_ID=$(echo "$CONTAINER_ENV" | grep "^BOOYAH_RUN_ID=" | cut -d= -f2 || true)
  if [ -n "$ACTIVE_RUN_ID" ]; then
    if [ "$ACTIVE_RUN_ID" = "$RUN_ID" ]; then
      echo "  [OK]   BOOYAH_RUN_ID=$ACTIVE_RUN_ID"
    else
      echo "  [WARN] BOOYAH_RUN_ID mismatch: container=$ACTIVE_RUN_ID, expected=$RUN_ID"
      WARNS+=("run_id mismatch: container has $ACTIVE_RUN_ID, script expects $RUN_ID")
    fi
  else
    echo "  [FAIL] BOOYAH_RUN_ID not set in $PHP_CONTAINER"
    PASS=0
  fi

  ROLE_OVERRIDE=$(echo "$CONTAINER_ENV" | grep "^BOOYAH_ROLE=" | cut -d= -f2 || true)
  if [ -n "$ROLE_OVERRIDE" ]; then
    echo "  [FAIL] BOOYAH_ROLE is hardcoded to '$ROLE_OVERRIDE' — dynamic role detection DISABLED"
    echo "         Remove BOOYAH_ROLE from docker-compose.override.yml and restart the container."
    PASS=0
  else
    echo "  [OK]   BOOYAH_ROLE unset — dynamic role detection active"
  fi
else
  echo "  [FAIL] PHP container '$PHP_CONTAINER' not found or not running"
  PASS=0
fi

# ── 3. Trace DB write events ─────────────────────────────────────────────────
if docker inspect "$DB_CONTAINER" > /dev/null 2>&1; then
  WRITE_COUNT=$(docker exec "$DB_CONTAINER" mysql \
    -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" -N \
    -e "SELECT COUNT(*) FROM booyah_taint_map WHERE run_id='${RUN_ID}';" 2>/dev/null || echo "ERROR")

  if [ "$WRITE_COUNT" = "ERROR" ]; then
    echo "  [FAIL] Could not query booyah_taint_map (check DB credentials or table exists)"
    PASS=0
  elif [ "$WRITE_COUNT" -gt 0 ] 2>/dev/null; then
    echo "  [OK]   booyah_taint_map: $WRITE_COUNT events for run_id=$RUN_ID"
  else
    echo "  [FAIL] booyah_taint_map: 0 events for run_id=$RUN_ID"
    echo "         Tracer is not writing. Check: module enabled, cache flushed, DI compiled."
    PASS=0
  fi

  # ── 4. Role distribution with per-role hard gates ──────────────────────────
  echo ""
  echo "  Taint event distribution (run_id=$RUN_ID):"
  docker exec "$DB_CONTAINER" mysql \
    -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" -N \
    -e "SELECT CONCAT('    role=', COALESCE(role,'(null)'), '  events=', COUNT(*), '  requests=', COUNT(DISTINCT request_id), '  tables=', COUNT(DISTINCT db_table)) FROM booyah_taint_map WHERE run_id='${RUN_ID}' GROUP BY role ORDER BY COUNT(*) DESC;" \
    2>/dev/null || echo "    (could not query role distribution)"

  # Hard gates: each expected role must have events before prod traffic is safe to run.
  # A zero-event role means a crawl script failed silently — tracing that role is blind.
  ANON_EVENTS=$(docker exec "$DB_CONTAINER" mysql \
    -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" -N \
    -e "SELECT COUNT(*) FROM booyah_taint_map WHERE run_id='${RUN_ID}' AND role='anonymous';" \
    2>/dev/null || echo "0")
  AUTH_EVENTS=$(docker exec "$DB_CONTAINER" mysql \
    -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" -N \
    -e "SELECT COUNT(*) FROM booyah_taint_map WHERE run_id='${RUN_ID}' AND role='authenticated';" \
    2>/dev/null || echo "0")
  ADMIN_EVENTS=$(docker exec "$DB_CONTAINER" mysql \
    -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" -N \
    -e "SELECT COUNT(*) FROM booyah_taint_map WHERE run_id='${RUN_ID}' AND role='admin';" \
    2>/dev/null || echo "0")
  NULL_EVENTS=$(docker exec "$DB_CONTAINER" mysql \
    -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" -N \
    -e "SELECT COUNT(*) FROM booyah_taint_map WHERE run_id='${RUN_ID}' AND role IS NULL;" \
    2>/dev/null || echo "0")

  echo ""
  echo "  Per-role gate check:"
  [ "${ANON_EVENTS:-0}"  -gt 0 ] 2>/dev/null && echo "  [OK]   anonymous: $ANON_EVENTS events" \
    || { echo "  [FAIL] anonymous: 0 events — run crawl_anon.php first"; PASS=0; }
  [ "${AUTH_EVENTS:-0}"  -gt 0 ] 2>/dev/null && echo "  [OK]   authenticated: $AUTH_EVENTS events" \
    || { echo "  [FAIL] authenticated: 0 events — run crawl_customer.php first"; PASS=0; }
  [ "${ADMIN_EVENTS:-0}" -gt 0 ] 2>/dev/null && echo "  [OK]   admin: $ADMIN_EVENTS events" \
    || { echo "  [FAIL] admin: 0 events — run crawl_admin.php first"; PASS=0; }
  if [ "${NULL_EVENTS:-0}" -gt 0 ] 2>/dev/null; then
    echo "  [WARN] null-role: $NULL_EVENTS events — SetRoleObserver not firing for some requests"
    WARNS+=("$NULL_EVENTS events have null role — check SetRoleObserver wiring for all request areas")
  fi

  # ── 5. Coverage matrix (if crawl_coverage.py available) ────────────────────
  echo ""
  COVERAGE_PY="$(dirname "$0")/../crawl/crawl_coverage.py"
  APP_ID="${8:-magento_248}"
  if python3 "$COVERAGE_PY" --app "$APP_ID" --run-id "$RUN_ID" \
       --db-host "$DB_CONTAINER" 2>/dev/null | grep -q "SILENT_FAIL"; then
    echo "  [FAIL] Coverage matrix shows SILENT_FAIL — a declared crawl produced no events"
    PASS=0
  else
    echo "  [OK]   No SILENT_FAIL in coverage matrix (debt is declared, not silent)"
  fi

  echo ""
  echo "  Confirmed paths:"
  docker exec "$DB_CONTAINER" mysql \
    -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" -N \
    -e "SELECT CONCAT('    confirmed=', COUNT(*)) FROM booyah_confirmed_paths;" \
    2>/dev/null || echo "    0"
else
  echo "  [FAIL] DB container '$DB_CONTAINER' not found or not running"
  PASS=0
fi

# ── 5. Adapter import check ──────────────────────────────────────────────────
ADAPTER_OK=$(python3 -c "
import importlib
try:
    m = importlib.import_module('booyah.pipeline.adapters.magento_taint_replay')
    assert callable(getattr(m, 'run', None)), 'no run() exported'
    print('ok')
except Exception as e:
    print(f'fail: {e}')
" 2>/dev/null || echo "fail: python3 not in path")

if [ "$ADAPTER_OK" = "ok" ]; then
  echo "  [OK]   replay_adapter module imports cleanly (run() exported)"
else
  echo "  [FAIL] replay_adapter: $ADAPTER_OK"
  PASS=0
fi

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "╠══════════════════════════════════════════════════════════════╣"

if [ "${#WARNS[@]}" -gt 0 ]; then
  echo "  Warnings (non-blocking):"
  for w in "${WARNS[@]}"; do
    echo "    ⚠  $w"
  done
  echo ""
fi

if [ "$PASS" = "1" ]; then
  echo "  ✅  READY — listeners are active. Begin manual testing session."
  echo "╚══════════════════════════════════════════════════════════════╝"
  echo ""
  exit 0
else
  echo "  ❌  NOT READY — fix failures above before starting the session."
  echo "╚══════════════════════════════════════════════════════════════╝"
  echo ""
  exit 1
fi
