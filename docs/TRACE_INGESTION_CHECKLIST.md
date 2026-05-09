# Trace Ingestion Checklist — Any-App Generic

How to wire a running application's runtime trace into Booyah Phase 5 so that
`verification_confidence` upgrades from `degraded` to `full`.

**Applies to:** any language, any framework. Magento-specific examples shown; the
pattern is the same for any app with a Booyah tracer module or equivalent.

---

## 1. Prerequisites

| Item | How to verify |
|---|---|
| App is running and serving traffic | `curl -o /dev/null -w "%{http_code}" http://<app_host>/` → 200 |
| Tracer module is deployed and enabled | Check framework module config (e.g. `app/etc/config.php` for Magento, `config/app.php` for Laravel, `settings.py` for Django) |
| Tracer environment vars are set | `BOOYAH_TAINT_ENABLED=1`, `BOOYAH_RUN_ID=<run_id>` — **do not** set `BOOYAH_ROLE` at container level |
| Trace persistence layer exists | Tracer DB tables created (e.g. `booyah_taint_map`, `booyah_confirmed_paths`, `booyah_unconfirmed_paths`) |
| Phase 4 composed graph available | `results/pipeline/<app_id>/04_compose/appmap_composed.db` exists |

---

## 2. Role Tagging — Critical Correctness Check

Role tagging is the most common silent failure. If `BOOYAH_ROLE` is hardcoded at the
container or process level, **all events from all roles will be mis-labelled**.

### Correct approach

Role must be detected dynamically per-request:

```
Priority:
  1. BOOYAH_ROLE env var (only if set by an automated crawl script for that session)
  2. Framework-native detection:
       - Admin/privileged area route prefix → "admin"
       - Authenticated session (session cookie / JWT / bearer token) → "authenticated"
       - No session → "anonymous"
```

### Verification

```bash
# Confirm BOOYAH_ROLE is NOT set at the container level
docker exec <php_container> env | grep BOOYAH_ROLE
# Expected: no output

# Make one anonymous and one authenticated request, then check:
#   SELECT role, COUNT(*) FROM booyah_taint_map GROUP BY role;
# Expected: rows with role="anonymous" AND role="authenticated" (not all "guest")
```

### Listener readiness gate

Before starting any role-based manual testing session, confirm:

```bash
# At least one write event exists in the trace DB — proves the tracer is firing
SELECT COUNT(*) FROM booyah_taint_map WHERE run_id = '<run_id>';
# Must be > 0. If 0: tracer module is not loaded or BOOYAH_TAINT_ENABLED is not reaching PHP.
```

---

## 3. Replay Adapter Implementation

Phase 5 live mode requires a replay adapter module. The module must expose:

```python
def run(routes: list[dict], trace_conn: sqlite3.Connection, scope: dict) -> None:
    """
    Read taint events from the app's tracer persistence layer.
    Write events, taints, and requests rows into trace_conn (runtime_trace_min.db).
    """
```

### Required writes to `runtime_trace_min.db`

```sql
-- At least one SOURCE event (tainted value entered app)
INSERT INTO events (event_id, request_id, event_type, fqn,
                    file_path, line_no, confidence_class, timestamp)
VALUES (?, ?, 'SOURCE', ?, ?, ?, 'Correlated', ?);

-- At least one SINK event (tainted value reached output boundary)
INSERT INTO events (...) VALUES (?, ?, 'SINK', ...);

-- At least one BOUNDARY_READ or BOUNDARY_WRITE event
INSERT INTO events (...) VALUES (?, ?, 'BOUNDARY_WRITE', ...);

-- One request record per HTTP request observed
INSERT INTO requests (request_id, url, method, area, risk_tier, replayed_at, trace_mode)
VALUES (?, ?, ?, ?, ?, ?, 'live');

-- Confirmed taint paths (source→sink with runtime evidence)
INSERT INTO taints (taint_id, request_id, source_event_id, sink_event_id,
                    path_fqns, confirmed)
VALUES (?, ?, ?, ?, ?, 1);
```

### FQN alignment

Event `fqn` values in `runtime_trace_min.db` must be comparable to FQNs in
`appmap_composed.db` nodes. Phase 5's delta computation matches on exact string equality.

```
Tracer write event on table "customer_entity", column "firstname"
→ fqn = "customer_entity.firstname"   (matches composed graph SOURCE node)

Tracer read event (re-entry) on same
→ fqn = "customer_entity.firstname (re-entry)"  (matches SINK node)
```

Use the same FQN derivation logic as Phase 4's `_compose_lineages()`.

### Confidence upgrade

Events confirmed by `booyah_confirmed_paths` (source_hash→sink_hash matched in the
same request) must have `confidence_class = 'Observed'`. All others: `'Correlated'`.

---

## 4. scope.yaml Configuration

```yaml
production_traffic:
  available: true
  capture_tool: "booyah_tracer"          # or "newrelic", "otel", "appmap"
  sensitive_fields_policy: "fields_policy.yaml"

adapters:
  replay_adapter: "booyah.pipeline.adapters.<app_id>_taint_replay"

database:                                 # only needed if adapter reads from MySQL/Postgres
  host: "127.0.0.1"
  port: 3307
  user: "<user>"
  password: "<password>"
  name: "<db_name>"
```

**Do not** leave `replay_adapter: ""` — Phase 5 will remain in offline/degraded mode.

---

## 5. Listener Readiness Verification Script

Run this before starting any manual testing session:

```bash
#!/usr/bin/env bash
# booyah/scripts/check_listener_ready.sh
# Usage: ./check_listener_ready.sh <app_host> <db_container> <db_name> <run_id>

APP_HOST=${1:-"http://localhost:8082"}
DB_CONTAINER=${2:-"magento2-248-p4-db-1"}
DB_NAME=${3:-"magento"}
RUN_ID=${4:-"run-full-20260507"}

PASS=1

echo "=== Booyah Listener Readiness Check ==="

# 1. App HTTP
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${APP_HOST}/")
if [ "$STATUS" = "200" ]; then
  echo "  [OK]   App HTTP: $STATUS"
else
  echo "  [FAIL] App HTTP: $STATUS (expected 200)"
  PASS=0
fi

# 2. Tracer env
TAINT_ENABLED=$(docker exec "${DB_CONTAINER%%-db*}-php-1" env 2>/dev/null | grep BOOYAH_TAINT_ENABLED | cut -d= -f2)
ROLE_OVERRIDE=$(docker exec "${DB_CONTAINER%%-db*}-php-1" env 2>/dev/null | grep "^BOOYAH_ROLE=" | cut -d= -f2)

if [ "$TAINT_ENABLED" = "1" ]; then
  echo "  [OK]   BOOYAH_TAINT_ENABLED=1"
else
  echo "  [FAIL] BOOYAH_TAINT_ENABLED not set or not 1 in PHP container"
  PASS=0
fi

if [ -n "$ROLE_OVERRIDE" ]; then
  echo "  [WARN] BOOYAH_ROLE is hardcoded to '$ROLE_OVERRIDE' — dynamic role detection is disabled"
  PASS=0
else
  echo "  [OK]   BOOYAH_ROLE not set — dynamic role detection active"
fi

# 3. Trace DB write events
WRITE_COUNT=$(docker exec "$DB_CONTAINER" mysql -u magento -pmagento "$DB_NAME" -N \
  -e "SELECT COUNT(*) FROM booyah_taint_map WHERE run_id='${RUN_ID}';" 2>/dev/null)

if [ -n "$WRITE_COUNT" ] && [ "$WRITE_COUNT" -gt 0 ]; then
  echo "  [OK]   booyah_taint_map: $WRITE_COUNT events for run_id=$RUN_ID"
else
  echo "  [FAIL] booyah_taint_map: 0 events — tracer not firing (check module enabled, cache flushed)"
  PASS=0
fi

# 4. Role distribution
echo ""
echo "  Current taint event distribution:"
docker exec "$DB_CONTAINER" mysql -u magento -pmagento "$DB_NAME" -N \
  -e "SELECT CONCAT('    role=', role, '  events=', COUNT(*), '  requests=', COUNT(DISTINCT request_id)) FROM booyah_taint_map WHERE run_id='${RUN_ID}' GROUP BY role;" 2>/dev/null

echo ""
if [ "$PASS" = "1" ]; then
  echo "=== READY — listeners are active. Begin manual testing session. ==="
else
  echo "=== NOT READY — fix failures above before starting the session. ==="
  exit 1
fi
```

---

## 6. Per-Role Session Protocol

For each role, follow this sequence:

```
1. Set up the session:
   - Anonymous: clear cookies / use incognito window
   - Authenticated: log in as the test customer account
   - Admin: log in to /admin with the scoped admin account for this role

2. Perform the actions from the capture matrix (live_capture_matrix.xlsx)
   - Use the tagged test values (e.g. TestBooyah_<lineage_suffix>)
   - Complete each action fully (don't abandon mid-form)

3. After each session, spot-check the trace DB:
   SELECT role, event_type, db_table, COUNT(*) cnt
   FROM booyah_taint_map
   WHERE run_id = '<run_id>'
   GROUP BY role, event_type, db_table
   ORDER BY cnt DESC;

4. Verify the new role appears in the distribution
   (e.g. after admin session: role='admin' rows must appear)
```

---

## 7. After Session: Run Phase 5–13

```bash
python3 -m booyah.pipeline.runner \
  --app-scope booyah/pipeline/apps/<app_id>/scope.yaml \
  --output-dir results/pipeline \
  --phase 5-13
```

### Expected Phase 5 outcome

| Field | Before (offline) | After (live) |
|---|---|---|
| `trace_mode` | `offline` | `live` |
| `trace_source` | `appmap.db` | `booyah_taint_map` |
| `verification_confidence` | `degraded` | `full` |
| `source_event_count` | > 0 (from appmap) | > 0 (from tracer) |
| `boundary_event_count` | 0 | > 0 |

### Expected Phase 9 outcome

- CORRELATED lineages whose source→sink value hashes were observed in the live trace → promoted to **CONFIRMED**
- `critical_coverage_debt` count decreases proportionally
- `unresolved_needs_live_replay` items in `contradiction_log.json` → resolved

---

## 8. Adapting to a New App

| Step | Magento example | New app equivalent |
|---|---|---|
| Tracer module | `Booyah_Tracer` Magento module | Middleware / plugin for the new framework |
| Trace persistence | `booyah_taint_map` MySQL table | Same table schema, any supported DB |
| Role detection | `SetRoleObserver` checks admin route prefix + `CustomerSession::isLoggedIn()` | Replace with new framework's session/auth API |
| Replay adapter | `booyah.pipeline.adapters.magento_taint_replay` | New `<app_id>_taint_replay.py` with same `run()` signature |
| FQN convention | `table.column` for DB sinks, URL path for HTTP sources | Same convention — Phase 4 composed graph drives the format |

The only per-app files are:
1. The tracer module (framework plugin)
2. The `SetRoleObserver` equivalent (or equivalent middleware)
3. The replay adapter (`<app_id>_taint_replay.py`)
4. `scope.yaml` adapter + database block

Pipeline phases 0–13 are unchanged.
