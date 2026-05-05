#!/usr/bin/env bash
# Booyah full pipeline runner.
#
# Runs all static analysis layers and (optionally) dynamic layers.
# Output: results/ directory with all findings.
#
# Usage:
#   ./run_full_pipeline.sh <magento-root>
#   ./run_full_pipeline.sh <magento-root> --dynamic --base-url http://localhost:8082
#
# Static layers (no running app needed): Psalm, Joern, route extraction
# Dynamic layers (require running Magento): instrumentation, ZAP, Playwright
#
# Flags:
#   --dynamic            Enable dynamic layers (requires running Magento instance)
#   --base-url URL       Magento URL (default: http://localhost:8082)
#   --zap-url URL        ZAP API URL (default: http://localhost:8090)
#   --admin-user USER    Magento admin username (default: admin)
#   --admin-pass PASS    Magento admin password (default: Admin123!)
#   --skip-joern         Skip Joern CPG build (slow)
#   --skip-psalm         Skip Psalm (requires composer in Magento)
#   --neo4j              Load results into Neo4j after correlation

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAGENTO_ROOT="${1:?Usage: $0 <magento-root> [options]}"
shift

DYNAMIC=false
BASE_URL="http://localhost:8082"
ZAP_URL="http://localhost:8090"
ZAP_KEY="booyah"
ADMIN_USER="admin"
ADMIN_PASS="Admin123!"
SKIP_JOERN=false
SKIP_PSALM=false
LOAD_NEO4J=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --dynamic) DYNAMIC=true ;;
        --base-url) BASE_URL="$2"; shift ;;
        --zap-url) ZAP_URL="$2"; shift ;;
        --admin-user) ADMIN_USER="$2"; shift ;;
        --admin-pass) ADMIN_PASS="$2"; shift ;;
        --skip-joern) SKIP_JOERN=true ;;
        --skip-psalm) SKIP_PSALM=true ;;
        --neo4j) LOAD_NEO4J=true ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
    shift
done

RESULTS="$SCRIPT_DIR/../results"
mkdir -p "$RESULTS"

JOERN_CLI="$SCRIPT_DIR/../tools/joern/joern-cli"
JAVA_HOME_PATH="$(brew --prefix openjdk@21)/libexec/openjdk.jdk/Contents/Home"
GNU_BIN="$(brew --prefix coreutils)/libexec/gnubin"

echo "========================================================"
echo "  Booyah XSS Pipeline"
echo "  Target: $MAGENTO_ROOT"
echo "  Results: $RESULTS"
echo "  Dynamic: $DYNAMIC"
echo "========================================================"

# --- Layer 0: Static route extraction ---
echo ""
echo "[L0] Extracting static routes..."
python3 "$SCRIPT_DIR/routes/extract_routes.py" \
    "$MAGENTO_ROOT" \
    --output "$RESULTS/routes.json" \
    --summary
echo "[L0] Done: $RESULTS/routes.json"

# --- Layer 1: Psalm taint analysis ---
if [ "$SKIP_PSALM" = false ]; then
    echo ""
    echo "[L1] Running Psalm taint analysis..."
    bash "$SCRIPT_DIR/psalm/run_psalm.sh" "$MAGENTO_ROOT" "$RESULTS"
    echo "[L1] Done: $RESULTS/psalm_taint.sarif"
else
    echo "[L1] Skipped (--skip-psalm)"
fi

# --- Layer 2: Joern CPG + taint ---
if [ "$SKIP_JOERN" = false ]; then
    echo ""
    echo "[L2] Building Joern CPG..."
    JOERN_CPG_DIR="$RESULTS/joern_cpg"
    mkdir -p "$JOERN_CPG_DIR"

    export JAVA_HOME="$JAVA_HOME_PATH"
    export PATH="$JAVA_HOME/bin:$GNU_BIN:$PATH"
    chmod +x "$JOERN_CLI/php2cpg" "$JOERN_CLI/joern" "$JOERN_CLI/bin/repl-bridge" 2>/dev/null || true

    "$JOERN_CLI/php2cpg" \
        --output "$JOERN_CPG_DIR/magento.bin" \
        "$MAGENTO_ROOT" \
        2>&1 | tee "$RESULTS/joern_build.log"

    echo "[L2] Running Joern taint analysis..."
    "$JOERN_CLI/joern" \
        --script "$SCRIPT_DIR/joern/xss_taint.sc" \
        --param "cpgFile=$JOERN_CPG_DIR/magento.bin" \
        --param "outFile=$RESULTS/joern_xss.json" \
        2>&1 | tee "$RESULTS/joern_run.log"
    echo "[L2] Done: $RESULTS/joern_xss.json"
else
    echo "[L2] Skipped (--skip-joern)"
fi

# --- Layer 3: Dynamic instrumentation + crawl (requires running Magento) ---
TRACE_DB="$RESULTS/booyah_trace.db"
if [ "$DYNAMIC" = true ]; then
    echo ""
    echo "[L3] Running PHP instrumentation..."
    INSTRUMENTED="$RESULTS/instrumented"

    php "$SCRIPT_DIR/instrumentor/bin/instrument" \
        --source-root "$MAGENTO_ROOT" \
        --output-root "$INSTRUMENTED" \
        --manifest "$RESULTS/instrument_manifest.json" \
        2>&1 | tee "$RESULTS/instrument.log"
    echo "[L3] Instrumentation done: $INSTRUMENTED"

    echo "[L3] Running ZAP crawl + active scan..."
    export BOOYAH_TRACE_DB="$TRACE_DB"
    python3 "$SCRIPT_DIR/crawl/zap_seed.py" \
        --routes "$RESULTS/routes.json" \
        --base-url "$BASE_URL" \
        --zap-url "$ZAP_URL" \
        --api-key "$ZAP_KEY" \
        --output "$RESULTS/zap_alerts.json"

    echo "[L3] Running Playwright crawler..."
    node "$SCRIPT_DIR/crawl/playwright_crawl.js" \
        --routes "$RESULTS/routes.json" \
        --base-url "$BASE_URL" \
        --admin-url "$BASE_URL/admin" \
        --admin-user "$ADMIN_USER" \
        --admin-pass "$ADMIN_PASS" \
        --output "$RESULTS/playwright_reflected.json"
    echo "[L3] Done"
else
    echo "[L3] Skipped (add --dynamic to run crawls)"
fi

# --- Correlation ---
echo ""
echo "[Correlate] Merging findings from all layers..."

PSALM_ARG=""
[ -f "$RESULTS/psalm_taint.sarif" ] && PSALM_ARG="--psalm $RESULTS/psalm_taint.sarif"
JOERN_ARG=""
[ -f "$RESULTS/joern_xss.json" ] && JOERN_ARG="--joern $RESULTS/joern_xss.json"
TRACE_ARG=""
[ -f "$TRACE_DB" ] && TRACE_ARG="--trace-db $TRACE_DB"
ZAP_ARG=""
[ -f "$RESULTS/zap_alerts.json" ] && ZAP_ARG="--zap $RESULTS/zap_alerts.json"

python3 "$SCRIPT_DIR/correlate/correlate.py" \
    $PSALM_ARG $JOERN_ARG $TRACE_ARG $ZAP_ARG \
    --routes "$RESULTS/routes.json" \
    --base-url "$BASE_URL" \
    --output "$RESULTS/correlated_findings.json"

echo "[Correlate] Done: $RESULTS/correlated_findings.json"

# --- Neo4j (optional) ---
if [ "$LOAD_NEO4J" = true ]; then
    echo ""
    echo "[Graph] Loading into Neo4j..."
    python3 "$SCRIPT_DIR/graph/neo4j_loader.py" \
        --correlated "$RESULTS/correlated_findings.json" \
        --routes "$RESULTS/routes.json"
fi

# --- Summary ---
echo ""
echo "========================================================"
echo "  Pipeline complete. Results:"
echo "========================================================"
ls -la "$RESULTS/"
