#!/usr/bin/env bash
# Run Psalm taint analysis on Magento.
# Prerequisites: composer require --dev vimeo/psalm in the Magento root.
#
# Usage: ./run_psalm.sh <magento-root> [output-dir]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAGENTO_ROOT="${1:?Usage: $0 <magento-root> [output-dir]}"
OUTPUT_DIR="${2:-$SCRIPT_DIR/../../results}"

mkdir -p "$OUTPUT_DIR"

PSALM_XML="$SCRIPT_DIR/psalm.xml"
PSALM_BIN="$MAGENTO_ROOT/vendor/bin/psalm"

if [ ! -f "$PSALM_BIN" ]; then
    echo "[*] Installing Psalm in Magento..."
    cd "$MAGENTO_ROOT"
    composer require --dev vimeo/psalm --no-interaction 2>&1 | tail -5
fi

echo "[*] Running Psalm taint analysis on $MAGENTO_ROOT"
echo "[*] Config: $PSALM_XML"
echo "[*] Output: $OUTPUT_DIR/psalm_taint.sarif"
echo "[*] This takes 15-60 minutes for a full Magento codebase..."

cd "$MAGENTO_ROOT"

# Run taint analysis with SARIF output
"$PSALM_BIN" \
    --config="$PSALM_XML" \
    --taint-analysis \
    --output-format=sarif \
    --no-progress \
    --threads=8 \
    2>&1 | tee "$OUTPUT_DIR/psalm_run.log" \
    | grep -v "^$" \
    > "$OUTPUT_DIR/psalm_taint.sarif" || true

# Also produce JSON for easier programmatic use
"$PSALM_BIN" \
    --config="$PSALM_XML" \
    --taint-analysis \
    --output-format=json \
    --no-progress \
    --threads=8 \
    2>/dev/null > "$OUTPUT_DIR/psalm_taint.json" || true

echo "[+] Psalm complete"
echo "[*] SARIF: $OUTPUT_DIR/psalm_taint.sarif"
echo "[*] JSON:  $OUTPUT_DIR/psalm_taint.json"

# Quick summary
if command -v python3 &>/dev/null; then
    python3 -c "
import json, sys
try:
    with open('$OUTPUT_DIR/psalm_taint.json') as f:
        d = json.load(f)
    issues = d.get('issues', [])
    tainted = [i for i in issues if 'Tainted' in i.get('type','')]
    print(f'Tainted findings: {len(tainted)}')
    by_type = {}
    for i in tainted:
        t = i.get('type','')
        by_type[t] = by_type.get(t,0) + 1
    for t,c in sorted(by_type.items(), key=lambda x: -x[1]):
        print(f'  {c:4d}  {t}')
except Exception as e:
    print(f'Could not summarize: {e}')
"
fi
