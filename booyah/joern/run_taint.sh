#!/usr/bin/env bash
# Run Joern taint analysis using xss_taint.sc.
# Usage: ./run_taint.sh <cpg-file> <out-json>

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JOERN_CLI="$SCRIPT_DIR/../../tools/joern/joern-cli"
TAINT_SCRIPT="$SCRIPT_DIR/xss_taint.sc"

CPG_FILE="${1:?Usage: $0 <cpg-file> <out-json>}"
OUT_JSON="${2:-$SCRIPT_DIR/../../results/joern_xss.json}"

export JAVA_HOME
JAVA_HOME="$(brew --prefix openjdk@21)/libexec/openjdk.jdk/Contents/Home"
export PATH="$JAVA_HOME/bin:$(brew --prefix coreutils)/libexec/gnubin:$PATH"

mkdir -p "$(dirname "$OUT_JSON")"

echo "[*] Running Joern taint analysis..."
echo "[*] CPG: $CPG_FILE"
echo "[*] Output: $OUT_JSON"

"$JOERN_CLI/joern" \
  --script "$TAINT_SCRIPT" \
  --param "cpgFile=$CPG_FILE" \
  --param "outFile=$OUT_JSON" \
  2>&1 | tee "$(dirname "$OUT_JSON")/joern_run.log"

echo "[+] Done. Results: $OUT_JSON"
