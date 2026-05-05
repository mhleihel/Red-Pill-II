#!/usr/bin/env bash
# Build Joern CPG for a PHP project.
# Usage: ./build_cpg.sh <source-root> <output-dir>
# Example: ./build_cpg.sh /Users/mhleihel/Desktop/magento2-2.4.8-p4 /Users/mhleihel/Desktop/Booyah/joern_cpg

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JOERN_CLI="$SCRIPT_DIR/../../tools/joern/joern-cli"

SOURCE_ROOT="${1:?Usage: $0 <source-root> <output-dir>}"
OUTPUT_DIR="${2:?Usage: $0 <source-root> <output-dir>}"
CPG_FILE="$OUTPUT_DIR/magento.bin"

export JAVA_HOME
JAVA_HOME="$(brew --prefix openjdk@21)/libexec/openjdk.jdk/Contents/Home"
export PATH="$JAVA_HOME/bin:$(brew --prefix coreutils)/libexec/gnubin:$PATH"

mkdir -p "$OUTPUT_DIR"

echo "[*] Building Joern CPG for $SOURCE_ROOT"
echo "[*] Output: $CPG_FILE"
echo "[*] This takes 15-45 minutes for a large codebase..."

# php2cpg is the frontend — produces binary CPG
"$JOERN_CLI/php2cpg" \
  --output "$CPG_FILE" \
  "$SOURCE_ROOT" \
  2>&1 | tee "$OUTPUT_DIR/build_cpg.log"

echo "[+] CPG built: $CPG_FILE"
echo "[*] File size: $(du -sh "$CPG_FILE" | cut -f1)"
