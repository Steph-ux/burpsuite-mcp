#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
LIB_DIR="$DIR/lib"
BUILD_DIR="$DIR/build"
OUT_JAR="$DIR/../burpsuite-mcp-bridge.jar"
MONTOYA_JAR="$LIB_DIR/montoya-api-2026.7.jar"
MONTOYA_URL="https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/2026.7/montoya-api-2026.7.jar"

mkdir -p "$LIB_DIR" "$BUILD_DIR"

if [ ! -f "$MONTOYA_JAR" ]; then
  echo "Downloading montoya-api-2026.7.jar..."
  curl -fsSL -o "$MONTOYA_JAR" "$MONTOYA_URL"
fi

rm -rf "$BUILD_DIR"/*
find "$DIR/src" -name "*.java" > "$BUILD_DIR/sources.txt"

javac --release 21 -cp "$MONTOYA_JAR" -d "$BUILD_DIR" @"$BUILD_DIR/sources.txt"

cat > "$BUILD_DIR/MANIFEST.MF" <<'EOF'
Manifest-Version: 1.0
Extension-Name: BurpSuite MCP Full Pro Bridge
Created-By: burpsuite-mcp build.sh
EOF

jar cfm "$OUT_JAR" "$BUILD_DIR/MANIFEST.MF" -C "$BUILD_DIR" com

echo "Built $OUT_JAR ($(du -h "$OUT_JAR" | cut -f1))"
