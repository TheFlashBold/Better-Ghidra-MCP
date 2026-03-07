#!/bin/bash
set -e

GHIDRA="${GHIDRA_INSTALL_DIR:-/opt/ghidra}"
EXT_DIR="$HOME/.ghidra/.ghidra_$(basename "$GHIDRA")/Extensions/GhidraMCP"

if [ ! -f build/GhidraMCP.jar ]; then
    echo "Run ./build.sh first"
    exit 1
fi

mkdir -p "$EXT_DIR/lib"
cp extension.properties "$EXT_DIR/"
cp build/GhidraMCP.jar "$EXT_DIR/lib/"

echo "Installed to $EXT_DIR"
echo "Restart Ghidra to load the plugin"
