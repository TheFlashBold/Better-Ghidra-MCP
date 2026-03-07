#!/bin/bash
set -e

GHIDRA="${GHIDRA_INSTALL_DIR:-/opt/ghidra}"

if [ ! -d "$GHIDRA" ]; then
    echo "Ghidra not found at $GHIDRA"
    echo "Set GHIDRA_INSTALL_DIR to your Ghidra installation directory"
    exit 1
fi

CP=$(find "$GHIDRA" -name "*.jar" | tr '\n' ':')

rm -rf build
mkdir -p build/classes/META-INF/extensions

javac -cp "$CP" -d build/classes \
    --source-path src/main/java \
    $(find src/main/java -name "*.java") 2>&1 | grep -v "Warnung\|Warning\|Note\|Hinweis" || true

cp extension.properties build/classes/META-INF/extensions/

cd build/classes
jar cf ../GhidraMCP.jar .
cd ../..

echo "Built build/GhidraMCP.jar ($(du -h build/GhidraMCP.jar | cut -f1))"
