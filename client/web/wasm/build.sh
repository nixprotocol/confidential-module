#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
echo "Building crypto.wasm..."
GOOS=js GOARCH=wasm go build -o ../public/crypto.wasm .
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" ../public/
echo "crypto.wasm: $(ls -lh ../public/crypto.wasm | awk '{print $5}')"
echo "Done"
