#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

echo "Building crypto.wasm..."
GOOS=js GOARCH=wasm go build -o ../public/crypto.wasm .
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" ../public/

# Record what the binary was built from.
#
# Go wasm builds are not byte-reproducible, so the committed crypto.wasm cannot
# be verified by rebuilding and comparing hashes. Recording a hash of the inputs
# is the next best thing, and it is what catches drift: this wallet once shipped
# a crypto.wasm whose main.go could not produce it -- the binary was copied from
# another wallet without the source, and the API silently disagreed with the
# checked-in code for as long as nobody rebuilt.
#
# mtimes cannot detect that. Git does not preserve them, so after a clone they
# reflect checkout order rather than edit order.
shasum -a 256 main.go go.mod go.sum | shasum -a 256 | awk '{print $1}' > ../public/crypto.wasm.srchash

echo "crypto.wasm: $(ls -lh ../public/crypto.wasm | awk '{print $5}')"
echo "source hash: $(cat ../public/crypto.wasm.srchash)"
echo "Done"
