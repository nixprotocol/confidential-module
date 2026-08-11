#!/bin/bash
# Browser end-to-end: run the real crypto.wasm in headless Chrome and verify the
# proofs it produces against the on-chain verifier.
#
# This is the only check that covers the WASM client and the keeper together.
# Every other test exercises the Go SDK, so a transcript or signature change
# that broke only the browser path would otherwise reach users first.
#
# Needs: Chrome, node 18+, python3. No npm installs (CDP over the built-in
# WebSocket).
set -euo pipefail
cd "$(dirname "$0")"

ALICE=cosmos1v9kxjcm9ta047h6lta047h6lta047h6l33fvfn
PORT=${PORT:-8731}
WORK=$(mktemp -d)
cleanup() {
  kill "${SRV_PID:-0}" "${CHROME_PID:-0}" 2>/dev/null || true
  # Wait for Chrome to finish flushing its profile before removing it, else rm
  # races the writes and reports "Directory not empty".
  wait "${CHROME_PID:-0}" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "==> building crypto.wasm"
../wasm/build.sh >/dev/null
cp ../public/crypto.wasm ../public/wasm_exec.js .

echo "==> serving on :$PORT"
python3 -m http.server "$PORT" >/dev/null 2>&1 &
SRV_PID=$!

echo "==> launching headless Chrome"
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --headless=new --remote-debugging-port=9222 \
  --user-data-dir="$WORK/chrome" --no-first-run --no-default-browser-check \
  about:blank >/dev/null 2>&1 &
CHROME_PID=$!
for _ in $(seq 1 30); do
  curl -sf http://localhost:9222/json/version >/dev/null && break
  sleep 0.5
done

echo "==> phase 1: register + shield + send in the browser"
node cdp.mjs "http://localhost:$PORT/index.html" phase1.js > "$WORK/phase1.json"

echo "==> verifying phase 1 against the chain verifier"
( cd ../../.. && NIX_BROWSER_E2E_PHASE1="$WORK/phase1.json" \
    NIX_BROWSER_E2E_AVAIL_OUT="$WORK/avail.hex" \
    go test -run TestBrowserE2E ./keeper/ )

echo "==> phase 2: unshield in the browser, bound to the on-chain balance"
AVAIL=$(cat "$WORK/avail.hex")
NEWR=$(python3 -c "import json;print(json.load(open('$WORK/phase1.json'))['send']['newAvailRandomnessHex'])")
cat > "$WORK/phase2.js" <<JS
(async () => {
  await window.wasmReady;
  const chk = (l, r) => { if (r && r.error) throw new Error(l + ': ' + r.error); return r; };
  const aliceK = chk('key', wasmDeriveKey('11'.repeat(32), 0));
  return chk('unshield', wasmUnshield(
    aliceK.secretKeyHex, aliceK.pubkeyHex, '200', '4000', '$NEWR',
    'test-chain-1', '$ALICE', 'uatom', '$AVAIL', 2, 64));
})()
JS
node cdp.mjs "http://localhost:$PORT/index.html" "$WORK/phase2.js" > "$WORK/phase2.json"

echo "==> verifying the full flow against the chain verifier"
( cd ../../.. && NIX_BROWSER_E2E_PHASE1="$WORK/phase1.json" \
    NIX_BROWSER_E2E_PHASE2="$WORK/phase2.json" \
    go test -run TestBrowserE2E -v ./keeper/ )

echo "==> full lifecycle: mint / transfer / claim / burn, with decrypted balance checks"
( cd ../../.. && NIX_BROWSER_E2E_DIR="$PWD/client/web/e2e" \
    NIX_BROWSER_E2E_URL="http://localhost:$PORT/index.html" \
    go test -run TestBrowserLifecycle -v ./keeper/ )

echo "PASS: browser crypto accepted by the chain verifier"
