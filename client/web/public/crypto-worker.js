// public/crypto-worker.js

// 1. Polyfill globalThis for Go WASM in Worker context
globalThis.process = { env: {}, argv: [], exit: function() {} };
globalThis.fs = {
  constants: { O_WRONLY: -1, O_RDWR: -1, O_CREAT: -1, O_TRUNC: -1, O_APPEND: -1, O_EXCL: -1 },
  writeSync: function() { return 0; },
  write: function(fd, buf, offset, length, position, callback) { if(callback) callback(null, length); },
  chmod: function(p, m, cb) { cb(null); },
  chown: function(p, u, g, cb) { cb(null); },
  close: function(fd, cb) { cb(null); },
  fstat: function(fd, cb) { cb(null); },
  fsync: function(fd, cb) { cb(null); },
  lstat: function(p, cb) { cb(null); },
  mkdir: function(p, m, cb) { cb(null); },
  open: function(p, f, m, cb) { cb(null); },
  read: function(fd, b, o, l, p, cb) { cb(null, 0); },
  readdir: function(p, cb) { cb(null, []); },
  stat: function(p, cb) { cb(null); },
  unlink: function(p, cb) { cb(null); },
};

// 2. Load Go WASM runtime
importScripts('/wasm_exec.js');

// 3. State
let wasmReady = false;
let bsgsReady = false;

// 4. Init: load and instantiate WASM
async function initWASM() {
  postMessage({ type: 'progress', stage: 'Loading WASM module...' });

  const go = new Go();

  // Try streaming compilation (faster — compiles while downloading)
  let instance;
  try {
    const result = await WebAssembly.instantiateStreaming(fetch('/crypto.wasm'), go.importObject);
    instance = result.instance;
  } catch (e) {
    // Fallback for browsers that don't support instantiateStreaming
    const resp = await fetch('/crypto.wasm');
    const bytes = await resp.arrayBuffer();
    const result = await WebAssembly.instantiate(bytes, go.importObject);
    instance = result.instance;
  }

  go.run(instance);
  wasmReady = true;
  postMessage({ type: 'progress', stage: 'WASM loaded' });
}

// 5. Lazy BSGS init (only when decrypt is needed)
function ensureBSGS(halfBits) {
  if (!bsgsReady) {
    postMessage({ type: 'progress', stage: 'Building decryption table...' });
    const result = wasmInitBSGS(halfBits || 15);
    bsgsReady = true;
    postMessage({ type: 'progress', stage: 'Decryption table ready' });
  }
}

// 6. Message handler

// The account sequence number is a required nonce for randomness derivation.
// Without it, two transactions built from the same balance snapshot (a retry at
// a different amount, two open tabs) would reuse the same ElGamal randomness,
// which publicly leaks the difference between the two amounts. Fail loudly
// rather than silently defaulting.
// The range-proof bit width must match the chain's params.max_transfer_bits.
// Defaulting it here would silently produce proofs the chain rejects on any
// deployment that lowered the parameter.
function requireMaxBits(msg) {
  if (!msg.maxBits) {
    throw new Error('maxBits is required for this operation');
  }
  return Number(msg.maxBits);
}

function requireSequence(msg) {
  if (msg.accountSequence === undefined || msg.accountSequence === null) {
    throw new Error('accountSequence is required for this operation');
  }
  return Number(msg.accountSequence);
}

self.onmessage = async function(e) {
  const msg = e.data;
  const id = msg.id;

  try {
    if (!wasmReady && msg.type !== 'init') {
      throw new Error('WASM not initialized');
    }

    let result;
    switch (msg.type) {
      case 'init':
        await initWASM();
        postMessage({ type: 'ready' });
        return;

      case 'deriveKey':
        result = wasmDeriveKey(msg.seedHex, msg.counter);
        break;

      case 'registerKeyProof':
        result = wasmRegisterKeyProof(msg.skHex, msg.pkHex, msg.chainId, msg.sender);
        break;

      case 'shield':
        result = wasmShield(msg.skHex, msg.pkHex, String(msg.amount), msg.chainId, msg.sender, msg.denom, msg.availBalanceHex || '', requireSequence(msg));
        break;

      case 'send':
        result = wasmSend(msg.skHex, msg.senderPkHex, msg.receiverPkHex, msg.auditorPkHex,
          String(msg.amount), String(msg.availAmount), msg.availRandomnessHex,
          msg.chainId, msg.sender, msg.receiver, msg.denom, msg.availBalanceHex || '',
          requireSequence(msg), requireMaxBits(msg));
        break;

      case 'applyPending':
        result = wasmApplyPending(msg.skHex, msg.pkHex, msg.pendingCtHex, String(msg.pendingAmount),
          msg.chainId, msg.sender, msg.denom, msg.availBalanceHex || '', requireSequence(msg));
        break;

      case 'unshield':
        result = wasmUnshield(msg.skHex, msg.pkHex, String(msg.amount), String(msg.availAmount), msg.availRandomnessHex,
          msg.chainId, msg.sender, msg.denom, msg.availBalanceHex || '',
          requireSequence(msg), requireMaxBits(msg));
        break;

      case 'decrypt':
        ensureBSGS(msg.halfBits);
        result = wasmDecryptBalance(msg.skHex, msg.ciphertextHex);
        break;

      case 'encryptMemo':
        result = wasmEncryptMemo(msg.pkHex, msg.randomnessHex, msg.amount, msg.txAmount || 0);
        break;

      case 'decryptMemo':
        result = wasmDecryptMemo(msg.skHex, msg.encryptedMemoHex);
        break;

      default:
        throw new Error('Unknown message type: ' + msg.type);
    }

    if (result && result.error) {
      postMessage({ type: 'error', id: id, message: result.error });
    } else {
      postMessage({ type: 'result', id: id, data: result });
    }
  } catch (err) {
    postMessage({ type: 'error', id: id, message: err.message || String(err) });
  }
};
