// src/lib/keplr.ts
import { CHAIN_CONFIG } from './config';

export function isKeplrInstalled(): boolean {
  return typeof window !== 'undefined' && !!window.keplr;
}

export async function suggestChain(): Promise<void> {
  if (!window.keplr) throw new Error('Keplr not installed');
  await window.keplr.experimentalSuggestChain({
    chainId: CHAIN_CONFIG.chainId,
    chainName: CHAIN_CONFIG.chainName,
    rpc: CHAIN_CONFIG.rpc,
    rest: CHAIN_CONFIG.rest,
    bip44: { coinType: CHAIN_CONFIG.coinType },
    bech32Config: {
      bech32PrefixAccAddr: CHAIN_CONFIG.bech32Prefix,
      bech32PrefixAccPub: CHAIN_CONFIG.bech32Prefix + 'pub',
      bech32PrefixValAddr: CHAIN_CONFIG.bech32Prefix + 'valoper',
      bech32PrefixValPub: CHAIN_CONFIG.bech32Prefix + 'valoperpub',
      bech32PrefixConsAddr: CHAIN_CONFIG.bech32Prefix + 'valcons',
      bech32PrefixConsPub: CHAIN_CONFIG.bech32Prefix + 'valconspub',
    },
    currencies: [{ coinDenom: 'NIX', coinMinimalDenom: 'anix', coinDecimals: 0 },
                 { coinDenom: 'FEE', coinMinimalDenom: 'fee', coinDecimals: 0 }],
    feeCurrencies: [{ coinDenom: 'FEE', coinMinimalDenom: 'fee', coinDecimals: 0,
      gasPriceStep: { low: 0.01, average: 0.025, high: 0.03 } }],
    stakeCurrency: { coinDenom: 'FEE', coinMinimalDenom: 'fee', coinDecimals: 0 },
  });
}

export async function connectKeplr(): Promise<{ address: string }> {
  if (!window.keplr) throw new Error('Keplr not installed');
  await suggestChain();
  await window.keplr.enable(CHAIN_CONFIG.chainId);
  const offlineSigner = window.keplr.getOfflineSigner(CHAIN_CONFIG.chainId);
  const accounts = await offlineSigner.getAccounts();
  return { address: accounts[0].address };
}

export async function signArbitrary(signer: string, data: string): Promise<Uint8Array> {
  if (!window.keplr) throw new Error('Keplr not installed');
  const result = await window.keplr.signArbitrary(CHAIN_CONFIG.chainId, signer, data);
  // Decode base64 signature to raw bytes
  const binaryString = atob(result.signature);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

/**
 * The message signed to derive the confidential seed. Fixed, so derivation is
 * deterministic: the same Keplr wallet reproduces the same seed on any browser.
 */
const SEED_DERIVATION_MESSAGE =
  'Derive nix confidential spending key\n\nx/confidential/elgamal/v1/0\n\n' +
  'Sign this only on a nix wallet you trust. The signature is your spending key.';

/**
 * Deterministic seed derivation from a Keplr SIGNATURE.
 *
 * The seed must depend on something only the account holder can produce. A
 * signature qualifies; the public key does not.
 *
 * This previously hashed SHA-256(pubKey || salt), which was a complete break of
 * confidentiality: an account's public key is published on chain as soon as it
 * signs anything, and the salt is a constant in this open-source file. Anyone
 * could recompute the seed, run it through the same HKDF the wasm uses, recover
 * the ElGamal secret key, and decrypt that account's entire balance and every
 * transfer it had ever received -- passively, offline, and retroactively.
 *
 * Deriving from a signature costs one Keplr popup per setup. That popup is the
 * security property, not an inconvenience to design around.
 *
 * CAVEAT: this relies on the signature being byte-stable for a fixed message.
 * Cosmos secp256k1 signing is deterministic (RFC 6979), so it is today. But the
 * seed is only reproducible while both that and the ADR-036 sign-doc encoding
 * stay fixed -- if either changes, a user's derived key changes with it. Treat
 * SEED_DERIVATION_MESSAGE as a consensus-critical constant: never edit it, and
 * if key derivation must change, add a new counter/version rather than
 * redefining this one.
 */
export async function deriveDeterministicSeed(signer: string): Promise<Uint8Array> {
  if (!window.keplr) throw new Error('Keplr not installed');
  return signArbitrary(signer, SEED_DERIVATION_MESSAGE);
}

export function getOfflineSigner() {
  if (!window.keplr) throw new Error('Keplr not installed');
  return window.keplr.getOfflineSigner(CHAIN_CONFIG.chainId);
}

// Type declaration for window.keplr
declare global {
  interface Window {
    keplr?: any;
  }
}
