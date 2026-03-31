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
                 { coinDenom: 'STAKE', coinMinimalDenom: 'stake', coinDecimals: 0 }],
    feeCurrencies: [{ coinDenom: 'STAKE', coinMinimalDenom: 'stake', coinDecimals: 0,
      gasPriceStep: { low: 0.01, average: 0.025, high: 0.03 } }],
    stakeCurrency: { coinDenom: 'STAKE', coinMinimalDenom: 'stake', coinDecimals: 0 },
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
 * Deterministic seed derivation from Keplr's public key.
 * Uses SHA-256(pubKey || salt) to derive a seed. This is deterministic:
 * same Keplr wallet = same pubKey = same seed on any browser.
 * No signing popup required — getKey() is non-interactive.
 */
export async function deriveDeterministicSeed(signer: string): Promise<Uint8Array> {
  if (!window.keplr) throw new Error('Keplr not installed');

  // Get the Keplr key (no popup, deterministic per wallet)
  const key = await window.keplr.getKey(CHAIN_CONFIG.chainId);
  const pubKeyBytes = key.pubKey; // Uint8Array

  // Derive seed: SHA-256(pubKey || "x/confidential/elgamal/v1/0")
  const salt = new TextEncoder().encode('x/confidential/elgamal/v1/0');
  const input = new Uint8Array(pubKeyBytes.length + salt.length);
  input.set(pubKeyBytes, 0);
  input.set(salt, pubKeyBytes.length);

  const hashBuffer = await crypto.subtle.digest('SHA-256', input);
  return new Uint8Array(hashBuffer);
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
