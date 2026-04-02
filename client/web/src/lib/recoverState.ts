// src/lib/recoverState.ts
// Recovers wallet state (amount + randomness) by replaying chain events.
// This is needed when local state is lost or desynchronized.

import type { Tendermint37Client } from '@cosmjs/tendermint-rpc';
import { toHex, fromHex } from '@cosmjs/encoding';
import { fromBech32 } from '@cosmjs/encoding';
import { addFieldElements, subFieldElements, ZERO_RANDOMNESS } from './fieldMath';

const FR_ORDER = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');

// ─── HKDF-SHA256 (matches Go's hkdf.New exactly) ───────────────────────────

async function hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, data);
  return new Uint8Array(sig);
}

async function hkdfExtract(salt: Uint8Array, ikm: Uint8Array): Promise<Uint8Array> {
  // If salt is empty, use zero-filled salt of hash length (32 bytes)
  const s = salt.length > 0 ? salt : new Uint8Array(32);
  return hmacSha256(s, ikm);
}

async function hkdfExpand(prk: Uint8Array, info: Uint8Array, length: number): Promise<Uint8Array> {
  const hashLen = 32; // SHA-256 output
  const n = Math.ceil(length / hashLen);
  const output = new Uint8Array(n * hashLen);
  let prev = new Uint8Array(0);

  for (let i = 1; i <= n; i++) {
    const input = new Uint8Array(prev.length + info.length + 1);
    input.set(prev, 0);
    input.set(info, prev.length);
    input[prev.length + info.length] = i;
    prev = await hmacSha256(prk, input);
    output.set(prev, (i - 1) * hashLen);
  }

  return output.slice(0, length);
}

// Derive deterministic randomness — matches Go WASM's deriveRandomness exactly
async function deriveRandomness(skHex: string, chainId: string, denom: string, availBalanceHex: string, opType: string): Promise<string> {
  const skBytes = fromHex(skHex);
  const salt = availBalanceHex ? fromHex(availBalanceHex) : new Uint8Array(0);
  const infoStr = `${chainId}/${denom}/${opType}`;
  const info = new TextEncoder().encode(infoStr);

  const prk = await hkdfExtract(salt, skBytes);
  const buf = await hkdfExpand(prk, info, 64);

  // Convert 64 bytes to field element (big-endian BigInt mod FR_ORDER)
  let val = 0n;
  for (let i = 0; i < 64; i++) {
    val = (val << 8n) | BigInt(buf[i]);
  }
  val = val % FR_ORDER;
  return val.toString(16).padStart(64, '0');
}

// ─── Store key builder ──────────────────────────────────────────────────────

function buildAvailKey(address: string, denom: string): Uint8Array {
  const addrBytes = fromBech32(address).data;
  const denomBytes = new TextEncoder().encode(denom);
  const prefix = new TextEncoder().encode('confidential/ab/');
  const key = new Uint8Array(prefix.length + addrBytes.length + 1 + denomBytes.length);
  key.set(prefix, 0);
  key.set(addrBytes, prefix.length);
  key[prefix.length + addrBytes.length] = 0x2F;
  key.set(denomBytes, prefix.length + addrBytes.length + 1);
  return key;
}

// ─── Query chain state at a specific height ─────────────────────────────────

async function queryBalanceAtHeight(tmClient: Tendermint37Client, address: string, denom: string, height: number): Promise<string> {
  const key = buildAvailKey(address, denom);
  const result = await tmClient.abciQuery({ path: '/store/confidential/key', data: key, height });
  if (!result.value || result.value.length === 0) return '';
  return toHex(result.value);
}

// ─── Event types and their randomness effect ────────────────────────────────

interface ChainEvent {
  type: string;
  height: number;
  attrs: Record<string, string>;
}

// ─── Main recovery function ─────────────────────────────────────────────────

export async function recoverState(
  tmClient: Tendermint37Client,
  address: string,
  skHex: string,
  chainId: string,
  denom: string,
): Promise<{ amount: number; randomness: string } | null> {

  // 1. Gather all events for this address+denom
  const events: ChainEvent[] = [];

  const eventTypes = ['shield', 'unshield', 'confidential_send', 'apply_pending'];
  for (const eventType of eventTypes) {
    // Events as sender
    try {
      const query = `${eventType}.sender='${address}'`;
      const result = await tmClient.txSearch({ query, order_by: 'asc', per_page: 50, page: 1 });
      for (const tx of result.txs) {
        if (tx.result.code !== 0) continue; // skip failed txs
        for (const event of tx.result.events) {
          if (event.type !== eventType) continue;
          const attrs: Record<string, string> = {};
          for (const attr of event.attributes) {
            attrs[attr.key] = attr.value;
          }
          if (attrs['denom'] === denom) {
            events.push({ type: eventType, height: tx.height, attrs });
          }
        }
      }
    } catch (e) {
      console.warn(`Failed to query ${eventType} events:`, e);
    }
  }

  if (events.length === 0) return null;

  // Sort by height ascending
  events.sort((a, b) => a.height - b.height);

  // 2. Replay events, deriving randomness at each step
  let cumulativeR = ZERO_RANDOMNESS;
  let cumulativeAmount = 0;


  for (const event of events) {
    // Query balance BEFORE this event (height - 1)
    const balHex = await queryBalanceAtHeight(tmClient, address, denom, event.height - 1);

    switch (event.type) {
      case 'shield': {
        const amount = Number(event.attrs['amount'] || '0');
        const r = await deriveRandomness(skHex, chainId, denom, balHex, 'shield');
        cumulativeR = addFieldElements(cumulativeR, r);
        cumulativeAmount += amount;
        break;
      }
      case 'confidential_send': {
        if (event.attrs['sender'] !== address) break;
        const rSender = await deriveRandomness(skHex, chainId, denom, balHex, 'send/sender');
        cumulativeR = subFieldElements(cumulativeR, rSender);
        break;
      }
      case 'unshield': {
        const amount = Number(event.attrs['amount'] || '0');
        const r = await deriveRandomness(skHex, chainId, denom, balHex, 'unshield');
        cumulativeR = subFieldElements(cumulativeR, r);
        cumulativeAmount -= amount;
        break;
      }
      case 'apply_pending': {
        const r = await deriveRandomness(skHex, chainId, denom, balHex, 'apply_pending');
        cumulativeR = addFieldElements(cumulativeR, r);
        break;
      }
    }
  }

  return { amount: cumulativeAmount, randomness: cumulativeR };
}
