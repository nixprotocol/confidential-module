// src/lib/syncFromChain.ts
import type { Tendermint37Client } from '@cosmjs/tendermint-rpc';
import { cryptoService } from './crypto';

export interface RecoveredDenomState {
  availableAmount: string;
  availableRandomness: string;
  blockHeight: number;
  stale: boolean;
}

export interface RecoveredState {
  [denom: string]: RecoveredDenomState;
}

const EVENT_TYPES = ['shield', 'unshield', 'confidential_send', 'apply_pending'];

/**
 * Scan chain events to recover wallet state (randomness + amount) per denom.
 * Only needs the user's ElGamal private key to decrypt the memos.
 */
export async function syncFromChain(
  tmClient: Tendermint37Client,
  address: string,
  skHex: string,
  denoms: string[],
): Promise<RecoveredState> {
  const recovered: RecoveredState = {};
  // Track max block height per denom across ALL events (for staleness check)
  const maxHeight: Record<string, number> = {};

  for (const eventType of EVENT_TYPES) {
    try {
      const query = `${eventType}.sender='${address}'`;
      const result = await tmClient.txSearch({
        query,
        order_by: 'desc',
        per_page: 20,
        page: 1,
      });

      for (const tx of result.txs) {
        const height = tx.height;

        for (const event of tx.result.events) {
          if (event.type !== eventType) continue;

          const attrs: Record<string, string> = {};
          for (const attr of event.attributes) {
            attrs[attr.key] = attr.value;
          }

          const denom = attrs['denom'];
          if (!denom || !denoms.includes(denom)) continue;

          // Track max height per denom for staleness
          if (!maxHeight[denom] || height > maxHeight[denom]) {
            maxHeight[denom] = height;
          }

          const memoHex = attrs['encrypted_memo'];
          if (!memoHex) continue;

          // Only keep the latest memo per denom (results are desc by height)
          if (recovered[denom]) continue;

          try {
            const decrypted = await cryptoService.decryptMemo(skHex, memoHex);
            recovered[denom] = {
              availableAmount: String(decrypted.amount),
              availableRandomness: decrypted.randomnessHex,
              blockHeight: height,
              stale: false,
            };
          } catch (e) {
            console.warn(`Failed to decrypt memo at height ${height} for ${denom}:`, e);
          }
        }
      }
    } catch (e) {
      console.warn(`Failed to query ${eventType} events:`, e);
    }
  }

  // Staleness check: if any tx for this denom is newer than the memo tx
  for (const denom of Object.keys(recovered)) {
    if (maxHeight[denom] && maxHeight[denom] > recovered[denom].blockHeight) {
      recovered[denom].stale = true;
    }
  }

  return recovered;
}
