// src/lib/tx.ts
// Transaction broadcasting via CosmJS with a custom registry passthrough.
// Our messages are pre-encoded as protobuf bytes in messages.ts, so we use
// a registry trick to pass them through without CosmJS re-encoding.

import { SigningStargateClient } from '@cosmjs/stargate';
import { Registry } from '@cosmjs/proto-signing';
import { getOfflineSigner } from './keplr';
import { CHAIN_CONFIG } from './config';
import type { EncodedMsg } from './messages';

// Passthrough type that returns pre-encoded bytes
function makePassthrough() {
  return {
    encode: (msg: any) => ({
      finish: () => msg.__rawBytes ?? new Uint8Array(0),
    }),
    decode: () => ({}),
    fromPartial: (obj: any) => obj,
  } as any;
}

// All our custom type URLs
const TYPE_URLS = [
  '/nixprotocol.confidential.v1.MsgRegisterKey',
  '/nixprotocol.confidential.v1.MsgShield',
  '/nixprotocol.confidential.v1.MsgConfidentialSend',
  '/nixprotocol.confidential.v1.MsgApplyPending',
  '/nixprotocol.confidential.v1.MsgUnshield',
];

function createRegistry(): Registry {
  const registry = new Registry();
  for (const url of TYPE_URLS) {
    registry.register(url, makePassthrough());
  }
  return registry;
}

/**
 * Broadcast a pre-encoded protobuf message via CosmJS + Keplr signer.
 * Returns the transaction hash on success, throws on failure.
 */
export async function broadcastMsg(msg: EncodedMsg): Promise<string> {
  const signer = getOfflineSigner();
  const registry = createRegistry();

  const client = await SigningStargateClient.connectWithSigner(
    CHAIN_CONFIG.rpc,
    signer,
    { registry },
  );

  const accounts = await signer.getAccounts();
  const address = accounts[0].address;

  const encodeObject = {
    typeUrl: msg.typeUrl,
    value: { __rawBytes: msg.value },
  };

  const fee = {
    amount: [{ denom: 'stake', amount: '500' }],
    gas: '900000',
  };

  const result = await client.signAndBroadcast(address, [encodeObject], fee, '');

  if (result.code !== 0) {
    throw new Error(`Tx failed (code ${result.code}): ${result.rawLog}`);
  }

  return result.transactionHash;
}
