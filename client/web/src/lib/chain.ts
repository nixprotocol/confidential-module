// src/lib/chain.ts
import { StargateClient } from '@cosmjs/stargate';
import { Tendermint37Client } from '@cosmjs/tendermint-rpc';
import { toHex, fromBech32 } from '@cosmjs/encoding';
import { CHAIN_CONFIG } from './config';

/**
 * Minimal protobuf decoder for the Params message.
 *
 * Proto layout:
 *   bytes  auditor_pub_key   = 1;
 *   int32  max_transfer_bits = 6;
 *
 * We only need auditor_pub_key (field 1, wire type 2 = length-delimited)
 * and max_transfer_bits (field 6, wire type 0 = varint).
 */
function decodeParams(data: Uint8Array): { auditorPubKey: Uint8Array | null; maxTransferBits: number } {
  let offset = 0;
  let auditorPubKey: Uint8Array | null = null;
  let maxTransferBits = 64;

  while (offset < data.length) {
    // Read tag (varint)
    let tag = 0;
    let shift = 0;
    while (offset < data.length) {
      const b = data[offset++];
      tag |= (b & 0x7f) << shift;
      if ((b & 0x80) === 0) break;
      shift += 7;
    }

    const fieldNumber = tag >>> 3;
    const wireType = tag & 0x07;

    if (wireType === 0) {
      // Varint
      let value = 0;
      shift = 0;
      while (offset < data.length) {
        const b = data[offset++];
        value |= (b & 0x7f) << shift;
        if ((b & 0x80) === 0) break;
        shift += 7;
      }
      if (fieldNumber === 6) maxTransferBits = value;
    } else if (wireType === 2) {
      // Length-delimited
      let length = 0;
      shift = 0;
      while (offset < data.length) {
        const b = data[offset++];
        length |= (b & 0x7f) << shift;
        if ((b & 0x80) === 0) break;
        shift += 7;
      }
      const fieldData = data.slice(offset, offset + length);
      offset += length;
      if (fieldNumber === 1) auditorPubKey = fieldData;
    } else {
      // Unknown wire type — skip (best-effort)
      break;
    }
  }

  return { auditorPubKey, maxTransferBits };
}

export class ChainClient {
  private client: StargateClient | null = null;
  private tmClient: Tendermint37Client | null = null;

  async connect(): Promise<void> {
    this.tmClient = await Tendermint37Client.connect(CHAIN_CONFIG.rpc);
    this.client = await StargateClient.create(this.tmClient);
  }

  getTmClient(): Tendermint37Client | null {
    return this.tmClient;
  }

  async queryBankBalance(address: string, denom: string): Promise<string> {
    if (!this.client) throw new Error('Not connected');
    const balance = await this.client.getBalance(address, denom);
    return balance.amount;
  }

  // Direct store query via ABCI
  private async queryStore(key: Uint8Array): Promise<Uint8Array | null> {
    if (!this.tmClient) throw new Error('Not connected');
    const result = await this.tmClient.abciQuery({
      path: '/store/confidential/key',
      data: key,
    });
    if (!result.value || result.value.length === 0) return null;
    return result.value;
  }

  async queryConfidentialBalance(address: string, denom: string): Promise<{ available: string | null, pending: string | null }> {
    // Build store keys matching confidential-module/types/keys.go
    // Keys use raw address bytes (not hex), format: prefix + rawAddr + "/" + denom
    const addrBytes = fromBech32(address).data;
    const denomBytes = new TextEncoder().encode(denom);

    const availPrefix = new TextEncoder().encode('confidential/ab/');
    const availKey = new Uint8Array(availPrefix.length + addrBytes.length + 1 + denomBytes.length);
    availKey.set(availPrefix, 0);
    availKey.set(addrBytes, availPrefix.length);
    availKey[availPrefix.length + addrBytes.length] = 0x2F; // "/"
    availKey.set(denomBytes, availPrefix.length + addrBytes.length + 1);

    const pendPrefix = new TextEncoder().encode('confidential/pb/');
    const pendKey = new Uint8Array(pendPrefix.length + addrBytes.length + 1 + denomBytes.length);
    pendKey.set(pendPrefix, 0);
    pendKey.set(addrBytes, pendPrefix.length);
    pendKey[pendPrefix.length + addrBytes.length] = 0x2F; // "/"
    pendKey.set(denomBytes, pendPrefix.length + addrBytes.length + 1);

    const avail = await this.queryStore(availKey);
    const pend = await this.queryStore(pendKey);

    return {
      available: avail ? toHex(avail) : null,
      pending: pend ? toHex(pend) : null,
    };
  }

  async queryAccountInfo(address: string): Promise<{ pubkey: string | null, registered: boolean }> {
    const addrBytes = fromBech32(address).data;
    const pkPrefix = new TextEncoder().encode('confidential/pk/');
    const pkKey = new Uint8Array(pkPrefix.length + addrBytes.length);
    pkKey.set(pkPrefix, 0);
    pkKey.set(addrBytes, pkPrefix.length);
    const pk = await this.queryStore(pkKey);
    return {
      pubkey: pk ? toHex(pk) : null,
      registered: pk !== null,
    };
  }

  async queryAuditorKey(): Promise<string | null> {
    const result = await this.queryStore(new TextEncoder().encode('confidential/params'));
    if (!result) return null;
    try {
      const params = decodeParams(result);
      if (params.auditorPubKey && params.auditorPubKey.length === 64) {
        return toHex(params.auditorPubKey);
      }
    } catch { /* ignore decode errors */ }
    return null;
  }

  async queryParams(): Promise<{ auditorPubKey: string | null; maxTransferBits: number } | null> {
    const result = await this.queryStore(new TextEncoder().encode('confidential/params'));
    if (!result) return null;
    const params = decodeParams(result);
    return {
      auditorPubKey: params.auditorPubKey ? toHex(params.auditorPubKey) : null,
      maxTransferBits: params.maxTransferBits,
    };
  }

  async broadcastTx(signedTxBytes: Uint8Array): Promise<string> {
    if (!this.tmClient) throw new Error('Not connected');
    const result = await this.tmClient.broadcastTxSync({ tx: signedTxBytes });
    return toHex(result.hash).toUpperCase();
  }
}

export const chainClient = new ChainClient();
