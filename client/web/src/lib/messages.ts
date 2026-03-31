// src/lib/messages.ts
// Hand-rolled protobuf encoders for confidential module message types.
// Each function returns { typeUrl, value } where value is pre-encoded protobuf bytes.

/** Encode a varint (unsigned) */
function encodeVarint(n: number): number[] {
  const bytes: number[] = [];
  while (n > 0x7f) {
    bytes.push((n & 0x7f) | 0x80);
    n >>>= 7;
  }
  bytes.push(n & 0x7f);
  return bytes;
}

/** Encode a string field: tag + length + utf8 bytes */
function encodeString(fieldNumber: number, value: string): Uint8Array {
  const tag = (fieldNumber << 3) | 2; // wire type 2 = length-delimited
  const strBytes = new TextEncoder().encode(value);
  return new Uint8Array([...encodeVarint(tag), ...encodeVarint(strBytes.length), ...strBytes]);
}

/** Encode a bytes field: tag + length + raw bytes */
function encodeBytes(fieldNumber: number, value: Uint8Array): Uint8Array {
  const tag = (fieldNumber << 3) | 2;
  return new Uint8Array([...encodeVarint(tag), ...encodeVarint(value.length), ...value]);
}

/** Encode a uint32/uint64 varint field */
function encodeUint(fieldNumber: number, value: number): Uint8Array {
  if (value === 0) return new Uint8Array(0); // default value, omit
  const tag = (fieldNumber << 3) | 0; // wire type 0 = varint
  return new Uint8Array([...encodeVarint(tag), ...encodeVarint(value)]);
}

/** Concatenate multiple Uint8Arrays */
function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, p) => sum + p.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    result.set(p, offset);
    offset += p.length;
  }
  return result;
}

export interface EncodedMsg {
  typeUrl: string;
  value: Uint8Array;
}

/**
 * MsgRegisterKey
 * Field 1: sender (string)
 * Field 2: pubkey (bytes)
 */
export function encodeMsgRegisterKey(sender: string, pubkey: Uint8Array): EncodedMsg {
  return {
    typeUrl: '/nixprotocol.confidential.v1.MsgRegisterKey',
    value: concat(
      encodeString(1, sender),
      encodeBytes(2, pubkey),
    ),
  };
}

/**
 * MsgShield
 * Field 1: sender (string)
 * Field 2: denom (string)
 * Field 3: amount (uint64)
 * Field 4: ciphertext (bytes) — encrypted balance update
 * Field 5: proof (bytes) — range proof / shield proof
 */
export function encodeMsgShield(
  sender: string,
  denom: string,
  amount: number,
  ciphertext: Uint8Array,
  proof: Uint8Array,
  encryptedMemo?: Uint8Array,
): EncodedMsg {
  const parts = [
    encodeString(1, sender),
    encodeString(2, denom),
    encodeString(3, String(amount)),
    encodeBytes(4, ciphertext),
    encodeBytes(5, proof),
  ];
  if (encryptedMemo && encryptedMemo.length > 0) {
    parts.push(encodeBytes(6, encryptedMemo));
  }
  return {
    typeUrl: '/nixprotocol.confidential.v1.MsgShield',
    value: concat(...parts),
  };
}

/**
 * MsgConfidentialSend
 * Field 1: sender (string)
 * Field 2: receiver (string)
 * Field 3: denom (string)
 * Field 4: sender_update (bytes) — updated sender ciphertext
 * Field 5: receiver_update (bytes) — updated receiver ciphertext
 * Field 6: auditor_update (bytes) — auditor ciphertext
 * Field 7: range_proof (bytes)
 * Field 8: equality_proof (bytes)
 */
export function encodeMsgConfidentialSend(
  sender: string,
  receiver: string,
  denom: string,
  senderUpdate: Uint8Array,
  receiverUpdate: Uint8Array,
  auditorUpdate: Uint8Array,
  rangeProof: Uint8Array,
  equalityProof: Uint8Array,
  encryptedMemo?: Uint8Array,
): EncodedMsg {
  const parts = [
    encodeString(1, sender),
    encodeString(2, receiver),
    encodeString(3, denom),
    encodeBytes(4, senderUpdate),
    encodeBytes(5, receiverUpdate),
    encodeBytes(6, auditorUpdate),
    encodeBytes(7, rangeProof),
    encodeBytes(8, equalityProof),
  ];
  if (encryptedMemo && encryptedMemo.length > 0) {
    parts.push(encodeBytes(10, encryptedMemo));
  }
  return {
    typeUrl: '/nixprotocol.confidential.v1.MsgConfidentialSend',
    value: concat(...parts),
  };
}

/**
 * MsgApplyPending
 * Field 1: sender (string)
 * Field 2: denom (string)
 * Field 3: new_available_update (bytes) — merged available ciphertext
 * Field 4: proof (bytes) — correctness proof
 */
export function encodeMsgApplyPending(
  sender: string,
  denom: string,
  newAvailableUpdate: Uint8Array,
  proof: Uint8Array,
  encryptedMemo?: Uint8Array,
): EncodedMsg {
  const parts = [
    encodeString(1, sender),
    encodeString(2, denom),
    encodeBytes(3, newAvailableUpdate),
    encodeBytes(4, proof),
  ];
  if (encryptedMemo && encryptedMemo.length > 0) {
    parts.push(encodeBytes(5, encryptedMemo));
  }
  return {
    typeUrl: '/nixprotocol.confidential.v1.MsgApplyPending',
    value: concat(...parts),
  };
}

/**
 * MsgUnshield
 * Field 1: sender (string)
 * Field 2: denom (string)
 * Field 3: amount (uint64)
 * Field 4: ciphertext (bytes) — updated balance ciphertext
 * Field 5: range_proof (bytes)
 * Field 6: decryption_proof (bytes)
 */
export function encodeMsgUnshield(
  sender: string,
  denom: string,
  amount: number,
  ciphertext: Uint8Array,
  rangeProof: Uint8Array,
  decryptionProof: Uint8Array,
  encryptedMemo?: Uint8Array,
): EncodedMsg {
  const parts = [
    encodeString(1, sender),
    encodeString(2, denom),
    encodeString(3, String(amount)),
    encodeBytes(4, ciphertext),
    encodeBytes(5, rangeProof),
    encodeBytes(6, decryptionProof),
  ];
  if (encryptedMemo && encryptedMemo.length > 0) {
    parts.push(encodeBytes(7, encryptedMemo));
  }
  return {
    typeUrl: '/nixprotocol.confidential.v1.MsgUnshield',
    value: concat(...parts),
  };
}
