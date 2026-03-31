// src/lib/fieldMath.ts

/** BN254 scalar field order */
const FR_ORDER = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');

/** Add two field elements (hex-encoded, 64-char). Returns 64-char hex. */
export function addFieldElements(aHex: string, bHex: string): string {
  const a = aHex ? BigInt('0x' + aHex) : 0n;
  const b = bHex ? BigInt('0x' + bHex) : 0n;
  const sum = (a + b) % FR_ORDER;
  return sum.toString(16).padStart(64, '0');
}

/** Subtract two field elements (hex-encoded, 64-char). Returns 64-char hex. */
export function subFieldElements(aHex: string, bHex: string): string {
  const a = aHex ? BigInt('0x' + aHex) : 0n;
  const b = bHex ? BigInt('0x' + bHex) : 0n;
  const diff = (a - b + FR_ORDER) % FR_ORDER;
  return diff.toString(16).padStart(64, '0');
}

/** Zero field element as 64-char hex */
export const ZERO_RANDOMNESS = '0'.repeat(64);
