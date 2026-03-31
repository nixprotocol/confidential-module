// src/lib/state.ts
export interface DenomBalance {
  availableAmount: string;
  availableRandomness: string;
  pendingApplied: boolean;
}

export interface WalletState {
  address: string;
  seed: string;
  counter: number;
  balances: Record<string, DenomBalance>;
}

const STORAGE_PREFIX = 'confwallet:';

export function loadState(address: string): WalletState | null {
  const raw = localStorage.getItem(STORAGE_PREFIX + address);
  if (!raw) return null;
  return JSON.parse(raw);
}

export function saveState(state: WalletState): void {
  localStorage.setItem(STORAGE_PREFIX + state.address, JSON.stringify(state));
}

export function updateBalance(address: string, denom: string, update: Partial<DenomBalance>): void {
  const state = loadState(address);
  if (!state) return;
  if (!state.balances[denom]) {
    state.balances[denom] = { availableAmount: '0', availableRandomness: '', pendingApplied: true };
  }
  Object.assign(state.balances[denom], update);
  saveState(state);
}

export function clearState(address: string): void {
  localStorage.removeItem(STORAGE_PREFIX + address);
}
