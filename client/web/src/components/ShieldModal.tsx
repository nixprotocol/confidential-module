// src/components/ShieldModal.tsx
import { useState } from 'react';
import { cryptoService } from '@/lib/crypto';
import { chainClient } from '@/lib/chain';
import { loadState, saveState } from '@/lib/state';
import { hexToBytes } from '@/lib/utils';
import { encodeMsgShield } from '@/lib/messages';
import { broadcastMsg } from '@/lib/tx';
import { CHAIN_CONFIG } from '@/lib/config';
import { addFieldElements, ZERO_RANDOMNESS } from '@/lib/fieldMath';
import { TxStatus, type TxStatusState } from './TxStatus';

interface ShieldModalProps {
  address: string;
  denom: string;
  publicBalance: string;
  onClose: () => void;
  onSuccess: () => void;
}

export function ShieldModal({ address, denom, publicBalance, onClose, onSuccess }: ShieldModalProps) {
  const [amount, setAmount] = useState('');
  const [txStatus, setTxStatus] = useState<TxStatusState>('idle');
  const [txHash, setTxHash] = useState<string>();
  const [error, setError] = useState<string>();

  const busy = txStatus !== 'idle' && txStatus !== 'confirmed' && txStatus !== 'failed';

  async function handleShield() {
    if (!amount || Number(amount) <= 0) return;
    setError(undefined);

    try {
      const state = loadState(address);
      if (!state?.seed) throw new Error('Wallet not initialized');

      // Step 1: Generate proof via WASM
      setTxStatus('proving');
      const keyResult = await cryptoService.deriveKey(state.seed, state.counter);
      const skHex: string = keyResult.secretKeyHex;
      const pkHex: string = keyResult.pubkeyHex;

      // Fetch current on-chain available balance for deterministic randomness.
      const onChainBalance = await chainClient.queryConfidentialBalance(address, denom);

      const shieldResult = await cryptoService.shield({
        skHex,
        pkHex,
        amount: Number(amount),
        chainId: CHAIN_CONFIG.chainId,
        sender: address,
        denom,
        availBalanceHex: onChainBalance.available || '',
      });

      // Step 2: Build and broadcast tx with encrypted memo
      setTxStatus('signing');
      const ciphertextBytes = hexToBytes(shieldResult.ciphertextHex);
      const proofBytes = hexToBytes(shieldResult.proofHex);

      // Compute cumulative state for memo (reuse pkHex from above)
      const oldR = state.balances[denom]?.availableRandomness || ZERO_RANDOMNESS;
      const oldAmount = Number(state.balances[denom]?.availableAmount) || 0;
      const newR = addFieldElements(oldR, shieldResult.randomnessHex);
      const newAmount = oldAmount + Number(amount);

      // Encrypt memo under user's pk
      const memoResult = await cryptoService.encryptMemo(pkHex, newR, newAmount);
      const memoBytes = hexToBytes(memoResult.encryptedMemoHex);

      const msg = encodeMsgShield(address, denom, Number(amount), ciphertextBytes, proofBytes, memoBytes);

      setTxStatus('broadcasting');
      const hash = await broadcastMsg(msg);
      setTxHash(hash);

      // Update local state
      const s = loadState(address)!;
      if (!s.balances[denom]) {
        s.balances[denom] = { availableAmount: '0', availableRandomness: '', pendingApplied: true };
      }
      s.balances[denom].availableAmount = String(newAmount);
      s.balances[denom].availableRandomness = newR;
      saveState(s);

      setTxStatus('confirmed');
      setTimeout(() => onSuccess(), 1500);
    } catch (e: any) {
      setError(e.message || String(e));
      setTxStatus('failed');
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={onClose}>
      <div className="w-full max-w-sm rounded-lg bg-zinc-900 border border-zinc-800 p-6 space-y-4" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-zinc-100">Shield {denom}</h2>
          <button onClick={onClose} className="text-zinc-500 hover:text-zinc-300 text-lg">&times;</button>
        </div>

        <p className="text-xs text-zinc-500">
          Public balance: <span className="font-mono">{publicBalance} {denom}</span>
        </p>

        <div>
          <label className="text-xs text-zinc-400 block mb-1">Amount</label>
          <div className="flex gap-2">
            <input
              type="number"
              value={amount}
              onChange={(e) => setAmount(e.target.value)}
              placeholder="0"
              disabled={busy}
              className="flex-1 rounded bg-zinc-800 border border-zinc-700 px-3 py-2 text-sm font-mono text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:border-blue-500"
            />
            <button
              onClick={() => setAmount(publicBalance)}
              disabled={busy}
              className="rounded bg-zinc-800 border border-zinc-700 px-3 py-2 text-xs text-zinc-400 hover:text-zinc-200"
            >
              Max
            </button>
          </div>
        </div>

        <button
          onClick={handleShield}
          disabled={busy || !amount || Number(amount) <= 0}
          className="w-full rounded-lg bg-blue-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-50"
        >
          {busy ? 'Processing...' : 'Shield'}
        </button>

        <TxStatus status={txStatus} txHash={txHash} error={error} />
      </div>
    </div>
  );
}
