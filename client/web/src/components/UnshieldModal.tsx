// src/components/UnshieldModal.tsx
import { useState } from 'react';
import { cryptoService } from '@/lib/crypto';
import { chainClient } from '@/lib/chain';
import { loadState, saveState } from '@/lib/state';
import { hexToBytes } from '@/lib/utils';
import { encodeMsgUnshield } from '@/lib/messages';
import { broadcastMsg } from '@/lib/tx';
import { CHAIN_CONFIG } from '@/lib/config';
import { TxStatus, type TxStatusState } from './TxStatus';

interface UnshieldModalProps {
  address: string;
  denom: string;
  availableAmount: string;
  onClose: () => void;
  onSuccess: () => void;
}

export function UnshieldModal({ address, denom, availableAmount, onClose, onSuccess }: UnshieldModalProps) {
  const [amount, setAmount] = useState('');
  const [txStatus, setTxStatus] = useState<TxStatusState>('idle');
  const [txHash, setTxHash] = useState<string>();
  const [error, setError] = useState<string>();

  const busy = txStatus !== 'idle' && txStatus !== 'confirmed' && txStatus !== 'failed';

  async function handleUnshield() {
    if (!amount || Number(amount) <= 0) return;
    setError(undefined);

    try {
      const state = loadState(address);
      if (!state?.seed) throw new Error('Wallet not initialized');

      const denomState = state.balances[denom];
      if (!denomState) throw new Error('No balance state for ' + denom);

      // Step 1: Generate proof
      setTxStatus('proving');
      const keyResult = await cryptoService.deriveKey(state.seed, state.counter);
      const skHex: string = keyResult.secretKeyHex;
      const pkHex: string = keyResult.pubkeyHex;

      // Fetch current on-chain available balance for deterministic randomness.
      const onChainBalance = await chainClient.queryConfidentialBalance(address, denom);

      const unshieldResult = await cryptoService.unshield({
        skHex,
        pkHex,
        amount: Number(amount),
        availAmount: Number(denomState.availableAmount),
        availRandomnessHex: denomState.availableRandomness,
        chainId: CHAIN_CONFIG.chainId,
        sender: address,
        denom,
        availBalanceHex: onChainBalance.available || '',
      });

      // Step 2: Build and broadcast
      setTxStatus('signing');
      const ciphertextBytes = hexToBytes(unshieldResult.ciphertextHex || unshieldResult.ciphertext);
      const rangeProofBytes = hexToBytes(unshieldResult.rangeProofHex || unshieldResult.rangeProof);
      const decryptionProofBytes = hexToBytes(unshieldResult.dleqProofHex || unshieldResult.decryptionProof || unshieldResult.decryptionProofHex);

      // Compute memo — WASM returns cumulative randomness for unshield
      const newR = unshieldResult.newAvailRandomnessHex;
      const newAmount = Number(denomState.availableAmount) - Number(amount);
      const memoResult = await cryptoService.encryptMemo(pkHex, newR, newAmount);
      const memoBytes = hexToBytes(memoResult.encryptedMemoHex);

      const msg = encodeMsgUnshield(address, denom, Number(amount), ciphertextBytes, rangeProofBytes, decryptionProofBytes, memoBytes);

      setTxStatus('broadcasting');
      const hash = await broadcastMsg(msg);
      setTxHash(hash);

      // Update local state
      const s = loadState(address)!;
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
          <h2 className="text-lg font-semibold text-zinc-100">Unshield {denom}</h2>
          <button onClick={onClose} className="text-zinc-500 hover:text-zinc-300 text-lg">&times;</button>
        </div>

        <p className="text-xs text-zinc-500">
          Available (confidential): <span className="font-mono">{availableAmount} {denom}</span>
        </p>

        <div>
          <label className="text-xs text-zinc-400 block mb-1">Amount to unshield</label>
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
              onClick={() => setAmount(availableAmount)}
              disabled={busy}
              className="rounded bg-zinc-800 border border-zinc-700 px-3 py-2 text-xs text-zinc-400 hover:text-zinc-200"
            >
              Max
            </button>
          </div>
        </div>

        <button
          onClick={handleUnshield}
          disabled={busy || !amount || Number(amount) <= 0}
          className="w-full rounded-lg bg-blue-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-50"
        >
          {busy ? 'Processing...' : 'Unshield'}
        </button>

        <TxStatus status={txStatus} txHash={txHash} error={error} />
      </div>
    </div>
  );
}
