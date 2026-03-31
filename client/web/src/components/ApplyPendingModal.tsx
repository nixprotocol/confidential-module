// src/components/ApplyPendingModal.tsx
import { useState } from 'react';
import { cryptoService } from '@/lib/crypto';
import { chainClient } from '@/lib/chain';
import { loadState, saveState } from '@/lib/state';
import { hexToBytes } from '@/lib/utils';
import { encodeMsgApplyPending } from '@/lib/messages';
import { broadcastMsg } from '@/lib/tx';
import { CHAIN_CONFIG } from '@/lib/config';
import { addFieldElements, ZERO_RANDOMNESS } from '@/lib/fieldMath';
import { TxStatus, type TxStatusState } from './TxStatus';

interface ApplyPendingModalProps {
  address: string;
  denom: string;
  pendingAmount: string;
  onClose: () => void;
  onSuccess: () => void;
}

export function ApplyPendingModal({ address, denom, pendingAmount, onClose, onSuccess }: ApplyPendingModalProps) {
  const [txStatus, setTxStatus] = useState<TxStatusState>('idle');
  const [txHash, setTxHash] = useState<string>();
  const [error, setError] = useState<string>();

  const busy = txStatus !== 'idle' && txStatus !== 'confirmed' && txStatus !== 'failed';

  async function handleApply() {
    setError(undefined);

    try {
      const state = loadState(address);
      if (!state?.seed) throw new Error('Wallet not initialized');

      // Step 1: Fetch the pending ciphertext from chain
      setTxStatus('proving');
      const balance = await chainClient.queryConfidentialBalance(address, denom);
      if (!balance.pending) throw new Error('No pending balance on chain');

      const keyResult = await cryptoService.deriveKey(state.seed, state.counter);
      const skHex: string = keyResult.secretKeyHex;
      const pkHex: string = keyResult.pubkeyHex;

      // Generate apply-pending proof
      const applyResult = await cryptoService.applyPending({
        skHex,
        pkHex,
        pendingCtHex: balance.pending,
        pendingAmount: Number(pendingAmount),
        chainId: CHAIN_CONFIG.chainId,
        sender: address,
        denom,
        availBalanceHex: balance.available || '',
      });

      // Step 2: Build and broadcast with encrypted memo
      setTxStatus('signing');
      const newAvailBytes = hexToBytes(applyResult.newAvailHex);
      const proofBytes = hexToBytes(applyResult.proofHex);

      // Compute memo — applyPending adds to available, so cumulate
      const oldR = state.balances[denom]?.availableRandomness || ZERO_RANDOMNESS;
      const oldAmount = Number(state.balances[denom]?.availableAmount) || 0;
      const newR = addFieldElements(oldR, applyResult.newRandomnessHex);
      const newAmount = oldAmount + Number(pendingAmount);
      const memoResult = await cryptoService.encryptMemo(pkHex, newR, newAmount);
      const memoBytes = hexToBytes(memoResult.encryptedMemoHex);

      // Skip memo on ApplyPending until ignite's proto-gen consistently includes field 5.
      // Shield/send/unshield memos work (those fields are in the original proto).
      const msg = encodeMsgApplyPending(address, denom, newAvailBytes, proofBytes);

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
      s.balances[denom].pendingApplied = true;
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
          <h2 className="text-lg font-semibold text-zinc-100">Apply Pending - {denom}</h2>
          <button onClick={onClose} className="text-zinc-500 hover:text-zinc-300 text-lg">&times;</button>
        </div>

        <div className="rounded-lg bg-zinc-800/50 p-4 space-y-2">
          <p className="text-sm text-zinc-300">
            You have <span className="font-mono text-yellow-400">{pendingAmount} {denom}</span> pending.
          </p>
          <p className="text-xs text-zinc-500">
            Applying pending will merge it into your available balance. This requires a transaction with a proof.
          </p>
        </div>

        <button
          onClick={handleApply}
          disabled={busy}
          className="w-full rounded-lg bg-yellow-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-yellow-500 disabled:opacity-50"
        >
          {busy ? 'Processing...' : 'Apply Pending'}
        </button>

        <TxStatus status={txStatus} txHash={txHash} error={error} />
      </div>
    </div>
  );
}
