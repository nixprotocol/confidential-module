// src/components/PendingPanel.tsx
import { useState } from 'react';
import { toast } from 'sonner';
import { cryptoService } from '@/lib/crypto';
import { chainClient } from '@/lib/chain';
import { loadState, saveState } from '@/lib/state';
import { hexToBytes } from '@/lib/utils';
import { encodeMsgApplyPending } from '@/lib/messages';
import { broadcastMsg } from '@/lib/tx';
import { CHAIN_CONFIG } from '@/lib/config';
import { addFieldElements, ZERO_RANDOMNESS } from '@/lib/fieldMath';
import { TokenSelect } from './TokenSelect';
import { Inbox } from 'lucide-react';

interface DenomBalances {
  publicBalance: string | null;
  availableAmount: string | null;
  pendingAmount: string | null;
}

interface PendingPanelProps {
  address: string;
  denoms: string[];
  selectedDenom: string;
  onDenomChange: (denom: string) => void;
  denomData: Record<string, DenomBalances>;
  onSuccess: () => void;
}

export function PendingPanel({ address, denoms, selectedDenom, onDenomChange, denomData, onSuccess }: PendingPanelProps) {
  const [busy, setBusy] = useState(false);

  const data = denomData[selectedDenom] ?? { publicBalance: null, availableAmount: null, pendingAmount: null };
  const hasPending = data.pendingAmount !== null && data.pendingAmount !== '0';

  async function handleApply() {
    const toastId = toast.loading('Generating proof...');
    setBusy(true);

    try {
      const state = loadState(address);
      if (!state?.seed) throw new Error('Wallet not initialized');

      const balance = await chainClient.queryConfidentialBalance(address, selectedDenom);
      if (!balance.pending) throw new Error('No pending balance on chain');

      const keyResult = await cryptoService.deriveKey(state.seed, state.counter);
      const skHex: string = keyResult.secretKeyHex;
      const pkHex: string = keyResult.pubkeyHex;

      const applyResult = await cryptoService.applyPending({
        skHex,
        pkHex,
        pendingCtHex: balance.pending,
        pendingAmount: Number(data.pendingAmount),
        chainId: CHAIN_CONFIG.chainId,
        sender: address,
        denom: selectedDenom,
        availBalanceHex: balance.available || '',
      });

      toast.loading('Sign in Keplr...', { id: toastId });
      const newAvailBytes = hexToBytes(applyResult.newAvailHex);
      const proofBytes = hexToBytes(applyResult.proofHex);

      const oldR = state.balances[selectedDenom]?.availableRandomness || ZERO_RANDOMNESS;
      const oldAmount = Number(state.balances[selectedDenom]?.availableAmount) || 0;
      const newR = addFieldElements(oldR, applyResult.newRandomnessHex);
      const newAmount = oldAmount + Number(data.pendingAmount);
      const memoResult = await cryptoService.encryptMemo(pkHex, newR, newAmount);
      const memoBytes = hexToBytes(memoResult.encryptedMemoHex);

      const msg = encodeMsgApplyPending(address, selectedDenom, newAvailBytes, proofBytes);

      toast.loading('Broadcasting...', { id: toastId });
      const hash = await broadcastMsg(msg);

      const s = loadState(address)!;
      if (!s.balances[selectedDenom]) {
        s.balances[selectedDenom] = { availableAmount: '0', availableRandomness: '', pendingApplied: true };
      }
      s.balances[selectedDenom].availableAmount = String(newAmount);
      s.balances[selectedDenom].availableRandomness = newR;
      s.balances[selectedDenom].pendingApplied = true;
      saveState(s);

      toast.success('Pending applied', { id: toastId, description: `TX: ${hash.slice(0, 8)}...${hash.slice(-4)}` });
      onSuccess();
    } catch (e: any) {
      toast.error('Apply pending failed', { id: toastId, description: e.message || String(e) });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-4">
      <TokenSelect
        denoms={denoms}
        selectedDenom={selectedDenom}
        onSelect={onDenomChange}
        denomData={denomData}
      />

      {hasPending ? (
        <>
          <div className="rounded-lg bg-zinc-800/50 p-4 space-y-2">
            <p className="text-sm text-zinc-300">
              You have <span className="font-mono text-yellow-400">{data.pendingAmount} {selectedDenom}</span> pending.
            </p>
            <p className="text-xs text-zinc-500">
              Applying pending will merge it into your available balance. This requires a transaction with a proof.
            </p>
          </div>

          <button
            onClick={handleApply}
            disabled={busy}
            className="w-full rounded-lg bg-yellow-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-yellow-500 disabled:opacity-50 transition-colors"
          >
            {busy ? 'Processing...' : 'Apply Pending'}
          </button>
        </>
      ) : (
        <div className="flex flex-col items-center gap-3 py-8 text-zinc-500">
          <Inbox className="h-10 w-10" />
          <p className="text-sm">No pending transfers</p>
        </div>
      )}
    </div>
  );
}
