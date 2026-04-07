// src/components/ShieldPanel.tsx
import { useState } from 'react';
import { toast } from 'sonner';
import { cryptoService } from '@/lib/crypto';
import { chainClient } from '@/lib/chain';
import { loadState, saveState } from '@/lib/state';
import { hexToBytes } from '@/lib/utils';
import { encodeMsgShield } from '@/lib/messages';
import { broadcastMsg } from '@/lib/tx';
import { CHAIN_CONFIG } from '@/lib/config';
import { addFieldElements, ZERO_RANDOMNESS } from '@/lib/fieldMath';
import { TokenSelect } from './TokenSelect';

interface DenomBalances {
  publicBalance: string | null;
  availableAmount: string | null;
  pendingAmount: string | null;
  synced: boolean;
}

interface ShieldPanelProps {
  address: string;
  denoms: string[];
  selectedDenom: string;
  onDenomChange: (denom: string) => void;
  denomData: Record<string, DenomBalances>;
  onSuccess: () => void;
}

export function ShieldPanel({ address, denoms, selectedDenom, onDenomChange, denomData, onSuccess }: ShieldPanelProps) {
  const [amount, setAmount] = useState('');
  const [busy, setBusy] = useState(false);

  const data = denomData[selectedDenom] ?? { publicBalance: null, availableAmount: null, pendingAmount: null, synced: true };
  // If chain already has a confidential balance but local randomness is missing,
  // shielding would start from ZERO_RANDOMNESS and create a new desync. Block it
  // and direct the user to Repair State instead.
  const localR = loadState(address)?.balances[selectedDenom]?.availableRandomness;
  const blockedByDesync = !localR && Number(data.availableAmount) > 0;

  async function handleShield() {
    if (!amount || Number(amount) <= 0) return;

    const toastId = toast.loading('Generating proof...');
    setBusy(true);

    try {
      const state = loadState(address);
      if (!state?.seed) throw new Error('Wallet not initialized');

      const keyResult = await cryptoService.deriveKey(state.seed, state.counter);
      const skHex: string = keyResult.secretKeyHex;
      const pkHex: string = keyResult.pubkeyHex;

      const onChainBalance = await chainClient.queryConfidentialBalance(address, selectedDenom);

      const shieldResult = await cryptoService.shield({
        skHex,
        pkHex,
        amount: Number(amount),
        chainId: CHAIN_CONFIG.chainId,
        sender: address,
        denom: selectedDenom,
        availBalanceHex: onChainBalance.available || '',
      });

      toast.loading('Sign in Keplr...', { id: toastId });
      const ciphertextBytes = hexToBytes(shieldResult.ciphertextHex);
      const proofBytes = hexToBytes(shieldResult.proofHex);

      const oldR = state.balances[selectedDenom]?.availableRandomness || ZERO_RANDOMNESS;
      const oldAmount = Number(state.balances[selectedDenom]?.availableAmount) || 0;
      const newR = addFieldElements(oldR, shieldResult.randomnessHex);
      const newAmount = oldAmount + Number(amount);

      const memoResult = await cryptoService.encryptMemo(pkHex, newR, newAmount);
      const memoBytes = hexToBytes(memoResult.encryptedMemoHex);

      const msg = encodeMsgShield(address, selectedDenom, Number(amount), ciphertextBytes, proofBytes, memoBytes);

      toast.loading('Broadcasting...', { id: toastId });
      const hash = await broadcastMsg(msg);

      const s = loadState(address)!;
      if (!s.balances[selectedDenom]) {
        s.balances[selectedDenom] = { availableAmount: '0', availableRandomness: '', pendingApplied: true };
      }
      s.balances[selectedDenom].availableAmount = String(newAmount);
      s.balances[selectedDenom].availableRandomness = newR;
      saveState(s);

      toast.success('Shield confirmed', { id: toastId, description: `TX: ${hash.slice(0, 8)}...${hash.slice(-4)}` });
      setAmount('');
      onSuccess();
    } catch (e: any) {
      toast.error('Shield failed', { id: toastId, description: e.message || String(e) });
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

      <div>
        <label className="text-xs text-zinc-500 uppercase tracking-wide block mb-1">Amount</label>
        <div className="flex gap-2">
          <input
            type="number"
            value={amount}
            onChange={(e) => setAmount(e.target.value)}
            placeholder="0"
            disabled={busy}
            className="flex-1 rounded-lg bg-zinc-800 border border-zinc-700 px-3 py-2.5 text-sm font-mono text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:border-blue-500"
          />
          <button
            onClick={() => setAmount(data.publicBalance ?? '0')}
            disabled={busy}
            className="rounded-lg bg-zinc-800 border border-zinc-700 px-3 py-2.5 text-xs font-medium text-blue-400 hover:text-blue-300"
          >
            MAX
          </button>
        </div>
        <p className="text-xs text-zinc-500 mt-1">
          Available to shield: <span className="font-mono">{data.publicBalance ?? '--'} {selectedDenom}</span> (public)
        </p>
      </div>

      {blockedByDesync && (
        <p className="text-xs text-yellow-400 rounded-lg bg-yellow-950/30 border border-yellow-900/50 px-3 py-2">
          Local wallet state missing but chain has a confidential balance. Click 'Repair State' above before shielding — shielding now would create a state desync.
        </p>
      )}

      <button
        onClick={handleShield}
        disabled={busy || !amount || Number(amount) <= 0 || blockedByDesync}
        className="w-full rounded-lg bg-blue-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-50 transition-colors"
      >
        {busy ? 'Processing...' : 'Shield'}
      </button>
    </div>
  );
}
