// src/components/UnshieldPanel.tsx
import { useState } from 'react';
import { toast } from 'sonner';
import { cryptoService } from '@/lib/crypto';
import { chainClient } from '@/lib/chain';
import { loadState, saveState } from '@/lib/state';
import { hexToBytes } from '@/lib/utils';
import { encodeMsgUnshield } from '@/lib/messages';
import { broadcastMsg } from '@/lib/tx';
import { CHAIN_CONFIG } from '@/lib/config';
import { TokenSelect } from './TokenSelect';

interface DenomBalances {
  publicBalance: string | null;
  availableAmount: string | null;
  pendingAmount: string | null;
}

interface UnshieldPanelProps {
  address: string;
  denoms: string[];
  selectedDenom: string;
  onDenomChange: (denom: string) => void;
  denomData: Record<string, DenomBalances>;
  onSuccess: () => void;
}

export function UnshieldPanel({ address, denoms, selectedDenom, onDenomChange, denomData, onSuccess }: UnshieldPanelProps) {
  const [amount, setAmount] = useState('');
  const [busy, setBusy] = useState(false);

  const data = denomData[selectedDenom] ?? { publicBalance: null, availableAmount: null, pendingAmount: null };

  async function handleUnshield() {
    if (!amount || Number(amount) <= 0) return;

    const toastId = toast.loading('Generating proof...');
    setBusy(true);

    try {
      const state = loadState(address);
      if (!state?.seed) throw new Error('Wallet not initialized');

      const denomState = state.balances[selectedDenom];
      if (!denomState) throw new Error('No balance state for ' + selectedDenom);

      const keyResult = await cryptoService.deriveKey(state.seed, state.counter);
      const skHex: string = keyResult.secretKeyHex;
      const pkHex: string = keyResult.pubkeyHex;

      const onChainBalance = await chainClient.queryConfidentialBalance(address, selectedDenom);

      const unshieldResult = await cryptoService.unshield({
        skHex,
        pkHex,
        amount: Number(amount),
        availAmount: Number(denomState.availableAmount),
        availRandomnessHex: denomState.availableRandomness,
        chainId: CHAIN_CONFIG.chainId,
        sender: address,
        denom: selectedDenom,
        availBalanceHex: onChainBalance.available || '',
      });

      toast.loading('Sign in Keplr...', { id: toastId });
      const ciphertextBytes = hexToBytes(unshieldResult.ciphertextHex || unshieldResult.ciphertext);
      const rangeProofBytes = hexToBytes(unshieldResult.rangeProofHex || unshieldResult.rangeProof);
      const decryptionProofBytes = hexToBytes(unshieldResult.dleqProofHex || unshieldResult.decryptionProof || unshieldResult.decryptionProofHex);

      const newR = unshieldResult.newAvailRandomnessHex;
      const newAmount = Number(denomState.availableAmount) - Number(amount);
      const memoResult = await cryptoService.encryptMemo(pkHex, newR, newAmount);
      const memoBytes = hexToBytes(memoResult.encryptedMemoHex);

      const msg = encodeMsgUnshield(address, selectedDenom, Number(amount), ciphertextBytes, rangeProofBytes, decryptionProofBytes, memoBytes);

      toast.loading('Broadcasting...', { id: toastId });
      const hash = await broadcastMsg(msg);

      const s = loadState(address)!;
      s.balances[selectedDenom].availableAmount = String(newAmount);
      s.balances[selectedDenom].availableRandomness = newR;
      saveState(s);

      toast.success('Unshield confirmed', { id: toastId, description: `TX: ${hash.slice(0, 8)}...${hash.slice(-4)}` });
      setAmount('');
      onSuccess();
    } catch (e: any) {
      toast.error('Unshield failed', { id: toastId, description: e.message || String(e) });
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
            onClick={() => setAmount(data.availableAmount ?? '0')}
            disabled={busy}
            className="rounded-lg bg-zinc-800 border border-zinc-700 px-3 py-2.5 text-xs font-medium text-blue-400 hover:text-blue-300"
          >
            MAX
          </button>
        </div>
        <p className="text-xs text-zinc-500 mt-1">
          Available to unshield: <span className="font-mono">{data.availableAmount ?? '--'} {selectedDenom}</span> (confidential)
        </p>
      </div>

      <button
        onClick={handleUnshield}
        disabled={busy || !amount || Number(amount) <= 0}
        className="w-full rounded-lg bg-blue-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-50 transition-colors"
      >
        {busy ? 'Processing...' : 'Unshield'}
      </button>
    </div>
  );
}
