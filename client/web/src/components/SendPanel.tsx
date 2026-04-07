// src/components/SendPanel.tsx
import { useState } from 'react';
import { toast } from 'sonner';
import { cryptoService } from '@/lib/crypto';
import { chainClient } from '@/lib/chain';
import { loadState, saveState } from '@/lib/state';
import { hexToBytes } from '@/lib/utils';
import { encodeMsgConfidentialSend } from '@/lib/messages';
import { broadcastMsg } from '@/lib/tx';
import { CHAIN_CONFIG } from '@/lib/config';
import { TokenSelect } from './TokenSelect';

interface DenomBalances {
  publicBalance: string | null;
  availableAmount: string | null;
  pendingAmount: string | null;
  synced: boolean;
}

interface SendPanelProps {
  address: string;
  denoms: string[];
  selectedDenom: string;
  onDenomChange: (denom: string) => void;
  denomData: Record<string, DenomBalances>;
  onSuccess: () => void;
}

export function SendPanel({ address, denoms, selectedDenom, onDenomChange, denomData, onSuccess }: SendPanelProps) {
  const [recipient, setRecipient] = useState('');
  const [amount, setAmount] = useState('');
  const [busy, setBusy] = useState(false);
  const [recipientStatus, setRecipientStatus] = useState('');

  const data = denomData[selectedDenom] ?? { publicBalance: null, availableAmount: null, pendingAmount: null, synced: true };
  const isDesynced = data.synced === false;
  const hasLocalState = !!loadState(address)?.balances[selectedDenom]?.availableRandomness;

  async function checkRecipient() {
    if (!recipient) return;
    try {
      const info = await chainClient.queryAccountInfo(recipient);
      if (info.registered) {
        setRecipientStatus('Registered');
      } else {
        setRecipientStatus('Not registered - recipient must register first');
      }
    } catch (e: any) {
      setRecipientStatus('Could not verify: ' + e.message);
    }
  }

  async function handleSend() {
    if (!amount || Number(amount) <= 0 || !recipient) return;

    const toastId = toast.loading('Generating proof...');
    setBusy(true);

    try {
      const state = loadState(address);
      if (!state?.seed) throw new Error('Wallet not initialized');

      const [recipientInfo, auditorKey, onChainBalance] = await Promise.all([
        chainClient.queryAccountInfo(recipient),
        chainClient.queryAuditorKey(),
        chainClient.queryConfidentialBalance(address, selectedDenom),
      ]);

      if (!recipientInfo.registered || !recipientInfo.pubkey) {
        throw new Error('Recipient is not registered');
      }

      const keyResult = await cryptoService.deriveKey(state.seed, state.counter);
      const skHex: string = keyResult.secretKeyHex;
      const senderPkHex: string = keyResult.pubkeyHex;

      const denomState = state.balances[selectedDenom];
      if (!denomState) throw new Error('No balance state for ' + selectedDenom);

      // Verify local state matches on-chain balance (detect desync)
      if (onChainBalance.available) {
        try {
          const decrypted = await cryptoService.decrypt(skHex, onChainBalance.available);
          const chainAmount = Number(decrypted.amount ?? decrypted);
          const localAmount = Number(denomState.availableAmount);
          if (chainAmount !== localAmount) {
            console.warn(`State desync: chain=${chainAmount}, local=${localAmount}`);
            throw new Error(`Balance state out of sync (chain: ${chainAmount}, local: ${localAmount}). Try shielding a small amount first to resync, or clear wallet state.`);
          }
        } catch (e: any) {
          if (e.message?.includes('out of sync')) throw e;
          // Decryption failure is non-fatal — proceed with local state
        }
      }

      const sendResult = await cryptoService.send({
        skHex,
        senderPkHex,
        receiverPkHex: recipientInfo.pubkey,
        auditorPkHex: auditorKey || '',
        amount: Number(amount),
        availAmount: Number(denomState.availableAmount),
        availRandomnessHex: denomState.availableRandomness,
        chainId: CHAIN_CONFIG.chainId,
        sender: address,
        receiver: recipient,
        denom: selectedDenom,
        availBalanceHex: onChainBalance.available || '',
      });

      toast.loading('Sign in Keplr...', { id: toastId });
      const senderUpdate = hexToBytes(sendResult.senderCtHex || sendResult.senderUpdate || sendResult.senderUpdateHex);
      const receiverUpdate = hexToBytes(sendResult.receiverCtHex || sendResult.receiverUpdate || sendResult.receiverUpdateHex);
      const auditorUpdate = hexToBytes(sendResult.auditorCtHex || sendResult.auditorUpdate || sendResult.auditorUpdateHex || '');
      const rangeProof = hexToBytes(sendResult.rangeProofHex || sendResult.rangeProof);
      const equalityProof = hexToBytes(sendResult.eqProofHex || sendResult.equalityProof || sendResult.equalityProofHex);

      const newR = sendResult.newAvailRandomnessHex;
      const newAmount = Number(denomState.availableAmount) - Number(amount);
      const memoResult = await cryptoService.encryptMemo(senderPkHex, newR, newAmount);
      const memoBytes = hexToBytes(memoResult.encryptedMemoHex);

      const msg = encodeMsgConfidentialSend(
        address,
        recipient,
        selectedDenom,
        senderUpdate,
        receiverUpdate,
        auditorUpdate,
        rangeProof,
        equalityProof,
        memoBytes,
      );

      toast.loading('Broadcasting...', { id: toastId });
      const hash = await broadcastMsg(msg);

      const s = loadState(address)!;
      s.balances[selectedDenom].availableAmount = String(newAmount);
      s.balances[selectedDenom].availableRandomness = newR;
      saveState(s);

      toast.success('Send confirmed', { id: toastId, description: `TX: ${hash.slice(0, 8)}...${hash.slice(-4)}` });
      setAmount('');
      setRecipient('');
      setRecipientStatus('');
      onSuccess();
    } catch (e: any) {
      toast.error('Send failed', { id: toastId, description: e.message || String(e) });
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
        <label className="text-xs text-zinc-500 uppercase tracking-wide block mb-1">Recipient Address</label>
        <input
          type="text"
          value={recipient}
          onChange={(e) => { setRecipient(e.target.value); setRecipientStatus(''); }}
          onBlur={checkRecipient}
          placeholder="cosmos1..."
          disabled={busy}
          className="w-full rounded-lg bg-zinc-800 border border-zinc-700 px-3 py-2.5 text-sm font-mono text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:border-blue-500"
        />
        {recipientStatus && (
          <p className={`text-xs mt-1 ${recipientStatus.startsWith('Registered') ? 'text-green-400' : 'text-yellow-400'}`}>
            {recipientStatus}
          </p>
        )}
      </div>

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
          Available: <span className="font-mono">{data.availableAmount ?? '--'} {selectedDenom}</span> (confidential)
        </p>
      </div>

      {!hasLocalState && (
        <p className="text-xs text-yellow-400 rounded-lg bg-yellow-950/30 border border-yellow-900/50 px-3 py-2">
          {Number(data.availableAmount) > 0
            ? "Local wallet state missing. Click 'Repair State' above to recover from chain events."
            : 'No local balance state. Shield tokens first to initialize your wallet state.'}
        </p>
      )}

      {hasLocalState && isDesynced && (
        <p className="text-xs text-red-400 rounded-lg bg-red-950/30 border border-red-900/50 px-3 py-2">
          Balance state out of sync with chain. Shield a small amount to resync before sending.
        </p>
      )}

      <button
        onClick={handleSend}
        disabled={busy || !amount || Number(amount) <= 0 || !recipient || isDesynced || !hasLocalState}
        className="w-full rounded-lg bg-blue-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-50 transition-colors"
      >
        {busy ? 'Processing...' : 'Send'}
      </button>
    </div>
  );
}
