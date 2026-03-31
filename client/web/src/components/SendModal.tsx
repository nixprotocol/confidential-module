// src/components/SendModal.tsx
import { useState } from 'react';
import { cryptoService } from '@/lib/crypto';
import { chainClient } from '@/lib/chain';
import { loadState, saveState } from '@/lib/state';
import { hexToBytes } from '@/lib/utils';
import { encodeMsgConfidentialSend } from '@/lib/messages';
import { broadcastMsg } from '@/lib/tx';
import { CHAIN_CONFIG } from '@/lib/config';
import { TxStatus, type TxStatusState } from './TxStatus';

interface SendModalProps {
  address: string;
  denom: string;
  availableAmount: string;
  onClose: () => void;
  onSuccess: () => void;
}

export function SendModal({ address, denom, availableAmount, onClose, onSuccess }: SendModalProps) {
  const [recipient, setRecipient] = useState('');
  const [amount, setAmount] = useState('');
  const [txStatus, setTxStatus] = useState<TxStatusState>('idle');
  const [txHash, setTxHash] = useState<string>();
  const [error, setError] = useState<string>();
  const [recipientStatus, setRecipientStatus] = useState<string>('');

  const busy = txStatus !== 'idle' && txStatus !== 'confirmed' && txStatus !== 'failed';

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
    setError(undefined);

    try {
      const state = loadState(address);
      if (!state?.seed) throw new Error('Wallet not initialized');

      // Step 1: Fetch recipient info + auditor key
      setTxStatus('proving');
      const [recipientInfo, auditorKey, onChainBalance] = await Promise.all([
        chainClient.queryAccountInfo(recipient),
        chainClient.queryAuditorKey(),
        chainClient.queryConfidentialBalance(address, denom),
      ]);

      if (!recipientInfo.registered || !recipientInfo.pubkey) {
        throw new Error('Recipient is not registered');
      }

      // Derive our key
      const keyResult = await cryptoService.deriveKey(state.seed, state.counter);
      const skHex: string = keyResult.secretKeyHex;
      const senderPkHex: string = keyResult.pubkeyHex;

      const denomState = state.balances[denom];
      if (!denomState) throw new Error('No balance state for ' + denom);

      // Generate send proof via WASM
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
        denom,
        availBalanceHex: onChainBalance.available || '',
      });

      // Step 2: Build and broadcast
      setTxStatus('signing');
      const senderUpdate = hexToBytes(sendResult.senderCtHex || sendResult.senderUpdate || sendResult.senderUpdateHex);
      const receiverUpdate = hexToBytes(sendResult.receiverCtHex || sendResult.receiverUpdate || sendResult.receiverUpdateHex);
      const auditorUpdate = hexToBytes(sendResult.auditorCtHex || sendResult.auditorUpdate || sendResult.auditorUpdateHex || '');
      const rangeProof = hexToBytes(sendResult.rangeProofHex || sendResult.rangeProof);
      const equalityProof = hexToBytes(sendResult.eqProofHex || sendResult.equalityProof || sendResult.equalityProofHex);

      // Compute memo — WASM returns cumulative randomness for send
      const newR = sendResult.newAvailRandomnessHex;
      const newAmount = Number(denomState.availableAmount) - Number(amount);
      const memoResult = await cryptoService.encryptMemo(senderPkHex, newR, newAmount);
      const memoBytes = hexToBytes(memoResult.encryptedMemoHex);

      const msg = encodeMsgConfidentialSend(
        address,
        recipient,
        denom,
        senderUpdate,
        receiverUpdate,
        auditorUpdate,
        rangeProof,
        equalityProof,
        memoBytes,
      );

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
          <h2 className="text-lg font-semibold text-zinc-100">Send {denom}</h2>
          <button onClick={onClose} className="text-zinc-500 hover:text-zinc-300 text-lg">&times;</button>
        </div>

        <p className="text-xs text-zinc-500">
          Available: <span className="font-mono">{availableAmount} {denom}</span>
        </p>

        <div>
          <label className="text-xs text-zinc-400 block mb-1">Recipient Address</label>
          <input
            type="text"
            value={recipient}
            onChange={(e) => { setRecipient(e.target.value); setRecipientStatus(''); }}
            onBlur={checkRecipient}
            placeholder="cosmos1..."
            disabled={busy}
            className="w-full rounded bg-zinc-800 border border-zinc-700 px-3 py-2 text-sm font-mono text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:border-blue-500"
          />
          {recipientStatus && (
            <p className={`text-xs mt-1 ${recipientStatus.startsWith('Registered') ? 'text-green-400' : 'text-yellow-400'}`}>
              {recipientStatus}
            </p>
          )}
        </div>

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
              onClick={() => setAmount(availableAmount)}
              disabled={busy}
              className="rounded bg-zinc-800 border border-zinc-700 px-3 py-2 text-xs text-zinc-400 hover:text-zinc-200"
            >
              Max
            </button>
          </div>
        </div>

        <button
          onClick={handleSend}
          disabled={busy || !amount || Number(amount) <= 0 || !recipient}
          className="w-full rounded-lg bg-blue-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-50"
        >
          {busy ? 'Processing...' : 'Send'}
        </button>

        <TxStatus status={txStatus} txHash={txHash} error={error} />
      </div>
    </div>
  );
}
