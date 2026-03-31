// src/components/SetupWizard.tsx
import { useState } from 'react';
import { deriveDeterministicSeed } from '@/lib/keplr';
import { cryptoService } from '@/lib/crypto';
import { chainClient } from '@/lib/chain';
import { saveState, loadState } from '@/lib/state';
import { bytesToHex, hexToBytes } from '@/lib/utils';
import { encodeMsgRegisterKey } from '@/lib/messages';
import { broadcastMsg } from '@/lib/tx';
import { TxStatus, type TxStatusState } from './TxStatus';
import { Loader2 } from 'lucide-react';

interface SetupWizardProps {
  address: string;
  onComplete: () => void;
}

type Step = 'welcome' | 'deriving' | 'checking' | 'registering' | 'done' | 'error';

export function SetupWizard({ address, onComplete }: SetupWizardProps) {
  const [step, setStep] = useState<Step>('welcome');
  const [txStatus, setTxStatus] = useState<TxStatusState>('idle');
  const [txHash, setTxHash] = useState<string>();
  const [error, setError] = useState<string>();

  async function runSetup() {
    try {
      // Step 1: Derive deterministic seed from Keplr signature
      setStep('deriving');
      const signatureBytes = await deriveDeterministicSeed(address);
      const seedHex = bytesToHex(signatureBytes);

      // Call WASM to derive the keypair
      const keyResult = await cryptoService.deriveKey(seedHex, 0);
      const pubkeyHex: string = keyResult.pubkeyHex || keyResult.publicKey || keyResult.pubkey || '';

      // Save state immediately (seed is critical)
      saveState({
        address,
        seed: seedHex,
        counter: 0,
        balances: {},
      });

      // Step 2: Check if already registered on chain
      setStep('checking');
      const accountInfo = await chainClient.queryAccountInfo(address);

      if (accountInfo.registered && accountInfo.pubkey === pubkeyHex) {
        // Already registered with the same key, done
        setStep('done');
        onComplete();
        return;
      }

      // Step 3: Register (or re-register if key mismatch) on chain
      setStep('registering');
      setTxStatus('signing');

      const pubkeyBytes = hexToBytes(pubkeyHex);
      const msg = encodeMsgRegisterKey(address, pubkeyBytes);

      setTxStatus('broadcasting');
      const hash = await broadcastMsg(msg);
      setTxHash(hash);
      setTxStatus('confirmed');

      // Update state counter
      const updatedState = loadState(address);
      if (updatedState) {
        updatedState.counter = counter;
        saveState(updatedState);
      }

      setStep('done');
      setTimeout(() => onComplete(), 1500);
    } catch (e: any) {
      setError(e.message || String(e));
      setStep('error');
      setTxStatus('failed');
    }
  }

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-50 flex items-center justify-center">
      <div className="w-full max-w-md space-y-6 p-8">
        <h1 className="text-2xl font-bold text-center">Setup Confidential Wallet</h1>
        <p className="text-sm text-zinc-400 text-center font-mono">{address}</p>

        {step === 'welcome' && (
          <div className="space-y-4">
            <div className="rounded-lg bg-zinc-900 p-4 space-y-2">
              <p className="text-sm text-zinc-300">This wizard will:</p>
              <ol className="text-sm text-zinc-400 list-decimal list-inside space-y-1">
                <li>Derive your confidential (ElGamal) keypair using Keplr</li>
                <li>Check if your key is registered on chain</li>
                <li>Register your key if needed (requires a transaction)</li>
              </ol>
            </div>
            <button
              onClick={runSetup}
              className="w-full rounded-lg bg-blue-600 px-4 py-3 text-sm font-medium text-white hover:bg-blue-500"
            >
              Begin Setup
            </button>
          </div>
        )}

        {step === 'deriving' && (
          <div className="flex flex-col items-center gap-3">
            <Loader2 className="h-8 w-8 text-blue-400 animate-spin" />
            <p className="text-sm text-zinc-300">Deriving ElGamal keypair...</p>
            <p className="text-xs text-zinc-500">Please approve the signature request in Keplr</p>
          </div>
        )}

        {step === 'checking' && (
          <div className="flex flex-col items-center gap-3">
            <Loader2 className="h-8 w-8 text-blue-400 animate-spin" />
            <p className="text-sm text-zinc-300">Checking registration status...</p>
          </div>
        )}

        {step === 'registering' && (
          <div className="space-y-3">
            <p className="text-sm text-zinc-300 text-center">Registering your confidential key on chain...</p>
            <TxStatus status={txStatus} txHash={txHash} error={error} />
          </div>
        )}

        {step === 'done' && (
          <div className="flex flex-col items-center gap-3">
            <div className="h-12 w-12 rounded-full bg-green-900/30 flex items-center justify-center">
              <span className="text-green-400 text-xl">OK</span>
            </div>
            <p className="text-sm text-green-400">Setup complete! Redirecting to dashboard...</p>
            {txHash && <p className="text-xs text-zinc-500 font-mono break-all">TX: {txHash}</p>}
          </div>
        )}

        {step === 'error' && (
          <div className="space-y-4">
            <div className="rounded-lg bg-red-900/20 border border-red-900/50 p-4">
              <p className="text-sm text-red-400">{error}</p>
            </div>
            <button
              onClick={() => {
                setStep('welcome');
                setTxStatus('idle');
                setTxHash(undefined);
                setError(undefined);
              }}
              className="w-full rounded-lg bg-zinc-800 px-4 py-3 text-sm font-medium text-zinc-300 hover:bg-zinc-700"
            >
              Try Again
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
