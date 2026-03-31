// src/App.tsx
import { useState, useEffect } from 'react';
import { Toaster } from 'sonner';
import { WalletConnect } from './components/WalletConnect';
import { SetupWizard } from './components/SetupWizard';
import { Dashboard } from './components/Dashboard';
import { loadState, saveState } from './lib/state';
import { chainClient } from './lib/chain';
import { cryptoService } from './lib/crypto';
import { syncFromChain } from './lib/syncFromChain';

export default function App() {
  const [address, setAddress] = useState<string | null>(null);
  const [setup, setSetup] = useState(false);
  const [connecting, setConnecting] = useState(true);
  const [syncWarning, setSyncWarning] = useState<string>();

  // Connect to the chain on mount
  useEffect(() => {
    chainClient.connect()
      .catch((e) => console.warn('Chain connect failed (expected if node is offline):', e.message))
      .finally(() => setConnecting(false));
  }, []);

  // Check if user has existing state AND key is registered on-chain
  useEffect(() => {
    if (!address) return;

    async function checkState() {
      const state = loadState(address!);
      if (!state?.seed) {
        setSetup(false);
        return;
      }

      // Verify key is registered on-chain
      try {
        const info = await chainClient.queryAccountInfo(address!);
        if (!info.registered) {
          setSetup(false);
          return;
        }
      } catch {
        setSetup(!!state.seed);
        return;
      }

      // If balances are empty, try syncing from chain events
      const hasDenomState = Object.keys(state.balances).some(
        (d) => state.balances[d]?.availableRandomness
      );
      if (!hasDenomState && state.seed) {
        try {
          const keyResult = await cryptoService.deriveKey(state.seed, state.counter);
          const tmClient = chainClient.getTmClient();
          if (tmClient) {
            const recovered = await syncFromChain(tmClient, address!, keyResult.secretKeyHex, ['anix', 'stake']);
            if (Object.keys(recovered).length > 0) {
              for (const [denom, denomState] of Object.entries(recovered)) {
                state.balances[denom] = {
                  availableAmount: denomState.availableAmount,
                  availableRandomness: denomState.availableRandomness,
                  pendingApplied: true,
                };
                if (denomState.stale) {
                  setSyncWarning(`Recovered state for ${denom} may be stale — some transactions were found without memos.`);
                }
              }
              saveState(state);
            }
          }
        } catch (e) {
          console.warn('Sync from chain failed:', e);
        }
      }

      setSetup(true);
    }

    checkState();
  }, [address]);

  return (
    <>
      <Toaster
        position="bottom-right"
        theme="dark"
        toastOptions={{
          style: { background: '#18181b', border: '1px solid #27272a', color: '#fafafa' },
        }}
      />

      {/* Screen 1: Connect wallet */}
      {!address && (
        <div className="min-h-screen bg-zinc-950 text-zinc-50 flex items-center justify-center">
          <div className="text-center space-y-6">
            <h1 className="text-3xl font-bold">Confidential Wallet</h1>
            <p className="text-zinc-400">Private transactions on the Nix chain</p>
            {connecting ? (
              <p className="text-sm text-zinc-500">Connecting to chain...</p>
            ) : (
              <WalletConnect onConnect={setAddress} />
            )}
          </div>
        </div>
      )}

      {/* Screen 2: Setup wizard */}
      {address && !setup && (
        <SetupWizard address={address} onComplete={() => setSetup(true)} />
      )}

      {/* Screen 3: Main dashboard */}
      {address && setup && (
        <Dashboard address={address} syncWarning={syncWarning} />
      )}
    </>
  );
}
