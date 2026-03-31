// src/components/Dashboard.tsx
import { useState, useEffect, useCallback } from 'react';
import { WalletConnect } from './WalletConnect';
import { BalanceCard } from './BalanceCard';
import { ShieldModal } from './ShieldModal';
import { SendModal } from './SendModal';
import { UnshieldModal } from './UnshieldModal';
import { ApplyPendingModal } from './ApplyPendingModal';
import { chainClient } from '@/lib/chain';
import { cryptoService } from '@/lib/crypto';
import { loadState } from '@/lib/state';
import { truncateAddress } from '@/lib/utils';
import { Loader2 } from 'lucide-react';

type Modal = null | 'shield' | 'send' | 'unshield' | 'applyPending';

// Denoms the wallet tracks
const DENOMS = ['anix'];

interface DenomData {
  publicBalance: string | null;
  availableAmount: string | null;
  pendingAmount: string | null;
  loading: boolean;
}

interface DashboardProps {
  address: string;
  syncWarning?: string;
}

export function Dashboard({ address, syncWarning }: DashboardProps) {
  const [denomData, setDenomData] = useState<Record<string, DenomData>>({});
  const [activeModal, setActiveModal] = useState<Modal>(null);
  const [activeDenom, setActiveDenom] = useState<string>(DENOMS[0]);
  const [refreshKey, setRefreshKey] = useState(0);

  const refresh = useCallback(() => setRefreshKey((k) => k + 1), []);

  // Fetch balances
  useEffect(() => {
    let cancelled = false;

    async function fetchBalances() {
      const state = loadState(address);

      for (const denom of DENOMS) {
        setDenomData((prev) => ({
          ...prev,
          [denom]: { ...prev[denom], loading: true, publicBalance: prev[denom]?.publicBalance ?? null, availableAmount: prev[denom]?.availableAmount ?? null, pendingAmount: prev[denom]?.pendingAmount ?? null },
        }));

        try {
          // Public balance
          const pubBal = await chainClient.queryBankBalance(address, denom);

          // Confidential balance
          let availAmount: string | null = null;
          let pendAmount: string | null = null;

          try {
            const confBal = await chainClient.queryConfidentialBalance(address, denom);

            // Decrypt available balance if we have state
            if (confBal.available && state?.seed) {
              const keyResult = await cryptoService.deriveKey(state.seed, state.counter);
              const skHex: string = keyResult.secretKeyHex;
              try {
                const decrypted = await cryptoService.decrypt(skHex, confBal.available);
                availAmount = String(decrypted.amount ?? decrypted);
              } catch {
                // Decryption may fail if BSGS table not ready or balance is 0
                availAmount = state.balances[denom]?.availableAmount ?? '0';
              }
            } else if (state?.balances[denom]) {
              availAmount = state.balances[denom].availableAmount;
            }

            // Decrypt pending
            if (confBal.pending && state?.seed) {
              const keyResult = await cryptoService.deriveKey(state.seed, state.counter);
              const skHex: string = keyResult.secretKeyHex;
              try {
                const decrypted = await cryptoService.decrypt(skHex, confBal.pending);
                pendAmount = String(decrypted.amount ?? decrypted);
              } catch {
                pendAmount = '?';
              }
            }
          } catch {
            // Chain query may fail if no confidential account
            if (state?.balances[denom]) {
              availAmount = state.balances[denom].availableAmount;
            }
          }

          if (!cancelled) {
            setDenomData((prev) => ({
              ...prev,
              [denom]: {
                publicBalance: pubBal,
                availableAmount: availAmount,
                pendingAmount: pendAmount,
                loading: false,
              },
            }));
          }
        } catch (e) {
          console.error('Error fetching balance for', denom, e);
          if (!cancelled) {
            setDenomData((prev) => ({
              ...prev,
              [denom]: {
                publicBalance: prev[denom]?.publicBalance ?? null,
                availableAmount: prev[denom]?.availableAmount ?? null,
                pendingAmount: prev[denom]?.pendingAmount ?? null,
                loading: false,
              },
            }));
          }
        }
      }
    }

    fetchBalances();
    return () => { cancelled = true; };
  }, [address, refreshKey]);

  function openModal(modal: Modal, denom: string) {
    setActiveDenom(denom);
    setActiveModal(modal);
  }

  function closeAndRefresh() {
    setActiveModal(null);
    refresh();
  }

  const data = denomData[activeDenom] ?? { publicBalance: null, availableAmount: null, pendingAmount: null, loading: true };

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-50">
      {/* Header */}
      <header className="border-b border-zinc-800 px-6 py-4">
        <div className="max-w-2xl mx-auto flex items-center justify-between">
          <h1 className="text-lg font-bold">Confidential Wallet</h1>
          <div className="flex items-center gap-3">
            <span className="text-xs font-mono text-zinc-400">{truncateAddress(address)}</span>
            <span className="inline-flex items-center rounded-full bg-green-900/30 px-2 py-0.5 text-xs text-green-400">
              Connected
            </span>
          </div>
        </div>
      </header>

      {/* Main content */}
      <main className="max-w-2xl mx-auto p-6 space-y-6">
        {syncWarning && (
          <div className="rounded-lg bg-yellow-900/20 border border-yellow-800 p-3">
            <p className="text-sm text-yellow-400">{syncWarning}</p>
          </div>
        )}
        {/* Balance cards */}
        {DENOMS.map((denom) => {
          const d = denomData[denom] ?? { publicBalance: null, availableAmount: null, pendingAmount: null, loading: true };
          return (
            <BalanceCard
              key={denom}
              denom={denom}
              publicBalance={d.publicBalance}
              availableAmount={d.availableAmount}
              pendingAmount={d.pendingAmount}
              loading={d.loading}
              onApplyPending={() => openModal('applyPending', denom)}
            />
          );
        })}

        {/* Action buttons */}
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <button
            onClick={() => openModal('shield', activeDenom)}
            className="rounded-lg bg-blue-600 px-4 py-3 text-sm font-medium text-white hover:bg-blue-500"
          >
            Shield
          </button>
          <button
            onClick={() => openModal('send', activeDenom)}
            className="rounded-lg bg-blue-600 px-4 py-3 text-sm font-medium text-white hover:bg-blue-500"
          >
            Send
          </button>
          <button
            onClick={() => openModal('unshield', activeDenom)}
            className="rounded-lg bg-blue-600 px-4 py-3 text-sm font-medium text-white hover:bg-blue-500"
          >
            Unshield
          </button>
          <button
            onClick={refresh}
            className="rounded-lg bg-zinc-800 border border-zinc-700 px-4 py-3 text-sm font-medium text-zinc-300 hover:bg-zinc-700"
          >
            Refresh
          </button>
        </div>

        {/* Refresh hint */}
        <p className="text-xs text-zinc-600 text-center">
          Balances refresh automatically after transactions. Click Refresh to update manually.
        </p>
      </main>

      {/* Modals */}
      {activeModal === 'shield' && (
        <ShieldModal
          address={address}
          denom={activeDenom}
          publicBalance={data.publicBalance ?? '0'}
          onClose={() => setActiveModal(null)}
          onSuccess={closeAndRefresh}
        />
      )}
      {activeModal === 'send' && (
        <SendModal
          address={address}
          denom={activeDenom}
          availableAmount={data.availableAmount ?? '0'}
          onClose={() => setActiveModal(null)}
          onSuccess={closeAndRefresh}
        />
      )}
      {activeModal === 'unshield' && (
        <UnshieldModal
          address={address}
          denom={activeDenom}
          availableAmount={data.availableAmount ?? '0'}
          onClose={() => setActiveModal(null)}
          onSuccess={closeAndRefresh}
        />
      )}
      {activeModal === 'applyPending' && (
        <ApplyPendingModal
          address={address}
          denom={activeDenom}
          pendingAmount={data.pendingAmount ?? '0'}
          onClose={() => setActiveModal(null)}
          onSuccess={closeAndRefresh}
        />
      )}
    </div>
  );
}
