// src/components/Dashboard.tsx
import { useState, useEffect, useCallback } from 'react';
import { toast } from 'sonner';
import { chainClient } from '@/lib/chain';
import { cryptoService } from '@/lib/crypto';
import { loadState, saveState } from '@/lib/state';
import { truncateAddress } from '@/lib/utils';
import { recoverState } from '@/lib/recoverState';
import { CHAIN_CONFIG } from '@/lib/config';
import { Shield, ArrowUpRight, ArrowDownLeft, Clock, ScrollText, Copy, Loader2, Wrench } from 'lucide-react';
import { ShieldPanel } from './ShieldPanel';
import { SendPanel } from './SendPanel';
import { UnshieldPanel } from './UnshieldPanel';
import { PendingPanel } from './PendingPanel';
import { HistoryPanel } from './HistoryPanel';

type Tab = 'shield' | 'send' | 'unshield' | 'pending' | 'history';

const TABS: { id: Tab; label: string; icon: typeof Shield }[] = [
  { id: 'shield', label: 'Shield', icon: Shield },
  { id: 'send', label: 'Send', icon: ArrowUpRight },
  { id: 'unshield', label: 'Unshield', icon: ArrowDownLeft },
  { id: 'pending', label: 'Pending', icon: Clock },
  { id: 'history', label: 'History', icon: ScrollText },
];

const DENOMS = ['anix'];

interface DenomData {
  publicBalance: string | null;
  availableAmount: string | null;
  pendingAmount: string | null;
  loading: boolean;
  synced: boolean;
}

interface DashboardProps {
  address: string;
  syncWarning?: string;
}

export function Dashboard({ address, syncWarning }: DashboardProps) {
  const [activeTab, setActiveTab] = useState<Tab>('shield');
  const [selectedDenom, setSelectedDenom] = useState(DENOMS[0]);
  const [denomData, setDenomData] = useState<Record<string, DenomData>>({});
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
          [denom]: {
            ...prev[denom],
            loading: true,
            publicBalance: prev[denom]?.publicBalance ?? null,
            availableAmount: prev[denom]?.availableAmount ?? null,
            pendingAmount: prev[denom]?.pendingAmount ?? null,
            synced: prev[denom]?.synced ?? true,
          },
        }));

        try {
          const pubBal = await chainClient.queryBankBalance(address, denom);

          let availAmount: string | null = null;
          let pendAmount: string | null = null;
          let synced = true;

          try {
            const confBal = await chainClient.queryConfidentialBalance(address, denom);

            if (confBal.available && state?.seed) {
              const keyResult = await cryptoService.deriveKey(state.seed, state.counter);
              const skHex: string = keyResult.secretKeyHex;
              try {
                const decrypted = await cryptoService.decrypt(skHex, confBal.available);
                availAmount = String(decrypted.amount ?? decrypted);
                // Compare decrypted on-chain amount with local state
                const localAmount = state.balances[denom]?.availableAmount;
                if (localAmount != null && availAmount !== localAmount) {
                  console.warn(`[${denom}] State desync: chain=${availAmount}, local=${localAmount}`);
                  synced = false;
                }
              } catch {
                availAmount = state.balances[denom]?.availableAmount ?? '0';
              }
            } else if (state?.balances[denom]) {
              availAmount = state.balances[denom].availableAmount;
            }

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
                synced,
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
                synced: prev[denom]?.synced ?? true,
              },
            }));
          }
        }
      }
    }

    fetchBalances();
    return () => { cancelled = true; };
  }, [address, refreshKey]);

  async function copyAddress() {
    try {
      await navigator.clipboard.writeText(address);
      toast('Address copied');
    } catch {
      toast.error('Failed to copy address');
    }
  }

  const [repairing, setRepairing] = useState(false);

  async function handleRepairState() {
    const toastId = toast.loading('Replaying chain events to recover state...');
    setRepairing(true);
    try {
      const state = loadState(address);
      if (!state?.seed) throw new Error('Wallet not initialized');

      const keyResult = await cryptoService.deriveKey(state.seed, state.counter);
      const skHex: string = keyResult.secretKeyHex;
      const tmClient = chainClient.getTmClient();
      if (!tmClient) throw new Error('Not connected to chain');

      const recovered = await recoverState(tmClient, address, skHex, CHAIN_CONFIG.chainId, selectedDenom);
      if (!recovered) throw new Error('No events found for ' + selectedDenom);

      // Decrypt current on-chain balance for the amount
      const confBal = await chainClient.queryConfidentialBalance(address, selectedDenom);
      let amount = recovered.amount;
      if (confBal.available) {
        try {
          const decrypted = await cryptoService.decrypt(skHex, confBal.available);
          amount = Number(decrypted.amount ?? decrypted);
        } catch { /* use replayed amount as fallback */ }
      }

      // Save recovered state
      if (!state.balances[selectedDenom]) {
        state.balances[selectedDenom] = { availableAmount: '0', availableRandomness: '', pendingApplied: true };
      }
      state.balances[selectedDenom].availableAmount = String(amount);
      state.balances[selectedDenom].availableRandomness = recovered.randomness;
      saveState(state);

      toast.success('State repaired', { id: toastId, description: `Recovered: ${amount} ${selectedDenom}` });
      refresh();
    } catch (e: any) {
      toast.error('Repair failed', { id: toastId, description: e.message || String(e) });
    } finally {
      setRepairing(false);
    }
  }

  // Strip loading from denomData for child props
  const denomBalances: Record<string, { publicBalance: string | null; availableAmount: string | null; pendingAmount: string | null; synced: boolean }> = {};
  for (const [denom, d] of Object.entries(denomData)) {
    denomBalances[denom] = { publicBalance: d.publicBalance, availableAmount: d.availableAmount, pendingAmount: d.pendingAmount, synced: d.synced };
  }

  const isLoading = Object.values(denomData).some((d) => d.loading);

  const panelProps = {
    address,
    denoms: DENOMS,
    selectedDenom,
    onDenomChange: setSelectedDenom,
    denomData: denomBalances,
    onSuccess: refresh,
  };

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-50">
      {/* Header */}
      <header className="border-b border-zinc-800 px-6 py-4">
        <div className="max-w-2xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-2">
            <h1 className="text-lg font-bold">Confidential Wallet</h1>
            {isLoading && <Loader2 className="h-4 w-4 text-zinc-500 animate-spin" />}
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={copyAddress}
              className="flex items-center gap-1.5 rounded-md bg-zinc-800 border border-zinc-700 px-2.5 py-1 hover:bg-zinc-700/50 transition-colors"
            >
              <span className="text-xs font-mono text-zinc-400">{truncateAddress(address)}</span>
              <Copy className="h-3 w-3 text-zinc-500" />
            </button>
            <span className="inline-flex items-center rounded-full bg-green-900/30 px-2 py-0.5 text-xs text-green-400">
              Connected
            </span>
          </div>
        </div>
      </header>

      {/* Main content */}
      <main className="max-w-2xl mx-auto p-6 space-y-4">
        {syncWarning && (
          <div className="rounded-lg bg-yellow-900/20 border border-yellow-800 p-3">
            <p className="text-sm text-yellow-400">{syncWarning}</p>
          </div>
        )}

        {denomData[selectedDenom] && !denomData[selectedDenom].synced && (
          <div className="flex items-center gap-3 rounded-lg bg-red-950/30 border border-red-900/50 p-3">
            <p className="flex-1 text-sm text-red-400">Balance state out of sync with chain.</p>
            <button
              onClick={handleRepairState}
              disabled={repairing}
              className="flex items-center gap-1.5 rounded-md bg-red-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-red-500 disabled:opacity-50 whitespace-nowrap"
            >
              <Wrench className="h-3.5 w-3.5" />
              {repairing ? 'Repairing...' : 'Repair State'}
            </button>
          </div>
        )}

        {/* Tab bar */}
        <div className="flex gap-1 rounded-xl bg-zinc-900/80 border border-zinc-800/50 p-1.5 backdrop-blur-sm overflow-x-auto">
          {TABS.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            // Count denoms that have a non-zero pending balance
            const pendingCount = tab.id === 'pending'
              ? Object.values(denomData).filter((d) => {
                  const n = Number(d.pendingAmount);
                  return !isNaN(n) && n > 0;
                }).length
              : 0;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`relative flex-1 flex items-center justify-center gap-1.5 rounded-lg px-2.5 py-2.5 text-sm font-medium whitespace-nowrap transition-all duration-200 border ${
                  isActive
                    ? 'bg-blue-950 text-blue-400 border-blue-500/30 shadow-sm'
                    : 'text-zinc-400 hover:text-white hover:bg-zinc-700/50 border-transparent'
                }`}
              >
                <Icon className="h-4 w-4" />
                <span className="hidden sm:inline">{tab.label}</span>
                {tab.id === 'pending' && pendingCount > 0 && (
                  <span className="absolute -top-1 -right-1 flex h-4 w-4 items-center justify-center rounded-full bg-yellow-500 text-[10px] font-bold leading-none text-black">
                    {pendingCount}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {/* Tab content */}
        <div className="rounded-lg bg-zinc-900 border border-zinc-800 p-4">
          {activeTab === 'shield' && <ShieldPanel {...panelProps} />}
          {activeTab === 'send' && <SendPanel {...panelProps} />}
          {activeTab === 'unshield' && <UnshieldPanel {...panelProps} />}
          {activeTab === 'pending' && <PendingPanel {...panelProps} />}
          {activeTab === 'history' && <HistoryPanel address={address} />}
        </div>
      </main>
    </div>
  );
}
