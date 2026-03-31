// src/components/Dashboard.tsx
import { useState, useEffect, useCallback } from 'react';
import { toast } from 'sonner';
import { chainClient } from '@/lib/chain';
import { cryptoService } from '@/lib/crypto';
import { loadState } from '@/lib/state';
import { truncateAddress } from '@/lib/utils';
import { Shield, ArrowUpRight, ArrowDownLeft, Clock, ScrollText, Copy, Loader2 } from 'lucide-react';
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
          },
        }));

        try {
          const pubBal = await chainClient.queryBankBalance(address, denom);

          let availAmount: string | null = null;
          let pendAmount: string | null = null;

          try {
            const confBal = await chainClient.queryConfidentialBalance(address, denom);

            if (confBal.available && state?.seed) {
              const keyResult = await cryptoService.deriveKey(state.seed, state.counter);
              const skHex: string = keyResult.secretKeyHex;
              try {
                const decrypted = await cryptoService.decrypt(skHex, confBal.available);
                availAmount = String(decrypted.amount ?? decrypted);
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

  async function copyAddress() {
    await navigator.clipboard.writeText(address);
    toast('Address copied');
  }

  // Strip loading from denomData for child props
  const denomBalances: Record<string, { publicBalance: string | null; availableAmount: string | null; pendingAmount: string | null }> = {};
  for (const [denom, d] of Object.entries(denomData)) {
    denomBalances[denom] = { publicBalance: d.publicBalance, availableAmount: d.availableAmount, pendingAmount: d.pendingAmount };
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

        {/* Tab bar */}
        <div className="flex gap-1 rounded-xl bg-zinc-900/80 border border-zinc-800/50 p-1.5 backdrop-blur-sm overflow-x-auto">
          {TABS.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex-1 flex items-center justify-center gap-1.5 rounded-lg px-2.5 py-2.5 text-sm font-medium whitespace-nowrap transition-all duration-200 ${
                  isActive
                    ? 'bg-blue-600/20 text-blue-400 border border-blue-500/30 shadow-sm'
                    : 'text-zinc-400 hover:text-white hover:bg-zinc-700/50 border border-transparent'
                }`}
              >
                <Icon className="h-4 w-4" />
                <span className="hidden sm:inline">{tab.label}</span>
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
