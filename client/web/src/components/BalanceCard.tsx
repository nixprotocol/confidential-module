// src/components/BalanceCard.tsx
import { Loader2 } from 'lucide-react';

interface BalanceCardProps {
  denom: string;
  publicBalance: string | null;     // from bank module, null = loading
  availableAmount: string | null;   // decrypted confidential available
  pendingAmount: string | null;     // decrypted confidential pending, null = none
  loading?: boolean;
  onApplyPending?: () => void;
}

export function BalanceCard({
  denom,
  publicBalance,
  availableAmount,
  pendingAmount,
  loading,
  onApplyPending,
}: BalanceCardProps) {
  return (
    <div className="rounded-lg bg-zinc-900 border border-zinc-800 p-4 space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium text-zinc-200 uppercase tracking-wide">{denom}</h3>
        {loading && <Loader2 className="h-4 w-4 text-zinc-500 animate-spin" />}
      </div>

      {/* Public balance */}
      <div className="flex items-center justify-between">
        <span className="text-xs text-zinc-500">Public</span>
        <span className="text-sm font-mono text-zinc-300">
          {publicBalance !== null ? publicBalance : '--'}
        </span>
      </div>

      {/* Confidential available */}
      <div className="flex items-center justify-between">
        <span className="text-xs text-zinc-500">Available (confidential)</span>
        <span className="text-sm font-mono text-zinc-300">
          {availableAmount !== null ? availableAmount : '--'}
        </span>
      </div>

      {/* Pending */}
      {pendingAmount !== null && pendingAmount !== '0' && (
        <div className="flex items-center justify-between">
          <span className="text-xs text-yellow-500">Pending</span>
          <div className="flex items-center gap-2">
            <span className="text-sm font-mono text-yellow-400">{pendingAmount}</span>
            {onApplyPending && (
              <button
                onClick={onApplyPending}
                className="rounded bg-yellow-600/20 border border-yellow-600/40 px-2 py-0.5 text-xs text-yellow-400 hover:bg-yellow-600/30"
              >
                Apply
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
