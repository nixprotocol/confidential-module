// src/components/TxStatus.tsx
import { Loader2, Check, X } from 'lucide-react';

export type TxStatusState =
  | 'idle'
  | 'proving'
  | 'signing'
  | 'broadcasting'
  | 'confirmed'
  | 'failed';

interface TxStatusProps {
  status: TxStatusState;
  txHash?: string;
  error?: string;
}

const STEPS: { key: TxStatusState; label: string }[] = [
  { key: 'proving', label: 'Generating proof...' },
  { key: 'signing', label: 'Sign with Keplr' },
  { key: 'broadcasting', label: 'Broadcasting...' },
  { key: 'confirmed', label: 'Confirmed' },
];

export function TxStatus({ status, txHash, error }: TxStatusProps) {
  if (status === 'idle') return null;

  const currentIdx = STEPS.findIndex((s) => s.key === status);

  return (
    <div className="mt-4 space-y-2 rounded-lg bg-zinc-800/50 p-4">
      {STEPS.map((step, i) => {
        const isActive = step.key === status;
        const isDone = status === 'confirmed' ? true : currentIdx > i;
        const isFailed = status === 'failed' && isActive;
        const isPending = currentIdx < i && status !== 'confirmed';

        return (
          <div key={step.key} className="flex items-center gap-3 text-sm">
            {isDone && !isFailed ? (
              <Check className="h-4 w-4 text-green-400 shrink-0" />
            ) : isActive && !isFailed ? (
              <Loader2 className="h-4 w-4 text-blue-400 animate-spin shrink-0" />
            ) : isFailed ? (
              <X className="h-4 w-4 text-red-400 shrink-0" />
            ) : (
              <div className="h-4 w-4 rounded-full border border-zinc-600 shrink-0" />
            )}
            <span
              className={
                isDone
                  ? 'text-green-400'
                  : isActive
                    ? isFailed
                      ? 'text-red-400'
                      : 'text-blue-400'
                    : isPending
                      ? 'text-zinc-500'
                      : 'text-zinc-400'
              }
            >
              {step.label}
            </span>
          </div>
        );
      })}

      {txHash && (
        <p className="mt-2 text-xs text-zinc-400 font-mono break-all">
          TX: {txHash}
        </p>
      )}

      {error && (
        <p className="mt-2 text-xs text-red-400 break-all">{error}</p>
      )}
    </div>
  );
}
