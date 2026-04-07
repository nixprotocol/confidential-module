// src/components/HistoryPanel.tsx
import { useState, useEffect } from 'react';
import { chainClient } from '@/lib/chain';
import { cryptoService } from '@/lib/crypto';
import { loadState } from '@/lib/state';
import { toHex } from '@cosmjs/encoding';
import { Loader2, Shield, ArrowUpRight, ArrowDownLeft, Clock } from 'lucide-react';

interface TxEvent {
  type: 'shield' | 'unshield' | 'confidential_send' | 'apply_pending';
  denom: string;
  amount: string;
  txHash: string;
  height: number;
}

const EVENT_TYPES = ['shield', 'unshield', 'confidential_send', 'apply_pending'] as const;

const TYPE_CONFIG: Record<string, { label: string; icon: typeof Shield; color: string }> = {
  shield: { label: 'Shield', icon: Shield, color: 'text-blue-400' },
  confidential_send: { label: 'Send', icon: ArrowUpRight, color: 'text-purple-400' },
  unshield: { label: 'Unshield', icon: ArrowDownLeft, color: 'text-green-400' },
  apply_pending: { label: 'Apply Pending', icon: Clock, color: 'text-yellow-400' },
};

interface HistoryPanelProps {
  address: string;
}

export function HistoryPanel({ address }: HistoryPanelProps) {
  const [events, setEvents] = useState<TxEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>();

  useEffect(() => {
    let cancelled = false;

    async function fetchHistory() {
      setLoading(true);
      setError(undefined);

      const tmClient = chainClient.getTmClient();
      if (!tmClient) {
        setError('Not connected to chain');
        setLoading(false);
        return;
      }

      // Derive the wallet's secret key once so we can decrypt memos for
      // confidential_send / apply_pending events that have no plaintext amount.
      let skHex: string | null = null;
      const state = loadState(address);
      if (state?.seed) {
        try {
          const keyResult = await cryptoService.deriveKey(state.seed, state.counter);
          skHex = keyResult.secretKeyHex;
        } catch (e) {
          console.warn('Failed to derive wallet key for history decryption:', e);
        }
      }

      const allEvents: TxEvent[] = [];

      for (const eventType of EVENT_TYPES) {
        try {
          const query = `${eventType}.sender='${address}'`;
          const result = await tmClient.txSearch({
            query,
            order_by: 'desc',
            per_page: 20,
            page: 1,
          });

          for (const tx of result.txs) {
            const txHash = toHex(tx.hash).toUpperCase();

            for (const event of tx.result.events) {
              if (event.type !== eventType) continue;

              const attrs: Record<string, string> = {};
              for (const attr of event.attributes) {
                attrs[attr.key] = attr.value;
              }

              // Plaintext amount is only present on shield/unshield events.
              // For confidential_send / apply_pending, decrypt the memo to
              // recover the txAmount the sender stored at construction time.
              let amount = attrs['amount'] || '?';
              if (amount === '?' && skHex && attrs['encrypted_memo']) {
                try {
                  const decrypted = await cryptoService.decryptMemo(skHex, attrs['encrypted_memo']);
                  if (decrypted?.txAmount != null && Number(decrypted.txAmount) > 0) {
                    amount = String(decrypted.txAmount);
                  }
                } catch (e) {
                  // Legacy memo, foreign key, or decode failure — leave as '?'.
                }
              }

              allEvents.push({
                type: eventType,
                denom: attrs['denom'] || '?',
                amount,
                txHash,
                height: tx.height,
              });
            }
          }
        } catch (e) {
          console.warn(`Failed to query ${eventType} events:`, e);
        }
      }

      // Sort by height descending
      allEvents.sort((a, b) => b.height - a.height);

      if (!cancelled) {
        setEvents(allEvents);
        setLoading(false);
      }
    }

    fetchHistory();
    return () => { cancelled = true; };
  }, [address]);

  if (loading) {
    return (
      <div className="flex flex-col items-center gap-3 py-8">
        <Loader2 className="h-6 w-6 text-zinc-500 animate-spin" />
        <p className="text-sm text-zinc-500">Loading history...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="rounded-lg bg-red-900/20 border border-red-900/50 p-4">
        <p className="text-sm text-red-400">{error}</p>
      </div>
    );
  }

  if (events.length === 0) {
    return (
      <div className="flex flex-col items-center gap-3 py-8 text-zinc-500">
        <Clock className="h-10 w-10" />
        <p className="text-sm">No transaction history yet</p>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {events.map((evt, i) => {
        const config = TYPE_CONFIG[evt.type] ?? TYPE_CONFIG.shield;
        const Icon = config.icon;
        return (
          <div key={`${evt.txHash}-${i}`} className="flex items-center gap-3 rounded-lg bg-zinc-800/50 px-3 py-3">
            <div className={`shrink-0 ${config.color}`}>
              <Icon className="h-4 w-4" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <span className={`text-sm font-medium ${config.color}`}>{config.label}</span>
                <span className="text-xs text-zinc-500 uppercase">{evt.denom}</span>
              </div>
              <div className="text-xs text-zinc-500 font-mono truncate">
                TX: {evt.txHash.slice(0, 8)}...{evt.txHash.slice(-4)}
              </div>
            </div>
            <div className="text-right shrink-0">
              <div className="text-sm font-mono text-zinc-300">{evt.amount}</div>
              <div className="text-[10px] text-zinc-600">Block {evt.height}</div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
