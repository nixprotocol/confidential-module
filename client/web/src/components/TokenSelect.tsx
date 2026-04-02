// src/components/TokenSelect.tsx
import { useState, useRef, useEffect } from 'react';
import { ChevronDown } from 'lucide-react';

interface DenomBalances {
  publicBalance: string | null;
  availableAmount: string | null;
  pendingAmount: string | null;
  synced: boolean;
}

interface TokenSelectProps {
  denoms: string[];
  selectedDenom: string;
  onSelect: (denom: string) => void;
  denomData: Record<string, DenomBalances>;
}

export function TokenSelect({ denoms, selectedDenom, onSelect, denomData }: TokenSelectProps) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  // Close on outside click
  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    if (open) document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, [open]);

  const data = denomData[selectedDenom] ?? { publicBalance: null, availableAmount: null, pendingAmount: null };

  return (
    <div ref={ref} className="relative">
      <label className="text-xs text-zinc-500 uppercase tracking-wide block mb-1">Token</label>
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="w-full rounded-lg bg-zinc-800 border border-zinc-700 px-3 py-2.5 flex items-center justify-between hover:bg-zinc-700/50 transition-colors"
      >
        <div className="flex items-center gap-2.5">
          <div className="w-6 h-6 rounded-full bg-blue-600/20 flex items-center justify-center text-xs font-bold text-blue-400">
            {selectedDenom.charAt(0).toUpperCase()}
          </div>
          <span className="text-sm font-medium text-zinc-100 uppercase">{selectedDenom}</span>
        </div>
        <div className="flex items-center gap-3">
          <div className="text-right">
            <div className="text-[10px] text-zinc-500">
              Public: <span className="font-mono text-zinc-300">{data.publicBalance ?? '--'}</span>
            </div>
            <div className="text-[10px] text-zinc-500">
              Confidential: <span className="font-mono text-zinc-300">{data.availableAmount ?? '--'}</span>
            </div>
          </div>
          <ChevronDown className={`h-4 w-4 text-zinc-500 transition-transform duration-200 ${open ? 'rotate-180' : ''}`} />
        </div>
      </button>

      {open && denoms.length > 1 && (
        <div className="absolute z-10 mt-1 w-full rounded-lg bg-zinc-800 border border-zinc-700 shadow-lg overflow-hidden">
          {denoms.map((denom) => {
            const d = denomData[denom] ?? { publicBalance: null, availableAmount: null, pendingAmount: null };
            const isSelected = denom === selectedDenom;
            return (
              <button
                key={denom}
                type="button"
                onClick={() => { onSelect(denom); setOpen(false); }}
                className={`w-full px-3 py-2.5 flex items-center justify-between hover:bg-zinc-700/50 transition-colors ${isSelected ? 'bg-zinc-700/30' : ''}`}
              >
                <div className="flex items-center gap-2.5">
                  <div className="w-6 h-6 rounded-full bg-blue-600/20 flex items-center justify-center text-xs font-bold text-blue-400">
                    {denom.charAt(0).toUpperCase()}
                  </div>
                  <span className="text-sm font-medium text-zinc-100 uppercase">{denom}</span>
                </div>
                <div className="text-right">
                  <div className="text-[10px] text-zinc-500">
                    Public: <span className="font-mono text-zinc-300">{d.publicBalance ?? '--'}</span>
                  </div>
                  <div className="text-[10px] text-zinc-500">
                    Confidential: <span className="font-mono text-zinc-300">{d.availableAmount ?? '--'}</span>
                  </div>
                </div>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}
