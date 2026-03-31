import { useState } from 'react';
import { isKeplrInstalled, connectKeplr } from '@/lib/keplr';
import { truncateAddress } from '@/lib/utils';

export function WalletConnect({ onConnect }: { onConnect: (address: string) => void }) {
  const [address, setAddress] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [connecting, setConnecting] = useState(false);

  if (!isKeplrInstalled()) {
    return (
      <div className="flex items-center gap-2">
        <span className="text-sm text-zinc-400">Keplr not detected</span>
        <a href="https://www.keplr.app/download" target="_blank" rel="noopener noreferrer"
           className="text-sm text-blue-400 hover:text-blue-300 underline">
          Install Keplr
        </a>
      </div>
    );
  }

  if (address) {
    return (
      <div className="flex items-center gap-2">
        <span className="inline-flex items-center rounded-full bg-green-900/30 px-2.5 py-0.5 text-xs text-green-400">
          Connected
        </span>
        <span className="text-sm font-mono text-zinc-300">{truncateAddress(address)}</span>
      </div>
    );
  }

  return (
    <div className="flex items-center gap-2">
      <button
        onClick={async () => {
          setConnecting(true); setError(null);
          try {
            const { address: addr } = await connectKeplr();
            setAddress(addr);
            onConnect(addr);
          } catch (e: any) { setError(e.message); }
          setConnecting(false);
        }}
        disabled={connecting}
        className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-50"
      >
        {connecting ? 'Connecting...' : 'Connect Keplr'}
      </button>
      {error && <span className="text-sm text-red-400">{error}</span>}
    </div>
  );
}
