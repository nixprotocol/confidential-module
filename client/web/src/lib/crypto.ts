// src/lib/crypto.ts
type PendingRequest = { resolve: (data: any) => void; reject: (err: Error) => void };

export class CryptoService {
  private worker: Worker;
  private pending = new Map<string, PendingRequest>();
  private readyPromise: Promise<void>;
  private nextId = 0;
  private onProgress?: (stage: string) => void;

  constructor() {
    this.worker = new Worker('/crypto-worker.js');
    this.worker.onmessage = (e) => this.handleMessage(e.data);
    this.readyPromise = new Promise((resolve) => {
      const handler = (e: MessageEvent) => {
        if (e.data.type === 'ready') {
          this.worker.removeEventListener('message', handler);
          resolve();
        }
      };
      this.worker.addEventListener('message', handler);
    });
    this.worker.postMessage({ type: 'init' });
  }

  private handleMessage(msg: any) {
    if (msg.type === 'progress' && this.onProgress) {
      this.onProgress(msg.stage);
      return;
    }
    const pending = this.pending.get(msg.id);
    if (!pending) return;
    this.pending.delete(msg.id);
    if (msg.type === 'error') {
      pending.reject(new Error(msg.message));
    } else {
      pending.resolve(msg.data);
    }
  }

  private async call(type: string, params: Record<string, any> = {}): Promise<any> {
    await this.readyPromise;
    const id = String(this.nextId++);
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.worker.postMessage({ type, id, ...params });
    });
  }

  setProgressHandler(handler: (stage: string) => void) { this.onProgress = handler; }

  async deriveKey(seedHex: string, counter: number) { return this.call('deriveKey', { seedHex, counter }); }
  async shield(params: any) { return this.call('shield', params); }
  async send(params: any) { return this.call('send', params); }
  async applyPending(params: any) { return this.call('applyPending', params); }
  async unshield(params: any) { return this.call('unshield', params); }
  async decrypt(skHex: string, ciphertextHex: string) { return this.call('decrypt', { skHex, ciphertextHex }); }
  async encryptMemo(pkHex: string, randomnessHex: string, amount: number) { return this.call('encryptMemo', { pkHex, randomnessHex, amount }); }
  async decryptMemo(skHex: string, encryptedMemoHex: string) { return this.call('decryptMemo', { skHex, encryptedMemoHex }); }
}

export const cryptoService = new CryptoService();
