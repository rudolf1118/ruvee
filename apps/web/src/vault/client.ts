import type {
  VaultErrorCode,
  VaultEvent,
  VaultMethod,
  VaultMethods,
  VaultRequest,
  VaultResponse,
} from '@ruvee/vault';

export class VaultClientError extends Error {
  constructor(
    readonly code: VaultErrorCode,
    readonly retryAfterSeconds?: number,
  ) {
    super(code);
    this.name = 'VaultClientError';
  }
}

type Params<M extends VaultMethod> = Parameters<VaultMethods[M]>[0];
type Result<M extends VaultMethod> = ReturnType<VaultMethods[M]>;

/**
 * The UI side of the vault worker. One client lives from unlock to lock: `lock()` asks the
 * worker to zero what it can and then terminates it, which discards every key it held.
 */
export class VaultClient {
  private readonly worker: Worker;
  private next = 1;
  private readonly waiting = new Map<
    number,
    { resolve: (value: unknown) => void; reject: (error: VaultClientError) => void }
  >();
  private readonly listeners = new Set<(event: VaultEvent) => void>();
  private terminated = false;

  constructor() {
    this.worker = new Worker(new URL('./worker/vault.worker.ts', import.meta.url), {
      type: 'module',
      name: 'ruvee-vault',
    });
    this.worker.onmessage = (event: MessageEvent<VaultResponse | VaultEvent>) => {
      const data = event.data;
      if ('event' in data) {
        for (const listener of this.listeners) listener(data);
        return;
      }
      const pending = this.waiting.get(data.id);
      if (!pending) return;
      this.waiting.delete(data.id);
      if (data.ok) pending.resolve(data.result);
      else pending.reject(new VaultClientError(data.error.code, data.error.retryAfterSeconds));
    };
    this.worker.onerror = () => {
      this.failAll('internal');
    };
  }

  call<M extends VaultMethod>(
    method: M,
    ...params: Params<M> extends undefined ? [] : [Params<M>]
  ): Promise<Result<M>> {
    if (this.terminated) return Promise.reject(new VaultClientError('locked'));
    const id = this.next++;
    const request = { id, method, params: params[0] } as VaultRequest<M>;
    return new Promise<Result<M>>((resolve, reject) => {
      this.waiting.set(id, { resolve: resolve as (value: unknown) => void, reject });
      this.worker.postMessage(request);
    });
  }

  subscribe(listener: (event: VaultEvent) => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  /** Zeroes what the worker can (best effort), then terminates it. */
  async lock(): Promise<void> {
    if (this.terminated) return;
    await Promise.race([
      this.call('wipe').catch(() => undefined),
      new Promise((resolve) => setTimeout(resolve, 250)),
    ]);
    this.terminate();
  }

  terminate(): void {
    if (this.terminated) return;
    this.terminated = true;
    this.worker.terminate();
    this.failAll('locked');
    this.listeners.clear();
  }

  private failAll(code: VaultErrorCode): void {
    for (const pending of this.waiting.values()) pending.reject(new VaultClientError(code));
    this.waiting.clear();
  }
}
