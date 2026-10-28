/**
 * Ownership of key buffers inside one engine operation (INV-15, follow-up review F-19).
 *
 * An operation `own`s every key buffer it derives, unwraps or reads from the device store; the
 * crypto layer and the store return new buffers the caller owns (operations.ts, store.ts). When
 * it hands a buffer on to something that outlives it (the session, a pending recovery or pairing,
 * the device record kept in memory), it `release`s it, and that holder zeroes it later. Whatever
 * is still owned when the operation ends, by returning or by throwing, is zeroed.
 *
 * Never `own` a buffer the caller passed in or one that something else still holds: zeroing it
 * would break that holder. Zeroing is best-effort: it reaches only these `Uint8Array`s, not
 * strings, copies the JavaScript runtime made, or memory inside the WASM library.
 */
export class KeyScope {
  private readonly owned = new Set<Uint8Array>();

  /** Takes ownership of `key` and returns it. */
  own<T extends Uint8Array>(key: T): T {
    this.owned.add(key);
    return key;
  }

  /** Takes ownership of every key in a keyset: its `SK` and each vault's `VK`. */
  ownKeyset<T extends { secretKey: Uint8Array; vaults: readonly { vk: Uint8Array }[] }>(
    keyset: T,
  ): T {
    this.own(keyset.secretKey);
    for (const vault of keyset.vaults) this.own(vault.vk);
    return keyset;
  }

  /** Hands `key` on: its new holder zeroes it. */
  release<T extends Uint8Array>(key: T): T {
    this.owned.delete(key);
    return key;
  }

  /** Zeroes everything still owned. */
  wipe(): void {
    for (const key of this.owned) key.fill(0);
    this.owned.clear();
  }
}

/** Runs `task` with a scope whose keys are zeroed when it settles, however it settles. */
export async function withKeys<T>(task: (keys: KeyScope) => Promise<T>): Promise<T> {
  const keys = new KeyScope();
  try {
    return await task(keys);
  } finally {
    keys.wipe();
  }
}
