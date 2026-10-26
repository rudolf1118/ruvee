import { randomBytes } from 'node:crypto';
import { Injectable } from '@nestjs/common';

/** authentication.md §4: a server login state lives for 60 seconds and is consumed once. */
export const LOGIN_STATE_TTL_MS = 60_000;
/** Bound on pending logins, so unauthenticated requests cannot exhaust memory. */
const MAX_PENDING = 10_000;

export interface PendingLogin {
  readonly serverLoginState: string;
  readonly username: string;
  /** Null for an unknown username; such a login can never succeed. */
  readonly accountId: string | null;
  readonly deviceId: string | undefined;
  readonly platform: 'web' | 'extension';
  /** Set for `reauth`: the state can only finish on this session. */
  readonly sessionId?: string;
  /** Set for a reopening (backup-restore.md §3.13): finishes only at /reopen/login/finish. */
  readonly reopenCodeId?: string;
  /** The 32-byte nonce an enrolled device signs at finish (device-proof.md §5). */
  readonly challenge: Uint8Array;
  readonly expiresAt: number;
}

/**
 * Single-process store of pending OPAQUE logins (V1 runs one API instance). `consume` removes the
 * entry before returning it, so a `loginId` is usable at most once, which the library itself
 * does not ensure (spike OP-07, INV-23). The same store serves `reauth`.
 */
@Injectable()
export class LoginStateStore {
  private readonly pending = new Map<string, PendingLogin>();

  put(
    login: Omit<PendingLogin, 'expiresAt' | 'challenge'>,
    now = Date.now(),
  ): {
    loginId: string;
    challenge: Uint8Array;
  } {
    if (this.pending.size >= MAX_PENDING) this.sweep(now);
    if (this.pending.size >= MAX_PENDING) {
      // Still full of live entries: drop the oldest rather than refuse every new login.
      const oldest = this.pending.keys().next().value;
      if (oldest !== undefined) this.pending.delete(oldest);
    }
    const loginId = randomBytes(16).toString('base64url');
    const challenge = new Uint8Array(randomBytes(32));
    this.pending.set(loginId, { ...login, challenge, expiresAt: now + LOGIN_STATE_TTL_MS });
    return { loginId, challenge };
  }

  consume(loginId: string, now = Date.now()): PendingLogin | undefined {
    const login = this.pending.get(loginId);
    this.pending.delete(loginId);
    if (!login || login.expiresAt <= now) return undefined;
    return login;
  }

  private sweep(now: number): void {
    for (const [id, login] of this.pending) if (login.expiresAt <= now) this.pending.delete(id);
  }
}
