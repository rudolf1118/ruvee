import { randomBytes } from 'node:crypto';
import { Injectable, type OnModuleDestroy, type OnModuleInit } from '@nestjs/common';
import {
  initRuveeCrypto,
  uuidToBytes,
  type LoginStateContext,
  type RuveeCrypto,
} from '@ruvee/crypto';
import { ApiException } from '../common/api-exception.js';
import { sha256, type Bytes } from '../common/secrets.js';
import { PrismaService } from '../database/prisma.service.js';
import { OpaqueServerService } from './opaque-server.service.js';

/** authentication.md §4: a server login state lives for 60 seconds and is consumed once. */
export const LOGIN_STATE_TTL_MS = 60_000;
/** Bound on live pending logins, so unauthenticated requests cannot exhaust the database. */
export const MAX_PENDING = 10_000;
/** Expired states removed per new login, at most. */
const PRUNE_BATCH = 500;
const LOGIN_ID_BYTES = 16;
const CHALLENGE_BYTES = 32;

export interface PendingLogin {
  readonly serverLoginState: string;
  /** SHA-256 of the normalized username (throttle.service.ts `loginSubject`), never the name. */
  readonly loginSubject: Bytes;
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
}

interface Row {
  purpose: 'login' | 'reauth' | 'reopen';
  login_subject: Buffer;
  account_id: string | null;
  device_id: string | null;
  platform: 'web' | 'extension';
  session_id: string | null;
  reopen_code_id: string | null;
  sealed: Buffer;
  expires_at: Date;
  now: Date;
}

function purposeOf(login: { sessionId?: string; reopenCodeId?: string }): Row['purpose'] {
  if (login.sessionId !== undefined) return 'reauth';
  if (login.reopenCodeId !== undefined) return 'reopen';
  return 'login';
}

const uuid = (id: string | null) => (id === null ? null : uuidToBytes(id));

/** Every column but `sealed`: the seal opens only for the row it was made for. */
function sealContext(idHash: Buffer, row: Omit<Row, 'sealed' | 'now'>): LoginStateContext {
  return {
    idHash,
    purpose: row.purpose,
    loginSubject: row.login_subject,
    accountId: uuid(row.account_id),
    deviceId: uuid(row.device_id),
    platform: row.platform,
    sessionId: uuid(row.session_id),
    reopenCodeId: uuid(row.reopen_code_id),
    expiresAtMs: row.expires_at.getTime(),
  };
}

/**
 * Pending OPAQUE logins, step-ups and reopenings, in the database so that a login started on one
 * API process can be finished on another (follow-up review §17.2 option B). The row stores only
 * SHA-256 of the `loginId`, and what the state is bound to. The OPAQUE server login state (from
 * which the expected client MAC follows) and the device challenge are sealed by `@ruvee/crypto`
 * (XChaCha20-Poly1305, authentication.md §4.1) under a key of the setup file and the `loginId`
 * the client holds, neither of which is in the database: reading the table, or a dump of it, is
 * not enough to finish someone's login.
 *
 * `consume` deletes the row and returns it in one statement, so a `loginId` is usable at most
 * once however many processes race for it (spike OP-07, INV-23); the library itself does not
 * ensure that. No transaction stays open while OPAQUE runs. The same store serves `reauth`.
 */
@Injectable()
export class LoginStateStore implements OnModuleInit, OnModuleDestroy {
  private crypto: RuveeCrypto | undefined;
  /** `K_seal`, derived once from the setup; wiped when the module stops. */
  private key: Uint8Array | undefined;

  constructor(
    private readonly prisma: PrismaService,
    private readonly opaque: OpaqueServerService,
  ) {}

  async onModuleInit(): Promise<void> {
    this.crypto = await initRuveeCrypto();
  }

  onModuleDestroy(): void {
    this.key?.fill(0);
    this.key = undefined;
  }

  /** Derived on first use, after the setup has loaded, whatever order the modules start in. */
  private seal(): { crypto: RuveeCrypto; sealKey: Uint8Array } {
    if (!this.crypto) throw new Error('login-state crypto not loaded');
    if (!this.key) {
      const setup = this.opaque.setupBytes();
      try {
        this.key = this.crypto.deriveLoginStateSealKey(setup);
      } finally {
        setup.fill(0);
      }
    }
    return { crypto: this.crypto, sealKey: this.key };
  }

  /**
   * Stores a new state, in database time. One statement removes up to PRUNE_BATCH expired states
   * and inserts this one only while fewer than MAX_PENDING live states exist; otherwise the login
   * is refused (`rate_limited`). A live state is never removed to make room. Statements that run
   * at the same moment can each see room, so the bound may be passed by at most their number.
   */
  async put(
    login: Omit<PendingLogin, 'challenge'>,
    now?: Date,
  ): Promise<{ loginId: string; challenge: Uint8Array }> {
    const loginId = randomBytes(LOGIN_ID_BYTES);
    const challenge = new Uint8Array(randomBytes(CHALLENGE_BYTES));
    const idHash = Buffer.from(sha256(loginId));
    const [clock] = await this.prisma.$queryRaw<{ now: Date }[]>`
      SELECT COALESCE(${now ?? null}::timestamptz, now())::timestamptz(3) AS now`;
    if (!clock) throw new Error('no database time');
    const row = {
      purpose: purposeOf(login),
      login_subject: Buffer.from(login.loginSubject),
      account_id: login.accountId,
      device_id: login.deviceId ?? null,
      platform: login.platform,
      session_id: login.sessionId ?? null,
      reopen_code_id: login.reopenCodeId ?? null,
      expires_at: new Date(clock.now.getTime() + LOGIN_STATE_TTL_MS),
    };
    const { crypto, sealKey } = this.seal();
    const state = new TextEncoder().encode(login.serverLoginState);
    const sealed = Buffer.from(
      crypto.sealLoginState({
        sealKey,
        loginId,
        context: sealContext(idHash, row),
        challenge,
        serverLoginState: state,
      }),
    );
    state.fill(0);
    const inserted = await this.prisma.$executeRaw`
      WITH pruned AS (
        DELETE FROM login_states
        WHERE expires_at <= ${clock.now}
          AND id_hash IN (SELECT id_hash FROM login_states WHERE expires_at <= ${clock.now}
                          LIMIT ${PRUNE_BATCH})
        RETURNING 1)
      INSERT INTO login_states (id_hash, purpose, login_subject, account_id, device_id,
        platform, session_id, reopen_code_id, sealed, created_at, expires_at)
      SELECT ${idHash}, ${row.purpose}::login_purpose, ${row.login_subject},
        ${row.account_id}::uuid, ${row.device_id}::uuid, ${row.platform}::device_platform,
        ${row.session_id}::uuid, ${row.reopen_code_id}::uuid, ${sealed}, ${clock.now},
        ${row.expires_at}
      WHERE (SELECT count(*) FROM login_states WHERE expires_at > ${clock.now}) < ${MAX_PENDING}`;
    if (inserted !== 1)
      throw new ApiException('rate_limited', undefined, LOGIN_STATE_TTL_MS / 1000);
    const id = loginId.toString('base64url');
    loginId.fill(0);
    return { loginId: id, challenge };
  }

  /**
   * Removes the state and returns it if it was live and opens. Anything else (unknown, already
   * consumed, expired, altered, sealed under another setup) is undefined; the row is gone in
   * every case.
   */
  async consume(loginId: string, now?: Date): Promise<PendingLogin | undefined> {
    const id = Buffer.from(loginId, 'base64url');
    if (id.length !== LOGIN_ID_BYTES || id.toString('base64url') !== loginId) return undefined;
    const idHash = Buffer.from(sha256(id));
    const [row] = await this.prisma.$queryRaw<Row[]>`
      DELETE FROM login_states WHERE id_hash = ${idHash}
      RETURNING purpose::text AS purpose, login_subject, account_id::text AS account_id,
        device_id::text AS device_id, platform::text AS platform, session_id::text AS session_id,
        reopen_code_id::text AS reopen_code_id, sealed, expires_at,
        COALESCE(${now ?? null}::timestamptz, now()) AS now`;
    if (!row || row.expires_at <= row.now) return undefined;
    const { crypto, sealKey } = this.seal();
    const opened = crypto.openLoginState({
      sealKey,
      loginId: id,
      context: sealContext(idHash, { ...row, login_subject: Buffer.from(row.login_subject) }),
      sealed: new Uint8Array(row.sealed),
    });
    id.fill(0);
    if (!opened) return undefined;
    const login: PendingLogin = {
      serverLoginState: new TextDecoder().decode(opened.serverLoginState),
      loginSubject: new Uint8Array(row.login_subject),
      accountId: row.account_id,
      deviceId: row.device_id ?? undefined,
      platform: row.platform,
      challenge: opened.challenge,
      ...(row.session_id === null ? {} : { sessionId: row.session_id }),
      ...(row.reopen_code_id === null ? {} : { reopenCodeId: row.reopen_code_id }),
    };
    opened.serverLoginState.fill(0);
    return login;
  }
}
