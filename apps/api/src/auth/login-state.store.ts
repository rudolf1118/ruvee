import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { Injectable } from '@nestjs/common';
import { OPAQUE_CONFIG_ID } from '@ruvee/contracts';
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
const SEAL_VERSION = 0x01;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
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

/**
 * Everything the row binds the sealed state to: a state moved to another row, or a row whose
 * account, device, session, code, purpose or expiry was changed, no longer opens.
 */
function associatedData(idHash: Buffer, row: Omit<Row, 'sealed' | 'now'>): Buffer {
  return Buffer.from(
    JSON.stringify([
      'ruvee-login-state-v1',
      OPAQUE_CONFIG_ID,
      idHash.toString('hex'),
      row.purpose,
      row.login_subject.toString('hex'),
      row.account_id,
      row.device_id,
      row.platform,
      row.session_id,
      row.reopen_code_id,
      row.expires_at.getTime(),
    ]),
  );
}

/**
 * Pending OPAQUE logins, step-ups and reopenings, in the database so that a login started on one
 * API process can be finished on another (follow-up review §17.2 option B). The row stores only
 * SHA-256 of the `loginId`, and what the state is bound to. The OPAQUE server login state (from
 * which the expected client MAC follows) and the device challenge are sealed with AES-256-GCM
 * under `OpaqueServerService.loginStateKey`, which is derived from the setup file and never in
 * the database: reading the table, or a dump of it, is not enough to finish someone's login.
 *
 * `consume` deletes the row and returns it in one statement, so a `loginId` is usable at most
 * once however many processes race for it (spike OP-07, INV-23); the library itself does not
 * ensure that. No transaction stays open while OPAQUE runs. The same store serves `reauth`.
 */
@Injectable()
export class LoginStateStore {
  constructor(
    private readonly prisma: PrismaService,
    private readonly opaque: OpaqueServerService,
  ) {}

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
    const loginId = randomBytes(16);
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
    const key = this.opaque.loginStateKey();
    const nonce = randomBytes(NONCE_BYTES);
    const cipher = createCipheriv('aes-256-gcm', key, nonce);
    key.fill(0);
    cipher.setAAD(associatedData(idHash, row));
    const plain = Buffer.concat([challenge, Buffer.from(login.serverLoginState, 'utf8')]);
    const sealed = Buffer.concat([
      Buffer.of(SEAL_VERSION),
      nonce,
      cipher.update(plain),
      cipher.final(),
      cipher.getAuthTag(),
    ]);
    plain.fill(0);
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
    return { loginId: loginId.toString('base64url'), challenge };
  }

  /**
   * Removes the state and returns it if it was live and opens. Anything else (unknown, already
   * consumed, expired, altered, sealed under another setup) is undefined; the row is gone in
   * every case.
   */
  async consume(loginId: string, now?: Date): Promise<PendingLogin | undefined> {
    const id = Buffer.from(loginId, 'base64url');
    if (id.length !== 16 || id.toString('base64url') !== loginId) return undefined;
    const idHash = Buffer.from(sha256(id));
    const [row] = await this.prisma.$queryRaw<Row[]>`
      DELETE FROM login_states WHERE id_hash = ${idHash}
      RETURNING purpose::text AS purpose, login_subject, account_id::text AS account_id,
        device_id::text AS device_id, platform::text AS platform, session_id::text AS session_id,
        reopen_code_id::text AS reopen_code_id, sealed, expires_at,
        COALESCE(${now ?? null}::timestamptz, now()) AS now`;
    if (!row || row.expires_at <= row.now) return undefined;
    const sealed = Buffer.from(row.sealed);
    if (sealed.length < 1 + NONCE_BYTES + TAG_BYTES + CHALLENGE_BYTES || sealed[0] !== SEAL_VERSION)
      return undefined;
    const key = this.opaque.loginStateKey();
    let plain: Buffer;
    try {
      const decipher = createDecipheriv('aes-256-gcm', key, sealed.subarray(1, 1 + NONCE_BYTES));
      decipher.setAAD(
        associatedData(idHash, { ...row, login_subject: Buffer.from(row.login_subject) }),
      );
      decipher.setAuthTag(sealed.subarray(sealed.length - TAG_BYTES));
      plain = Buffer.concat([
        decipher.update(sealed.subarray(1 + NONCE_BYTES, sealed.length - TAG_BYTES)),
        decipher.final(),
      ]);
    } catch {
      return undefined;
    } finally {
      key.fill(0);
    }
    const login: PendingLogin = {
      serverLoginState: plain.subarray(CHALLENGE_BYTES).toString('utf8'),
      loginSubject: new Uint8Array(row.login_subject),
      accountId: row.account_id,
      deviceId: row.device_id ?? undefined,
      platform: row.platform,
      challenge: new Uint8Array(plain.subarray(0, CHALLENGE_BYTES)),
      ...(row.session_id === null ? {} : { sessionId: row.session_id }),
      ...(row.reopen_code_id === null ? {} : { reopenCodeId: row.reopen_code_id }),
    };
    plain.fill(0);
    return login;
  }
}
