import { randomBytes, randomUUID } from 'node:crypto';
import { Injectable, type OnModuleInit } from '@nestjs/common';
import {
  initRuveeCrypto,
  PROOF_OPERATIONS,
  uuidToBytes,
  type ProofField,
  type ProofOperation,
  type RuveeCrypto,
} from '@ruvee/crypto';
import type { ProofNonceOperation, ProofNonceResponse } from '@ruvee/contracts';
import { ApiException } from '../common/api-exception.js';
import { sha256, toBase64url, type Bytes } from '../common/secrets.js';
import { PrismaService } from '../database/prisma.service.js';
import type { Prisma } from '../generated/prisma/client.js';
import type { AuthenticatedSession } from './session.service.js';

/** device-proof.md §6: a nonce lives 2 minutes; a session has one open nonce per operation. */
export const PROOF_NONCE_TTL_MS = 2 * 60_000;
/** First setup signs 32 zero bytes as its nonce: the setup token is single-use (§4). */
export const SETUP_NONCE = new Uint8Array(32);

export interface ProofCheck {
  readonly operation: ProofOperation;
  readonly accountId: string;
  readonly deviceId: string;
  readonly binding: Uint8Array;
  readonly nonce: Uint8Array;
  readonly payload: Uint8Array;
  /** `DPK` and its signature. */
  readonly device: { readonly publicKey: Uint8Array; readonly signature: Uint8Array };
  /** `AVPK` and its signature, for operations that replace key material. */
  readonly accountKey?: {
    readonly akId: Uint8Array;
    readonly akEpoch: number;
    readonly publicKey: Uint8Array;
    readonly signature: Uint8Array;
  };
}

/**
 * Device proof of possession on the server (docs/security/device-proof.md, D-31 A). The signed
 * bytes come from `@ruvee/crypto`, the same code the clients sign with. Verification changes no
 * state; a nonce is consumed only inside the transaction of the operation it authorizes.
 */
@Injectable()
export class ProofService implements OnModuleInit {
  private crypto: RuveeCrypto | undefined;

  constructor(private readonly prisma: PrismaService) {}

  async onModuleInit(): Promise<void> {
    this.crypto = await initRuveeCrypto();
  }

  private get ops(): RuveeCrypto {
    if (!this.crypto) throw new ApiException('internal_error');
    return this.crypto;
  }

  payload(operation: ProofOperation, fields: readonly ProofField[]): Uint8Array {
    return this.ops.proofPayload(operation, fields);
  }

  sessionRef(sessionId: string): Uint8Array {
    return this.ops.sessionRef(uuidToBytes(sessionId));
  }

  loginBinding(loginId: Uint8Array): Uint8Array {
    return this.ops.loginBinding(loginId);
  }

  setupBinding(bootstrapToken: Uint8Array): Uint8Array {
    return this.ops.setupBinding(bootstrapToken);
  }

  /**
   * A fresh nonce for one operation of this session (§6); it replaces any open nonce of the same
   * session and operation, so retries never pile up and a session holds at most one open nonce
   * per operation. Only its SHA-256 is stored.
   */
  async issue(
    session: AuthenticatedSession,
    operation: ProofNonceOperation,
    now = new Date(),
  ): Promise<ProofNonceResponse> {
    const nonce = new Uint8Array(randomBytes(32));
    const expiresAt = new Date(now.getTime() + PROOF_NONCE_TTL_MS);
    await this.prisma.proofNonce.deleteMany({
      where: {
        sessionId: session.sessionId,
        operation: PROOF_OPERATIONS[operation],
        consumedAt: null,
      },
    });
    await this.prisma.proofNonce.create({
      data: {
        id: randomUUID(),
        accountId: session.accountId,
        deviceId: session.deviceId,
        sessionId: session.sessionId,
        operation: PROOF_OPERATIONS[operation],
        nonceHash: sha256(nonce),
        createdAt: now,
        expiresAt,
      },
    });
    return {
      nonce: toBase64url(nonce),
      sessionRef: toBase64url(this.sessionRef(session.sessionId)),
      expiresAt: expiresAt.toISOString(),
    };
  }

  /** Both signatures of `check` are valid. Pure: nothing is consumed or recorded. */
  valid(check: ProofCheck): boolean {
    const base = {
      operation: check.operation,
      accountId: uuidToBytes(check.accountId),
      binding: check.binding,
      nonce: check.nonce,
      payload: check.payload,
    };
    try {
      if (
        !this.ops.verifyDeviceProof({
          ...base,
          deviceId: uuidToBytes(check.deviceId),
          publicKey: check.device.publicKey,
          signature: check.device.signature,
        })
      )
        return false;
      return (
        !check.accountKey ||
        this.ops.verifyAccountProof({
          ...base,
          accountKeyId: check.accountKey.akId,
          accountKeyEpoch: check.accountKey.akEpoch,
          publicKey: check.accountKey.publicKey,
          signature: check.accountKey.signature,
        })
      );
    } catch {
      // A malformed key or signature is simply not a valid proof.
      return false;
    }
  }

  /**
   * Checks the signatures of a nonce-bound operation. An invalid proof burns its nonce, so it
   * cannot be retried, and fails with `device_proof_failed`.
   */
  async verifyBound(check: ProofCheck, sessionId: string): Promise<void> {
    if (this.valid(check)) return;
    await this.prisma.proofNonce.updateMany({
      where: { nonceHash: sha256(check.nonce), sessionId, consumedAt: null },
      data: { consumedAt: new Date() },
    });
    throw new ApiException('device_proof_failed');
  }

  /**
   * Consumes the nonce inside the operation's transaction (§6): bound to this session and
   * operation, unexpired and unused. Exactly one concurrent request can succeed.
   */
  async consume(
    tx: Prisma.TransactionClient,
    sessionId: string,
    operation: ProofOperation,
    nonce: Bytes,
  ): Promise<void> {
    const consumed = await tx.proofNonce.updateMany({
      where: {
        nonceHash: sha256(nonce),
        sessionId,
        operation: PROOF_OPERATIONS[operation],
        consumedAt: null,
        expiresAt: { gt: new Date() },
      },
      data: { consumedAt: new Date() },
    });
    if (consumed.count !== 1) throw new ApiException('device_proof_failed');
  }
}
