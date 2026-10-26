import { Injectable } from '@nestjs/common';
import {
  MAX_OPEN_PAIRINGS,
  MAX_PAIRINGS_PER_HOUR,
  PAIRING_TTL_MS,
  type PairingApproveRequest,
  type PairingJoinRequest,
  type PairingStateResponse,
} from '@ruvee/contracts';
import { ApiException } from '../common/api-exception.js';
import { envelopeHeaderOk, fromBase64url, sha256, toBase64url } from '../common/secrets.js';
import { PrismaService } from '../database/prisma.service.js';
import type { Pairing } from '../generated/prisma/client.js';
import { SecurityEventsService } from '../security-events/security-events.service.js';
import { uuidToBytes } from '@ruvee/crypto';
import { ProofService } from '../sessions/proof.service.js';
import type { AuthenticatedSession } from '../sessions/session.service.js';
import type { ClientContext } from '../auth/auth.service.js';

const HOUR_MS = 60 * 60_000;

/**
 * The relay half of device-enrollment.md §3. The server stores opaque values, enforces the
 * single-request rule, expiry and limits, and takes `device_id_B` from B's session, never from a
 * body. It cannot check either MAC: only A and B hold `S`.
 */
@Injectable()
export class PairingService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly events: SecurityEventsService,
    private readonly proofs: ProofService,
  ) {}

  private async live(pairingIdText: string, accountId: string): Promise<Pairing> {
    const pairingId = fromBase64url(pairingIdText);
    const row = await this.prisma.pairing.findUnique({ where: { pairingId } });
    // Unknown, expired and other accounts' pairings all look the same (§3.1 "Attempts").
    if (row?.accountId !== accountId) throw new ApiException('not_found');
    if (row.expiresAt <= new Date()) {
      await this.prisma.pairing.deleteMany({ where: { pairingId } });
      throw new ApiException('not_found');
    }
    return row;
  }

  /** At most 3 open pairings and 10 created per hour per account (authentication.md §7). */
  async create(
    session: AuthenticatedSession,
    pairingIdText: string,
  ): Promise<{ expiresAt: string }> {
    const now = new Date();
    const pairingId = fromBase64url(pairingIdText);
    return this.prisma.$transaction(async (tx) => {
      await tx.pairing.deleteMany({
        where: { accountId: session.accountId, expiresAt: { lte: now } },
      });
      const open = await tx.pairing.count({ where: { accountId: session.accountId } });
      const subjectHash = sha256(`pairing\u0000${session.accountId}`);
      const key = { scope: 'pairing' as const, subjectHash };
      const window = await tx.authThrottle.findUnique({ where: { scope_subjectHash: key } });
      const fresh = !window || now.getTime() - window.windowStart.getTime() >= HOUR_MS;
      if (open >= MAX_OPEN_PAIRINGS || (!fresh && window.failureCount >= MAX_PAIRINGS_PER_HOUR)) {
        const retry = fresh ? 60 : (window.windowStart.getTime() + HOUR_MS - now.getTime()) / 1000;
        throw new ApiException('rate_limited', undefined, retry);
      }
      await tx.authThrottle.upsert({
        where: { scope_subjectHash: key },
        create: { ...key, failureCount: 1, windowStart: now },
        update: fresh ? { failureCount: 1, windowStart: now } : { failureCount: { increment: 1 } },
      });
      const exists = await tx.pairing.findUnique({ where: { pairingId } });
      if (exists) throw new ApiException('pairing_state');
      const expiresAt = new Date(now.getTime() + PAIRING_TTL_MS);
      await tx.pairing.create({
        data: {
          pairingId,
          accountId: session.accountId,
          initiatorDeviceId: session.deviceId,
          state: 'open',
          createdAt: now,
          expiresAt,
        },
      });
      return { expiresAt: expiresAt.toISOString() };
    });
  }

  async state(session: AuthenticatedSession, pairingIdText: string): Promise<PairingStateResponse> {
    const row = await this.live(pairingIdText, session.accountId);
    const role =
      row.initiatorDeviceId === session.deviceId
        ? 'initiator'
        : row.requesterDeviceId === session.deviceId
          ? 'requester'
          : undefined;
    // A pending device that has not requested yet sees nothing; it uses the request endpoint.
    if (!role) throw new ApiException('not_found');
    const base = {
      pairingId: toBase64url(row.pairingId),
      state: row.state,
      role,
      expiresAt: row.expiresAt.toISOString(),
    } as const;
    if (
      role === 'initiator' &&
      row.requesterDeviceId &&
      row.requestPlatform &&
      row.requestEpk &&
      row.requestDevicePublicKey &&
      row.requestMac &&
      row.requestedAt
    )
      return {
        ...base,
        request: {
          requesterDeviceId: row.requesterDeviceId,
          platform: row.requestPlatform,
          epk: toBase64url(row.requestEpk),
          devicePublicKey: toBase64url(row.requestDevicePublicKey),
          mac: toBase64url(row.requestMac),
          requestedAt: row.requestedAt.toISOString(),
        },
      };
    if (
      role === 'requester' &&
      row.state === 'approved' &&
      row.responseCiphertext &&
      row.responseMac
    )
      return {
        ...base,
        response: {
          ciphertext: toBase64url(row.responseCiphertext),
          mac: toBase64url(row.responseMac),
        },
      };
    return base;
  }

  /** Device B. Exactly one request per pairing; a second gets `409 pairing_state` (V-09). */
  async request(
    session: AuthenticatedSession,
    pairingIdText: string,
    body: PairingJoinRequest,
    client: ClientContext,
  ): Promise<void> {
    if (session.deviceStatus !== 'pending') throw new ApiException('forbidden');
    // The platform A is shown (and that the MAC binds) must be the one B logged in as.
    const device = await this.prisma.device.findUniqueOrThrow({ where: { id: session.deviceId } });
    if (device.platform !== body.platform) throw new ApiException('invalid_request');
    const row = await this.live(pairingIdText, session.accountId);
    const updated = await this.prisma.pairing.updateMany({
      where: { pairingId: row.pairingId, state: 'open', requesterDeviceId: null },
      data: {
        state: 'requested',
        requesterDeviceId: session.deviceId,
        requestPlatform: body.platform,
        requestEpk: fromBase64url(body.epk),
        // B's DPK, covered by `req_mac`, which only A can check (device-proof.md §8).
        requestDevicePublicKey: fromBase64url(body.devicePublicKey),
        requestMac: fromBase64url(body.mac),
        requestedAt: new Date(),
      },
    });
    if (updated.count !== 1) throw new ApiException('pairing_state');
    await this.events.record('device_pairing_requested', {
      accountId: session.accountId,
      deviceId: session.deviceId,
      ...client,
      details: { requesterDeviceId: session.deviceId },
    });
  }

  /**
   * Device A, after verifying `req_mac`: stores the sealed reply and enrolls B with the device key
   * of B's request. A's own `DSK` proof (op 8) covers B's id and key, the reply and the label, so
   * the server enrolls exactly the key A verified and approved.
   */
  async approve(
    session: AuthenticatedSession,
    pairingIdText: string,
    body: PairingApproveRequest,
    client: ClientContext,
  ): Promise<void> {
    const row = await this.live(pairingIdText, session.accountId);
    if (row.initiatorDeviceId !== session.deviceId) throw new ApiException('not_found');
    const label = body.label === undefined ? null : fromBase64url(body.label);
    if (label !== null && !envelopeHeaderOk(label, 0x08, { min: 61, max: 189 }))
      throw new ApiException('invalid_request');
    const requester = row.requesterDeviceId;
    const requesterKey = row.requestDevicePublicKey;
    if (row.state !== 'requested' || !requester || !requesterKey)
      throw new ApiException('pairing_state');
    const approver = await this.prisma.device.findUniqueOrThrow({
      where: { id: session.deviceId },
    });
    if (!approver.publicKey) throw new ApiException('device_proof_failed');
    const nonce = fromBase64url(body.nonce);
    const ciphertext = fromBase64url(body.ciphertext);
    const mac = fromBase64url(body.mac);
    await this.proofs.verifyBound(
      {
        operation: 'pairing_approve',
        accountId: session.accountId,
        deviceId: session.deviceId,
        binding: this.proofs.sessionRef(session.sessionId),
        nonce,
        payload: this.proofs.payload('pairing_approve', [
          row.pairingId,
          uuidToBytes(requester),
          requesterKey,
          ciphertext,
          mac,
          label,
        ]),
        device: { publicKey: approver.publicKey, signature: fromBase64url(body.proof.device) },
      },
      session.sessionId,
    );
    const now = new Date();
    await this.prisma.$transaction(async (tx) => {
      await this.proofs.consume(tx, session.sessionId, 'pairing_approve', nonce);
      const updated = await tx.pairing.updateMany({
        where: { pairingId: row.pairingId, state: 'requested', requesterDeviceId: requester },
        data: {
          state: 'approved',
          responseCiphertext: ciphertext,
          responseMac: mac,
        },
      });
      if (updated.count !== 1) throw new ApiException('pairing_state');
      const device = await tx.device.updateMany({
        where: { id: requester, accountId: session.accountId, status: 'pending' },
        data: {
          status: 'active',
          enrolledVia: 'pairing',
          approvedByDeviceId: session.deviceId,
          enrolledAt: now,
          label,
          publicKey: requesterKey,
        },
      });
      if (device.count !== 1) throw new ApiException('pairing_state');
      await this.events.record(
        'device_enrolled',
        {
          accountId: session.accountId,
          deviceId: session.deviceId,
          ...client,
          details: { enrolledDeviceId: requester, via: 'pairing' },
        },
        tx,
      );
    });
  }

  /** Device B, now active, after it verified and stored everything: the pairing is deleted. */
  async complete(session: AuthenticatedSession, pairingIdText: string): Promise<void> {
    const row = await this.live(pairingIdText, session.accountId);
    if (row.requesterDeviceId !== session.deviceId || row.state !== 'approved')
      throw new ApiException('pairing_state');
    await this.prisma.pairing.deleteMany({ where: { pairingId: row.pairingId } });
  }

  /** Either device cancels; A reports a failed `req_mac`, which burns the pairing (§3.2 step 6). */
  async cancel(
    session: AuthenticatedSession,
    pairingIdText: string,
    reason: 'user' | 'mac_failed' | undefined,
    client: ClientContext,
  ): Promise<void> {
    const row = await this.live(pairingIdText, session.accountId);
    if (row.initiatorDeviceId !== session.deviceId && row.requesterDeviceId !== session.deviceId)
      throw new ApiException('not_found');
    await this.prisma.pairing.deleteMany({ where: { pairingId: row.pairingId } });
    if (reason === 'mac_failed' && row.requesterDeviceId)
      await this.events.record('pairing_mac_failed', {
        accountId: session.accountId,
        deviceId: session.deviceId,
        ...client,
        details: { requesterDeviceId: row.requesterDeviceId },
      });
  }
}
