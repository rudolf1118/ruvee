import type { RecoveryCompleteRequest } from '@ruvee/contracts';
import { ApiException } from '../common/api-exception.js';
import { constantTimeEqual, fromBase64url, type Bytes } from '../common/secrets.js';
import type { AccountKeys } from '../generated/prisma/client.js';
import type { ProofService } from './proof.service.js';
import type { AuthenticatedSession } from './session.service.js';

export interface CompletionKeys {
  readonly nonce: Bytes;
  readonly devicePublicKey: Bytes;
  readonly akVerifyKey: Bytes;
}

/**
 * device-proof.md §8, recovery and reopening: the completion carries the device key the device
 * will use from now on and the account's `AVPK`, with a `DSK` proof and an `AVSK` proof over the
 * same fields (op 9 or 11). `deviceKey` is the key the `DSK` proof must verify with: the new key
 * for a recovery, the restored key for the reopening password path. The `AVSK` proof is checked
 * against the account's stored `AVPK`, so only a holder of `AK` replaces the wraps. An account
 * from before D-31 has none, and the presented one is never taken as the trust anchor: it must
 * move to a new account (device-proof.md §9). Checked before anything changes; the caller
 * consumes `nonce` in its transaction.
 */
export async function proveCompletion(
  proofs: ProofService,
  operation: 'recovery_complete' | 'reopen_complete',
  session: AuthenticatedSession,
  body: RecoveryCompleteRequest,
  keys: AccountKeys,
  deviceKey: Uint8Array,
): Promise<CompletionKeys> {
  const devicePublicKey = fromBase64url(body.devicePublicKey);
  const akVerifyKey = fromBase64url(body.akVerifyKey);
  if (!keys.akVerifyKey) throw new ApiException('migration_required');
  if (!constantTimeEqual(keys.akVerifyKey, akVerifyKey))
    throw new ApiException('device_key_mismatch');
  const nonce = fromBase64url(body.nonce);
  await proofs.verifyBound(
    {
      operation,
      accountId: session.accountId,
      deviceId: session.deviceId,
      binding: proofs.sessionRef(session.sessionId),
      nonce,
      payload: proofs.payload(operation, [
        fromBase64url(body.registrationRecord),
        { u8: body.kdfProfile },
        fromBase64url(body.saltPw),
        fromBase64url(body.wrappedAkPassword),
        fromBase64url(body.recoveryKeyId),
        fromBase64url(body.wrappedAkRecovery),
        fromBase64url(body.recoveryVerifier),
        { u64: body.expectedRowVersion },
        body.label === undefined ? null : fromBase64url(body.label),
        devicePublicKey,
        akVerifyKey,
      ]),
      device: { publicKey: deviceKey, signature: fromBase64url(body.proof.device) },
      accountKey: {
        akId: keys.akId,
        akEpoch: keys.akEpoch,
        publicKey: keys.akVerifyKey,
        signature: fromBase64url(body.proof.accountKey),
      },
    },
    session.sessionId,
  );
  return { nonce, devicePublicKey, akVerifyKey };
}
