import type { ExtensionRequest, ExtensionResponse } from '../messages';

export class CallError extends Error {
  constructor(
    readonly code: string,
    readonly retryAfterSeconds?: number,
  ) {
    super(code);
    this.name = 'CallError';
  }
}

/** One request to the service worker; its reply is the only channel back. */
export async function call<T>(request: ExtensionRequest): Promise<T> {
  const response = (await chrome.runtime.sendMessage(request)) as ExtensionResponse | undefined;
  if (!response) throw new CallError('internal');
  if (!response.ok) throw new CallError(response.code, response.retryAfterSeconds);
  return response.result as T;
}

const PAIRING_INTERRUPTED =
  'This browser was already approved, but the pairing was interrupted before it could finish here, so a code cannot complete it. Log in again to start over, then add this browser with a new code. The unfinished entry can be removed under Devices in the web app.';

/**
 * During pairing, codes that mean this device left the pending state without the join that could
 * finish it (the server answers `forbidden` or `device_proof_required` to another request, or the
 * session ended). Only a new login recovers: it starts a new device.
 */
export const PAIRING_RESTART_CODES: ReadonlySet<string> = new Set([
  'pairing_interrupted',
  'forbidden',
  'device_proof_required',
  'device_key_missing',
  'device_not_enrolled',
  'session_expired',
]);

/** `messageFor`, worded for the pairing screen. */
export function pairingMessageFor(e: unknown): string {
  const code = e instanceof CallError ? e.code : 'internal';
  if (PAIRING_RESTART_CODES.has(code)) return PAIRING_INTERRUPTED;
  return messageFor(e);
}

/**
 * `messageFor`, and for a code it has no words for, which call failed and its code: the
 * development build has no other way to tell (codes are never secret, INV-12).
 */
export function stepMessageFor(step: string, e: unknown): string {
  const text = messageFor(e);
  if (text !== GENERIC) return text;
  const code = e instanceof CallError ? e.code : 'internal';
  return `${GENERIC} (${step}: ${code})`;
}

const GENERIC = 'Something went wrong. Try again.';

/** User-facing text for the codes the worker reports. Never says more than the code does. */
export function messageFor(e: unknown): string {
  const code = e instanceof CallError ? e.code : 'internal';
  switch (code) {
    case 'wrong_password':
      return "That's not the right master password.";
    case 'login_failed':
      return 'The username or master password is not correct.';
    case 'rate_limited':
      return 'Too many attempts. Wait a few minutes and try again.';
    case 'offline':
      return "Can't reach your Ruvee server. Check the server address in Settings and your connection.";
    case 'session_expired':
      return 'Your session ended. Unlock again.';
    case 'device_revoked':
      return 'This browser was removed from your account, and its local copy was erased.';
    case 'invalid_pairing_code':
      return 'That code has a typo. Check it against the code shown on your other device.';
    case 'pairing_used':
      return 'This code was already used. Start again on the other device.';
    case 'pairing_expired':
      return 'This pairing has expired or was cancelled. Start again on the other device.';
    case 'pairing_failed':
      return 'This request did not match. Nothing was shared. Start again.';
    case 'password_required':
      return 'Enter your master password to finish adding this browser.';
    case 'pairing_interrupted':
      return PAIRING_INTERRUPTED;
    case 'previous_password_required':
      return 'Your master password and Secret Key were both changed on another device. Also enter the master password this browser used before.';
    case 'not_found':
      return 'That item is no longer in your vault. It may have been deleted on another device.';
    case 'locked':
      return 'The vault is locked.';
    case 'server_reopening':
      return 'Your Ruvee server was restored and waits for its owner to reopen it in the web app. This browser keeps its copy, read-only.';
    case 'server_maintenance':
      return 'Your Ruvee server is being restored by its owner and is not available yet. This browser keeps its copy, read-only.';
    default:
      return GENERIC;
  }
}
