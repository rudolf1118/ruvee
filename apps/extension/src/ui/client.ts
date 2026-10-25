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
    case 'previous_password_required':
      return 'Your master password and Secret Key were both changed on another device. Also enter the master password this browser used before.';
    case 'locked':
      return 'The vault is locked.';
    default:
      return 'Something went wrong. Try again.';
  }
}
