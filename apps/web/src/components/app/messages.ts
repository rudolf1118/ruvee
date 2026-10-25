import type { VaultErrorCode } from '@/vault/protocol';

/** User-facing text for worker error codes. Never says more than the code does. */
export function messageFor(code: VaultErrorCode, retryAfterSeconds?: number): string {
  switch (code) {
    case 'wrong_password':
      return "That's not the right master password. Check that Caps Lock is off and try again.";
    case 'login_failed':
      return 'The username or master password is not correct.';
    case 'rate_limited':
      return `Too many attempts. Wait ${retryAfterSeconds ? formatSeconds(retryAfterSeconds) : 'a moment'} and try again.`;
    case 'bootstrap_failed':
      return 'This setup token is not valid. It may have expired or been used already. Create a new one with ruvee-admin bootstrap-token.';
    case 'registration_closed':
      return 'This server already has an account. Log in instead.';
    case 'invalid_password':
      return 'Choose a master password of at least 12 characters.';
    case 'invalid_username':
      return 'Use 1 to 64 letters, digits, dots, dashes or underscores.';
    case 'invalid_recovery_key':
      return 'That Recovery Key has a typo. Check each group of characters against your kit.';
    case 'kit_mismatch':
      return "That Recovery Key doesn't match the one shown for this account.";
    case 'offline':
      return "Can't reach the Ruvee server. Check your connection and try again.";
    case 'session_expired':
      return 'Your session ended. Unlock again to continue.';
    case 'device_revoked':
      return 'This device was removed from your account. Its local copy has been erased.';
    case 'device_not_enrolled':
      return 'This device is not set up yet.';
    case 'read_only':
      return "Changes are paused because the server's copy didn't pass Ruvee's checks.";
    case 'invalid_item':
      return 'Some fields are not valid. Check them and try again.';
    case 'not_found':
      return 'That item no longer exists.';
    case 'locked':
      return 'The vault is locked.';
    case 'internal':
      return 'Something went wrong. Try again.';
  }
}

function formatSeconds(seconds: number): string {
  if (seconds < 60) return `${Math.ceil(seconds)} seconds`;
  return `${Math.ceil(seconds / 60)} minutes`;
}
