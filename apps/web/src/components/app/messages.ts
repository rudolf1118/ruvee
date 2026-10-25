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
    case 'invalid_pairing_code':
      return 'That code has a typo. Check it against the code shown on your other device.';
    case 'pairing_used':
      return 'This code was already used. Cancel on the other device and start again.';
    case 'pairing_expired':
      return 'This pairing has expired or was cancelled. Start again on the other device.';
    case 'pairing_failed':
      return 'This request did not come from the device you are pairing. Nothing was shared. Start again.';
    case 'password_required':
      return 'Enter your master password to finish adding this device.';
    case 'recovery_failed':
      return "That username and Recovery Key don't work together. Check both and try again.";
    case 'cannot_revoke_current':
      return "You can't remove the device you are using. Log out on it instead.";
    case 'changed_elsewhere':
      return 'Your account changed on another device in the meantime. Nothing was changed here. Try again.';
    case 'integrity':
      return "The server's copy of your keys didn't pass Ruvee's checks. Nothing was changed.";
    case 'internal':
      return 'Something went wrong. Try again.';
  }
}

function formatSeconds(seconds: number): string {
  if (seconds < 60) return `${Math.ceil(seconds)} seconds`;
  return `${Math.ceil(seconds / 60)} minutes`;
}
