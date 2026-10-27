import type { VaultErrorCode } from '@ruvee/vault';

/**
 * User-facing text for engine error codes: the web app's wording
 * (apps/web/src/components/app/messages.ts), with "this browser" read as "this device". Never
 * says more than the code does.
 */
export function messageFor(code: VaultErrorCode, retryAfterSeconds?: number): string {
  switch (code) {
    case 'wrong_password':
      return "That's not the right master password. Try again.";
    case 'login_failed':
      return 'The username or master password is not correct.';
    case 'rate_limited':
      return `Too many attempts. Wait ${retryAfterSeconds ? formatSeconds(retryAfterSeconds) : 'a moment'} and try again.`;
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
    case 'changed_elsewhere':
      return 'Your account changed on another device in the meantime. Nothing was changed here. Try again.';
    case 'previous_password_required':
      return 'Your master password and Secret Key were both changed on another device. To move this device over, also enter the master password you used here before.';
    case 'integrity':
      return "The server's copy of your keys didn't pass Ruvee's checks. Nothing was changed.";
    case 'server_maintenance':
      return 'The server is being restored by its owner and is not available yet. Your local copy is kept, read-only.';
    case 'server_reopening':
      return 'The server was restored and waits for its owner to reopen it. Your local copy is kept, read-only.';
    case 'device_key_missing':
      return "This device can't prove its device key to the server, so it won't sync. Everything on this device is kept. Recovery with the Recovery Kit is available in the web app.";
    case 'migration_required':
      return "This account was created before device keys and can't be enrolled on a device again. Nothing was changed.";
    case 'unsynced_changes':
      return 'Some changes are still waiting to sync or are in conflict. Resolve them, then try again.';
    case 'import_in_progress':
      return 'An import is still uploading. You can edit once it is complete.';
    default:
      return 'Something went wrong. Try again.';
  }
}

function formatSeconds(seconds: number): string {
  if (seconds < 60) return `${Math.ceil(seconds)} seconds`;
  return `${Math.ceil(seconds / 60)} minutes`;
}
