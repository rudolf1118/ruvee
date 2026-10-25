/**
 * Messages between the UI and the vault worker. Keys, `SK` and passwords stay inside the worker;
 * the UI receives only what it displays. A stored password leaves the worker only when the user
 * reveals, copies or edits it.
 */

export type ItemType = 'login' | 'note';

export type ConflictKind = 'edited_on_both' | 'deleted_elsewhere' | 'edited_after_delete';

export interface ItemSummary {
  readonly id: string;
  readonly type: ItemType;
  readonly title: string;
  /** Username for a login, first line of a note. */
  readonly subtitle: string;
  readonly favorite: boolean;
  readonly trashed: boolean;
  readonly tags: readonly string[];
  readonly urls: readonly string[];
  readonly updatedAtMs: number;
  /** Waiting to be uploaded. */
  readonly pending: boolean;
  readonly conflict: ConflictKind | null;
}

export interface ItemDetail extends ItemSummary {
  readonly username: string;
  readonly hasPassword: boolean;
  readonly notes: string;
  readonly noteText: string;
  readonly createdAtMs: number;
}

/** What the editor submits. `id` is absent for a new item. */
export interface ItemDraft {
  readonly id?: string;
  readonly type: ItemType;
  readonly title: string;
  readonly username: string;
  readonly password: string;
  readonly urls: readonly string[];
  readonly notes: string;
  readonly noteText: string;
  readonly tags: readonly string[];
  readonly favorite: boolean;
}

/** For the conflict panel: the other version, without its password. */
export interface ConflictView {
  readonly itemId: string;
  readonly kind: ConflictKind;
  readonly local: ItemDetail | null;
  readonly remote: ItemDetail | null;
  readonly remoteAuthor: 'this_device' | 'another_device' | 'unknown';
}

export type SyncState =
  'synced' | 'syncing' | 'offline' | 'pending' | 'session_expired' | 'integrity_error';

export interface SyncStatus {
  readonly state: SyncState;
  readonly pendingCount: number;
  readonly lastSyncedAtMs: number | null;
  /** The newest verified commit: when and whether this device wrote it. */
  readonly lastChange: { readonly atMs: number; readonly byThisDevice: boolean } | null;
  /** Set for `integrity_error`: the vault is read-only until resolved. */
  readonly integrity?: string;
  /** The Recovery Kit was used at this time and this device has not acknowledged it yet. */
  readonly recoveryUsedAtMs?: number;
}

export type DevicePhase =
  /** Nothing on this device: set up a new account or log in. */
  | { readonly phase: 'new' }
  /** Logged in, waiting to be enrolled by pairing. */
  | { readonly phase: 'pending'; readonly username: string; readonly deviceId: string }
  | { readonly phase: 'enrolled'; readonly username: string; readonly deviceId: string };

export interface UnlockedVault {
  readonly username: string;
  readonly deviceId: string;
  readonly items: readonly ItemSummary[];
  readonly sync: SyncStatus;
  /** Set when the server session could not be restored; the vault still works offline. */
  readonly sessionProblem?: 'login_failed' | 'offline' | 'rate_limited';
  /** Set right after a recovery: this device has no trusted checkpoint (sync-protocol §5). */
  readonly recovered?: { readonly lastChange: SyncStatus['lastChange'] };
  /** The local password wrap was replaced because the password changed on another device. */
  readonly passwordUpdated?: boolean;
  /** The Secret Key was replaced on another device, and this device now uses the new one. */
  readonly secretKeyUpdated?: boolean;
}

export interface RecoveryKitView {
  readonly recoveryKey: string;
  readonly recoveryKeyIdShort: string;
  readonly username: string;
  readonly serverOrigin: string;
  readonly createdAtMs: number;
}

/** Error codes the worker reports. Messages shown to users are chosen by the UI. */
export type VaultErrorCode =
  | 'wrong_password'
  | 'login_failed'
  | 'rate_limited'
  | 'bootstrap_failed'
  | 'registration_closed'
  | 'invalid_password'
  | 'invalid_username'
  | 'invalid_recovery_key'
  | 'kit_mismatch'
  | 'offline'
  | 'session_expired'
  | 'device_revoked'
  | 'device_not_enrolled'
  | 'read_only'
  | 'invalid_item'
  | 'not_found'
  | 'locked'
  | 'invalid_pairing_code'
  | 'pairing_used'
  | 'pairing_expired'
  | 'pairing_failed'
  | 'password_required'
  | 'recovery_failed'
  | 'cannot_revoke_current'
  | 'changed_elsewhere'
  | 'previous_password_required'
  | 'integrity'
  | 'internal';

export interface VaultErrorPayload {
  readonly code: VaultErrorCode;
  readonly retryAfterSeconds?: number;
}

/** Device A's view of a pairing it started (device-enrollment §3.2 steps 2 to 8). */
export type PairingHostStatus =
  | { readonly state: 'waiting' }
  /** A request arrived and its MAC verified; the user decides. */
  | { readonly state: 'request'; readonly platform: string; readonly requestedAtMs: number }
  /** The request MAC did not verify; the pairing was cancelled and cannot be retried. */
  | { readonly state: 'failed' }
  | { readonly state: 'approved' }
  | { readonly state: 'expired' };

export interface PairingCode {
  readonly code: string;
  readonly pairingId: string;
  readonly expiresAtMs: number;
}

/** A device of the account, for the Devices screen. Times are server times. */
export interface DeviceView {
  readonly id: string;
  readonly platform: 'web' | 'extension' | 'ios' | 'android';
  readonly status: 'pending' | 'active' | 'revoked';
  readonly enrolledVia: 'bootstrap' | 'pairing' | 'recovery' | null;
  /** This browser. */
  readonly current: boolean;
  readonly createdAtMs: number;
  readonly enrolledAtMs: number | null;
  readonly lastSeenAtMs: number | null;
  readonly revokedAtMs: number | null;
  readonly sessions: readonly SessionView[];
}

export interface SessionView {
  readonly id: string;
  readonly current: boolean;
  readonly createdAtMs: number;
  readonly lastUsedAtMs: number;
}

export type PairingJoinStatus =
  { readonly state: 'waiting' } | { readonly state: 'enrolled'; readonly vault: UnlockedVault };

export interface VaultMethods {
  phase(): DevicePhase;
  setupBegin(params: {
    bootstrapToken: string;
    username: string;
    password: string;
  }): RecoveryKitView;
  setupVerifyKit(params: { recoveryKey: string }): true;
  setupFinish(): UnlockedVault;
  login(params: { username: string; password: string }): DevicePhase;
  unlock(params: { password: string; previousPassword?: string }): UnlockedVault;
  items(): readonly ItemSummary[];
  detail(params: { id: string }): ItemDetail;
  secret(params: { id: string }): string;
  save(params: { draft: ItemDraft }): ItemSummary;
  setFavorite(params: { id: string; favorite: boolean }): ItemSummary;
  trash(params: { id: string }): ItemSummary;
  restore(params: { id: string }): ItemSummary;
  purge(params: { id: string }): true;
  conflict(params: { id: string }): ConflictView;
  resolveConflict(params: { id: string; choice: 'mine' | 'theirs' | 'both' }): true;
  sync(): SyncStatus;
  pairingStart(): PairingCode;
  pairingStatus(params: { pairingId: string }): PairingHostStatus;
  pairingApprove(params: { pairingId: string }): true;
  pairingCancel(params: { pairingId: string }): true;
  pairingNeedsPassword(): boolean;
  pairingJoin(params: { code: string; password?: string }): true;
  pairingWait(): PairingJoinStatus;
  recoveryBegin(params: { username: string; recoveryKey: string }): true;
  recoverySetPassword(params: { password: string }): RecoveryKitView;
  recoveryVerifyKit(params: { recoveryKey: string }): true;
  recoveryFinish(): UnlockedVault;
  acknowledgeRecoveryNotice(): true;
  devices(): readonly DeviceView[];
  endSession(params: { sessionId: string }): true;
  revokeDevice(params: { deviceId: string; reason: 'retired' | 'lost'; password: string }): {
    secretKeyRotated: boolean;
  };
  changePassword(params: { currentPassword: string; newPassword: string }): true;
  rotateSecretKey(params: { password: string }): true;
  kitRotateBegin(): RecoveryKitView;
  kitRotateVerify(params: { recoveryKey: string }): true;
  kitRotateFinish(params: { password: string }): true;
  kitRotateCancel(): true;
  logout(): true;
  /** Best-effort zeroing of keys before the worker is terminated. */
  wipe(): true;
}

export type VaultMethod = keyof VaultMethods;

export interface VaultRequest<M extends VaultMethod = VaultMethod> {
  readonly id: number;
  readonly method: M;
  readonly params: Parameters<VaultMethods[M]>[0];
}

export type VaultResponse =
  | { readonly id: number; readonly ok: true; readonly result: unknown }
  | { readonly id: number; readonly ok: false; readonly error: VaultErrorPayload };

/** Unsolicited messages from the worker. */
export type VaultEvent =
  | { readonly event: 'sync'; readonly status: SyncStatus }
  | { readonly event: 'items'; readonly items: readonly ItemSummary[] }
  /** The session ended or the device was revoked: the UI must lock (INV-15). */
  | { readonly event: 'ended'; readonly reason: 'session_expired' | 'device_revoked' };
