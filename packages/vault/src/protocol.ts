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
  | 'synced'
  | 'syncing'
  | 'offline'
  | 'pending'
  | 'session_expired'
  | 'integrity_error'
  /** The server is being restored by its owner (backup-restore.md §3.5): local copy, read-only. */
  | 'maintenance'
  /** The restored server waits for its owner to reopen it (§3.13): local copy, read-only. */
  | 'reopening';

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
  /**
   * The server says it was restored from a backup at this time (`server_restored`). For wording
   * only: it is the server's own claim, never proof of anything (backup-restore.md §3.6).
   */
  readonly serverRestoredAtMs?: number;
  /** An import into this vault (backup-restore.md §4.4a). */
  readonly import?: {
    readonly state: 'uploading' | 'complete';
    readonly total: number;
    readonly uploaded: number;
    readonly sourceAsOfMs: number;
  };
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
  readonly sessionProblem?:
    /**
     * The server needs this device to prove its key and it cannot (the key is not the server's):
     * usable offline; re-enroll with the Recovery Kit to sync.
     */
    | 'device_key_missing'
    /**
     * The account was created before D-31 and has no `AVPK`, so nothing can enroll a key for it:
     * usable offline; its data moves to a new account (docs/guides/legacy-account-migration.md).
     */
    | 'migration_required'
    | 'login_failed'
    | 'offline'
    | 'rate_limited'
    /** The server is in restore review (backup-restore.md §3.5). */
    | 'maintenance'
    /** The restored server waits to be reopened with a code from its host (§3.13). */
    | 'reopening'
    /** The password works, but the server does not know this device (a restored server). */
    | 'device_unknown';
  /**
   * Set right after a recovery. With `keptLocal`, this browser kept its own copy of the vault:
   * its checkpoint, unsynced edits and conflicts (review R6, R20). Without it, this device has
   * no trusted checkpoint (sync-protocol §5).
   */
  readonly recovered?: {
    readonly lastChange: SyncStatus['lastChange'];
    readonly keptLocal?: { readonly pending: number; readonly conflicts: number };
  };
  /** The local password wrap was replaced because the password changed on another device. */
  readonly passwordUpdated?: boolean;
  /** The Secret Key was replaced on another device, and this device now uses the new one. */
  readonly secretKeyUpdated?: boolean;
  /** This device reopened the restored server, with a new password and Recovery Kit (§3.13). */
  readonly reopened?: boolean;
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
  /** Another tab or engine took over this device's vault; this one locked (F-2). */
  | 'open_elsewhere'
  /** The server refused one signed request; nothing changed, and it can be tried again (F-17). */
  | 'proof_rejected'
  | 'previous_password_required'
  | 'invalid_export'
  | 'unsynced_changes'
  | 'import_in_progress'
  | 'vault_not_empty'
  | 'integrity'
  | 'server_maintenance'
  | 'server_reopening'
  | 'reopen_failed'
  | 'reopen_needs_kit'
  | 'local_data_present'
  /** This browser holds another account's vault; recovery here erases it unless confirmed. */
  | 'local_data_other_account'
  /** This device has no device key the server accepts (docs/security/device-proof.md §9). */
  | 'device_key_missing'
  /** The account predates D-31 and cannot establish a trusted `AVPK` (device-proof.md §9). */
  | 'migration_required'
  | 'export_first'
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

/** One security event for the activity screen (P2-15). */
export interface ActivityEvent {
  readonly id: string;
  readonly type: string;
  readonly atMs: number;
  /** This browser, another device of the account, or none. */
  readonly device: 'this_device' | 'other' | null;
  readonly ip: string | null;
  readonly userAgent: string | null;
  readonly details: Readonly<Record<string, string | boolean>>;
}

export interface ActivityPage {
  readonly events: readonly ActivityEvent[];
  readonly nextCursor: string | null;
}

/** An encrypted export opened read-only; passwords stay in the worker until revealed. */
export interface ExportView {
  /** Authenticated by the export's manifest. */
  readonly asOfMs: number;
  readonly authorDeviceId: string;
  /** The export's manifest `seq`: which snapshot of the source vault this is. */
  readonly seq: number;
  /** Deleted items in the export: deletion markers with no content, never imported. */
  readonly deletedCount: number;
  readonly items: readonly ItemDetail[];
}

/** An export made from this device's own verified copy, with no server (backup-restore.md §3.12). */
export interface LocalExport {
  readonly fileName: string;
  readonly text: string;
  /** Exactly what is in the file: the last snapshot this device verified, and nothing else. */
  readonly snapshot: { readonly seq: number; readonly asOfMs: number; readonly items: number };
  /** Changes on this device that are not in the file, because nothing verified them. */
  readonly notIncluded: { readonly pending: number; readonly conflicts: number };
}

/** What this device holds that the server has not verified, for the "start over" screen. */
export interface LocalStateView {
  readonly snapshot: {
    readonly seq: number;
    readonly asOfMs: number | null;
    readonly items: number;
  };
  readonly pending: number;
  readonly conflicts: number;
  /** A local export of the current state was made since the last change. */
  readonly exported: boolean;
}

/**
 * What a move to a new account must carry by hand (device-proof.md §9): every change this device
 * holds that no export can, by item. Read from this device only.
 */
export interface MigrationReport {
  readonly snapshot: LocalStateView['snapshot'];
  /** Edits waiting to sync: in the export at their last verified version, or not at all. */
  readonly changes: readonly {
    readonly id: string;
    readonly title: string;
    readonly change: 'created' | 'edited' | 'deleted';
  }[];
  /** Unresolved conflicts: this device's version is in no export. */
  readonly conflicts: readonly {
    readonly id: string;
    readonly title: string;
    readonly kind: ConflictKind;
    /** This device's version deletes the item. */
    readonly localDeleted: boolean;
  }[];
  readonly exported: boolean;
}

export interface SessionView {
  readonly id: string;
  readonly current: boolean;
  /** A recovery in progress: it cannot be signed out; a new Recovery Kit ends it. */
  readonly recovery: boolean;
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
  recoveryBegin(params: {
    username: string;
    recoveryKey: string;
    reopenCode?: string;
    replaceLocalData?: boolean;
  }): true;
  /** Reopening, password path, on this unlocked device (backup-restore.md §3.13). */
  reopenBegin(params: { reopenCode: string; password: string }): true;
  recoverySetPassword(params: { password: string }): RecoveryKitView;
  recoveryVerifyKit(params: { recoveryKey: string }): true;
  recoveryFinish(): UnlockedVault;
  acknowledgeRecoveryNotice(): true;
  devices(): readonly DeviceView[];
  activity(params: { cursor?: string }): ActivityPage;
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
  exportVault(params: { password: string; recoveryKey: string }): {
    fileName: string;
    text: string;
  };
  exportOpen(params: { text: string; recoveryKey: string }): ExportView;
  exportSecret(params: { id: string }): string;
  exportClose(): true;
  importIntoEmptyVault(): SyncStatus;
  localState(): LocalStateView;
  migrationReport(): MigrationReport;
  exportLocal(params: {
    password: string;
    recoveryKey: string;
    acknowledgeNotIncluded?: boolean;
  }): LocalExport;
  startOver(params: {
    confirm: 'erase-this-device';
    withoutExport?: boolean;
    pendingSeen: number;
    conflictsSeen: number;
  }): true;
  logout(): true;
  /** Resolves when every queued operation has finished, so nothing is mid-write (F-2). */
  settle(): true;
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
  | {
      readonly event: 'ended';
      readonly reason: 'session_expired' | 'device_revoked' | 'open_elsewhere';
    };
