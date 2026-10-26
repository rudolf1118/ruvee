import type { Env } from '../config/env.js';

/**
 * What a server backup must account for (backup-restore.md §3.1). Descriptive only: it says what
 * each input is and where it comes from on a restore. It contains no restore policy (D-28 is
 * open) and is not used by any running code yet. A test keeps it complete: a new table or
 * configuration variable fails until it is classified here.
 */

export type ConfigHandling =
  /** Copied into the backup's sidecar: the restored server must use the same value. */
  | 'sidecar'
  /** Points to a secret kept apart from the dump; only the path is configuration. */
  | 'separate-secret'
  /** Chosen anew on the restoring host; holds a host secret or nothing a restore needs. */
  | 'host';

export const CONFIG_INVENTORY: Record<keyof Env, { handling: ConfigHandling; why: string }> = {
  NODE_ENV: { handling: 'host', why: 'production on the restoring host' },
  API_HOST: { handling: 'host', why: 'listening address of the new host' },
  API_PORT: { handling: 'host', why: 'listening port of the new host' },
  DATABASE_URL: {
    handling: 'host',
    why: 'contains the new database password; the restore target is a new, empty database',
  },
  LOG_LEVEL: { handling: 'host', why: 'operational preference' },
  READINESS_DB_TIMEOUT_MS: { handling: 'host', why: 'operational preference' },
  OPAQUE_SERVER_SETUP_FILE: {
    handling: 'separate-secret',
    why: 'the OPAQUE server setup is never in the dump (INV-21); its own offline copy is restored',
  },
  PUBLIC_ORIGIN: {
    handling: 'sidecar',
    why: 'cookies, CSRF and every client are bound to it; a different origin is a new server',
  },
  SESSION_COOKIE_SECURE: { handling: 'sidecar', why: 'must stay true in production' },
  TRUSTED_PROXY_ADDRESS: {
    handling: 'host',
    why: 'address of the new host’s reverse proxy',
  },
  EXTENSION_ORIGINS: {
    handling: 'sidecar',
    why: 'the extension’s login and refresh calls are accepted only from these origins',
  },
};

/** Every table of the database, what it holds, and whether a dump contains secrets from it. */
export const TABLE_INVENTORY: Record<string, { holds: string; secretMaterial: boolean }> = {
  accounts: { holds: 'account id, normalized username', secretMaterial: false },
  opaque_credentials: {
    holds: 'OPAQUE registration record (with the setup file: offline password guessing, V-01)',
    secretMaterial: true,
  },
  account_keys: {
    holds: 'AK wraps (password, recovery), SHA-256(RAK), keyset envelope, salt, profile',
    secretMaterial: true,
  },
  devices: {
    holds: 'device ids, platform, status, times, and the encrypted device label (DEVICE_LABEL)',
    secretMaterial: true,
  },
  sessions: {
    holds: 'SHA-256 of cookie and access tokens, expiries, revocation',
    secretMaterial: true,
  },
  refresh_tokens: { holds: 'SHA-256 of refresh tokens and rotation times', secretMaterial: true },
  auth_throttle: { holds: 'failure counters by hashed subject', secretMaterial: false },
  bootstrap_tokens: { holds: 'SHA-256 of setup tokens, expiry, use', secretMaterial: true },
  security_events: { holds: 'allow-listed event history (INV-12)', secretMaterial: false },
  pairings: { holds: 'open pairings: ephemeral key, MACs, sealed reply', secretMaterial: true },
  vaults: { holds: 'vault id, VK id, current seq', secretMaterial: false },
  vault_items: { holds: 'item records (ciphertext) and tombstones', secretMaterial: true },
  vault_commits: { holds: 'commit ids and manifest envelopes (ciphertext)', secretMaterial: true },
};

/** Not in the database at all. Attachments do not exist yet (Phase 7). */
export const OUTSIDE_DATABASE = [
  'OPAQUE server setup file: separate offline copy, never with the dump',
  'deploy/Caddyfile and the web export: part of the Ruvee release, not of the backup',
  'TLS certificates: issued again for the restoring host',
  '.env: rebuilt on the restoring host from CONFIG_INVENTORY (sidecar values plus new host values)',
  'client devices: their local copies are not part of any server backup',
] as const;
