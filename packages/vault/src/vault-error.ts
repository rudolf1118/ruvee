import type { VaultErrorCode } from './protocol.js';

/** An error the worker reports to the UI by code only; messages are chosen by the UI. */
export class VaultError extends Error {
  constructor(
    readonly code: VaultErrorCode,
    readonly retryAfterSeconds?: number,
  ) {
    super(code);
    this.name = 'VaultError';
  }
}
