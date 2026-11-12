/**
 * The difference between this device's clock and the server's `Date` header, for the
 * authenticator's clock warning only (totp-authenticator.md §4.3). Codes are always computed from
 * the device clock; the server's time never feeds them.
 */
let skewMs: number | null = null;

/** Called with each API response's `Date` header and the local time it arrived. */
export function noteServerDate(header: string | null, localMs: number): void {
  if (!header) return;
  const serverMs = Date.parse(header);
  if (!Number.isFinite(serverMs)) return;
  skewMs = localMs - serverMs;
}

/** Local minus server, in milliseconds; null before any response. The header has 1 s precision. */
export function clockSkewMs(): number | null {
  return skewMs;
}

/** Above this the UI warns that codes may be rejected (§4.3). */
export const CLOCK_SKEW_WARNING_MS = 30_000;
