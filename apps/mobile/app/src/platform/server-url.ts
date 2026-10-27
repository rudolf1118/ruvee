/**
 * The self-hosted server's address, as an origin: `https://host[:port]`, nothing after it.
 * Plain HTTP is accepted only for this device's loopback (`127.0.0.1`, `localhost`) and only in
 * development builds, matching the debug-only network security config; a release build refuses
 * it here and the OS refuses it again (android/app/src/main/res/xml/network_security_config.xml).
 * TLS verification is never relaxed.
 */
const HTTPS =
  /^https:\/\/((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(:\d{1,5})?\/?$/;
const LOOPBACK_HTTP = /^http:\/\/(127\.0\.0\.1|localhost)(:\d{1,5})?\/?$/;

export type ServerUrlProblem = 'invalid' | 'insecure';

export function parseServerOrigin(
  input: string,
  development: boolean,
): { origin: string } | { problem: ServerUrlProblem } {
  const text = input.trim().toLowerCase();
  const https = HTTPS.exec(text);
  const loopback = LOOPBACK_HTTP.exec(text);
  const match = https ?? (development ? loopback : null);
  if (!match) return { problem: loopback || text.startsWith('http://') ? 'insecure' : 'invalid' };
  const port = match[2];
  if (port !== undefined) {
    const n = Number(port.slice(1));
    if (!Number.isInteger(n) || n < 1 || n > 65_535) return { problem: 'invalid' };
  }
  return { origin: text.replace(/\/$/, '') };
}
