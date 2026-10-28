import { isIP } from 'node:net';
import type { Request } from 'express';

/**
 * The client address: the socket peer, or the last X-Forwarded-For hop when the peer is the
 * configured reverse proxy (authentication.md §7). Anything that is not an IP address is dropped.
 */
export function clientIp(req: Request, trustedProxy: string | undefined): string | undefined {
  const peer = canonicalIp(req.socket.remoteAddress);
  if (trustedProxy !== undefined && peer === canonicalIp(trustedProxy)) {
    const header = req.headers['x-forwarded-for'];
    const value = Array.isArray(header) ? header.at(-1) : header;
    const last = value?.split(',').at(-1)?.trim();
    const forwarded = canonicalIp(last);
    if (forwarded) return forwarded;
  }
  return peer;
}

/** Whether the request's peer is the configured reverse proxy, compared in canonical form. */
export function fromTrustedProxy(req: Request, trustedProxy: string): boolean {
  const peer = canonicalIp(req.socket.remoteAddress);
  return peer !== undefined && peer === canonicalIp(trustedProxy);
}

/**
 * One spelling per address (follow-up review F-7): IPv6 lower-case and compressed as the URL
 * standard writes it, and an IPv4-mapped IPv6 address as plain IPv4, so a configured
 * `TRUSTED_PROXY_ADDRESS` matches the peer however either is written. Not an address: undefined.
 */
export function canonicalIp(address: string | undefined): string | undefined {
  const text = address?.trim();
  if (!text) return undefined;
  const kind = isIP(text);
  if (kind === 4) return text;
  if (kind !== 6) return undefined;
  let host: string;
  try {
    host = new URL(`http://[${text}]/`).hostname.slice(1, -1);
  } catch {
    // A zone index (fe80::1%en0) is not a URL host: compare it as written, lower-case.
    return text.toLowerCase();
  }
  const mapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(host);
  if (!mapped) return host;
  const hi = parseInt(mapped[1] ?? '0', 16);
  const lo = parseInt(mapped[2] ?? '0', 16);
  return `${String(hi >> 8)}.${String(hi & 255)}.${String(lo >> 8)}.${String(lo & 255)}`;
}

export function userAgent(req: Request): string | undefined {
  const ua = req.headers['user-agent'];
  return typeof ua === 'string' && ua.length > 0 ? ua.slice(0, 256) : undefined;
}

/** Reads one cookie without a cookie-parsing dependency. Values are not URL-decoded. */
export function readCookie(req: Request, name: string): string | undefined {
  const header = req.headers.cookie;
  if (typeof header !== 'string') return undefined;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq > 0 && part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
  }
  return undefined;
}
