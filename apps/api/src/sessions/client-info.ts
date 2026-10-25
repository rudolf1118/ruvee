import { isIP } from 'node:net';
import type { Request } from 'express';

/**
 * The client address: the socket peer, or the last X-Forwarded-For hop when the peer is the
 * configured reverse proxy (authentication.md §7). Anything that is not an IP address is dropped.
 */
export function clientIp(req: Request, trustedProxy: string | undefined): string | undefined {
  const peer = normalize(req.socket.remoteAddress);
  if (trustedProxy !== undefined && peer === normalize(trustedProxy)) {
    const header = req.headers['x-forwarded-for'];
    const value = Array.isArray(header) ? header.at(-1) : header;
    const last = value?.split(',').at(-1)?.trim();
    const forwarded = normalize(last);
    if (forwarded) return forwarded;
  }
  return peer;
}

function normalize(address: string | undefined): string | undefined {
  if (address === undefined) return undefined;
  const plain = address.startsWith('::ffff:') ? address.slice(7) : address;
  return isIP(plain) ? plain : undefined;
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
