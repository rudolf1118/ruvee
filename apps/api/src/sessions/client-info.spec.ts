import type { Request } from 'express';
import { canonicalIp, clientIp } from './client-info.js';

/** Follow-up review F-7: the trusted proxy matches the peer however either address is written. */
const req = (remoteAddress: string, forwarded?: string) =>
  ({
    socket: { remoteAddress },
    headers: forwarded === undefined ? {} : { 'x-forwarded-for': forwarded },
  }) as unknown as Request;

describe('canonicalIp', () => {
  it.each([
    ['198.51.100.7', '198.51.100.7'],
    ['2001:DB8::1', '2001:db8::1'],
    ['2001:0db8:0000:0000:0000:0000:0000:0001', '2001:db8::1'],
    ['::ffff:198.51.100.7', '198.51.100.7'],
    ['::FFFF:198.51.100.7', '198.51.100.7'],
    ['::ffff:c633:6407', '198.51.100.7'],
    [' 198.51.100.7 ', '198.51.100.7'],
    ['fe80::1%en0', 'fe80::1%en0'],
    ['not an address', undefined],
    ['', undefined],
    [undefined, undefined],
  ])('%s → %s', (input, expected) => {
    expect(canonicalIp(input)).toBe(expected);
  });
});

describe('clientIp behind a trusted proxy', () => {
  it.each([
    ['2001:db8::1', '2001:DB8::1'],
    ['2001:db8::1', '2001:0db8:0:0:0:0:0:1'],
    ['::ffff:10.0.0.2', '10.0.0.2'],
    ['10.0.0.2', '::ffff:10.0.0.2'],
  ])('peer %s matches TRUSTED_PROXY_ADDRESS %s', (peer, proxy) => {
    expect(clientIp(req(peer, '203.0.113.9'), proxy)).toBe('203.0.113.9');
  });

  it('ignores X-Forwarded-For from any other peer', () => {
    expect(clientIp(req('10.0.0.3', '203.0.113.9'), '10.0.0.2')).toBe('10.0.0.3');
    expect(clientIp(req('::1', '203.0.113.9'), '127.0.0.1')).toBe('::1');
  });

  it('uses the last hop, in canonical form, and drops what is not an address', () => {
    expect(clientIp(req('10.0.0.2', '198.51.100.1, 2001:DB8::5'), '10.0.0.2')).toBe('2001:db8::5');
    expect(clientIp(req('10.0.0.2', 'unknown'), '10.0.0.2')).toBe('10.0.0.2');
  });
});
