import type { PrismaService } from '../database/prisma.service.js';
import { addressKey, ThrottleService } from './throttle.service.js';

/** The in-memory limits (no database): per address (review R17) and per session (R16). */
describe('addressKey', () => {
  it.each([
    ['198.51.100.7', '198.51.100.7'],
    ['2001:db8:1:2:3:4:5:6', '2001:db8:1:2::/64'],
    ['2001:DB8:1:2::99', '2001:db8:1:2::/64'],
    ['2001:db8::1', '2001:db8:0:0::/64'],
    ['::1', '0:0:0:0::/64'],
    ['fe80::1%en0', 'fe80:0:0:0::/64'],
    ['2001:db8:1:2:3:4:192.0.2.1', '2001:db8:1:2::/64'],
    ['not an address', 'not an address'],
  ])('%s → %s', (ip, key) => {
    expect(addressKey(ip)).toBe(key);
  });
});

describe('ThrottleService in-memory windows', () => {
  const throttle = () => new ThrottleService({} as PrismaService);
  const refused = (run: () => void) => {
    try {
      run();
      return false;
    } catch (error) {
      return (error as { code?: string }).code === 'rate_limited';
    }
  };

  it('limits one IPv6 /64 as one client, however many addresses it rotates through', () => {
    const t = throttle();
    for (let i = 1; i <= 20; i++) t.assertIpAllowed(`2001:db8:1:2::${i.toString(16)}`, 1000);
    expect(
      refused(() => {
        t.assertIpAllowed('2001:db8:1:2:ffff::1', 1000);
      }),
    ).toBe(true);
    // Another /64 has its own window.
    expect(
      refused(() => {
        t.assertIpAllowed('2001:db8:1:3::1', 1000);
      }),
    ).toBe(false);
    // And the window ends.
    expect(
      refused(() => {
        t.assertIpAllowed('2001:db8:1:2::1', 61_001);
      }),
    ).toBe(false);
  });

  it('allows 300 authenticated requests a minute per session, then 429', () => {
    const t = throttle();
    for (let i = 0; i < 300; i++) t.assertSessionAllowed('session-a', 5000);
    expect(
      refused(() => {
        t.assertSessionAllowed('session-a', 5000);
      }),
    ).toBe(true);
    expect(
      refused(() => {
        t.assertSessionAllowed('session-b', 5000);
      }),
    ).toBe(false);
    expect(
      refused(() => {
        t.assertSessionAllowed('session-a', 65_001);
      }),
    ).toBe(false);
  });

  it('limits wrong reopening codes per /64 without counting the check itself', () => {
    const t = throttle();
    for (let i = 0; i < 10; i++) {
      t.assertReopenCodeGuessesAllowed('2001:db8:9:9::1', 0);
      t.recordWrongReopenCode(`2001:db8:9:9::${String(i + 1)}`, 0);
    }
    expect(
      refused(() => {
        t.assertReopenCodeGuessesAllowed('2001:db8:9:9::77', 0);
      }),
    ).toBe(true);
    expect(
      refused(() => {
        t.assertReopenCodeGuessesAllowed('198.51.100.9', 0);
      }),
    ).toBe(false);
  });
});
