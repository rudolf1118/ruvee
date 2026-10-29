import { addressKey } from './throttle.service.js';

/** The key an address is limited under (review R17); the windows themselves are in the database. */
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
