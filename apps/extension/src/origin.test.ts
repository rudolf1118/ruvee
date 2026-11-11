import { fillableOrigin, originMatches, storedOrigin } from './origin';

describe('exact-origin matching (extension-design.md §4)', () => {
  it.each([
    ['https://mail.example', 'https://mail.example/login?next=/', true],
    ['https://mail.example/path', 'https://mail.example/other', true],
    ['mail.example', 'https://mail.example/', true],
    ['https://mail.example:443', 'https://mail.example/', true],
    ['http://127.0.0.1:3105', 'http://127.0.0.1:3105/form', true],
    ['https://MAIL.example', 'https://mail.example/', true],
  ])('matches %s on %s', (stored, tab, expected) => {
    expect(originMatches(stored, tab)).toBe(expected);
  });

  it.each([
    ['https://mail.example', 'https://login.mail.example/', 'a subdomain'],
    ['https://login.mail.example', 'https://mail.example/', 'a parent domain'],
    ['https://mail.example', 'http://mail.example/', 'plain HTTP'],
    ['http://mail.example', 'http://mail.example/', 'plain HTTP off loopback'],
    ['https://mail.example', 'https://mail.example:8443/', 'another port'],
    ['http://127.0.0.1:3105', 'http://127.0.0.1:3106/', 'another loopback port'],
    ['https://mail.example', 'https://mail.example.evil.example/', 'a look-alike suffix'],
    ['https://mail.example', 'https://mail.example./', 'a trailing dot'],
    ['https://xn--mail-xya.example', 'https://mail.example/', 'a punycode look-alike'],
    ['https://mail.example', 'https://user@mail.example/', 'userinfo in the tab URL'],
    ['https://mail.example', 'chrome://settings', 'a browser page'],
    ['https://mail.example', 'file:///tmp/login.html', 'a file'],
    ['https://mail.example', 'data:text/html,<form>', 'a data URL'],
    ['https://mail.example', undefined, 'an unknown tab URL'],
    ['not a url at all', 'https://mail.example/', 'an unparsable stored URL'],
  ])('refuses %s on %s (%s)', (stored, tab, why) => {
    expect(why).not.toBe('');
    expect(originMatches(stored, tab)).toBe(false);
  });

  it('normalizes the stored URL the same way the browser does', () => {
    expect(storedOrigin('https://Mail.Example:443/a')).toBe('https://mail.example');
    expect(storedOrigin('javascript:alert(1)')).toBeNull();
    expect(fillableOrigin('https://[::1]:8443/')).toBe('https://[::1]:8443');
    expect(fillableOrigin('http://[::1]:3105/')).toBe('http://[::1]:3105');
  });
});
