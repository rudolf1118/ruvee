// @vitest-environment node
import { createHmac } from 'node:crypto';
import {
  decodeBase32,
  hotp,
  parseTotpInput,
  totpCodes,
  totpSchema,
  type Hmac,
  type Totp,
  type TotpInputError,
} from './totp.js';

const utf8 = (s: string) => new TextEncoder().encode(s);

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
/** An independent encoder, so the tests do not check the decoder against itself. */
function encodeBase32(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32.charAt((value >>> (bits - 5)) & 31);
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32.charAt((value << (5 - bits)) & 31);
  return out;
}

// RFC 6238 Appendix B seeds: ASCII "1234567890" repeated to the hash's output size.
const SEED = {
  SHA1: utf8('12345678901234567890'),
  SHA256: utf8('12345678901234567890123456789012'),
  SHA512: utf8('1234567890123456789012345678901234567890123456789012345678901234'),
} as const;

// RFC 6238 Appendix B, Table 1 (8 digits, 30-second steps, T0 = 0).
const RFC6238: [number, string, string, string][] = [
  [59, '94287082', '46119246', '90693936'],
  [1111111109, '07081804', '68084774', '25091201'],
  [1111111111, '14050471', '67062674', '99943326'],
  [1234567890, '89005924', '91819424', '93441116'],
  [2000000000, '69279037', '90698825', '38618901'],
  [20000000000, '65353130', '77737706', '47863826'],
];

// RFC 4226 Appendix D: 6-digit HOTP values for counters 0 to 9 with the SHA-1 seed.
const RFC4226 = [
  '755224',
  '287082',
  '359152',
  '969429',
  '338314',
  '254676',
  '287922',
  '162583',
  '399871',
  '520489',
];

const totpOf = (algorithm: Totp['algorithm'], digits: Totp['digits'] = 8, period = 30): Totp => ({
  secret: encodeBase32(SEED[algorithm]),
  algorithm,
  digits,
  period,
});

describe('TOTP generation (RFC 6238, RFC 4226)', () => {
  it.each(RFC6238)('RFC 6238 Appendix B at T = %i', async (seconds, sha1, sha256, sha512) => {
    for (const [algorithm, expected] of [
      ['SHA1', sha1],
      ['SHA256', sha256],
      ['SHA512', sha512],
    ] as const) {
      const codes = await totpCodes(totpOf(algorithm), seconds * 1000);
      expect(codes.code, algorithm).toBe(expected);
    }
  });

  it('RFC 4226 Appendix D truncation for counters 0 to 9', async () => {
    for (const [counter, expected] of RFC4226.entries())
      expect(await hotp('SHA1', SEED.SHA1, counter, 6)).toBe(expected);
  });

  it('agrees with an independent HMAC (node:crypto) at 6, 7 and 8 digits and leading zeros', async () => {
    const nodeHmac: Hmac = (algorithm, key, message) =>
      Promise.resolve(
        new Uint8Array(createHmac(algorithm.toLowerCase(), key).update(message).digest()),
      );
    // T = 1111111109 gives 07081804 at 8 digits: the leading zero must survive.
    for (const digits of [6, 7, 8] as const) {
      const t = totpOf('SHA1', digits);
      const viaWebCrypto = await totpCodes(t, 1111111109_000);
      const viaNode = await totpCodes(t, 1111111109_000, nodeHmac);
      expect(viaWebCrypto).toEqual(viaNode);
      expect(viaWebCrypto.code).toHaveLength(digits);
    }
    expect((await totpCodes(totpOf('SHA1', 8), 1111111109_000)).code).toBe('07081804');
  });

  it('changes code exactly at the period boundary and reports when it expires', async () => {
    const t = totpOf('SHA1', 6, 30);
    const k = 37_037_037; // 30 * k seconds, 2005-03-18
    const boundary = 30 * k * 1000;
    const before = await totpCodes(t, boundary - 1);
    const at = await totpCodes(t, boundary);
    expect(before.validUntilMs).toBe(boundary);
    expect(at.validUntilMs).toBe(boundary + 30_000);
    expect(before.nextCode).toBe(at.code);
    expect(before.code).toBe(await hotp('SHA1', SEED.SHA1, k - 1, 6));
    expect(at.code).toBe(await hotp('SHA1', SEED.SHA1, k, 6));
  });

  it('works past 2038 and with a 60-second period', async () => {
    const t = totpOf('SHA256', 6, 60);
    const ms = 4_102_444_800_000; // 2100-01-01
    const codes = await totpCodes(t, ms);
    expect(codes.code).toBe(await hotp('SHA256', SEED.SHA256, Math.floor(ms / 60_000), 6));
    expect(codes.validUntilMs).toBe((Math.floor(ms / 60_000) + 1) * 60_000);
  });

  it('refuses a counter it cannot represent', async () => {
    await expect(hotp('SHA1', SEED.SHA1, -1, 6)).rejects.toThrow(RangeError);
    await expect(hotp('SHA1', SEED.SHA1, 2 ** 53, 6)).rejects.toThrow(RangeError);
  });
});

describe('base32', () => {
  it('decodes RFC 4648 vectors and refuses padding, bad lengths and stray tail bits', () => {
    const hex = (b: Uint8Array | undefined) => (b ? Buffer.from(b).toString('hex') : undefined);
    expect(hex(decodeBase32('MZXW6YTBOI'))).toBe(Buffer.from('foobar').toString('hex'));
    expect(hex(decodeBase32('MY'))).toBe(Buffer.from('f').toString('hex'));
    expect(hex(decodeBase32(''))).toBe('');
    expect(decodeBase32('MZ')).toBeUndefined(); // tail bits not zero
    expect(decodeBase32('M')).toBeUndefined(); // no whole byte
    expect(decodeBase32('MZXW6===')).toBeUndefined();
    expect(decodeBase32('mzxw6ytboi')).toBeUndefined(); // the parser uppercases, not the decoder
    expect(decodeBase32('MZXW6YTB0I')).toBeUndefined(); // zero is not base32
  });
});

describe('parseTotpInput', () => {
  const SECRET = encodeBase32(SEED.SHA1); // GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ

  it('accepts a bare secret with spaces, hyphens, lowercase and padding, with the defaults', () => {
    const spaced = SECRET.toLowerCase()
      .replace(/(.{4})/g, '$1 ')
      .replace(/ (.)/, '-$1');
    for (const input of [SECRET, spaced, `${SECRET}====`, `  ${SECRET}\n`])
      expect(parseTotpInput(input)).toEqual({
        ok: true,
        totp: { secret: SECRET, algorithm: 'SHA1', digits: 6, period: 30 },
      });
  });

  it('accepts a full URI, with the label and issuer as hints only', () => {
    const result = parseTotpInput(
      `otpauth://totp/Synthetic%20Corp:alice%40example.test?secret=${SECRET}&issuer=Synthetic%20Corp&algorithm=sha256&digits=8&period=60&image=https%3A%2F%2Ftracker.example%2Fx.png&color=red`,
    );
    expect(result).toEqual({
      ok: true,
      totp: { secret: SECRET, algorithm: 'SHA256', digits: 8, period: 60 },
      issuer: 'Synthetic Corp',
      account: 'alice@example.test',
    });
  });

  it('accepts a URI with only the secret, and an issuer only in the label', () => {
    expect(parseTotpInput(`otpauth://totp/?secret=${SECRET}`)).toEqual({
      ok: true,
      totp: { secret: SECRET, algorithm: 'SHA1', digits: 6, period: 30 },
    });
    expect(parseTotpInput(`OTPAUTH://TOTP/Acme:bob?SECRET=${SECRET}`)).toMatchObject({
      ok: true,
      issuer: 'Acme',
      account: 'bob',
    });
  });

  const refused: [string, TotpInputError][] = [
    ['', 'empty'],
    ['   ', 'empty'],
    ['not a secret!', 'not_base32'],
    ['GEZDGNBVGY3TQOJ1', 'not_base32'],
    ['GEZDGNBVGY3TQOJQ'.slice(0, 15), 'not_base32'],
    [encodeBase32(new Uint8Array(9).fill(7)), 'secret_too_short'],
    [encodeBase32(new Uint8Array(65).fill(7)), 'secret_too_long'],
    [`otpauth://hotp/x?secret=${SECRET}&counter=0`, 'hotp'],
    ['otpauth-migration://offline?data=CjEKCkhlbGxvId6tvu8', 'migration'],
    [`https://example.test/?secret=${SECRET}`, 'unsupported_scheme'],
    [`javascript:alert(1)`, 'unsupported_scheme'],
    ['otpauth://totp/x?issuer=Acme', 'missing_secret'],
    ['otpauth://totp/x?secret=', 'missing_secret'],
    [`otpauth://totp/x?secret=${SECRET}&secret=${SECRET}`, 'duplicate_parameter'],
    [`otpauth://totp/x?secret=${SECRET}&Digits=6&digits=6`, 'duplicate_parameter'],
    [`otpauth://totp/x?secret=${SECRET}&algorithm=MD5`, 'unsupported_algorithm'],
    [`otpauth://totp/x?secret=${SECRET}&digits=5`, 'unsupported_digits'],
    [`otpauth://totp/x?secret=${SECRET}&digits=9`, 'unsupported_digits'],
    [`otpauth://totp/x?secret=${SECRET}&digits=06`, 'unsupported_digits'],
    [`otpauth://totp/x?secret=${SECRET}&period=0`, 'unsupported_period'],
    [`otpauth://totp/x?secret=${SECRET}&period=-30`, 'unsupported_period'],
    [`otpauth://totp/x?secret=${SECRET}&period=1e3`, 'unsupported_period'],
    [`otpauth://totp/x?secret=${SECRET}&period=301`, 'unsupported_period'],
    [`otpauth://totp/x?secret=${SECRET}&period=9`, 'unsupported_period'],
    [`otpauth://totp/x?secret=${SECRET}&encoder=steam`, 'steam'],
    [`otpauth://user:pw@totp/x?secret=${SECRET}`, 'malformed_uri'],
    [`otpauth://totp:443/x?secret=${SECRET}`, 'malformed_uri'],
    [`otpauth://totp/x?secret=${SECRET}#frag`, 'malformed_uri'],
    [`otpauth://other/x?secret=${SECRET}`, 'malformed_uri'],
    [`otpauth://totp/x?secret=${SECRET}&x=${'a'.repeat(4096)}`, 'too_long'],
  ];
  it.each(refused)('refuses %j as %s', (input, error) => {
    expect(parseTotpInput(input)).toEqual({ ok: false, error });
  });

  it('ignores a malformed label instead of failing the secret', () => {
    expect(parseTotpInput(`otpauth://totp/%E0%A4%A?secret=${SECRET}`)).toEqual({
      ok: true,
      totp: { secret: SECRET, algorithm: 'SHA1', digits: 6, period: 30 },
    });
  });

  it('every accepted value is a valid stored value', () => {
    const inputs = [
      SECRET,
      encodeBase32(new Uint8Array(10).fill(1)),
      encodeBase32(new Uint8Array(64).fill(255)),
      `otpauth://totp/x?secret=${SECRET}&algorithm=SHA512&digits=7&period=10`,
      `otpauth://totp/x?secret=${SECRET}&period=300`,
    ];
    for (const input of inputs) {
      const parsed = parseTotpInput(input);
      if (!parsed.ok) throw new Error(`refused ${input}`);
      expect(totpSchema.parse(parsed.totp)).toEqual(parsed.totp);
    }
  });
});

describe('totpSchema', () => {
  const valid: Totp = { secret: encodeBase32(SEED.SHA1), algorithm: 'SHA1', digits: 6, period: 30 };
  it('refuses non-canonical or out-of-range stored values', () => {
    expect(totpSchema.safeParse(valid).success).toBe(true);
    for (const bad of [
      { ...valid, secret: valid.secret.toLowerCase() },
      { ...valid, secret: `${valid.secret}==` },
      { ...valid, secret: `${'A'.repeat(17)}B` }, // 11 bytes and two stray tail bits
      { ...valid, secret: encodeBase32(new Uint8Array(9)) },
      { ...valid, algorithm: 'sha1' },
      { ...valid, digits: 5 },
      { ...valid, period: 9 },
      { ...valid, period: 30.5 },
      { ...valid, issuer: 'Acme' },
      { secret: valid.secret, algorithm: 'SHA1', digits: 6 },
    ])
      expect(totpSchema.safeParse(bad).success, JSON.stringify(bad)).toBe(false);
  });
});
