// Parses expected values out of the hash-verified published files. Nothing here computes an
// expected output: every value under an `expected` key is read from the source text.

import { te, unhex } from './bytes.mjs';

class ParseError extends Error {
  constructor(source, message) {
    super(`${source}: ${message}`);
    this.name = 'VectorParseError';
  }
}

function between(text, startMarker, endMarker, { occurrence = 1, source }) {
  let from = -1;
  for (let i = 0; i < occurrence; i++) {
    from = text.indexOf(startMarker, from + 1);
    if (from < 0) throw new ParseError(source, `marker not found: ${startMarker}`);
  }
  const to = endMarker ? text.indexOf(endMarker, from + startMarker.length) : text.length;
  if (to < 0) throw new ParseError(source, `end marker not found: ${endMarker}`);
  return text.slice(from, to);
}

// Reads `count` space-separated hex bytes that follow `label`, skipping page headers and footers.
function bytesAfter(section, label, count, source) {
  const at = section.indexOf(label);
  if (at < 0) throw new ParseError(source, `label not found: ${label}`);
  const out = [];
  for (const token of section.slice(at + label.length).split(/\s+/)) {
    if (out.length === count) break;
    if (/^[0-9a-fA-F]{2}$/.test(token)) out.push(parseInt(token, 16));
  }
  if (out.length !== count) throw new ParseError(source, `${label} has ${out.length} bytes`);
  return Uint8Array.from(out);
}

function cArray(section, name, source) {
  const m = section.match(new RegExp(`${name}\\[\\d+\\] = \\{([^}]*)\\}`));
  if (!m) throw new ParseError(source, `array not found: ${name}`);
  return m[1]
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => Number(s));
}

const pageNoise = /^(RFC \d+ .*\d{4}|.*\[Page \d+\]|Internet-Draft .*|Arciszewski .*)$/;

// Draft-style blocks: a "Label:" line followed by lines of hex.
function labelledHexBlocks(section) {
  const blocks = {};
  let current = null;
  for (const raw of section.split('\n')) {
    const line = raw.trim();
    if (!line || pageNoise.test(line)) continue;
    const label = line.match(/^([A-Za-z0-9][A-Za-z0-9 -]*):$/);
    if (label) {
      current = label[1];
      blocks[current] = '';
    } else if (current && /^[0-9a-fA-F]+$/.test(line)) {
      blocks[current] += line;
    }
  }
  return Object.fromEntries(Object.entries(blocks).map(([k, v]) => [k, unhex(v)]));
}

function parseRfc9106(text) {
  const source = 'rfc9106 §5.3';
  const s = between(text, '5.3.  Argon2id Test Vectors', '6.  IANA Considerations', {
    occurrence: 2,
    source,
  });
  const version = s.match(/Argon2id version number (\d+)/);
  const params = s.match(
    /Memory: (\d+) KiB, Passes: (\d+),\s+Parallelism: (\d+) lanes, Tag length: (\d+) bytes/,
  );
  if (!version || !params) throw new ParseError(source, 'parameters not found');
  const len = (label) => Number(s.match(new RegExp(`${label}\\[(\\d+)\\]`))?.[1]);
  const tagLength = Number(params[4]);
  return {
    source,
    version: Number(version[1]),
    mKiB: Number(params[1]),
    t: Number(params[2]),
    p: Number(params[3]),
    tagLength,
    password: bytesAfter(s, 'Password[32]:', len('Password'), source),
    salt: bytesAfter(s, 'Salt[16]:', len('Salt'), source),
    secret: bytesAfter(s, 'Secret[8]:', len('Secret'), source),
    associatedData: bytesAfter(s, 'Associated data[12]:', len('Associated data'), source),
    expected: { tag: bytesAfter(s, 'Tag:', tagLength, source) },
  };
}

function parsePhcArgon2(text) {
  const source = 'phc-winner-argon2 src/test.c (Argon2id section)';
  const s = between(text, 'printf("Test Argon2id version number', 'Common error state tests', {
    source,
  });
  const re =
    /hashtest\(version, (\d+), (\d+), (\d+), "([^"]*)", "([^"]*)",\s*"([0-9a-f]{64})",\s*"([^"]*)"\s*"([^"]*)", Argon2_id\);/g;
  const cases = [...s.matchAll(re)].map((m) => {
    const encoded = m[7] + m[8];
    const v = encoded.match(/^\$argon2id\$v=(\d+)\$m=(\d+),t=(\d+),p=(\d+)\$/);
    if (!v) throw new ParseError(source, `unexpected encoded string ${encoded}`);
    const c = {
      t: Number(m[1]),
      mKiB: 2 ** Number(m[2]),
      p: Number(m[3]),
      password: m[4],
      salt: m[5],
      version: Number(v[1]),
      expected: { tag: unhex(m[6]), encoded },
    };
    if (Number(v[2]) !== c.mKiB || Number(v[3]) !== c.t || Number(v[4]) !== c.p)
      throw new ParseError(source, `encoded parameters disagree with hashtest() arguments`);
    return c;
  });
  if (cases.length !== 8)
    throw new ParseError(source, `expected 8 Argon2id cases, found ${cases.length}`);
  return { source, outLength: 32, cases };
}

function parseDraftXChaCha(text) {
  const source = 'draft-irtf-cfrg-xchacha-03';
  const h = between(text, '2.2.1.  Test Vector for the HChaCha20 Block Function', '2.3.', {
    occurrence: 2,
    source: `${source} §2.2.1`,
  });
  const key = h.match(/Key = ([0-9a-f:\s]+)\./);
  const nonce = h.match(/Nonce = \(([0-9a-f:]+)\)/);
  const tail = h.slice(h.indexOf('resulting in the following 256-bit key:'));
  const words = tail.match(/\b[0-9a-f]{8}\b/g)?.slice(0, 8);
  if (!key || !nonce || words?.length !== 8) throw new ParseError(`${source} §2.2.1`, 'not parsed');

  const a = labelledHexBlocks(
    between(text, 'A.3.1.  AEAD_XCHACHA20_POLY1305', 'A.3.2.  XChaCha20', {
      occurrence: 2,
      source: `${source} §A.3.1`,
    }),
  );
  for (const f of ['Plaintext', 'AAD', 'Key', 'IV', 'Ciphertext', 'Tag'])
    if (!a[f]) throw new ParseError(`${source} §A.3.1`, `missing ${f}`);
  return {
    hchacha20: {
      source: `${source} §2.2.1`,
      key: unhex(key[1]),
      nonce: unhex(nonce[1]),
      expected: { subkey: unhex(words.join('')) },
    },
    aead: {
      source: `${source} §A.3.1`,
      plaintext: a.Plaintext,
      aad: a.AAD,
      key: a.Key,
      nonce: a.IV,
      expected: { ciphertext: a.Ciphertext, tag: a.Tag },
    },
  };
}

function parseWycheproof(text) {
  const source = 'wycheproof xchacha20_poly1305_test.json';
  const d = JSON.parse(text);
  if (d.algorithm !== 'XCHACHA20-POLY1305') throw new ParseError(source, 'wrong algorithm');
  const tests = d.testGroups.flatMap((g) =>
    g.tests.map((t) => ({
      tcId: t.tcId,
      comment: t.comment,
      flags: t.flags,
      key: unhex(t.key),
      iv: unhex(t.iv),
      aad: unhex(t.aad),
      // ct and tag are inputs to decryption and, for valid tests, expected encryption outputs.
      expected: {
        valid: t.result === 'valid',
        msg: unhex(t.msg),
        ct: unhex(t.ct),
        tag: unhex(t.tag),
      },
      result: t.result,
    })),
  );
  if (tests.length !== d.numberOfTests) throw new ParseError(source, 'test count mismatch');
  if (tests.some((t) => !['valid', 'invalid'].includes(t.result)))
    throw new ParseError(source, 'unexpected result value (acceptable results need a policy)');
  return { source, tests };
}

function parseRfc7693(text) {
  const source = 'rfc7693';
  const abc = text.match(/BLAKE2b-512\("abc"\) = ((?:[0-9A-F]{2}\s+)+)/);
  if (!abc) throw new ParseError(`${source} Appendix A`, 'BLAKE2b-512("abc") not found');
  const st = between(text, 'int blake2b_selftest()', 'int blake2s_selftest()', {
    source: `${source} Appendix E`,
  });
  const seq = text.match(/a = (0x[0-9A-F]+) \* seed;/);
  const init = st.match(/blake2b_init\(&ctx, (\d+), NULL, 0\)/);
  if (!seq || !init) throw new ParseError(`${source} Appendix E`, 'generator or init not found');
  return {
    abc: {
      source: `${source} Appendix A`,
      input: te.encode('abc'),
      outLength: 64,
      expected: { hash: unhex(abc[1]) },
    },
    selftest: {
      source: `${source} Appendix E`,
      mdLengths: cArray(st, 'b2b_md_len', source),
      inLengths: cArray(st, 'b2b_in_len', source),
      seedMultiplier: Number(seq[1]),
      grandHashLength: Number(init[1]),
      expected: { grandHash: Uint8Array.from(cArray(st, 'blake2b_res', source)) },
    },
  };
}

function parseBlake2bKat(text) {
  const source = 'BLAKE2 blake2b-kat.txt';
  const entries = text
    .trim()
    .split(/\n\s*\n/)
    .map((block) => {
      const f = Object.fromEntries(
        block.split('\n').map((l) => l.split(':\t').map((x) => x.trim())),
      );
      return { input: unhex(f.in ?? ''), key: unhex(f.key), expected: { hash: unhex(f.hash) } };
    });
  if (entries.length !== 256)
    throw new ParseError(source, `expected 256 entries, got ${entries.length}`);
  return { source, entries };
}

function parseRfc7748(text) {
  const source = 'rfc7748';
  const s52 = between(text, '5.2.  Test Vectors', '6.  Diffie-Hellman', { occurrence: 2, source });
  const firstX448 = s52.indexOf('X448:');
  const direct = s52.slice(s52.indexOf('X25519:'), firstX448);
  const vectors = [
    ...direct.matchAll(
      /Input scalar:\s+([0-9a-f]{64})[\s\S]*?Input u-coordinate:\s+([0-9a-f]{64})[\s\S]*?Output u-coordinate:\s+([0-9a-f]{64})/g,
    ),
  ].map((m) => ({ scalar: unhex(m[1]), u: unhex(m[2]), expected: { out: unhex(m[3]) } }));
  const start = s52.match(/For X25519:\s+([0-9a-f]{64})/);
  const it = s52.slice(s52.indexOf('X25519:', firstX448));
  const one = it.match(/After one iteration:\s+([0-9a-f]{64})/);
  const thousand = it.match(/After 1,000 iterations:\s+([0-9a-f]{64})/);
  const million = it.match(/After 1,000,000 iterations:\s+([0-9a-f]{64})/);
  const s61 = between(text, '6.1.  Curve25519', '6.2.  Curve448', { occurrence: 2, source });
  const field = (label) => s61.match(new RegExp(`${label}\\s+([0-9a-f]{64})`))?.[1];
  const dh = {
    a: field("Alice's private key, a:"),
    A: field("Alice's public key, X25519\\(a, 9\\):"),
    b: field("Bob's private key, b:"),
    B: field("Bob's public key, X25519\\(b, 9\\):"),
    K: field('Their shared secret, K:'),
  };
  if (
    vectors.length !== 2 ||
    !start ||
    !one ||
    !thousand ||
    !million ||
    Object.values(dh).some((v) => !v)
  )
    throw new ParseError(source, 'X25519 vectors not parsed');
  return {
    source: `${source} §5.2, §6.1`,
    vectors,
    iterated: {
      start: unhex(start[1]),
      expected: { one: unhex(one[1]), thousand: unhex(thousand[1]) },
      notRun: {
        million: unhex(million[1]),
        reason: '1,000,000 iterations exceeds the run-time bound',
      },
    },
    dh: {
      a: unhex(dh.a),
      b: unhex(dh.b),
      expected: { A: unhex(dh.A), B: unhex(dh.B), K: unhex(dh.K) },
    },
  };
}

export function parseVectors(sources) {
  const x = parseDraftXChaCha(sources['draft-xchacha-03'].text);
  const b = parseRfc7693(sources.rfc7693.text);
  return {
    argon2Rfc9106: parseRfc9106(sources.rfc9106.text),
    argon2Phc: parsePhcArgon2(sources['phc-argon2-test'].text),
    hchacha20: x.hchacha20,
    xchachaDraft: x.aead,
    wycheproof: parseWycheproof(sources['wycheproof-xchacha'].text),
    blake2bAbc: b.abc,
    blake2bSelftest: b.selftest,
    blake2bKat: parseBlake2bKat(sources['blake2b-kat'].text),
    x25519: parseRfc7748(sources.rfc7748.text),
  };
}

// Negative controls. expectedFieldPaths lists every expected field of a vector set; in a list of
// cases it uses the last case (the last valid one for Wycheproof-style lists), so a check that
// stops early or skips cases is also caught. mutateAt returns a copy with that one field wrong.
export function expectedFieldPaths(vectorSet) {
  const paths = [];
  const walk = (node, path) => {
    if (!node || typeof node !== 'object' || node instanceof Uint8Array) return;
    if (Array.isArray(node)) {
      let i = node.length - 1;
      while (i > 0 && node[i]?.expected?.valid === false) i--;
      if (i >= 0) walk(node[i], [...path, i]);
      return;
    }
    for (const [k, v] of Object.entries(node)) {
      if (k === 'notRun') continue;
      if (k === 'expected') for (const f of Object.keys(v)) paths.push([...path, k, f]);
      else walk(v, [...path, k]);
    }
  };
  walk(vectorSet, []);
  return paths;
}

export function mutateAt(vectorSet, path) {
  const clone = structuredClone(vectorSet);
  let parent = clone;
  for (const k of path.slice(0, -1)) parent = parent[k];
  const key = path[path.length - 1];
  const v = parent[key];
  if (v instanceof Uint8Array) {
    if (v.length === 0) parent[key] = Uint8Array.of(0);
    else v[v.length - 1] ^= 0x01;
  } else if (typeof v === 'string') {
    // Change a character well inside the string, so the change cannot fall into base64 padding bits.
    const i = Math.max(0, v.length - 10);
    parent[key] = v.slice(0, i) + (v[i] === 'A' ? 'B' : 'A') + v.slice(i + 1);
  } else if (typeof v === 'boolean') parent[key] = !v;
  else throw new Error(`cannot mutate ${typeof v} at ${path.join('.')}`);
  return clone;
}
