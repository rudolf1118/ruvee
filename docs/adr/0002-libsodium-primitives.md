# ADR-0002: libsodium primitives on every platform

- Status: Proposed
- Date: 2026-10-22
- Specification: [cryptographic-design.md](../security/cryptographic-design.md)
- Evidence: [research-sources.md](../security/research-sources.md)

## Context

Web, extension, Node.js, iOS and Android must produce and read the same bytes. The master prompt
asks for Argon2id, authenticated encryption, domain-separated derivation and safe nonces, and it
forbids hand-written primitives.

## Decision

Use libsodium everywhere: `libsodium-wrappers-sumo` on web and extension, and
`react-native-libsodium` on mobile. Use only:

- XChaCha20-Poly1305-IETF with random 24-byte nonces
- Argon2id (`crypto_pwhash`)
- keyed BLAKE2b and `crypto_kdf_derive_from_key`
- `crypto_box_seal`
- `randombytes_buf`

## Consequences

- One library family and one set of primitives on every platform. Random 192-bit nonces remove
  nonce-tracking state.
- There is no HKDF, because libsodium.js does not export its functions and React Native marks them
  unstable. BLAKE2b-based derivation is used instead.
- There is no AES-GCM, because libsodium.js lacks it.
- libsodium's Argon2id fixes parallelism at 1.
- Audits are dated and don't cover current versions (R-02). Mobile exposes a subset of functions,
  so padding is implemented in `packages/crypto` and covered by vectors (R-16).

## Alternatives considered

- **WebCrypto (AES-GCM, HKDF) plus a separate Argon2 library.** It has no Argon2 and no XChaCha,
  splits the implementation across libraries, and needs nonce care with 96-bit nonces.
- **`@noble/*`.** Audited in 2024 and pure TypeScript, but slower for Argon2 and a second
  implementation to keep consistent. It is kept as a fallback candidate.
