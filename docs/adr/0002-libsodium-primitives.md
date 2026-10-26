# ADR-0002: libsodium primitives on every platform

- Status: **Accepted for development** (owner approval of D-01, 2026-10-24). This is an
  implementation decision, not a security audit, and not approval to store real secrets.
  Independent review (D-19) is still open.
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
- Ed25519 (`crypto_sign_keypair`, `crypto_sign_seed_keypair`, `crypto_sign_detached`,
  `crypto_sign_verify_detached`), for device proof of possession only
  ([ADR-0011](0011-device-proof-of-possession.md), added 2026-10-26 with D-31 option A as the
  development direction; not reviewed)

## Consequences

- One library family and one set of primitives on every platform. Random 192-bit nonces remove
  nonce-tracking state.
- There is no HKDF, because libsodium.js does not export its functions and React Native marks them
  unstable. BLAKE2b-based derivation is used instead.
- There is no AES-GCM, because libsodium.js lacks it.
- libsodium's Argon2id fixes parallelism at 1.
- The libraries need `'wasm-unsafe-eval'` in the web CSP and in the extension manifest. Without it
  they abort; there is no JavaScript fallback (verified in four browser engines).
- libsodium.js does not enforce every documented length minimum, so `packages/crypto` checks
  lengths itself.
- Audits are dated and don't cover current versions (R-02). Mobile exposes a subset of functions,
  so padding is implemented in `packages/crypto` and covered by vectors (R-16).

## Alternatives considered

- **WebCrypto (AES-GCM, HKDF) plus a separate Argon2 library.** It has no Argon2 and no XChaCha,
  splits the implementation across libraries, and needs nonce care with 96-bit nonces.
- **`@noble/*`.** Pure TypeScript, with audits of earlier versions (its Argon2 was outside the
  audit scope), slower for Argon2, and a second implementation to keep consistent. It is not
  used in production. It is the **independent test oracle** for the vector plan, replacing the
  Python and Go generators.

## Changes after architecture validation

Still **Proposed**. Changes made on 2026-10-22 from
[architecture-validation.md](../security/architecture-validation.md):

- Consequences: the `'wasm-unsafe-eval'` requirement and Ruvee-side length checks (V-11, V-12).
- Alternatives: noble's audit scope corrected, and its role as test oracle recorded (V-10, V-13).
- The decision itself is unchanged.

## Changes after P2-03

On 2026-10-24 the owner approved D-01 for this development milestone: `libsodium-wrappers-sumo`
0.8.4 and `libsodium-sumo` 0.8.4 (libsodium 1.0.22), exactly pinned. `packages/crypto` now uses
them on web through a guarded interface that checks every length itself, which contains V-15
and the V-12 discrepancies for its callers without fixing them upstream
([cryptographic-design.md §10](../security/cryptographic-design.md#10-implementation-status-packagescrypto-p2-03)).
`react-native-libsodium` remains untested, and the decision is unchanged.
