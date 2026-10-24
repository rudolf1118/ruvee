# Architecture decision records

Each ADR records one decision: its context, the choice, its consequences and the alternatives
rejected. The specification itself lives in the linked document, not in the ADR.

An ADR becomes Accepted only when the owner approves it. Decisions on security-critical components
also need the independent review listed in the
[roadmap](../planning/implementation-roadmap.md#independent-review). An agent's recommendation is
neither. **Accepted for development** means the owner approved the decision for building the
next milestone; it is not an independent review and not approval to store real secrets.

| ADR                                           | Title                                                   | Status                                |
| --------------------------------------------- | ------------------------------------------------------- | ------------------------------------- |
| [0001](0001-record-architecture-decisions.md) | Record architecture decisions                           | Proposed                              |
| [0002](0002-libsodium-primitives.md)          | libsodium primitives on every platform                  | Accepted for development (2026-10-24) |
| [0003](0003-two-secret-key-derivation.md)     | Two-secret key derivation with a device-held Secret Key | Accepted for development (2026-10-24) |
| [0004](0004-opaque-authentication.md)         | OPAQUE authentication, separate from vault keys         | Proposed                              |
| [0005](0005-device-pairing.md)                | Device enrollment by MAC-authenticated pairing          | Proposed                              |
| [0006](0006-user-held-recovery-key.md)        | User-held Recovery Key, no administrator recovery       | Proposed                              |
| [0007](0007-sync-manifest-chain.md)           | Linear commits with an encrypted manifest chain         | Proposed                              |
| [0008](0008-session-model.md)                 | Cookie sessions for web, rotating tokens elsewhere      | Proposed                              |
| [0009](0009-web-client-trust.md)              | The web app trusts its server; say so                   | Proposed                              |

New ADRs copy the structure of an existing one and take the next number. An ADR is never edited
to reverse its decision; a new ADR supersedes it.
