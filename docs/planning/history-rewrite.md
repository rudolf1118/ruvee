# Commit history rewrite (2026-10-28)

On 2026-10-28 every commit on every branch was rewritten once, before the repository was
published. The author and committer of each commit were set to the project identity, and
`Co-authored-by` trailers were removed from commit messages. **File contents did not change:**
each rewritten commit has exactly the same tree as the commit it replaces. Only the commit IDs
changed.

The documents on `vault/web-vault` that cite commits (the security reviews, the review checklist,
the architecture validation and the status page) were updated to the new IDs. Use this table for
any other old ID: in notes, in conversation logs, or in the `docs/mobile` documents on
`mobile/vault-app`. The table lists every commit that existed then, oldest first, with the
author date.

| Old ID    | New ID    | Date       | Subject                                                                                    |
| --------- | --------- | ---------- | ------------------------------------------------------------------------------------------ |
| `e912e7c` | `5c47579` | 2026-10-21 | Phase 1 foundation: monorepo, API health/config/logging, web app shell and dev-only UI ... |
| `0a6cd24` | `678b630` | 2026-10-22 | docs: Phase 0 security architecture (proposed)                                             |
| `1d4ce85` | `554d01a` | 2026-10-22 | docs(security): architecture validation and compatibility spike                            |
| `ed87006` | `0e406b1` | 2026-10-22 | P2-01: primitive validation harness for the candidate crypto libraries                     |
| `5b8fbba` | `5171c48` | 2026-10-23 | tools(crypto-validation): Argon2id calibration benchmark and local measurements (P2-02,... |
| `1c002cd` | `54cbc1b` | 2026-10-23 | api: shared contracts, error codes, body limits and route-template logging (P2-05)         |
| `94b1c0c` | `4240324` | 2026-10-24 | crypto: packages/crypto with password rule, AUK, password wrap, keyset envelope and pad... |
| `3e73ff1` | `3b42469` | 2026-10-24 | web: hashed CSP, security headers and crypto worker under the static export (P2-04, cry... |
| `ed43986` | `e044474` | 2026-10-25 | web: OPAQUE under the production CSP in three engines; diagnostics-only export (P2-04)     |
| `498871a` | `ae012b3` | 2026-10-25 | crypto: Recovery Key, recovery wrap, item records, manifests and local records             |
| `7a0f41e` | `4d14638` | 2026-10-25 | api: first migration with the identity and vault tables                                    |
| `19e43ed` | `5cb1c24` | 2026-10-25 | api: OPAQUE registration and login, cookie sessions, CSRF, throttling and sync             |
| `5cab515` | `6f677b8` | 2026-10-25 | web: vault worker, account setup, unlock, items and sync in the existing UI                |
| `efa9b7e` | `062295f` | 2026-10-25 | crypto, api: device pairing (D-21, approved for development)                               |
| `6481bac` | `259a990` | 2026-10-25 | web: pairing screens and a two-device browser suite; status and handoff docs               |
| `80eda26` | `73f30ff` | 2026-10-25 | recovery: Recovery Kit recovery on a new or existing browser (P2-13)                       |
| `aa67bbb` | `69ed527` | 2026-10-25 | account: step-up, sessions, device revocation and password change (P2-11, P2-14)           |
| `c9b430c` | `315b459` | 2026-10-25 | keys: Secret Key rotation on lost-device removal and from Security (D-24)                  |
| `aee6fb1` | `58f3b27` | 2026-10-25 | recovery: Recovery Kit rotation from Security (P2-14)                                      |
| `ebe44d3` | `2634786` | 2026-10-25 | account: activity screen from security events (P2-15)                                      |
| `34cb857` | `6e1adc1` | 2026-10-25 | docs, tests: Phase 2 self-review packet (P2-16)                                            |
| `27feae1` | `66c245e` | 2026-10-25 | docs: browser extension design and threat-model addendum (Phase 5 gate)                    |
| `203c1d1` | `4322ef1` | 2026-10-25 | api: token sessions for the extension (Phase 5)                                            |
| `778e12b` | `8d54b48` | 2026-10-25 | refactor: move the vault engine into @ruvee/vault for the web app and the extension        |
| `9bd640d` | `6c7869c` | 2026-10-25 | extension: Chromium MV3 extension with pairing, unlock and exact-origin fill (Phase 5)     |
| `75f5dda` | `0c83151` | 2026-10-25 | extension: ask for the previous password when the password and SK both changed             |
| `5840042` | `f0c1a9c` | 2026-10-26 | test, fix: close browser-level gaps for the extension; self-host the web fonts             |
| `61b133c` | `231452c` | 2026-10-26 | docs: backup and restore design for owner decision; review packet for the extension        |
| `7e74f8f` | `0310311` | 2026-10-26 | export: portable encrypted export, D-13 option A (approved for development)                |
| `0d2166d` | `c247edc` | 2026-10-26 | import: restore an encrypted export into a fresh installation (D-13 A, M2)                 |
| `fffbbaa` | `fc36e0e` | 2026-10-26 | docs, test: decision-ready server restore design (M1, D-28 open)                           |
| `1e10cd7` | `974240d` | 2026-10-26 | restore: maintenance-mode server restore under the revised D-28 (synthetic data only)      |
| `dc2a97c` | `8e40efe` | 2026-10-26 | backup: age-encrypted server backups and verified restore (D-29 B, synthetic data only)    |
| `2caa795` | `039a960` | 2026-10-26 | reopen: host-issued reopening after a restore, server side (D-30 B, synthetic data only)   |
| `d5a07c8` | `f9bf05e` | 2026-10-26 | reopen: client reopening flows on both credential paths (D-30 B)                           |
| `5605095` | `ffa8b67` | 2026-10-26 | deps: patch body-parser 2.4.0 and multer 2.5.0 (GHSA-27r3-jxmh-p828, GHSA-q7qp-rjg7-q26m)  |
| `0617ba1` | `ba0396f` | 2026-10-26 | docs: reopening (D-30 B), age interoperability, advisory disposition                       |
| `e1056db` | `e99af74` | 2026-10-26 | review: pre-deployment security review of ba0396f and reproduction tests                   |
| `509b092` | `5fb89b6` | 2026-10-26 | fix(R1): decide the gate, CSRF and bearer rules by the matched route, not URL text         |
| `4367db9` | `ed72460` | 2026-10-26 | fix(R7): back up and restore exactly the database that was checked                         |
| `5bc18cd` | `8d85df6` | 2026-10-26 | fix(R8): keep restore authority out of reach of the SQL in a restored dump                 |
| `40dc0bc` | `024f0a9` | 2026-10-26 | fix(R8): typed catalog map in the restored-object check (lint)                             |
| `e8259da` | `deaf04f` | 2026-10-26 | fix(R9): restore exactly the bytes that were verified                                      |
| `bfb248a` | `ec360da` | 2026-10-26 | fix(R10): serve only the CSP and cache rules generated from the build                      |
| `d179588` | `1713058` | 2026-10-26 | docs(R1,R7,R8,R9,R10): record remediation evidence and new deployment assumptions          |
| `e957b20` | `cf8db8e` | 2026-10-26 | docs(R2): propose D-31 device proof of possession for the owner's decision                 |
| `70c6a15` | `4c10265` | 2026-10-26 | test: drop temporary databases on every failure path, by exact name                        |
| `d239bb5` | `5412637` | 2026-10-26 | fix(R14): open only on an explicit lifecycle answer, cache only open                       |
| `b990cd0` | `7aba2c0` | 2026-10-26 | fix(R3): reserve every password and recovery check atomically                              |
| `56eef75` | `316cba5` | 2026-10-26 | fix(R11): wrong reopening codes never use up the real one                                  |
| `233333d` | `c3698e0` | 2026-10-26 | fix(R13): serialize a reopening's completion with host-issued codes                        |
| `6ed27df` | `4b9cd1f` | 2026-10-26 | fix(R15): never hand pg_restore an unverified complete archive                             |
| `417acfe` | `5f8eafe` | 2026-10-26 | fix(R16,R17): per-session request limit; key IPv6 by /64; warn without a proxy             |
| `40a6cf4` | `7871713` | 2026-10-26 | fix(R5): a commit reply never lowers the verified checkpoint                               |
| `a916561` | `0d6ead8` | 2026-10-26 | fix(R6,R20): recovery keeps this browser's vault and its rollback floors                   |
| `32acea1` | `f12a23d` | 2026-10-26 | docs: record remediation milestone 2 and tighten the D-31 proposal                         |
| `6c127d7` | `368eae3` | 2026-10-26 | docs(D-31): specify device proof of possession before implementing it                      |
| `3876ad1` | `8687ce8` | 2026-10-26 | feat(D-31): Ed25519 device and account proofs in @ruvee/crypto                             |
| `a98e299` | `3563e31` | 2026-10-26 | feat(D-31): server enforces device proof of possession (R2, R12)                           |
| `e62a198` | `c352f2b` | 2026-10-26 | feat(D-31): clients hold a device key and prove possession (R2, R12)                       |
| `640a12b` | `3a8efa5` | 2026-10-26 | docs(D-31): record device proof across the specifications                                  |
| `3d9b8bf` | `7fd57e6` | 2026-10-26 | test(D-31): bind operation proofs to account, operation and session                        |
| `f702fe0` | `8b10ac3` | 2026-10-26 | docs(review): R2 and R12 fixed by D-31; record the milestone                               |
| `56731e2` | `c43c910` | 2026-10-27 | fix(R19,R22,R23): a lock wins over work in flight; start-over and import counts            |
| `e67266f` | `858a5d9` | 2026-10-27 | fix(R18): fill only fields the user can actually see                                       |
| `82183d7` | `37166f0` | 2026-10-27 | fix(R23): burn pairing requests the server altered; show A's own time                      |
| `09c0cad` | `29b9bbc` | 2026-10-27 | style: format the enrollment spec and the fake server                                      |
| `5d1f571` | `f1ec0ca` | 2026-10-27 | fix(R21,R23): serialized pairing and nonce issue; extension CSRF per route                 |
| `fa73e0c` | `f52619d` | 2026-10-27 | feat(deploy): enforce one API process per database                                         |
| `74ab988` | `52e3aa7` | 2026-10-27 | docs(R23): the extension filters messages by sender id and origin                          |
| `fbb72fb` | `fe2d275` | 2026-10-27 | test(D-31): sequential migration, logout cleanup, a lost session proof                     |
| `773626b` | `711c04f` | 2026-10-27 | test(R18,R19): extension in Chromium: hidden fields, lock races, worker stops              |
| `6164089` | `01bc449` | 2026-10-27 | docs(review): disposition of all 23 findings; follow-up review checklist                   |
| `6e9ebeb` | `51ab3d8` | 2026-10-27 | fix(D-31): pre-D-31 accounts never acquire an AVPK; move them by export                    |
| `d04e211` | `1702ea6` | 2026-10-27 | docs(R23): defer device names for V1; amend the enrollment spec                            |
| `11cda6a` | `0298e58` | 2026-10-27 | docs(D-31): accounts from before D-31 move to a new account                                |
| `e0a8586` | `3b67a30` | 2026-10-27 | docs(review): §13 legacy-account hardening and device names; checklist at 1702ea6          |
| `5594768` | `39b1c5b` | 2026-10-27 | test(review): follow-up reproductions; fix two races in test:migrate                       |
| `048000d` | `6576324` | 2026-10-27 | docs(review): fresh follow-up review of 1702ea6; integration DB note                       |
| `5561779` | `bdf5ba5` | 2026-10-27 | fix(review): F-1 to F-4 from the follow-up review                                          |
| `71e2fb5` | `7992777` | 2026-10-27 | feat(SC-1): ios and android log in and pair as token platforms                             |
| `3f05b80` | `6d5bfee` | 2026-10-27 | chore(SC-6): prettier ignores the mobile lockfiles and native build output                 |
| `533618e` | `5cd2628` | 2026-10-27 | feat(mobile): native OPAQUE client binding of opaque-ke 4.0.1 (D-05 option 2)              |
| `5577eb4` | `64507a6` | 2026-10-27 | feat(mobile): React Native Android app with the first vault slice                          |
| `0f786b0` | `49a3fb5` | 2026-10-27 | test(mobile): end-to-end suite on the Android emulator against a real API                  |
| `f138555` | `1e4bd5d` | 2026-10-27 | docs(mobile): status, native compatibility evidence, storage policy, tests, shared-chan... |
