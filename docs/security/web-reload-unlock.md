# Keeping the web vault unlocked across a reload (D-34)

Status: **Proposed (2026-11-11). A design for the owner to decide; nothing is implemented.** Not
reviewed. The decision is [D-34](../architecture/open-decisions.md). Approving it would change the
wording of INV-15 and INV-16 and add one invariant (§6), so it needs the owner's explicit
decision, like D-27.

## 1. The problem

On the private rehearsal server (2026-11-11), every reload of the web vault showed the lock screen
and asked for the master password. That is the documented behaviour, not a defect:

- The web session cookie (`__Host-ruvee_session`, 12 h idle, 14 days absolute, D-08) survives a
  reload, so the user stays **logged in**.
- `AK`, and everything derived from it (`K_keyset`, `K_local`, `VK`, the device key `DSK`), lives
  only in the vault worker's memory (`apps/web/src/vault/worker/vault.worker.ts`). A reload ends the
  worker, so the vault is **locked** (INV-15, INV-16). Unlocking costs one Argon2id derivation and
  the password; it stays offline-capable because locking is local (D-23).
- [followup-review.md](followup-review.md) records "A reload shows the lock screen" as expected.

Two facts about the current code shape every option:

1. **`AK` never reaches the page's main thread.** The engine's `accountKeyForResume()` is not in
   the worker's dispatch allow-list (`packages/vault/src/vault-engine.ts`, "no UI can ask for
   it"). Script in the page, including an XSS, can drive the worker's allow-listed API while the
   vault is unlocked (T-18), but it cannot copy `AK` out. Today `AK` leaves memory only wrapped
   under `AUK` (password) or `RWK` (Recovery Key).
2. **One tab runs the vault** (follow-up F-2, `apps/web/src/vault/tab-lock.ts`). A second tab takes
   the Web Lock over a `BroadcastChannel`; the first tab finishes its writes and locks. So "a new
   tab" is not a second unlocked copy; it is a take-over, and today it always asks for the
   password.

The engine already has what a resume needs: `resume({ accountKey })` rebuilds the unlocked state
from `AK`, refusing any `AK` that does not open this device's own keyset (D-27, used by the
extension). Every option below that keeps the vault open ends in that call.

## 2. What a resume must not weaken

These are the properties that the owner approved and that an option is judged against:

- **Auto-lock (D-10):** 15 minutes by default, 1 minute to 8 hours, no "never" on web. Today a
  closed tab is locked at once, and an idle open tab locks on the page's timer.
- **A locked device cannot sign** ([device-proof.md](device-proof.md)): `DSK` is sealed under
  `K_local`, so whatever recovers `AK` also recovers the device's proof key.
- **A stolen locked device needs the password** (T-22): the profile holds `SK` and the wrapped
  `AK`, which cost one Argon2id per guess. It may also hold a live session cookie (R-18), which
  gives T-12 and T-14 but decrypts nothing (INV-06).
- **Logout, session expiry and revocation lock** (authentication.md §5, INV-15).

## 3. Attackers considered

From [threat-model.md §3](threat-model.md): **A6** XSS in the Ruvee origin; **A7** a stolen or lost
device at rest, which here includes **a copied browser profile** (a backup, a sync tool, malware
that copies files and leaves); **A8** a malicious browser extension with host access to the Ruvee
origin, or other malware running as the user. A3 (the server serves modified JavaScript, T-10)
already defeats every web option, so it is mentioned only where an option extends its reach
beyond the web app.

Browser facts this analysis relies on, each to be confirmed by the spike in §8 before
implementation:

- **`sessionStorage` reaches disk.** Chromium keeps it in the profile's `Session Storage` store so
  that session restore can bring tabs back; Firefox keeps it in its session-restore file. A copied
  profile can contain it, and "Continue where you left off" restores it into a tab after a browser
  restart. It is per tab: a new tab starts empty, but **Duplicate tab** copies it.
- **A non-extractable WebCrypto key is not protected at rest.** `extractable: false` stops
  `exportKey`, not use. When the `CryptoKey` is stored in IndexedDB, the browser serializes the
  key bytes into the profile; no browser documents encrypting them with an OS key. Script in the
  origin (XSS) can use the key to decrypt without exporting it.
- **Hidden-tab timers are throttled.** Chromium may run a hidden page's chained timers once a
  minute after 5 minutes; dedicated-worker timers are not documented as throttled the same way.

## 4. Options

### Option A: keep it as it is

Every reload and every new tab asks for the password.

| Attacker                  | Gains compared with today                                                                                                                        |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| XSS (A6)                  | Nothing new. While unlocked it drives the worker (T-18); it can show a fake lock screen and phish the password, which needs the user to type it. |
| Stolen locked device (A7) | Nothing new (T-22, R-18).                                                                                                                        |
| Malicious extension (A8)  | Nothing new (T-23); it reads what the page shows, and can capture the password when the user types it.                                           |
| Copied profile (A7)       | Nothing new: `SK`, wrapped `AK`, maybe a live cookie; the password is still needed.                                                              |

- **Invariants:** none change.
- **Auto-lock:** unchanged.
- **Cost:** the owner's complaint stands. Two cheap mitigations fit this option and every other
  one: a `beforeunload` prompt while unlocked ("Reloading locks Ruvee"), and no app-initiated full
  reloads (the "Ruvee couldn't start" screen's Reload button, update banners). Neither helps a
  user who presses reload on purpose.
- **Tests:** the existing ones (`two-devices.spec.ts` reload-then-unlock, the INV-16 scan).

### Option B: `AK` under a non-extractable WebCrypto key, with a per-tab secret

On unlock the worker wraps `AK` under a non-extractable AES-GCM `CryptoKey` kept in IndexedDB,
with a random 32-byte per-tab secret mixed in; the secret goes to `sessionStorage` (the main
thread must hold it: workers cannot read `sessionStorage`). On load, the page hands the secret to
the worker, which unwraps `AK` and calls `resume`. Lock, auto-lock and logout delete the wrapped
`AK`, the key and the secret; `pagehide` cannot be used to clear them, because a reload fires it
too.

| Attacker                  | Gains compared with today                                                                                                                                                                                                                                                                                                                   |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| XSS (A6)                  | **`AK` itself, silently.** Script in the tab reads the secret and the wrapped record and calls `crypto.subtle.decrypt` with the stored key. With `SK` (already readable, T-19) it holds the account's root key until a full key rotation, and can sign as the device (`DSK` under `K_local`). Today it needs the user to type the password. |
| Stolen locked device (A7) | If the browser was closed without locking, **everything, with no password**, when session restore is on or the `Session Storage` files survived: the secret, the wrapped `AK` and the key bytes are all in the profile. Auto-lock is a timer in the page and does not run while the browser is closed.                                      |
| Malicious extension (A8)  | With host access to the origin it runs as XSS does: `AK`, silently. Today it must wait for the password.                                                                                                                                                                                                                                    |
| Copied profile (A7)       | Same as the stolen device: no cryptographic barrier remains after the browser has written its session state. The non-extractable flag adds nothing at rest.                                                                                                                                                                                 |

- **Invariants:** INV-16 needs a real exception, not D-27's reading: `AK` is written to persistent
  storage (IndexedDB, and possibly the session-restore files), protected only by values stored
  next to it. INV-15 must add "and deletes the stored wrap". T-19 and T-22 change from "needs the
  password" to "does not, until the next lock".
- **Auto-lock:** the page must store its last-activity time with the wrap and refuse a resume past
  the auto-lock period, as the extension does (`SESSION_ACTIVITY` in `apps/extension/src/background.ts`).
  That check is code, not cryptography: an attacker with the files ignores it.
- **New tab:** not covered (no `sessionStorage`); a duplicated tab is.
- **Tests:** reload resumes; lock, auto-lock (fake clock) and logout leave no wrap; a page loaded
  past the activity limit locks; the INV-16 byte scan after lock covers IndexedDB and
  `sessionStorage`.

**Not recommended**: its at-rest guarantee depends on browser behaviour the app does not control,
and in the common case (session restore on) it removes the password from T-22.

### Option C: the web app unlocks through the installed extension

The extension, when unlocked, holds `AK` in `chrome.storage.session` (D-27). The web page would
ask it for `AK` (or for a wrap of `AK` to the page) over `externally_connectable` and resume.

| Attacker                  | Gains compared with today                                                                                                                                                                                                                   |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| XSS (A6)                  | **`AK` from the extension**, silently unless every hand-off needs a click in extension UI; with the click, `AK` still lands in the page the XSS runs in. Worse, it reaches users who only use the extension and never unlock the web vault. |
| Stolen locked device (A7) | Nothing new: `chrome.storage.session` is memory only, and the extension locks on its own alarm.                                                                                                                                             |
| Malicious extension (A8)  | Nothing new from the channel itself (only the listed web origin can connect), but a malicious extension with host access to the Ruvee origin can use the page to ask, as XSS does.                                                          |
| Copied profile (A7)       | Nothing new.                                                                                                                                                                                                                                |
| Server (A3, T-10)         | **New reach:** today modified web JavaScript attacks only users who type their password into the web app. With C, it pulls `AK` out of the extension of every user who has it unlocked.                                                     |

- **Invariants:** extension-design.md §1 and E-03 ("no `externally_connectable`") reverse; INV-19's
  spirit (pages never receive keys from the extension) needs an exception; T-10's scope widens to
  extension users.
- **Auto-lock:** two locks to keep consistent; the page would also need its own.
- **Reach:** Chromium only, and only while the extension is installed, paired and unlocked.
- **Tests:** a Playwright run with the unpacked extension: hand-off only to the exact web origin,
  refused while the extension is locked, refused from another origin or extension id.

**Not recommended**: it moves the web origin's weakest trust assumption (ADR-0009, D-07) into the
extension, which was built to avoid it.

### Option D (recommended): a reload ticket split between the tab and the server

Option B with its at-rest weakness removed: the key that wraps `AK` needs a second half that only
the server holds, only for a short time, and only for this session. A copied profile or a stolen
device then needs a live ticket on the server, which lock, logout, auto-lock, and a closed tab
all remove within minutes. Details are in §5.

| Attacker                  | Gains compared with today                                                                                                                                                                                                                                                                                                                                                   |
| ------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| XSS (A6)                  | **`AK`, silently, while a ticket is live** (the vault is unlocked, or its tab closed under 3 minutes ago): the tab half is in `sessionStorage` and the redeem request carries the same cookie the page sends. This is the same escalation as B and the one cost of D. It is bounded by the ticket's life; XSS after a lock or an expiry gains nothing new (T-19 unchanged). |
| Stolen locked device (A7) | Nothing new **once the ticket has expired**: at most 3 minutes after the tab or browser closed, or the auto-lock period after the last activity, whichever comes first, and at once after a lock or logout that reached the server. Within that window, a thief with the running or just-closed browser resumes the vault, like taking an unlocked laptop today (T-23).     |
| Malicious extension (A8)  | As XSS: `AK` while a ticket is live. Today it gets the plaintext the page shows and the password when typed (T-23).                                                                                                                                                                                                                                                         |
| Copied profile (A7)       | Nothing new after the ticket expires: the profile holds the tab half and the sealed `AK`, never the server half. A copy made inside the window and used inside it resumes once (the ticket is single-use), and the user's next reload then shows the lock screen, a visible sign.                                                                                           |
| Database thief (A2)       | Server halves of live tickets, which alone open nothing (they are random, not derived from any key).                                                                                                                                                                                                                                                                        |

- **Invariants:** INV-15 and INV-16 change wording; a new INV-25 states the ticket's rules; T-18
  records the `AK` exposure; T-19 and T-22 gain a bounded window (§6).
- **Auto-lock:** enforced twice: the page's timer as today, and the server's idle limit, which a
  closed tab or a copied profile cannot bypass.
- **New tab:** optional second step (§5.6), through the existing take-over.
- **Offline:** a reload without the server shows the lock screen, as today; unlocking with the
  password still works offline (D-23 unchanged).
- **Cost:** two API endpoints, one small table, one new envelope purpose, a heartbeat; about the
  size of the D-27 change plus the server part.
- **Tests:** §7.

### Option E: quick unlock with a passkey (WebAuthn PRF)

Not "stay unlocked", but "unlock without typing the password": on unlock, wrap `AK` under a key
from the PRF output of a platform passkey, store the wrap in IndexedDB, and after a reload ask the
browser for the passkey (Touch ID, Windows Hello).

- **XSS:** can start a WebAuthn request; the OS prompt appears and the user may approve it,
  which is the passkey version of today's fake password prompt. **Stolen device / copied profile:**
  nothing without the authenticator and the user's biometric or PIN. **Malicious extension:** as
  XSS.
- **Invariants:** a new persistent wrap of `AK` under a key that is not from the password or `RK`
  (a new INV-17-style rule and a new purpose); D-11 deferred biometric unlock to Phase 6, so this
  reopens D-11 for the web.
- **Reach:** PRF support is recent and uneven across browsers and authenticators; a fallback to
  the password is always needed.
- **Verdict:** a good later addition for the lock screen, compatible with D. It does not answer the
  complaint (a reload still interrupts), so it is listed, not recommended now.

### Options considered and rejected

- **Keep `AK` in a service worker or `SharedWorker`.** A service worker is stopped after about 30
  seconds idle, the same problem MV3 has, so the result would depend on timing. A
  `SharedWorker` dies with the last tab of the origin, which a reload of the only tab is. A
  service worker would also give XSS a way to persist across loads (it intercepts every later
  request), which the web app deliberately does not have today.
- **The extension hosts the vault UI** (D-07's public-mode question). It would make reloads a
  non-issue, but it is a product change, Chromium-only, and already its own decision.
- **Lock less: end the server session on lock instead.** Unrelated to reloads; D-23 decided it.

## 5. Option D in detail

Names: `H_tab` (tab half), `H_srv` (server half), `K_reload`, ticket id `tid`. (`S` already names
the pairing secret, so it is not reused.)

### 5.1 Creating a ticket

After every unlock, resume or successful redeem, while the tab holds the vault lock:

1. The worker draws `tid` (16 B), `H_tab` (32 B) and asks the server for a ticket:
   `POST /api/v1/reload-tickets` with `{ tid, idleSeconds }`. The session must be an **active,
   proven device session** (INV-24): a pre-proof session cannot create one. `idleSeconds` is the
   auto-lock period, which the server caps at D-10's 8 hours.
2. The server draws `H_srv` (32 B) and stores a row: `tid`, session id, device id, `H_srv`,
   `expires_at = now + 3 min`, `idle_expires_at = now + idleSeconds`. It answers `{ hSrv }`. At most
   one live ticket per session: a new one replaces the old.
3. The worker computes
   `K_reload = MAC(H_srv, "ruvee/v1/reload" ‖ H_tab ‖ tid)` (keyed BLAKE2b, as for `AUK`) and seals
   `AK` as a new envelope purpose (`RELOAD_TICKET`, from the reserved `0x09`–`0x0F`, specified in
   cryptographic-design.md §4.3 before use): key id `tid`, context
   `account_id ‖ device_id ‖ ak_id`. It zeroes `H_srv` and `K_reload`.
4. The worker gives the page `{ tid, H_tab, envelope }`, which writes it to `sessionStorage` under
   one key. Nothing goes to IndexedDB. The page never sees `H_srv` or `AK`.

### 5.2 Keeping it alive

- **Heartbeat:** the worker sends `POST /api/v1/reload-tickets/:tid/heartbeat` every 60 seconds
  while the tab is open (worker timers, to avoid hidden-tab throttling), which moves `expires_at`
  to now + 3 minutes. A closed tab, a closed browser and a sleeping laptop stop it.
- **Activity:** the page already tracks pointer and key events for auto-lock. At most once a
  minute, a heartbeat carries `active: true`, which moves `idle_expires_at` to now + `idleSeconds`.
- The server never extends either limit past the session's own expiry.

### 5.3 Reload

1. The new page finds the `sessionStorage` entry, takes the tab lock as today, and passes
   `{ tid, H_tab, envelope }` to the new worker. It deletes the entry at once, before any request,
   so a failed resume leaves nothing behind.
2. The worker calls `POST /api/v1/reload-tickets/:tid/redeem`. The server, in one transaction,
   deletes the row and returns `H_srv` only if the row exists, belongs to this session and device,
   the device is active, and neither limit has passed (INV-23 style: single use, concurrent
   redeems get one success).
3. The worker derives `K_reload`, opens the envelope with the expected context, calls
   `resume({ accountKey })` (which refuses an `AK` that does not open this device's keyset), and
   creates a fresh ticket (§5.1).
4. Any failure (offline, expired, revoked, wrong session, a changed keyset) shows the lock screen
   with no message beyond today's. Nothing is retried with the same ticket.

### 5.4 Ending a ticket

| Event                                     | Effect                                                                                                       |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| Lock now, auto-lock in the page           | `sessionStorage` entry deleted; `DELETE /api/v1/reload-tickets/:tid` (best effort; the timers cover offline) |
| Logout, session expiry, session revoked   | Server deletes every ticket of the session; the page deletes its entry                                       |
| Device revoked                            | Its sessions end, so its tickets do                                                                          |
| Tab closed, browser closed, laptop asleep | No heartbeat: the ticket expires within 3 minutes                                                            |
| Idle past the auto-lock period            | `idle_expires_at` passes: redeem refused even if heartbeats continued                                        |
| Take-over by another tab                  | The old tab locks, which deletes its ticket (unless §5.6 hands it over)                                      |
| Password change                           | Nothing: `AK` is unchanged                                                                                   |
| Key rotation (new `AK`), vault reset      | Server deletes every ticket of the account                                                                   |

### 5.5 What the server sees

`tid`, the session and device it belongs to, `H_srv`, and the times of heartbeats, which reveal
when the user had the vault open (comparable to existing request logs). `H_srv` is random and not
derived from any key, so INV-01 holds as written; it is returned only in a response body and
never logged (INV-12). Rows are deleted, not kept; a database backup holds at most the live
tickets at backup time, which are useless without the tab half.

### 5.6 New tab (separate approval, optional)

When a new tab asks for the vault, the old tab (in `tab-lock.ts`'s hand-over) finishes its writes,
creates a fresh ticket, posts `{ tid, H_tab, envelope }` on the `BroadcastChannel`, and locks
without deleting that ticket. The new tab redeems it as on reload. Only same-origin script can
listen on the channel, so this exposes nothing that XSS in the origin does not already reach under
D. Without this step, a new tab keeps asking for the password and the old tab keeps locking, as
today.

## 6. Proposed invariant and threat-model wording (Option D)

- **INV-15**, append: "On the web, locking also deletes the tab's reload ticket from
  `sessionStorage` and asks the server to delete its half."
- **INV-16**, replace the last sentence with: "Local stores hold only encrypted envelopes and
  records, plus the exceptions in INV-17 and the web reload ticket (INV-25)." Keep the D-27
  reading note for the extension.
- **New INV-25:** "The web reload ticket seals `AK` under a key that needs a random half held by
  the tab and a random half held by the server. The server half is created only for an active,
  proven device session, is returned at most once, and is deleted on lock, logout, session end,
  device revocation and key rotation, 3 minutes after the last heartbeat, and after the auto-lock
  period without activity. Verified by: API integration tests for each of those, including
  concurrent redeems; a browser test that a profile copied after expiry does not resume; the INV-01
  and INV-12 capture scans with the ticket flow included."
- **T-18:** add "With a live reload ticket (D-34), XSS can also obtain `AK` itself, not only drive
  the worker. A ticket lives while the vault is unlocked and at most 3 minutes after the tab
  closes."
- **T-19, T-22:** add "except within a live reload ticket's window (D-34, INV-25)".
- **R-18** gets a sentence: the stolen-device case now also covers the ticket window.
- **device-proof.md**, "a locked device cannot sign": unchanged in meaning; add that a tab resumed
  from a ticket is unlocked.

Option B would need the same INV-15 change and a broader INV-16 exception without INV-25's
server limits.

## 7. Tests for Option D

- **Crypto:** vectors for `K_reload` and the new envelope purpose; negative cases for a wrong
  `tid`, account, device or `ak_id` in the context (INV-03), and a wrong `H_tab` or `H_srv`.
- **API (integration):** create needs a proven session (pre-proof refused); one ticket per
  session; redeem once, and two concurrent redeems give one success; redeem from another session
  or device refused; heartbeat moves only `expires_at`, `active` also `idle_expires_at`; neither
  passes session expiry; `idleSeconds` above 8 hours capped; logout, session revocation, device
  revocation and key rotation delete tickets; `H_srv` never in logs (the INV-12 sentinel test).
- **Engine:** resume from a ticket refuses an `AK` that does not open the device's keyset;
  every failure leaves the vault locked with no `sessionStorage` entry.
- **Browser (Playwright, Chromium, Firefox, WebKit):**
  - unlock, reload: unlocked, no password, items shown, a new `tid`;
  - Lock now, then reload: lock screen; the server row is gone;
  - auto-lock with a fake clock, then reload: lock screen;
  - stop heartbeats (close the page), advance the server clock 3 minutes, restore the
    `sessionStorage` entry into a fresh page: lock screen;
  - **copied profile:** a persistent context, unlock, close the browser, copy the profile, advance
    3 minutes, open the copy with session restore: lock screen, and the INV-16 byte scan finds no
    `AK` marker in the profile files;
  - offline reload: lock screen, then a password unlock offline works;
  - duplicate tab: one tab resumes, the other shows the lock screen;
  - hidden tab for 10 minutes (heartbeats from the worker keep the ticket), then reload resumes;
  - INV-01 capture scan with the ticket flow: no `AK`, `H_tab` or `K_reload` in any request.
- **New tab (if §5.6 is approved):** a second tab takes over without a password; the first tab
  shows the lock screen.

## 8. Before implementation

A short spike, in the three Playwright engines, confirms the browser facts in §3 (whether
`sessionStorage` and stored `CryptoKey` bytes appear in the profile files; worker timers in a
hidden tab) and measures the reload time with a resume. If worker timers are throttled, the
heartbeat interval and the 3-minute limit are revised before the owner's final approval.

## 9. Recommendation

**Option D, reload only (§5.1 to §5.5), after the §8 spike. Decide §5.6 (new tab) separately.** It answers the complaint, keeps T-22's guarantee for a closed
browser after a short, server-enforced window, and makes auto-lock hold even for a copied profile.
Its cost is real and should be accepted explicitly: while a ticket is live, XSS or a malicious
extension in the Ruvee origin can take `AK` without the user typing anything, where today it has
to phish the password. If the owner does not accept that, Option A stays, with the
`beforeunload` notice, and Option E is the next improvement to consider.

The parameters are the owner's to set: the 3-minute heartbeat limit, and whether the ticket
follows the auto-lock setting (proposed) or a shorter fixed limit.
