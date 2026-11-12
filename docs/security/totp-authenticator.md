# Authenticator codes (TOTP) in login items: design and threat-model addendum

Status: **D-35 approved by the owner for development (2026-11-12). Not independently reviewed.**
The owner accepted all six recommendations in §10: V-A (optional `login.totp` in item schema
version 1), W-A (available on every login, the trade-off stated in the add dialog), TOTP only with
paste and image-QR entry in the web app and no web screen capture (extension page scan later,
T3b), "Fill code" from the popup under the manual-fill rules (T3) and then the inline icon on
one-time-code fields (T4, allowed now that D-33 phase A is built, sequenced after T3), WebCrypto
HMAC in the web and extension workers with `@noble/hashes` exactly pinned for mobile later, and
the "keep outside Ruvee" guidance shown briefly in the add dialog and in full here (§8.2). The
rule changes in §9 land in the pull request of the phase that needs them. The server, the API and
the sync protocol do not change.

## 1. What is being asked

On 2026-11-12 the owner asked for two-factor authenticator support "like 1Password and Bitwarden"
and said they do not know how it should work. In those products a login item can hold the secret
that a site shows as a QR code when you turn on two-factor authentication. The app then shows the
current 6-digit code for that site, with a countdown, and can copy or fill it. This replaces a
separate authenticator app on the phone for those sites.

How it works, in brief: when you enable 2FA on a site, the site generates a random secret and shows
it as a QR code containing a URI such as
`otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example`. Both sides keep the secret.
Every 30 seconds both compute `HMAC(secret, floor(unix_time / 30))` and cut the result down to 6
digits (TOTP, [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238), built on HOTP,
[RFC 4226](https://www.rfc-editor.org/rfc/rfc4226)). The site accepts the code if it matches its
own, usually allowing one step of clock difference. Nothing is sent between the app and the site;
the secret and a correct clock are all that is needed.

What this proposal covers: the item format (§2), how the secret is entered (§3), how codes are
computed (§4), how they are shown and copied (§5), filling a code from the extension (§6), import
and export (§7), the security trade-off of keeping both factors in one vault (§8), what changes in
existing rules (§9), the questions for the owner (§10), phases and tests (§11).

Out of scope: Ruvee's own login (it has no TOTP; it uses OPAQUE plus the device-bound Secret Key),
passkeys, push-based 2FA, SMS codes, Steam Guard codes, and HOTP (§2.3).

## 2. Item format

### 2.1 The field

A login body gains one optional field, `login.totp`, stored in canonical, already-validated form
rather than as the pasted text:

```ts
const totpSchema = z.strictObject({
  /** RFC 4648 base32, uppercase, no padding, no spaces. 10 to 64 bytes once decoded. */
  secret: z
    .string()
    .regex(/^[A-Z2-7]+$/)
    .min(16)
    .max(103),
  algorithm: z.enum(['SHA1', 'SHA256', 'SHA512']),
  digits: z.union([z.literal(6), z.literal(7), z.literal(8)]),
  period: z.int().min(10).max(300),
});

export const loginBodySchema = z.strictObject({
  ...common,
  type: z.literal('login'),
  login: z.strictObject({
    username: text(ITEM_LIMITS.username),
    password: text(ITEM_LIMITS.password),
    urls: z.array(text(ITEM_LIMITS.url).min(1)).max(ITEM_LIMITS.urls),
    notes: text(ITEM_LIMITS.notes),
    totp: totpSchema.optional(), // absent = no authenticator
  }),
});
```

Why this shape:

- **Canonical, not the raw URI.** The URI or secret is parsed once, in the editor path (§3.2), and
  every client then reads four checked values. No client re-parses a URI at code time, and two
  clients cannot disagree about what a pasted string meant. Defaults are written out (`SHA1`, `6`,
  `30`), never implied.
- **Issuer and account label are not stored.** The item already has a title and a username; on
  paste they prefill those fields when they are empty (§3.2). This keeps the field ASCII-only and
  small: at most about 160 bytes of JSON, against a body budget that the existing
  every-field-at-maximum test keeps below `ITEM_BODY_MAX_BYTES` with a wide margin
  (`packages/vault/src/item-schema.test.ts`).
- **Optional, not nullable.** A login without an authenticator is written exactly as today, so
  every existing body stays byte-identical and readable by every client, old or new (§2.2).
- **Bounds.** 10 bytes (80 bits) is the shortest secret real sites still issue; RFC 4226 asks for
  at least 128 bits and recommends 160, and most sites use 160. Shorter than 80 bits is refused.
  64 bytes is the SHA-512 block-size key RFC 6238's test vectors use. Periods outside 10 to 300
  seconds and digits other than 6, 7 or 8 have not been seen in practice and are refused rather
  than guessed at.

### 2.2 Schema version and mixed client versions

The item schema version (`ITEM_SCHEMA_VERSION = 1`) is part of the `ITEM_BODY` AAD
([cryptographic-design.md §4.3](cryptographic-design.md#43-purposes)), but it is **not stored in
the record**: every client opens every item as version 1. A version 2 would need a way for a
client to learn the version before decrypting, and trying 2 then 1 is the fallback INV-04 forbids.

| Option                                                      | What it takes                                                                                                                                              | What an old client does with an item that has a code                                                                                                                                                    |
| ----------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **V-A. Optional field in version 1** (recommended)          | The schema change above. No crypto, record, sync or server change.                                                                                         | `decodeItemBody` refuses it (`strictObject`), so the item shows as **unreadable** (cryptographic-design §7). The record is kept, never overwritten or re-uploaded. Items without a code are unaffected. |
| V-B. Version 2 with the version in the record               | A new record format (`"RVI" ‖ u8(2) ‖ u16(schema) ‖ …`), the version read before decryption and bound by the AAD, a crypto-package change and new vectors. | Refuses the record format; the item shows as unreadable. Same outcome for the user.                                                                                                                     |
| V-C. Make version 1 tolerant of unknown fields (`z.object`) | Drop the strict parsing.                                                                                                                                   | Reads the item **without the code**, and an edit on that client writes it back without it. **Silent loss of the second factor. Rejected.**                                                              |

V-A and V-B fail the same way, closed and without data loss; V-B costs a format change that buys
nothing for an additive field. V-B becomes worth doing when a field changes meaning or an item type
is restructured, and should be designed then, for all such changes at once.

Rollout under V-A: the first implementation step (T1, §11) teaches every client to read and keep
the field before any client can write it. For the private rehearsal the web app is served by the
server and updates on reload; the extension is loaded unpacked and must be rebuilt in the same step;
the mobile app (branch `mobile/vault-app`) must take `packages/vault` from the same commit before
it is used against a vault that has codes.

### 2.3 HOTP is not supported

HOTP codes come from a counter instead of the clock, and the counter must move forward every time a
code is used. In Ruvee that means a vault write per code: a new item revision, a commit, and an
explicit conflict (INV-08) whenever two devices show a code before syncing. It also leaks to the
server, as commit timing, each time the user signs in to that site. Very few sites still use HOTP.
Recommendation: refuse `otpauth://hotp/` with a clear message; revisit only if a real need appears.

### 2.4 What the server sees

Nothing new in content: the field is inside the `ITEM_BODY` envelope like the password
([threat-model.md §4](threat-model.md#4-what-the-server-can-see)). Adding a code changes the
body's padded size only if it crosses a 256-byte padding boundary, and creates a new item revision,
which is the same metadata any edit produces. A code is never written back on use (it is computed,
not stored), so using the authenticator produces no server traffic.

## 3. Entering a secret

### 3.1 Where

In the web vault's login editor, an "Authenticator" section with an "Add" button. In the extension
popup, later (T3): the popup has no editor today, and D-33 phase B adds the first vault write from
the extension; adding a code from the popup waits for that path to exist.

### 3.2 Paste a URI or a secret

One text field accepts either form. `parseTotpInput(text)` in `packages/vault` returns the
canonical `totp` value or a typed error, never a partly filled value:

- **Plain secret.** Remove spaces and hyphens, uppercase, strip trailing `=`; the rest must be
  base32 (`A-Z`, `2-7`) and decode to 10 to 64 bytes. Defaults `SHA1`, `6`, `30`.
- **`otpauth://totp/` URI** ([Key Uri Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)).
  At most 4,096 characters before parsing. Parsed with the platform `URL` parser, then:
  `secret` required, normalised as above; `algorithm` `SHA1`/`SHA256`/`SHA512` (case-insensitive),
  default `SHA1`; `digits` 6, 7 or 8, default 6; `period` 10 to 300, default 30. A parameter that
  appears twice is refused. `issuer` and the label are decoded only to prefill an empty title and
  username, shown to the user, not stored separately. Unknown parameters (`image`, `color`, …) are
  ignored; Ruvee never fetches an `image` URL or any other network resource named in a URI.
  `encoder=steam` is refused, because ignoring it would show wrong codes.
- **Refused with a specific message:** `otpauth://hotp/` (§2.3), `otpauth-migration://` (Google
  Authenticator's multi-account export, §7), any other scheme, and an empty or invalid secret.

The editor shows the first code computed from the parsed value before the user saves, so a wrong
secret is noticed while the site's setup page is still open. Sites usually ask for one code to
confirm setup; that is the moment to check.

### 3.3 Scan a QR code from an image (web)

- The dialog accepts an image by paste (a `paste` event's `clipboardData` file; no clipboard-read
  permission is needed), drag and drop, or a file picker. A screenshot copied to the clipboard is
  the expected path (Ctrl/Cmd+Shift+4 with the clipboard modifier on macOS, Win+Shift+S on
  Windows).
- Decoding runs in a **dedicated, short-lived worker**, not the vault worker and not the main
  thread: the image is attacker-influenced input (a page screenshot), and the QR library is new
  third-party code that must not share a realm with keys. The worker receives the pixels, returns
  only the decoded text, and is terminated. Pixel buffers are zeroed after use where the runtime
  allows. The text then goes through §3.2 like a paste.
- The library is a pure-JavaScript QR decoder (no new WebAssembly), pinned to an exact version and
  reviewed as a dependency that handles secrets (INV-22 by analogy; it is not a crypto library). The
  candidate is chosen in the implementation pull request. `BarcodeDetector` is not used: it is
  missing from desktop Chrome on Windows and Linux, and two decoders would mean two behaviours.
- The image is never uploaded, stored, logged or kept after decoding.

### 3.4 Scan from the screen, and camera

- **Web, screen capture: not recommended for now.** It needs `getDisplayMedia`, which the
  Permissions-Policy disables today (`display-capture=()` in `apps/web/security-headers.ts`), and
  it shows the page a live view of the whole screen. A screenshot and paste covers the need.
- **Extension, "scan the QR on this page": a later step (T3b).** The popup can call
  `chrome.tabs.captureVisibleTab` under the existing `activeTab` grant, decode in an extension
  page, and offer the result for the current item. No new permission. It reads the visible pixels
  of the tab the user clicked on, which `activeTab` already allows.
- **Web camera:** the policy allows `camera=(self)` for pairing QR codes, but pointing a laptop
  camera at a phone screen is rare; not proposed.
- **Mobile camera:** with the mobile app, later (D-11 and Phase 6 timing); same parser.

## 4. Computing codes

### 4.1 Where

The code is computed where the vault plaintext already is: the web **vault worker** and the
extension **service worker**, through a new engine method `totp({ id })` that returns
`{ code, period, validUntilMs }`. The secret stays inside the engine; the UI receives codes, like
it receives `detail()` with `hasPassword` instead of the password. The secret leaves the engine
only through an explicit "Show secret" in the editor (as `secret({ id })` does for the password),
and the editor's draft carries `totp` as "unchanged" unless the user replaced or removed it, so
editing a title never round-trips the secret through the page.

### 4.2 HMAC: WebCrypto, not libsodium

RFC 6238's default, and what almost every site uses, is HMAC-**SHA-1**. libsodium (D-01) has
HMAC-SHA-256 and HMAC-SHA-512 but no SHA-1, so it cannot be the only implementation.

| Option                                 | SHA-1 | Available in                                                                | New dependency | Notes                                                                                                                                 |
| -------------------------------------- | ----- | --------------------------------------------------------------------------- | -------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| **`crypto.subtle` HMAC** (recommended) | Yes   | Web workers and MV3 service workers in secure contexts; all target browsers | None           | Built in. Asynchronous, which suits the engine's message API. The key can be imported non-extractable for the one call.               |
| libsodium `crypto_auth_hmacsha*`       | No    | Everywhere Ruvee runs                                                       | None           | Covers only SHA-256 and SHA-512 secrets; SHA-1 would still need a second path.                                                        |
| `@noble/hashes` HMAC                   | Yes   | Everywhere, including React Native                                          | Yes (runtime)  | Already pinned in `tools/crypto-validation`, not in a runtime package. The likely choice for mobile, where `crypto.subtle` is absent. |

HMAC-SHA-1 is not a weakness here: HMAC's security does not rest on SHA-1 collision resistance,
and RFC 6238 and every site depend on it. The generator is a pure function with the HMAC injected,
`totpCode(totp, nowMs, hmac)`, so the mobile app can supply another HMAC without a second
implementation of the truncation logic. Counter: `floor(nowMs / 1000 / period)` as a 64-bit
big-endian integer (T0 = 0); dynamic truncation per RFC 4226 §5.3; left-padded to `digits`.

### 4.3 Time

- **The device clock (`Date.now()`) is the only time source.** The Ruvee server's time is not used
  to compute codes: codes must work offline (D-23, locking is local), and Ruvee does not let the
  server influence client output it does not need to.
- **Clock skew.** Sites usually accept the previous and next step, so a device up to about 30
  seconds off still works; beyond that codes are rejected and the user cannot tell why. When the
  client is online, it compares the `Date` header of an API response with the local clock and, if
  they differ by more than 30 seconds, shows "Your device clock is about N seconds off; codes may
  be rejected" next to the code. The header is used only for that warning, never for the code.
- **Clock jumps.** Each refresh recomputes from `Date.now()`; nothing accumulates timer ticks, so
  an NTP correction or a laptop waking from sleep shows the right code at the next tick.

### 4.4 Memory and lock

The secret is handled like the password: decoded from the body for each call, the decrypted bytes
zeroed as `openBody` already does, the JavaScript string not zeroable (the documented limit of
INV-15). No per-item key cache. Locking stops every refresh timer, and the UI drops every code it
shows (INV-15). Codes and secrets never appear in logs, URLs, error payloads or activity events
(INV-12); no route or deep link ever carries an `otpauth` URI.

## 5. Showing and copying

- **Web vault, item detail:** the code in two groups (`123 456`), a ring or bar counting down the
  remaining seconds of the period, and a copy button. In the last 5 seconds the next code is shown
  beside it, so the user does not paste a code that expires in transit. The list view shows a small
  "has authenticator" mark, never a code.
- **Extension popup:** for each login matching the tab's origin that has a code, the code, the
  countdown and "Copy code"; "Fill code" is §6.
- **Copy** uses the existing clipboard rule: cleared after 30 seconds, best effort
  (`apps/web/src/components/app/clipboard.ts`, T-26). A code is useless after its period anyway.
- **No automatic copy.** Some managers copy the code to the clipboard after filling a password.
  That writes to the clipboard without a click and leaves a value there for other apps to read; not
  proposed for V1.

## 6. Filling a code from the extension

### 6.1 From the popup (T3; does not need D-33)

The same manual-fill rules as a password ([extension-design.md §4](extension-design.md#4-manual-fill)),
unchanged:

1. The user opens the popup on the tab. The service worker reads the **top-level URL from
   `chrome.tabs`**, never from the page, and lists logins whose stored URL has the **exact same
   origin**. Non-`https:` pages (except loopback) get no matches.
2. The user picks "Fill code" on one login. The service worker computes the code (§4) and reads
   the tab URL again; if the origin changed, it stops.
3. It injects a fill function into the **top frame only**, with the code as its only argument. The
   function fills one visible, enabled `<input>`:
   - the single field with `autocomplete="one-time-code"`; otherwise
   - the single text, tel or number field whose `name`, `id`, `aria-label` or `placeholder`
     matches a fixed list (`otp`, `totp`, `2fa`, `mfa`, `one-time`, `verification code`,
     `security code`, `authenticator`, …) and whose `maxlength` is unset or 6 to 8.
     If there is no candidate, or more than one, it fills nothing and the popup offers "Copy code".
     It never fills a `type=password` field with a code, never fills split one-digit boxes in V1, and
     does not submit. It returns only whether it filled.

Many sites ask for the code on the same origin as the password; some move to another host (for
example `login.` then `account.`). Exact origin matching means no "Fill code" on the second host
unless the user adds that URL to the item; "Copy code" always works from the item. This is
consistent with D-33's decision not to match subdomains.

What the page learns: the code, after the user chose to fill it, for that origin only. That is the
code the site itself would accept for the next few seconds. It learns nothing about other items, and
nothing before the user's click.

### 6.2 Inline icon in a one-time-code field (T4, after D-33 phase A)

D-33 phase A draws a state-free icon in password fields that opens the popup (option I1,
[extension-inline-autofill.md §2](extension-inline-autofill.md)). The same content script would draw
the same icon in fields that §6.1 recognises as one-time-code fields, on every `https:` page,
whether or not any item has a code, so the page learns nothing from the icon (D-33 §4). A click
opens the popup, where §6.1 applies. The DEF CON 33 clickjacking research that D-33 cites filled
TOTP codes through injected in-page menus; I1 keeps the choice in the popup, so that attack opens
the popup at worst. No in-page menu, no fill without a popup click, and the cross-origin frame rule
is unchanged: a code is never filled into a frame whose origin differs from the top-level origin.

## 7. Import and export

- **Ruvee's own encrypted export** ([backup-restore.md §4](../architecture/backup-restore.md#4-portable-encrypted-export-milestone-m2))
  carries item bodies as envelopes, so a code travels with its item without any format change. An
  older Ruvee build importing such an export shows those items as unreadable (§2.2); tests cover
  both directions.
- **Other managers:** Ruvee has no import from other managers today (the only import is its own
  export, `packages/vault/src/import.test.ts`). When one is built it should map Bitwarden JSON's
  `login.totp` (a URI or a bare secret, the same two forms as §3.2), 1Password's one-time-password
  fields (`otpauth` URIs), and, from authenticator apps, Aegis and 2FAS exports, all through
  `parseTotpInput`, with per-item errors listed, never silently dropped. Google Authenticator's
  `otpauth-migration://` export (a protobuf of many accounts in one QR) is a separate, later
  parser. That is a separate decision; nothing here depends on it.
- **Plaintext export** (Phase 7, step-up, INV-14) would write codes as `otpauth://totp/` URIs.

## 8. The trade-off: both factors in one vault

### 8.1 Plainly

**For a site whose code is in Ruvee, anyone who gets that Ruvee vault unlocked has both factors.
For that person, two-factor authentication on that site becomes one factor: the vault.** The site
still sees two factors, but they are no longer independent.

The second factor exists to protect the account when the password alone leaks. Whether keeping the
code in Ruvee keeps that protection depends on how the password leaked:

| How an attacker gets the password                                                | Code in Ruvee                                                                                              | Code in a separate authenticator app (phone)                                              |
| -------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| Another site's breach, password reuse, credential stuffing                       | **Protected.** The secret is not in that breach.                                                           | Protected.                                                                                |
| The site's own breach                                                            | Same as separate app: the site holds the secret too.                                                       | Same.                                                                                     |
| Phishing on a look-alike domain                                                  | **Somewhat better:** exact-origin fill offers neither password nor code there. A copied code is phishable. | Code is phishable in real time (TOTP always is).                                          |
| Malware or a hostile extension on the computer while Ruvee is unlocked (T-23)    | **Lost.** It can read every secret and generate codes forever.                                             | It gets the password and the codes the user types, not the secret: harder to keep access. |
| Stolen unlocked device, or someone at the keyboard                               | **Lost** for every site with a code.                                                                       | Needs the phone too.                                                                      |
| Modified web-app JavaScript from the server while unlocked (T-10), or XSS (T-18) | **Lost**, like passwords.                                                                                  | Not exposed.                                                                              |
| Master password **and** Secret Key **and** ciphertext (T-01 with `SK` theft)     | **Lost.**                                                                                                  | Not exposed.                                                                              |
| Losing the phone                                                                 | **Better:** codes survive on every Ruvee device and in the Recovery Kit path.                              | Risk of lockout without backup codes.                                                     |

Ruvee's design already makes the "vault compromised" rows harder than in many managers: unlocking
needs the password and the device-held Secret Key (INV-17, D-04), so a stolen server database or a
phished master password alone opens nothing. That raises the bar for the bad rows; it does not
remove them.

### 8.2 Guidance

- For most sites, keeping the code in Ruvee is a reasonable trade: it keeps protection against the
  most common attacks (reuse and other sites' breaches), improves phishing resistance with exact
  origin fill, and removes the lockout risk of a lost phone.
- **Keep outside Ruvee** the second factor of accounts that could take over everything else: the
  email account used for password resets, the Ruvee server host and its access (SSH, the tailnet
  admin, the cloud console), the domain registrar, and the bank. Use a separate authenticator or a
  hardware key for those.
- Where a site offers passkeys or a security key, that is stronger than TOTP in either place.

### 8.3 Warn, or make it opt-in?

| Option                                                                                     | Effect                                                                                                                                                                                                                          |
| ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **W-A. Per item by nature, with the trade-off stated where a code is added** (recommended) | No global switch. Adding a code to an item is itself the opt-in. The "Add authenticator" dialog always shows one short paragraph (§8.1's first sentence and the "keep outside" list), not a click-through modal. Docs carry §8. |
| W-B. Off by default; a vault setting turns the feature on                                  | One more setting to find. The risk is per item, so a global switch adds a step without changing the decision; and a vault setting needs an encrypted settings record that does not exist yet.                                   |
| W-C. Confirmation every time a code is added                                               | Click-through fatigue; the warning stops being read.                                                                                                                                                                            |
| W-D. Do not offer the feature                                                              | The owner asked for it; users then paste secrets into notes, which is worse (no format check, shown in plain text in the editor).                                                                                               |

Recommendation: W-A. The owner may prefer W-B; both are safe, and the format does not depend on it.

### 8.4 New threat-model row (proposed)

| ID   | Threat                                                                                                                          | Attacker                   | Outcome                             | Mitigation                                                                                                                                              |
| ---- | ------------------------------------------------------------------------------------------------------------------------------- | -------------------------- | ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| T-34 | Second factor stored with the password: an unlocked or decrypted vault yields both factors for every site that has a code in it | A3 (via T-10), A6, A8, A10 | **Accepted** (user choice per item) | Codes are opt-in per item (W-A or W-B); the trade-off is stated where a code is added; same protection as passwords (T-10, T-18, T-22, T-23 unchanged). |

## 9. What changes in existing rules

Nothing changes until the owner approves D-35. Each change lands in the pull request that needs it.

| Document or rule                                                                | Change                                                                                                                                                                                          |
| ------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `packages/vault/src/item-schema.ts`                                             | `login.totp` optional (§2.1); `ITEM_SCHEMA_VERSION` stays 1.                                                                                                                                    |
| [cryptographic-design.md §5.2](cryptographic-design.md#52-item-record-and-body) | A sentence: version 1 may gain optional fields; a client that does not know a field refuses the body (unreadable), never strips it. V-C is ruled out.                                           |
| [security-invariants.md](security-invariants.md) INV-19                         | "…at most the single credential the user chose to fill **(a username and password, or one current one-time code)**, for the verified origin."                                                   |
| security-invariants.md, new INV-26 (INV-25 is proposed by D-34)                 | "A one-time-password secret leaves the vault engine only to the item editor after an explicit user action. Displays, the clipboard and fills receive codes, never the secret."                  |
| [threat-model.md §5](threat-model.md#5-threats-and-outcomes)                    | T-34 (§8.4). T-20 notes that a filled code is in scope of the same origin and frame rules.                                                                                                      |
| [extension-design.md](extension-design.md) §1, §4, §5, §6                       | The injected function may receive one code instead of a username and password; one-time-code field selection (§6.1); E-01, E-02 cover codes; tests below.                                       |
| [extension-inline-autofill.md](extension-inline-autofill.md) (D-33)             | Phase A's icon also appears on one-time-code fields (§6.2), once T4 is approved; no other change.                                                                                               |
| `apps/web/security-headers.ts`                                                  | **No change** in the recommended options (no `display-capture`).                                                                                                                                |
| [research-sources.md](research-sources.md)                                      | RFC 4226, RFC 6238, the Key Uri Format page, the DEF CON 33 inline-menu research (already cited by D-33; TOTP fill is part of it), and the chosen QR decoder with its version and review notes. |
| API, Prisma schema, sync protocol, envelope formats                             | **No change.**                                                                                                                                                                                  |

## 10. Questions decided by D-35 (approved 2026-11-12, as recommended)

1. **Format:** an optional `login.totp` field in item schema version 1 (V-A), with old clients
   showing such items as unreadable until updated? (Alternatives: V-B, a record-format change;
   V-C is rejected.)
2. **Warning:** available on every login with the trade-off stated in the add dialog (W-A), or
   off by default behind a vault setting (W-B)?
3. **Scope of V1:** TOTP only (no HOTP, no Steam); paste and image-QR in the web app; no screen
   capture in the web app; extension page-scan later (T3b)?
4. **Extension fill:** "Fill code" from the popup under the existing manual-fill rules (T3), and
   the inline icon on one-time-code fields only after D-33 phase A (T4)?
5. **HMAC:** WebCrypto in the web and extension workers; `@noble/hashes` (exactly pinned) for
   mobile when it gets the feature?
6. **The "keep outside Ruvee" guidance** in §8.2: shown in the product, or in the docs only?

The owner answered all six as recommended. For question 4, T4 may follow T3 without a further
decision, because D-33 phase A exists (draft PR #6).

## 11. Phases and tests

| Step  | Content                                                                                                                                                                                   | Depends on  |
| ----- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- |
| T1    | `packages/vault`: schema field, `parseTotpInput`, `totpCode`, engine `totp({ id })`, draft "unchanged/replace/remove" semantics. Every client reads and keeps the field; no UI writes it. | D-35 Q1, Q5 |
| T2    | Web vault: add/replace/remove in the editor (paste, image QR), code with countdown and copy in the detail view, clock-skew warning, the W-A text.                                         | T1, Q2, Q3  |
| T3    | Extension popup: code, countdown, copy; "Fill code" (§6.1).                                                                                                                               | T1, Q4      |
| T3b   | Extension: scan the QR on the current tab; add a code from the popup (needs D-33 phase B's vault-write path).                                                                             | T3, D-33 B  |
| T4    | Inline icon on one-time-code fields.                                                                                                                                                      | D-33 A, Q4  |
| Later | Mobile (camera, `@noble/hashes`), other managers' import, plaintext export.                                                                                                               | Phase 6, 7  |

Tests, by step:

- **Generator (T1).** All RFC 6238 Appendix B vectors (SHA-1, SHA-256, SHA-512 with their 20-,
  32- and 64-byte seeds, 8 digits, T = 59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000) and the RFC 4226 Appendix D HOTP values for the truncation step; leading zeros kept;
  6- and 7-digit truncation; counter boundaries (`nowMs` at `period·k·1000 − 1` and
  `period·k·1000`); a time past 2038 and past 2^32 counter steps; `validUntilMs` exact.
- **Parser (T1).** Accepted: a bare secret with spaces, hyphens, lowercase and `=` padding; a full
  URI; a URI with only `secret`; percent-encoded issuer and label; unknown parameters. Refused, each
  with its own error: empty input, non-base32 characters, a secret under 10 or over 64 bytes,
  invalid base32 tail bits, `otpauth://hotp/`, `otpauth-migration://`, other schemes, missing
  `secret`, duplicated parameters, `algorithm=MD5`, `digits=5` and `9`, `period=0`, `-30`, `1e3`
  and `301`, `encoder=steam`, input over 4,096 characters, a URI with userinfo or a port. No input
  ever yields a partly defaulted value. A property test: any accepted value round-trips through the
  schema unchanged.
- **Schema and migration (T1).** Every existing fixture body, including
  `test/fixtures/export-v1.expected.json`, decodes unchanged and re-encodes byte-identically; a
  login without a code encodes without a `totp` key; the every-field-at-maximum test with a maximal
  `totp` stays under `ITEM_BODY_MAX_BYTES`; a body with a `totp` of the wrong shape is refused as a
  whole. A body with a code, decoded by the current (pre-T1) schema, is refused, and the engine
  marks that item unreadable without overwriting it (a mixed-version test that pins the old
  schema).
- **Engine (T1).** `detail()` exposes `hasTotp` and never the secret; `totp()` on a locked vault,
  a note, a login without a code, and a trashed item; saving a draft with `totp` unchanged keeps
  the secret; replace and remove; a conflict where one side added a code (INV-08, the code is not
  lost); the plaintext capture checks (INV-01, INV-16) extended with a secret sentinel, which must
  not appear in requests, IndexedDB, `chrome.storage` or logs.
- **Export and import (T1).** A vault with codes exports and imports with the codes intact.
- **Web (T2).** QR images: a generated `otpauth` QR, a screenshot with a QR among other content, a
  QR holding a non-`otpauth` URL (refused), a damaged image, an oversized image (size cap before
  decoding). The decoder worker is terminated after one image; the vault worker is not given the
  image. Lock clears codes and stops timers. Clock-skew warning at ±29 s (none) and ±31 s (shown).
  Clipboard cleared after 30 seconds.
- **Extension (T3, Playwright).** "Fill code" on a matching origin fills an
  `autocomplete="one-time-code"` field; no fill and no injection on another port, scheme or
  subdomain, in a cross-origin frame, or after the page changes origin between listing and filling;
  no fill with two candidate fields or none; never into a password field; no submit. The injected
  function's arguments contain the code and not the secret.

## 12. Sources

- RFC 4226, HOTP: An HMAC-Based One-Time Password Algorithm (2005), §5.3 truncation, Appendix D
  vectors.
- RFC 6238, TOTP: Time-Based One-Time Password Algorithm (2011), §4 and Appendix B vectors.
- Google Authenticator "Key Uri Format" wiki page (de facto `otpauth://` format).
- Marek Tóth, DOM-based extension clickjacking, DEF CON 33 (August 2025), as cited by D-33.
- RFC 2104 and its security discussion for HMAC with SHA-1.

These must be checked and added to [research-sources.md](research-sources.md) before review, as
D-33 requires for its own sources.
