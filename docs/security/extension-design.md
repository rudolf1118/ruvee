# Browser extension design and threat-model addendum

Status: **Proposed (2026-10-25).** The Phase 5 gate in the
[roadmap](../planning/implementation-roadmap.md#later-phases-outline). Not reviewed. Decisions
it depends on are in [open-decisions.md](../architecture/open-decisions.md): D-27 (option 2 below)
was approved by the owner for development on 2026-10-25.

Scope of the first extension: **Chromium, Manifest V3**, logins only, **manual** fill. No
automatic fill on page load, no saving of new logins from forms, no passkeys, no Firefox yet.

## 1. Contexts and what each may hold

| Context                                  | Trust     | Holds                                                                                                                                |
| ---------------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| Service worker (`background`)            | Trusted   | The vault engine: `packages/crypto`, OPAQUE, sync, the encrypted local store (extension-origin IndexedDB). Keys while unlocked (§3). |
| Extension pages (popup, options, unlock) | Trusted   | Only what they display, as the web UI does with its worker. They talk to the service worker with `chrome.runtime` messages.          |
| Injected fill function                   | Untrusted | One username and one password, passed as arguments for a single call, in one frame the extension checked (§4). Nothing persists.     |
| Web pages, other extensions              | Hostile   | Nothing. No `externally_connectable`, no `web_accessible_resources`, no long-lived content script.                                   |

Extension pages and the service worker share the extension origin; that is the boundary that
matters. Any message whose `sender.id` is not this extension, or whose `sender.origin` is not the
extension's own origin, is dropped before parsing. That excludes content scripts and other
extensions, whose origin is the page's or their own; `sender.tab` is not used, because an extension
page opened in a tab (the popup as a page, the options page) has it set too. Messages are validated
against a schema like API responses are.

The extension CSP is the MV3 default plus WebAssembly:
`script-src 'self' 'wasm-unsafe-eval'; object-src 'self'`. No remote code (MV3 forbids it), no
`eval`.

## 2. Server, sessions and enrollment

- **Server origin:** the user types it on the options page. It must be `https://`, or
  `http://127.0.0.1`/`http://localhost` for development. The extension then requests host
  permission for **that origin only** (`optional_host_permissions`); the manifest grants none by
  default. With the permission, the service worker's `fetch` needs no CORS from the API.
- **Sessions** follow [authentication.md §5](authentication.md#5-sessions) and D-08: a 10-minute
  bearer access token and a rotating refresh token (30 days idle, 90 absolute), family revocation
  on reuse. The access token stays in service-worker memory and `chrome.storage.session`; the
  refresh token in extension-origin IndexedDB. The API rejects a request with both a cookie and a
  bearer token (already enforced), so the extension fetches with `credentials: 'omit'`: the
  browser would otherwise attach the user's web-app cookie for the same server. The API accepts
  the extension's unauthenticated calls (login, refresh) only from origins in `EXTENSION_ORIGINS`
  ([authentication.md §6](authentication.md#6-csrf)).
- **Enrollment** is the existing pairing (device-enrollment §3) with platform code 2. The
  extension never receives `SK` any other way, except by Recovery Kit recovery.

## 3. Unlocked state across service-worker restarts (D-27)

Chrome stops an idle MV3 service worker after about 30 seconds. Everything in its memory is lost.
The options:

1. **Keep keys in service-worker memory only.** Any pause longer than ~30 s locks the vault, so the
   user types the master password (one Argon2id at profile 1) for nearly every fill.
2. **Keep `AK` in `chrome.storage.session`** (recommended). This store is held in memory by the
   browser, never written to disk, cleared when the browser exits or the extension reloads, and by
   default readable only by trusted extension contexts (not content scripts). The worker reloads
   `AK` when it wakes and derives the rest. Lock, the auto-lock alarm and session end delete it.
3. **An offscreen document** kept open to hold the keys. Chrome documents offscreen documents for
   specific reasons, and "hold secrets" is not one; it could be closed or restricted later.

Option 2 reads INV-16 ("no client persists unwrapped keys") as "never written to persistent
storage": `chrome.storage.session` is browser memory, like the worker heap. It widens exposure only
to code that can already run in trusted extension contexts. If the owner does not accept that
reading, option 1 applies and INV-16 stays literal.

## 4. Manual fill

1. The user opens the popup (or presses the extension's keyboard shortcut) on a tab.
2. The service worker reads the tab's **top-level URL** from `chrome.tabs` (the `activeTab`
   grant), not from the page.
3. It lists logins whose stored URL has exactly the same **origin** (scheme, host, port). No
   subdomain or registrable-domain matching, no `http` for a stored `https` login. Pages that are
   not `https:` (except loopback) get no matches.
4. The user picks one login. The worker injects a fill function with `chrome.scripting` into the
   **top frame only**. Cross-origin frames are never filled. Same-origin frames are a later
   decision.
5. Just before injecting, the worker reads the tab URL again; if the origin changed since step 2,
   it stops.
6. The function fills only visible, enabled `<input>` elements: the password into a
   `type=password` field, the username into the nearest preceding text or email field of the same
   form. It does not submit the form. It returns only whether it filled, never page content.

Nothing is injected without that user action. The username and password exist in the page only as
the arguments of that one call; afterwards they are in the page's DOM, because filling puts them
there.

## 5. Threats specific to the extension

| ID   | Threat                                                           | Attacker | Mitigation                                                                                                                                                      |
| ---- | ---------------------------------------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| E-01 | A page triggers a fill without the user, or for another origin   | A5       | Fill needs a user action in extension UI; the origin comes from `chrome.tabs`; exact origin match; re-check before injecting (§4).                              |
| E-02 | A page frames a login page, or hides fields, to harvest a fill   | A5       | Top frame only; visible, enabled fields only; no autofill on load. Clickjacking of the popup is impossible because the popup is extension UI, not page content. |
| E-03 | A page or another extension sends messages to the service worker | A5, A8   | No `externally_connectable`; drop messages with a foreign `sender.id` or `sender.origin`; schema validation.                                                    |
| E-04 | A content script reads the vault (T-20)                          | A5       | There is no persistent content script; the injected function receives one credential and returns a boolean.                                                     |
| E-05 | A stolen browser profile while the browser runs                  | A7, A8   | Auto-lock (D-10) clears `AK` from `chrome.storage.session`; at rest the store needs the password, as on the web (T-22).                                         |
| E-06 | A malicious extension update or build                            | A10      | Store signing and review are outside Ruvee's control (R-12). Pinned dependencies, reproducible build script, no remote code.                                    |
| E-07 | The server swaps in a key or reply during pairing                | A3       | Unchanged: the pairing protocol (device-enrollment §3.3).                                                                                                       |
| E-08 | A refresh token copied from the profile                          | A7       | Rotation with family revocation on reuse; the token alone decrypts nothing (INV-06); revocation from Devices.                                                   |
| E-09 | Phishing look-alike origins                                      | A5       | Exact origin matching never offers a login on a look-alike domain. The popup shows the origin it matched.                                                       |

The extension does **not** protect against: malware or another extension with broad host
permissions on an unlocked browser (T-23), a page reading a filled field after the fill, or a
compromised API server serving wrong ciphertext (that is detected by sync verification, INV-07).

## 6. Tests required before the extension holds real data

- Unit: origin matching (ports, schemes, IDNs in punycode, trailing dots, userinfo), message
  sender filtering, fill-field selection on fixture DOMs.
- Browser (Playwright with the unpacked extension in Chromium): pairing with the web app, a fill
  on a matching test origin, **no** match and no injection on a different port, scheme, subdomain
  or cross-origin frame, a page that changes its URL between listing and filling, lock after the
  auto-lock alarm, and `chrome.storage.session` empty after lock.
- INV-01, INV-16 and INV-19 capture checks like the web vault's, including the extension's
  IndexedDB and `chrome.storage.local`.

## 7. As built (2026-10-25)

`apps/extension` implements §1 to §4 for Chromium, with these specifics:

- The vault engine is `packages/vault`, the same code the web worker runs. The service worker
  dispatches only an allow-listed subset of its methods; `secret` is not among them, so a
  password reaches only the fill function.
- Messages are accepted only when `sender.id` is this extension and `sender.origin` is its own
  origin, then validated with a schema.
- Fill re-reads the tab's origin from `chrome.tabs` just before injecting, and the injected
  function compares `location.origin` again inside the page.
- The test build differs only by `__RUVEE_TEST__` (the popup may name its target tab with
  `?tab=`) and host permission for `127.0.0.1`. It is written to `dist-test/`, which is never
  distributed.
- The browser test runs in Chromium against a throwaway database. It covers pairing from the web
  app, fill on the saved origin, no offer and a refused forged fill on another port, a real
  service-worker restart followed by resume from `chrome.storage.session`, lock, and scans of the
  network, `chrome.storage` and the extension's IndexedDB.

### Verification added on 2026-10-26

The browser suite now also covers auto-lock (including an unlock that expired while the worker
was stopped, which must not resume), `chrome.storage.session` being refused to a content script
and absent from the page's world, a stale fill after the tab navigated, previous-password unlock,
refresh-token reuse, logout and a revoked extension reconnecting
([phase-2-review-packet.md §2a](phase-2-review-packet.md#2a-browser-level-evidence-added-on-2026-10-26-and-its-limits)).
Two defects found by those tests were fixed: idleness is now checked before every message (a
late alarm could let a message resume an expired unlock), and logout and revocation now remove
both tokens, not only `AK`. The popup syncs when opened, which is how a revoked browser or an
ended session is noticed while unlocked.
