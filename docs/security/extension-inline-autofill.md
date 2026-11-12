# Extension inline fill, save and generate: design and threat-model addendum

Status: **D-33 approved by the owner for development (2026-11-12). Phases A and B, and the automatic save popup (B+), implemented for
development (2026-11-12, §8.1, §8.2); phases C and D not started. Not independently reviewed.** The
owner accepted the recommendation in §9 as a whole: opt-in permission for `https:` sites, the
installed-extension disclosure in §4, option I1 first, vault writes from the extension with the
previous password kept on update, and the order A, B, C, D. Phase E (an in-page menu) and
cross-origin frame fill remain separate, undecided questions.
[extension-design.md](extension-design.md) stays the rule for the code until each phase lands:
the rules in §7 change in the pull request that implements the phase that needs them.

Why now: on 2026-11-11 the owner paired the extension in real Chrome on the rehearsal server and
asked for what 1Password and Bitwarden offer: an icon in login fields that fills, an offer to save
a login after signing in, an offer to update a changed password, and a generated password on
sign-up forms. Each of these moves part of Ruvee's UI or logic into pages it does not control. This
document says what each feature needs, what new attacks it opens, which existing rules change, and
in what order to build it.

## 1. Features and what each one requires

| Feature                                | Needs                                                                                                                                                                                                                                                        |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| F1. Inline fill trigger in a field     | A content script on every page the user visits (host permission for all `https:` sites), login-field detection, an icon drawn in or next to the field, and a way for the user to choose a login (§2).                                                        |
| F2. Offer to save a new login          | F1's content script, plus submit detection (form `submit`, click or Enter on a submit control, a password field removed after a click), capture of the username and password at that moment, a prompt, and a **vault write** from the extension.             |
| F3. Offer to update a changed password | F2, plus recognising a change-password form (current, new, confirm) or a sign-in with a known username and a different password, and an **item update** that keeps the previous password (§5.3).                                                             |
| F4. Suggest a generated password       | F1, plus detection of sign-up and new-password fields (`autocomplete="new-password"`, two password fields), a password generator in `packages/` (the Phase 3 generator is not built: the web app shows it as unavailable), and saving before filling (§5.4). |

What the extension has today and lacks for these:

- **Host permissions.** The manifest grants none by default; the options page asks for the server
  origin only. `activeTab` gives access to one tab after a click on the toolbar icon. F1 to F4 need
  the content script to run before any click, which is host permission for `https://*/*`. Chrome
  then warns "Read and change all your data on all websites".
- **Content scripts.** None. The fill function is injected per fill with `chrome.scripting` and
  returns a boolean.
- **Message boundary.** The service worker drops every message whose `sender.origin` is not the
  extension's own (extension-design §1). Content scripts are dropped by that rule.
- **Vault writes.** The service worker's allow-list (`EXTENSION_VAULT_METHODS` in
  `apps/extension/src/messages.ts`) has no create or update method. The extension has never written
  to the vault.
- **Generator.** None in `packages/`.

## 2. Where the inline UI lives

The page owns the DOM, the layout and every CSS property of any element Ruvee adds to it. Whatever
Ruvee draws in a page, the page can hide, move, cover, make transparent, or redraw as a fake. Three
ways to build F1:

| Option                                                           | How                                                                                                                                                                                                                | Clickjacking                                                                                                                               | What the page can read                                                                                    |
| ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------- |
| **I1. In-page trigger, choice in the popup** (recommended first) | The content script draws only an icon in a closed shadow root. A trusted click on it asks the service worker to open the extension popup (`chrome.action.openPopup()`), which lists matches for the tab, as today. | The choice is made in browser UI the page cannot draw over. Clickjacking the icon at worst opens the popup.                                | That Ruvee is installed and the user clicked the icon. No vault state (§4).                               |
| I2. In-page menu in an extension iframe                          | The content script inserts an `<iframe>` of an extension page (`menu.html`, listed in `web_accessible_resources` with `use_dynamic_url`). The list and the click are inside the frame.                             | The page controls the iframe element: opacity, `clip-path`, filters, overlays, top-layer popovers, timing. Needs every mitigation in E-10. | Not the frame's content (cross-origin). Its size, timing, focus and mouse movement over it, unless fixed. |
| I3. In-page menu in a closed shadow root                         | The content script renders the list into a closed shadow root in the page.                                                                                                                                         | As I2, and the page can also restyle it through inherited properties and the host element.                                                 | Risky: rendered text in the page's own DOM tree (selection, layout probes, accessibility tree). Rejected. |

**Recommendation: I1 first.** It gives the "click the icon in the field" experience while every
decision that matters (which login, save, update, use this password) stays in the popup, which the
page cannot cover or fake inside the browser's toolbar UI. A spike on 2026-11-12 confirmed
that `chrome.action.openPopup()`, called by the service worker on a message from a content
script's click, opens the popup in Playwright's Chromium 156, headless and headed. It was not
tried on older versions (the manifest's minimum is 120): where it fails (an older browser, an
unfocused window), the worker puts a badge on the toolbar button for that tab and the user clicks
it, which is the current flow. I2 is a later, separate decision (Phase E in §7), taken
only if I1 proves too awkward; I3 is rejected for anything that shows vault data.

The public research this must survive: DOM-based clickjacking of password-manager inline menus
(Marek Tóth, DEF CON 33, August 2025: a page made the injected menu transparent and lured a click,
which filled credentials, cards or TOTP codes in most major managers), and earlier autofill attacks
on cross-origin iframes (Flashpoint's 2023 report on Bitwarden filling a login into an embedded
iframe) and on WebViews (AutoSpill, Black Hat Europe 2023). The owner's brief refers to 2023 work on
inline-autofill clickjacking; these sources must be checked and added to
[research-sources.md](research-sources.md) before review.

## 3. Origin and frame rules

These stay as strict as manual fill, and are now enforced for content-script messages too.

- **The origin comes from the browser, never from the page.** For a content-script message the
  service worker uses `sender.origin` and `sender.frameId` (set by Chrome) and the tab's top-level
  URL from `chrome.tabs`. Any origin or URL in the message body is ignored.
- **Exact origin match stays.** Scheme, host and port, against each URL in the item's `urls`
  array. No subdomain, registrable-domain or public-suffix matching. A user who wants a login on
  `login.example.com` and `example.com` adds both URLs to the item. (T-20 mentions the public
  suffix list; under this design it is not used for matching, and T-20's wording should say so.)
- **Top frame only, unchanged.** Phase A registers the content script for the top frame only
  (`allFrames: false`), because the fill reaches only the top frame; an icon in a same-origin
  frame would open a popup that cannot fill it. If later phases run it in frames, a fill, a save
  or an update is accepted only when the frame's origin equals the top-level origin. Cross-origin frames get no icon, no save prompt and no
  fill. A per-item "also fill in frames from X" setting is a possible later decision, not part of
  D-33.
- **Re-check at every step.** The origin is read when the icon is clicked, when the popup lists
  matches, and again just before the fill function is injected (as today, extension-design §4). A
  page that navigates, or swaps the frame, between steps gets nothing.
- **Non-`https:` pages** (except loopback) get no icon and no save prompt, as they get no matches
  today.

## 4. What a page can learn, and what it must not

A hostile page can always tell that Ruvee is installed once a content script runs in it: the icon
appears, the DOM changes, timing changes. That is accepted, and the owner should accept it
explicitly (D-33). With I2, `web_accessible_resources` adds a probe; `use_dynamic_url` removes the
fixed-URL probe but not the others.

A page must **not** be able to learn:

- whether the vault is locked or unlocked,
- whether the vault has a login for this origin, how many, or any title or username,
- whether the user has saved, updated or dismissed anything.

So the content script never receives any of that. It does not ask the service worker "is there a
match?". It draws the same icon, in the same place, on every password field on every `https:` page,
whatever the vault state. Match counts, usernames and the lock screen appear only in the popup.
The one thing the page sees is the fill itself: after the user picks a login, the username and
password are in the page's fields, as with manual fill today.

A page can still infer some state from what the user does (they clicked the icon and the form got
filled, so a login existed). That is the same as manual fill and is accepted.

## 5. Feature design rules

### 5.1 Content script

- Registered dynamically (`chrome.scripting.registerContentScripts`) only after the user turns
  inline features on in the options page and grants the host permission. Off by default; manual
  fill keeps working without it.
- Runs in the isolated world; never injects code into the page's main world, never hooks the page's
  `fetch` or `XMLHttpRequest`.
- Holds no vault data, no keys, no item ids. Its only inputs from the service worker are "fill this
  username and password into these fields now" (as today) and acknowledgements.
- Reacts only to `isTrusted` events. A programmatic `focus()`, `click()` or synthetic `submit` from
  the page does nothing.

### 5.2 Save a new login (F2)

- On the user's own sign-in gesture, the content script sends the username and password from the
  form to the service worker. A trusted `submit` event is not enough: Chrome marks the submit
  event of a page's `form.requestSubmit()` or `button.click()` as trusted (checked 2026-11-12), so
  the script listens for the user's trusted click on a submit control, or Enter in a field. The page already has these values: the user just typed them into it.
- The service worker keeps the capture **in memory only**, for at most 5 minutes, keyed by tab and
  origin, and only while the vault is unlocked. It is never written to `chrome.storage` or
  IndexedDB, and lock, auto-lock, logout and service-worker restart drop it. If the vault is locked
  at submit time, nothing is captured.
- The prompt is a badge on the toolbar icon. The user opens the popup, which says "Save login for
  `https://origin`?" with the username shown and the password hidden. Saving creates an item with
  that origin as its URL. **Ruvee never shows a save, update or unlock prompt inside a page.**
- At most one pending capture per tab; a new one replaces the old. Captures with an empty password,
  or matching an existing item exactly, are dropped. "Never for this site" is stored as an
  encrypted vault setting, not in plaintext extension storage (the list of sites is vault data).

### 5.2a Opening the popup by itself for a save offer (B+, approved 2026-11-12)

The owner asked for the save offer to appear without a click on the toolbar button, still in the
popup (option I1), never as a bar in the page (I2 stays out).

- After a new capture is kept (§5.2), the worker calls `chrome.action.openPopup()` for the
  capture's window, **only** when that tab is the active tab of the focused window, at most once
  per tab per 5 minutes and once per 30 seconds across the browser
  (`src/inline/auto-open.ts`). In every other case, and when Chrome refuses, the "+" badge is
  the offer, as before. No capture means no popup, so it never opens while locked, after a
  page's own submit, or on a page where nothing was captured.
- The badge stays while the offer waits: opening the popup no longer clears a "+" (the user may
  close the popup without answering).
- **Off by default**, under "Open Ruvee by itself to offer saving a login" in the options. Why:
  the popup taking focus may be visible to the page (E-25). The page would then learn something
  §4 says it must not: the vault is unlocked and has no login with that username. The test
  browser cannot show whether Chrome fires `blur` here, because Playwright fakes page focus. If
  a hand check in Chrome shows no focus change the page can see, the default can be switched on.
- **Spike** (Chromium 156, 2026-11-12, no user gesture; headed results, headless in brackets):

  | Situation                            | Result                                             |
  | ------------------------------------ | -------------------------------------------------- |
  | Target window focused                | opens                                              |
  | A popup already open                 | fails                                              |
  | The capture's tab not the active one | opens, for the active tab: refused by Ruvee (E-26) |
  | Another window focused               | fails (headless: opens)                            |
  | Window minimized                     | fails                                              |

  Chrome versions before 156 were not tried; the manifest's minimum is 120, and anything that
  throws falls back to the badge.

### 5.3 Update a changed password (F3)

- Triggered by a change-password form, or a sign-in with a username that matches an item for the
  origin and a different password. Same capture and badge rules as §5.2.
- The popup names the item that will change and asks for confirmation. Nothing is changed without
  that click.
- The previous password is kept on the item (a "previous passwords" field, or version history when
  Phase 7 brings it), so a fabricated or mistaken update cannot destroy the real password.
- A sync conflict follows INV-08: an update to an item with remote changes produces a conflict.

### 5.4 Generated password on sign-up (F4)

- The generator lives in `packages/vault` (CSPRNG, unbiased sampling, Phase 3), shared with the web
  app, and runs in the service worker.
- The popup shows the suggestion. On "Use", the service worker **first** saves it (a new item for
  the origin, or a "generated, not yet confirmed" entry), **then** fills the new-password fields. A
  password that reached a site and was not saved is the failure that matters here.
- The generated password is given to the page only by the fill, like any other fill.

## 6. Threats added by inline features

These extend the table in [extension-design.md §5](extension-design.md#5-threats-specific-to-the-extension).
"Phase" refers to §7.

| ID   | Threat                                                                                                                                                                                                                           | Attacker | Mitigation                                                                                                                                                                                                                                                                                                                                                         | Phase |
| ---- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----- |
| E-10 | **Clickjacking of the inline UI**: the page makes the icon or menu transparent, clips or covers it, puts it in the top layer, or times a double click so the user's click fills or saves                                         | A5       | I1: the in-page icon only opens the popup; every choice is in the popup. If I2 is ever built: IntersectionObserver v2 `trackVisibility` inside the frame, refuse clicks unless visible for at least 500 ms, ignore clicks within 500 ms of opening, close on any layout or style change of the host element, and still require the service-worker origin re-check. | A, E  |
| E-11 | **A page embeds or reuses the inline UI**: frames `menu.html` itself (allowed by `web_accessible_resources`), or copies the frame's URL                                                                                          | A5       | I1 has no `web_accessible_resources`. For I2: the menu frame takes no input from its URL; it gets data only for a one-time menu session that the service worker opened after a trusted click, bound to the tab, the content script's frame and the first frame that claims it.                                                                                     | A, E  |
| E-12 | **A page reads the inline UI**                                                                                                                                                                                                   | A5       | Nothing with vault data is rendered in the page's DOM (I3 rejected). For I2: fixed frame size and position, regardless of the number of matches; no focus moved into the frame until the user clicks it.                                                                                                                                                           | A, E  |
| E-13 | **A page draws a fake Ruvee UI**: a fake menu, save prompt or unlock box asking for the master password                                                                                                                          | A5       | Ruvee never asks for the master password, or offers save, update or unlock, inside a page. Documented in the product and in onboarding: "Ruvee only asks for your password in its own window." Accepted residual: users may still type it into a convincing fake.                                                                                                  | A     |
| E-14 | **A page learns vault state**: installed, locked or unlocked, has a login for the site, which username                                                                                                                           | A5       | Identical icon in every state (§4); the content script never receives match or lock state; badge and popup are outside the page. Installation is detectable and accepted.                                                                                                                                                                                          | A     |
| E-15 | **Cross-origin frame harvest**: a hostile page frames the victim's login page, or a hostile frame (an ad) sits inside the victim page and asks for a fill or a save                                                              | A5       | Fill, save and update only when the frame origin equals the top-level origin, both read from the browser (§3). Tested with both directions of framing.                                                                                                                                                                                                             | A, B  |
| E-16 | **Subdomain and look-alike matching**: user-content hosts (`*.github.io`), a taken-over subdomain, or a look-alike domain                                                                                                        | A5       | Exact origin match only; no registrable-domain or public-suffix matching (§3). A login is offered on another host only if the user added that URL to the item.                                                                                                                                                                                                     | A     |
| E-17 | **Save or update poisoning**: a page fabricates submits to plant items, floods prompts, or tries to overwrite a stored password                                                                                                  | A5       | Trusted events only; one pending capture per tab; the origin is the sender's, so a page can only create items for itself; every save and update needs a click in the popup that names the origin and item; updates keep the previous password (§5.3).                                                                                                              | B, C  |
| E-18 | **Save-prompt phishing**: the user is led to save credentials for a look-alike origin, or to attach them to the wrong item                                                                                                       | A5       | The popup shows the exact origin being saved; a save always creates a new item for that origin, never adds the origin to an existing item.                                                                                                                                                                                                                         | B     |
| E-19 | **Captured plaintext outlives its use**: a captured or generated password left in storage or memory                                                                                                                              | A7, A8   | Memory only, 5 minutes at most, only while unlocked, dropped on lock and restart (§5.2). INV-16 capture tests extended to pending captures.                                                                                                                                                                                                                        | B, D  |
| E-20 | **The content-script channel is abused**: a compromised renderer sends forged content-script messages, or a page reaches the service worker through the content script                                                           | A5, A8   | A separate, minimal message schema for content scripts (field found, icon clicked, submitted); it can never call a vault method or receive vault data. The fill credential is sent only after the user chose it in the popup.                                                                                                                                      | A     |
| E-21 | **Fill into the wrong field after a swap**: the page replaces or hides fields between the icon click and the fill                                                                                                                | A5       | The fill function re-selects visible, enabled fields at fill time and checks `location.origin` (as today); hidden fields and fields in other forms are never filled.                                                                                                                                                                                               | A     |
| E-22 | **Larger blast radius**: host permission on all sites makes an extension bug or a malicious update (E-06) able to read every page                                                                                                | A10      | Opt-in permission (§5.1), off by default; content script reviewed as security-sensitive code; no remote code. Accepted residual: once granted, a compromised build can read any page.                                                                                                                                                                              | A     |
| E-23 | **Generated password lost**: the site accepted a generated password that Ruvee never saved                                                                                                                                       | —        | Save before fill (§5.4).                                                                                                                                                                                                                                                                                                                                           | D     |
| E-24 | **Popup spam**: a page makes every click on one of its buttons look like a sign-in, so Ruvee keeps opening its popup                                                                                                             | A5       | The popup opens only after the user's own trusted click or Enter (§5.2), only for a new capture kept while unlocked, once per tab per 5 minutes and once per 30 seconds across the browser; afterwards only the badge. Off by default (§5.2a).                                                                                                                     | B+    |
| E-25 | **The automatic popup tells the page something**: when the popup takes focus, the page may see `blur` or `document.hasFocus()` turn false, and learn that the vault is unlocked and has no login with that username for the site | A5       | Off by default. Not measured: Playwright fakes page focus, so the test browser could not show it either way. A hand check in Chrome decides whether the default may change.                                                                                                                                                                                        | B+    |
| E-26 | **The popup opens for the wrong tab**: Chrome opens the action popup for the active tab, which may not be the one that signed in                                                                                                 | —        | Opened only when the capture's tab is the active tab of the focused window; otherwise the badge. The offer is read per tab (`pendingSave`), so the popup never shows another tab's capture.                                                                                                                                                                        | B+    |

Still not protected, as today: a page reading a value after it was filled; malware or another
extension on an unlocked browser (T-23); a compromised site origin (XSS on the real site) receiving
the credential the user chose to fill there.

## 7. What changes in existing rules

D-33 approves these changes. Each is edited in the same pull request as the code that needs it:

| Rule                                                                          | Today                                                     | Proposed                                                                                                                                                                     |
| ----------------------------------------------------------------------------- | --------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| extension-design scope                                                        | Manual fill only, no saving                               | Manual fill stays the default. Inline trigger, save, update and generate are opt-in.                                                                                         |
| extension-design §1: "no long-lived content script"                           | None                                                      | One content script, registered only after opt-in, holding no vault data (§5.1).                                                                                              |
| extension-design §1: "no `web_accessible_resources`"                          | None                                                      | Unchanged for I1. Only a separate decision for I2 would add `menu.html`.                                                                                                     |
| extension-design §1: messages from any origin but the extension's are dropped | Content scripts dropped                                   | A second, separate schema for content-script messages (E-20); the existing vault channel is unchanged and still refuses them.                                                |
| extension-design §2: host permission for the server origin only               | Server origin                                             | Plus `https://*/*` after explicit opt-in.                                                                                                                                    |
| extension-design §4: "Nothing is injected without that user action"           | True                                                      | The content script runs on every page after opt-in; a **fill** still needs a user action in the popup.                                                                       |
| E-02: "clickjacking of the popup is impossible"                               | No in-page UI                                             | Still true of the popup; the in-page icon is covered by E-10.                                                                                                                |
| INV-19                                                                        | Content scripts receive at most the one chosen credential | Unchanged in substance; add: content scripts may **send** a captured username and password to the service worker, and never learn lock state or whether a login exists (§4). |
| INV-16                                                                        | No plaintext persisted                                    | Unchanged; captured and generated passwords are memory-only until saved as an encrypted item.                                                                                |
| `EXTENSION_VAULT_METHODS`                                                     | Read-only                                                 | Adds item create and item update. The extension becomes a writing client, so INV-08 conflict handling and sync-protocol rules apply to it.                                   |
| T-20 (threat-model)                                                           | Mentions the public suffix list                           | Exact origin only; reference this document.                                                                                                                                  |
| Roadmap Phase 5                                                               | "Origin matching for autofill"                            | Phases A to D below; I2 and cross-origin frame fill as separate later decisions.                                                                                             |

Not changed: no automatic fill on page load or on focus, no fill without a user choice, exact
origin match, top-frame rule, D-27 key handling, pairing, sessions.

## 8. Phased order and tests

Each phase is one pull request with its tests, and starts only after the previous one is reviewed.
Browser tests use the existing Playwright harness with the unpacked test build in Chromium and
local fixture origins on several ports.

**Phase A: inline trigger with choice in the popup (I1).** Opt-in permission flow, dynamic
content-script registration, field detection, the icon, the content-script message schema,
`openPopup` (or the fallback).

- Unit: field detection on fixture DOMs (login, sign-up, change-password, hidden and disabled
  fields, shadow DOM forms); content-script schema rejects every vault method and any body origin.
- Browser: no content script before opt-in; icon on an `https` login page; none on `http`, in a
  cross-origin frame, or for a non-trusted `click()`/`focus()`; the DOM the page sees is **identical**
  (snapshot comparison) when locked, unlocked with a match and unlocked without a match; a page that
  sets `opacity: 0` on `html`, covers the icon or moves it into a popover still cannot cause a fill
  without a click in the popup; a field swapped after the icon click is not filled; a content
  script's forged `fill` or vault message is refused; revoking the permission unregisters the
  script.

### 8.1 Phase A as built (2026-11-12)

- `src/content.ts`, built to `content.js` and registered with
  `chrome.scripting.registerContentScripts` (top frame, `document_idle`, isolated world) only
  after the user chooses **Turn on** under "Fill from login fields" in the options page and the
  browser grants `https://*/*` (the test build: `http://127.0.0.1/*`). **Turn off** unregisters it
  and gives the permission back, then checks the server origin's permission is still there and
  says so if it is not. On every start, and when a permission is removed in the browser's own
  settings, the worker re-registers or unregisters to match the setting and the permission.
- The icon (the brand mark, inline SVG) sits in a closed shadow root, on each password field and
  the username field before it in the same form (`src/inline/detect.ts`, the fill function's
  rule), hidden when the field is not visible or too small. The script never sends a message on
  its own; only a click with `isTrusted` sends `{ kind: 'inlineOpen' }`, at most once a second.
- The worker answers that one message on a separate path (`src/inline/gate.ts`): this extension,
  not its own pages, `frameId` 0, a fillable origin that equals the tab's, inline fill on, the
  tab active and still on that origin. It opens the popup and replies `null` in every case. A
  content-script message never counts as activity for auto-lock and never reaches the vault
  channel, which still drops every sender but the extension's own pages.
- Unit tests: the sender gate and the one-message schema, field detection (login, sign-up,
  other form, disabled, read-only, shadow roots and frames skipped), and the content script
  (closed shadow root, no message on load, untrusted clicks ignored, icon restored after the page
  removes it).
- Browser test (`e2e/extension.spec.ts`, "inline icon (phase A)"): no script before opt-in; the
  icon after it; the page's whole markup **identical** when unlocked with a match, unlocked
  without one and locked, and the reply to the content script identical too; the user's click
  opens the toolbar popup (`chrome.runtime.getContexts`) and fills nothing; page-made clicks open
  nothing; with `opacity: 0` on `html` a click still only opens the popup; forged `fill`,
  `candidates`, vault, `status`, `setInline` and an `inlineOpen` carrying a tab id get no reply;
  no icon in a cross-origin frame; nothing after **Turn off**.
- **Not covered by tests:** the badge fallback (the test browser always opens the popup), giving
  back the permission and its effect on the server origin's permission (the test build's
  host permission is part of its manifest and cannot be removed), a browser withdrawing the
  permission, covering the icon or moving it into a top-layer popover (only `opacity` was tried;
  each still only opens the popup), and any Chrome older than 156.

**Phase B: save a new login.** Submit detection, capture, badge, popup save, item create from the
extension.

- Unit: capture rules (empty password, duplicate, one per tab, 5-minute expiry).
- Browser: a real form submit produces a badge and saves an item for the exact origin; a synthetic
  `submit` produces nothing; a capture from a cross-origin frame is refused; lock, auto-lock and a
  service-worker restart drop the pending capture; scans of `chrome.storage`, IndexedDB and the
  network show no plaintext capture; a page cannot learn that a capture is pending; the item syncs
  to the web vault.

### 8.2 Phase B as built (2026-11-12)

- **Capture** (`src/inline/capture.ts`, `src/content.ts`): on the user's trusted click on a submit
  control (a submit button or input in a form, any button outside one) or trusted Enter in a
  field, the content script reads the scope's form: one non-empty password, or several equal ones
  (sign-up), and the nearest text or email field before it. Two different passwords (a change of
  password) are left to phase C. It sends `{ kind: 'inlineCapture', username, password }`, once
  per gesture. The schema has no origin, tab or item field.
- **Worker:** the same sender gate as phase A (top frame, the tab's own fillable origin). It
  keeps the capture only while unlocked (an expired unlock is locked first), only if inline fill
  is on, and only if no login for exactly that origin has the same username: the same password is
  a duplicate, and a different one is phase C. One capture per tab, in a `Map` in worker memory,
  for 5 minutes, with a `+` badge on that tab. Lock, auto-lock, logout, closing the tab and a
  worker restart drop it. The reply is always `null`.
- **Popup:** "Save this login for `origin`?" with the username and never the password (the
  worker returns only origin and username). **Save login** creates a new login item, titled with
  the host, for exactly the form's origin, through the vault engine's `save`, which syncs it.
  **Not now** drops the capture.
- **Not built:** "Never for this site". It needs an encrypted per-vault setting, and the item
  schema has none yet. Until it exists, the only answer is "Not now".
- Unit tests: capture scope (other forms, no form, sign-up, change of password, limits), which
  clicks count, the schema (no origin, tab or item; size limits), and a page's `click()`,
  `requestSubmit()` and fake Enter sending nothing.
- Browser test ("save a new login (phase B)"):
  - a page's own `click()` and `requestSubmit()` produce no capture and no badge;
  - signing in while locked keeps nothing for after the unlock;
  - a real sign-in that posts to another origin gets a badge and an offer for the **form's**
    origin, not the tab's new one;
  - while it waits, the capture is not in `chrome.storage`, and the page shows nothing;
  - the popup never contains the password;
  - the saved item fills on its origin and is not offered on the other;
  - known usernames are not offered again;
  - **Not now**, a lock and a worker restart each drop the capture;
  - forged captures carrying an origin or tab id, and the popup's save messages sent from a
    content script, get no reply;
  - a capture sent from a cross-origin frame gets no reply and leaves nothing;
  - the final capture check finds the saved password neither in requests to the server nor in
    the extension's stores.
- **Not covered by tests:**
  - the 5-minute expiry;
  - auto-lock dropping a capture (lock and restart are tested; auto-lock goes through the same
    `lock()`);
  - the badge surviving every kind of navigation (re-applied when a page finishes loading);
  - sign-ins with no form submit and no button (some script-driven pages);
  - the item appearing in the web app (it syncs through the engine like any edit; not checked
    here).

**Rehearsal bug and fix (2026-11-12).** In real Chrome, the popup showed "Something went
wrong" on every page and offered no save. The extension had been updated **in place**: the
phase B files were copied over the phase A build without a reload. Chrome opens an unpacked
extension's pages from disk each time, but keeps running the service worker it loaded until the
extension is reloaded, even across a worker restart (reproduced in Chromium 156). The phase A
worker refused the new popup's `pendingSave` request as invalid (`internal`), and dropped the
content script's new `inlineCapture`, so nothing was captured. The phase B code itself works,
including a sign-in that goes on to a second same-origin page (browser test added). The fix:

- every build carries one id in all its bundles;
- the popup and options page compare it with the worker's, and on a mismatch send nothing else
  and offer **Reload Ruvee** (`chrome.runtime.reload()`), which locks the vault;
- the popup's three calls on opening (`candidates`, `pendingSave`, `sync`) no longer share one
  `try`, so one failure cannot hide the others' results;
- an error with no specific text names its call and code, for example "(pendingSave: internal)".

Covered by `e2e/upgrade.spec.ts`: an old worker with new files gets the reload offer, not "Something went wrong". The button itself is a hand check: the test browser loads the extension with `--load-extension`, and Chromium does not bring such an extension back after it reloads itself.

### 8.3 Automatic save popup (B+) as built (2026-11-12)

- `offerByPopup` in the worker, after `inlineCapture` keeps a capture; the pure decision is
  `shouldAutoOpen` (`src/inline/auto-open.ts`); the setting `autoOpenSave` in
  `chrome.storage.local` (absent means off), set from the options page with `setAutoOpenSave`.
- Unit tests: the decision (setting, active tab, focused window, per-tab and browser-wide
  limits).
- Browser test ("save offer opens the popup by itself"):
  - the setting is off by default;
  - turned on, a real sign-in opens the popup once, and the "+" stays;
  - a second sign-in in the same tab only updates the offer;
  - a page's own submit opens nothing;
  - a sign-in while locked opens nothing and leaves no badge;
  - with a popup already open, or for a tab in the background, the badge is the offer;
  - turned off, only the badge.
- **Hand checks in real Chrome:**
  - whether the page sees `blur` or `hasFocus() === false` when the popup opens (E-25; decides
    the default);
  - the popup after a real site's sign-in that navigates (it opens at the click; does it stay
    open through the navigation?);
  - a second window focused;
  - Chrome versions older than 156.

**Rehearsal report and diagnostics (2026-11-12).** On build 39271f4 the owner signed in on a
site: the "+" badge appeared, but the popup did not open by itself. A popup opened while the
sign-in navigates the tab stays open in Chromium 156 (spike: a fast and a slow POST,
headless and headed), so navigation is not the cause. The capture was kept (the badge), so the
open was either skipped or refused. The likely reason is the setting, which is off by default
(§5.2a), but the build could not say. Now:

- the worker records each reported sign-in: "popup opened", "badge only: <reason>" (`off`,
  `tab_not_active`, `window_not_focused`, `limit_any`, `limit_tab`, no window), "badge only:
  Chrome refused (<Chrome's message>)", or "not kept: locked" / "not kept: a login with this
  username is already saved";
- the last 8 records are kept in `chrome.storage.session` (memory, trusted contexts only;
  origins and outcomes, never a username or password) and cleared on logout and removal;
- the options page lists them under "Recent sign-ins (development build)";
- the popup's save offer says how to turn the setting on when it is off;
- browser test: the owner's case (setting at its default) ends in "badge only: off" with the
  hint shown, and every other path records its reason.

**Phase C: update a changed password.**

- Browser: change-password form and different-password sign-in both offer an update naming the
  right item; nothing changes without the popup click; the previous password is kept; a concurrent
  remote edit produces a conflict (INV-08).

**Phase D: generated password on sign-up.** Needs the Phase 3 generator in `packages/vault`
first, with its own tests (character-set distribution, length bounds, unbiased sampling vectors).

- Browser: suggestion offered only on new-password fields; the item is saved before the fill (kill
  the service worker between save and fill: the password is in the vault); the generated value
  appears nowhere in storage in plaintext.

**Phase E (separate decision, not part of D-33): in-page menu (I2).** Only if I1 is not usable.
Needs its own review, the E-10 to E-12 mitigations, and a fixture suite reproducing the published
clickjacking techniques.

Not planned: autofill on page load, fill on focus, registrable-domain matching, fill into
cross-origin frames, cards and identities inline, passkeys.

## 9. Questions decided by D-33 (approved 2026-11-12, as recommended)

1. Accept that inline features need permission to read all `https:` sites, off by default and
   granted on the options page?
2. Accept that any page can tell Ruvee is installed once inline features are on, while lock state
   and matches stay hidden (§4)?
3. Start with I1 (choice in the popup) rather than an in-page menu?
4. Accept the extension writing to the vault (save, update, generate), with the previous password
   kept on update?
5. Order A, B, C, D as in §8?
