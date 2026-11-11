# Extension inline fill, save and generate: design and threat-model addendum

Status: **Proposed (2026-11-11). Not approved, not implemented, not reviewed.** It proposes the
next scope for the browser extension and needs the owner's decision D-33
([open-decisions.md](../architecture/open-decisions.md#later-phase-decisions)). Until D-33 is
decided, [extension-design.md](extension-design.md) stays the rule: logins only, manual fill from
the popup, no autofill on load, no saving of new logins, no long-lived content script, no
`web_accessible_resources`.

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
page cannot cover or fake inside the browser's toolbar UI. `chrome.action.openPopup()` must be
confirmed in a spike on the minimum Chrome version (it needs a focused window and is not available
on every channel or version); if it is unavailable, the icon highlights the toolbar action and the
user clicks it, which is the current flow. I2 is a later, separate decision (Phase E in §7), taken
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
- **Top frame only, unchanged.** The content script runs with `all_frames: true` so it can see a
  login form in a same-origin frame, but a fill, a save or an update is accepted only when the
  frame's origin equals the top-level origin. Cross-origin frames get no icon, no save prompt and no
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

- On a trusted submit, the content script sends the username and password from the form to the
  service worker. The page already has these values: the user just typed them into it.
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

| ID   | Threat                                                                                                                                                                                   | Attacker | Mitigation                                                                                                                                                                                                                                                                                                                                                         | Phase |
| ---- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----- |
| E-10 | **Clickjacking of the inline UI**: the page makes the icon or menu transparent, clips or covers it, puts it in the top layer, or times a double click so the user's click fills or saves | A5       | I1: the in-page icon only opens the popup; every choice is in the popup. If I2 is ever built: IntersectionObserver v2 `trackVisibility` inside the frame, refuse clicks unless visible for at least 500 ms, ignore clicks within 500 ms of opening, close on any layout or style change of the host element, and still require the service-worker origin re-check. | A, E  |
| E-11 | **A page embeds or reuses the inline UI**: frames `menu.html` itself (allowed by `web_accessible_resources`), or copies the frame's URL                                                  | A5       | I1 has no `web_accessible_resources`. For I2: the menu frame takes no input from its URL; it gets data only for a one-time menu session that the service worker opened after a trusted click, bound to the tab, the content script's frame and the first frame that claims it.                                                                                     | A, E  |
| E-12 | **A page reads the inline UI**                                                                                                                                                           | A5       | Nothing with vault data is rendered in the page's DOM (I3 rejected). For I2: fixed frame size and position, regardless of the number of matches; no focus moved into the frame until the user clicks it.                                                                                                                                                           | A, E  |
| E-13 | **A page draws a fake Ruvee UI**: a fake menu, save prompt or unlock box asking for the master password                                                                                  | A5       | Ruvee never asks for the master password, or offers save, update or unlock, inside a page. Documented in the product and in onboarding: "Ruvee only asks for your password in its own window." Accepted residual: users may still type it into a convincing fake.                                                                                                  | A     |
| E-14 | **A page learns vault state**: installed, locked or unlocked, has a login for the site, which username                                                                                   | A5       | Identical icon in every state (§4); the content script never receives match or lock state; badge and popup are outside the page. Installation is detectable and accepted.                                                                                                                                                                                          | A     |
| E-15 | **Cross-origin frame harvest**: a hostile page frames the victim's login page, or a hostile frame (an ad) sits inside the victim page and asks for a fill or a save                      | A5       | Fill, save and update only when the frame origin equals the top-level origin, both read from the browser (§3). Tested with both directions of framing.                                                                                                                                                                                                             | A, B  |
| E-16 | **Subdomain and look-alike matching**: user-content hosts (`*.github.io`), a taken-over subdomain, or a look-alike domain                                                                | A5       | Exact origin match only; no registrable-domain or public-suffix matching (§3). A login is offered on another host only if the user added that URL to the item.                                                                                                                                                                                                     | A     |
| E-17 | **Save or update poisoning**: a page fabricates submits to plant items, floods prompts, or tries to overwrite a stored password                                                          | A5       | Trusted events only; one pending capture per tab; the origin is the sender's, so a page can only create items for itself; every save and update needs a click in the popup that names the origin and item; updates keep the previous password (§5.3).                                                                                                              | B, C  |
| E-18 | **Save-prompt phishing**: the user is led to save credentials for a look-alike origin, or to attach them to the wrong item                                                               | A5       | The popup shows the exact origin being saved; a save always creates a new item for that origin, never adds the origin to an existing item.                                                                                                                                                                                                                         | B     |
| E-19 | **Captured plaintext outlives its use**: a captured or generated password left in storage or memory                                                                                      | A7, A8   | Memory only, 5 minutes at most, only while unlocked, dropped on lock and restart (§5.2). INV-16 capture tests extended to pending captures.                                                                                                                                                                                                                        | B, D  |
| E-20 | **The content-script channel is abused**: a compromised renderer sends forged content-script messages, or a page reaches the service worker through the content script                   | A5, A8   | A separate, minimal message schema for content scripts (field found, icon clicked, submitted); it can never call a vault method or receive vault data. The fill credential is sent only after the user chose it in the popup.                                                                                                                                      | A     |
| E-21 | **Fill into the wrong field after a swap**: the page replaces or hides fields between the icon click and the fill                                                                        | A5       | The fill function re-selects visible, enabled fields at fill time and checks `location.origin` (as today); hidden fields and fields in other forms are never filled.                                                                                                                                                                                               | A     |
| E-22 | **Larger blast radius**: host permission on all sites makes an extension bug or a malicious update (E-06) able to read every page                                                        | A10      | Opt-in permission (§5.1), off by default; content script reviewed as security-sensitive code; no remote code. Accepted residual: once granted, a compromised build can read any page.                                                                                                                                                                              | A     |
| E-23 | **Generated password lost**: the site accepted a generated password that Ruvee never saved                                                                                               | —        | Save before fill (§5.4).                                                                                                                                                                                                                                                                                                                                           | D     |

Still not protected, as today: a page reading a value after it was filled; malware or another
extension on an unlocked browser (T-23); a compromised site origin (XSS on the real site) receiving
the credential the user chose to fill there.

## 7. What changes in existing rules

If D-33 is approved, these change and must be edited in the same pull request as the code:

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

**Phase B: save a new login.** Submit detection, capture, badge, popup save, item create from the
extension.

- Unit: capture rules (empty password, duplicate, one per tab, 5-minute expiry).
- Browser: a real form submit produces a badge and saves an item for the exact origin; a synthetic
  `submit` produces nothing; a capture from a cross-origin frame is refused; lock, auto-lock and a
  service-worker restart drop the pending capture; scans of `chrome.storage`, IndexedDB and the
  network show no plaintext capture; a page cannot learn that a capture is pending; the item syncs
  to the web vault.

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

## 9. Open questions for the owner (D-33)

1. Accept that inline features need permission to read all `https:` sites, off by default and
   granted on the options page?
2. Accept that any page can tell Ruvee is installed once inline features are on, while lock state
   and matches stay hidden (§4)?
3. Start with I1 (choice in the popup) rather than an in-page menu?
4. Accept the extension writing to the vault (save, update, generate), with the previous password
   kept on update?
5. Order A, B, C, D as in §8?
