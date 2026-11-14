# Ruvee browser extension (development build)

Chromium, Manifest V3. Logins only, filled on request into a page of exactly the saved origin.
Design and threats: [extension-design.md](../../docs/security/extension-design.md). Synthetic data
only; nothing here has been independently reviewed.

## Build and load

```sh
pnpm turbo run build --filter=@ruvee/extension   # writes apps/extension/dist/
```

Open `chrome://extensions`, turn on Developer mode, choose **Load unpacked** and pick
`apps/extension/dist`. After replacing the files with a newer build, press **Reload** on the
extension's card: Chrome opens the new popup from disk but keeps running the old service worker
until then. The popup notices the mismatch and offers **Reload Ruvee**. The manifest carries a development public key, so the id is always
`ikjjmgfofphmclnkphkceboclijkfkbd`. The matching private key was not kept; a store release gets
its own key.

The API accepts the extension's login and refresh calls only from listed origins. In `.env`:

```sh
EXTENSION_ORIGINS=chrome-extension://ikjjmgfofphmclnkphkceboclijkfkbd
```

Then, in the extension's settings, enter the server address (for local development the web app's
origin, such as `http://127.0.0.1:3100`, which forwards `/api`). The browser asks for permission to
reach that one origin.

## Using it

1. Create the account in the web app. Setup and recovery happen there only.
2. In the extension popup, log in. The browser is then a pending device.
3. In the web app, open **Devices**, choose **Add a device**, and type the code into the popup.
   Approve it in the web app.
4. On a login page, open the popup and choose **Fill** on a matching login. Only logins saved for
   exactly that origin (scheme, host and port) are offered.
5. Optional: in the extension's settings, **Turn on** "Fill from login fields". The Ruvee icon then
   appears in login fields; clicking it opens the same popup. It needs permission to run on every
   HTTPS site ([extension-inline-autofill.md](../../docs/security/extension-inline-autofill.md)).

The vault locks after 15 minutes without use, on **Lock**, and when the browser exits.

**Open Ruvee** in the popup's header and on the settings page opens the paired server's web vault,
or brings its tab forward if one is open. **Copy** on a login copies its username only; the
password never reaches the popup.

## Tests

```sh
pnpm --filter @ruvee/extension test                 # origin rules and the fill function
RUVEE_E2E_ADMIN_DATABASE_URL=… pnpm --filter @ruvee/extension test:extension
```

The second builds `dist-test/` (the same code with `__RUVEE_TEST__` and host permission for
127.0.0.1, because automation cannot click a permission prompt) and runs the end-to-end flow in
Chromium against a throwaway API database. It needs the API and web export built.

```sh
pnpm --filter @ruvee/extension build && node apps/extension/scripts/screenshots.mjs <dir>
```

Screenshots of the popup states and the settings page, light and dark, for design review. The
pages run against a stub of the `chrome` API with synthetic data; no server or worker is involved.
