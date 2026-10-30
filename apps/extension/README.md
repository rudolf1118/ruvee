# Ruvee browser extension (development build)

Chromium, Manifest V3. Logins only, filled on request into a page of exactly the saved origin.
Design and threats: [extension-design.md](../../docs/security/extension-design.md). Synthetic data
only; nothing here has been independently reviewed.

## Build and load

```sh
pnpm turbo run build --filter=@ruvee/extension   # writes apps/extension/dist/
```

Open `chrome://extensions`, turn on Developer mode, choose **Load unpacked** and pick
`apps/extension/dist`. The manifest carries a development public key, so the id is always
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

The vault locks after 15 minutes without use, on **Lock**, and when the browser exits.

## Tests

```sh
pnpm --filter @ruvee/extension test                 # origin rules and the fill function
RUVEE_E2E_ADMIN_DATABASE_URL=… pnpm --filter @ruvee/extension test:extension
```

The second builds `dist-test/` (the same code with `__RUVEE_TEST__` and host permission for
127.0.0.1, because automation cannot click a permission prompt) and runs the end-to-end flow in
Chromium against a throwaway API database. It needs the API and web export built.
