import './zod-config';
import { initRuveeCrypto } from '@ruvee/crypto';
import {
  createApi,
  DeviceStore,
  dispatch,
  errorPayload,
  refreshTokens,
  VaultEngine,
  VaultError,
  type OpaqueClient,
  type Transport,
} from '@ruvee/vault';
import * as opaque from '@serenity-kit/opaque';
import { fillPage, type FillResult } from './fill';
import { contentRequestSchema, INLINE_ORIGINS, inlineTarget } from './inline/gate';
import {
  requestSchema,
  type Candidates,
  type ExtensionRequest,
  type ExtensionResponse,
  type FillOutcome,
  type InlineSettings,
  type PairingView,
  type SetInlineResult,
  type SetServerResult,
  type Status,
} from './messages';
import { fillableOrigin, originMatches } from './origin';
import { accessToken, clearTokens, refreshToken, saveTokens } from './tokens';

/**
 * The extension's service worker: the only extension context that holds keys
 * (extension-design.md §1). Chrome stops it after ~30 s idle; while unlocked, `AK` waits in
 * `chrome.storage.session` and the next message resumes from it (D-27).
 */

/** D-02: the same OPAQUE configuration as the web app. */
const KEY_STRETCHING = 'memory-constrained' as const;
/** D-10: lock after 15 minutes without a message from the extension's pages. */
const AUTO_LOCK_MS = 15 * 60_000;
const SESSION_AK = 'ak';
const SESSION_ACTIVITY = 'lastActivityMs';
const LOCAL_SERVER = 'serverOrigin';
/** A join's secrets while this browser waits for approval (`VaultEngine.pairingJoinSnapshot`). */
const SESSION_JOIN = 'pairingJoin';
/** The error code that stopped the last join, for a popup opened after it stopped. */
const SESSION_JOIN_PROBLEM = 'pairingProblem';
const PAIRING_ALARM = 'pairing';
const PAIRING_POLL_MS = 2000;
/** A poll that failed with one of these is tried again; anything else stops the loop. */
const PAIRING_RETRY = new Set(['offline', 'proof_rejected', 'rate_limited', 'internal']);

const opaqueClient: OpaqueClient = {
  startRegistration: (password) => opaque.client.startRegistration({ password }),
  finishRegistration: (state, response, password) =>
    opaque.client.finishRegistration({
      clientRegistrationState: state,
      registrationResponse: response,
      password,
      keyStretching: KEY_STRETCHING,
    }).registrationRecord,
  startLogin: (password) => opaque.client.startLogin({ password }),
  finishLogin: (state, response, password) =>
    opaque.client.finishLogin({
      clientLoginState: state,
      loginResponse: response,
      password,
      keyStretching: KEY_STRETCHING,
    })?.finishLoginRequest,
};

const toB64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));
const fromB64 = (text: string) => Uint8Array.from(atob(text), (c) => c.charCodeAt(0));

async function serverOrigin(): Promise<string | null> {
  const stored = await chrome.storage.local.get(LOCAL_SERVER);
  const value = stored[LOCAL_SERVER];
  return typeof value === 'string' ? value : null;
}

function tokenTransport(origin: string): Transport {
  const base: Transport = {
    baseUrl: `${origin}/api/v1`,
    // Never the browser's cookies for this server: the API refuses cookie plus bearer.
    credentials: 'omit',
  };
  return {
    ...base,
    async authorization() {
      const token = await accessToken();
      return token ? `Bearer ${token}` : undefined;
    },
    async refresh() {
      const current = await refreshToken();
      if (!current) return false;
      try {
        await saveTokens(await refreshTokens(base, current));
        return true;
      } catch {
        await clearTokens();
        return false;
      }
    },
    onTokens: saveTokens,
  };
}

let engine: Promise<VaultEngine> | undefined;
/**
 * Bumped by every lock. Work that began before a lock (an unlock, a resume) must not store `AK`
 * again after it (review R19): the engine refuses to finish it, and this is checked as well.
 */
let lockGeneration = 0;

function getEngine(): Promise<VaultEngine> {
  if (engine) return engine;
  const starting = (async () => {
    const origin = await serverOrigin();
    if (!origin) throw new VaultError('offline');
    const [crypto] = await Promise.all([initRuveeCrypto(), opaque.ready]);
    const e = new VaultEngine({
      crypto,
      api: createApi(tokenTransport(origin)),
      store: await DeviceStore.open(),
      opaque: opaqueClient,
      origin,
      platform: 'extension',
      now: () => Date.now(),
      emit: (event) => {
        if (event.event === 'ended') void (event.reason === 'device_revoked' ? forget() : lock());
      },
    });
    // Back from a service-worker restart: resume the unlocked state if there is one (D-27).
    const generation = lockGeneration;
    const saved = (await chrome.storage.session.get(SESSION_AK))[SESSION_AK];
    if (typeof saved === 'string') {
      const ak = fromB64(saved);
      try {
        await e.resume({ accountKey: ak });
      } catch {
        await chrome.storage.session.remove(SESSION_AK);
      } finally {
        ak.fill(0);
      }
      // Locked while resuming: the resumed engine is discarded with everything it holds.
      if (generation !== lockGeneration) {
        e.wipeMemory();
        throw new VaultError('locked');
      }
    }
    // Back from a restart while waiting for approval: the join resumes (the password does not).
    const join = (await chrome.storage.session.get(SESSION_JOIN))[SESSION_JOIN];
    if (join !== undefined && !(await e.pairingJoinRestore(join)))
      await chrome.storage.session.remove(SESSION_JOIN);
    return e;
  })();
  engine = starting;
  // Only this attempt is forgotten; a lock may already have replaced it with a newer one.
  starting.catch(() => {
    if (engine === starting) engine = undefined;
  });
  return starting;
}

async function rememberUnlocked(e: VaultEngine, generation: number): Promise<void> {
  // A lock since the unlock began wins (R19): nothing is stored, the engine is wiped.
  if (generation !== lockGeneration) {
    e.wipeMemory();
    throw new VaultError('locked');
  }
  const ak = e.accountKeyForResume();
  try {
    await chrome.storage.session.set({ [SESSION_AK]: toB64(ak) });
  } finally {
    ak.fill(0);
  }
}

/** INV-15: drop `AK` everywhere it is held; the next message starts a locked engine. */
async function lock(): Promise<void> {
  lockGeneration++;
  await chrome.storage.session.remove([SESSION_AK, SESSION_JOIN]);
  await chrome.alarms.clear(PAIRING_ALARM);
  const current = engine;
  engine = undefined;
  if (current) (await current.catch(() => undefined))?.wipeMemory();
}

/** Lock, and drop this browser's tokens too: after logout or revocation they must not linger. */
async function forget(): Promise<void> {
  await lock();
  await clearTokens();
  await chrome.storage.session.remove(SESSION_JOIN_PROBLEM);
}

/**
 * D-10. Checked before every message as well as by the alarm: an alarm can be late (a suspended
 * worker, a sleeping laptop), and an unlock state that has expired must never be resumed.
 */
async function lockIfIdle(): Promise<void> {
  const last = (await chrome.storage.session.get(SESSION_ACTIVITY))[SESSION_ACTIVITY];
  if (typeof last !== 'number' || Date.now() - last >= AUTO_LOCK_MS) await lock();
}

async function isUnlocked(): Promise<boolean> {
  return typeof (await chrome.storage.session.get(SESSION_AK))[SESSION_AK] === 'string';
}

/** The tab's origin, read by the extension from `chrome.tabs`, never from the page. */
async function tabOrigin(tabId: number): Promise<string | null> {
  try {
    return fillableOrigin((await chrome.tabs.get(tabId)).url);
  } catch {
    return null;
  }
}

async function candidates(tabId: number): Promise<Candidates> {
  // The popup is open for this tab: a fallback badge from an inline click has done its job.
  await chrome.action.setBadgeText({ tabId, text: '' }).catch(() => undefined);
  const origin = await tabOrigin(tabId);
  if (!origin) return { origin: null, items: [] };
  const e = await getEngine();
  const items = e
    .items()
    .filter((i) => i.type === 'login' && !i.trashed && i.urls.some((u) => originMatches(u, origin)))
    .map((i) => ({ id: i.id, title: i.title, username: i.subtitle }));
  return { origin, items };
}

/** extension-design.md §4 steps 4 to 6. The password goes only into the page, never the popup. */
async function fill(tabId: number, itemId: string): Promise<FillOutcome> {
  const origin = await tabOrigin(tabId);
  if (!origin) return 'not_allowed';
  const e = await getEngine();
  let detail: ReturnType<VaultEngine['detail']>;
  try {
    detail = e.detail({ id: itemId });
  } catch (error) {
    // Deleted permanently on another device and synced since the popup listed it.
    if (error instanceof VaultError && error.code === 'not_found') return 'gone';
    throw error;
  }
  // In Trash (moved there on another device): not offered, and not filled either.
  if (detail.trashed) return 'gone';
  if (detail.type !== 'login' || !detail.urls.some((u) => originMatches(u, origin)))
    return 'not_allowed';
  const password = e.secret({ id: itemId });
  // Re-read the tab right before injecting; the page itself checks once more (fill.ts).
  if ((await tabOrigin(tabId)) !== origin) return 'origin_changed';
  const [result] = await chrome.scripting.executeScript<[string, string, string], FillResult>({
    target: { tabId, frameIds: [0] },
    func: fillPage,
    args: [origin, detail.username, password],
    world: 'ISOLATED',
  });
  const outcome = result?.result;
  return outcome === 'filled' || outcome === 'origin_changed' || outcome === 'no_password_field'
    ? outcome
    : 'not_allowed';
}

// ---- Pairing (device-enrollment §3, device B): the worker owns the join ----

/**
 * The popup closes whenever the user switches to the device that approves, so the join cannot
 * live in it. The worker keeps the join's secrets in `chrome.storage.session` (memory only, like
 * `AK`) to survive its own restart, and polls by itself until the join ends; a reopened popup
 * only reads where it stands.
 */
async function saveJoin(e: VaultEngine): Promise<void> {
  const snapshot = e.pairingJoinSnapshot();
  if (snapshot) {
    await chrome.storage.session.set({ [SESSION_JOIN]: snapshot });
    // Wakes a stopped worker to go on polling (Chrome's shortest period is 30 seconds).
    if (!(await chrome.alarms.get(PAIRING_ALARM)))
      await chrome.alarms.create(PAIRING_ALARM, { periodInMinutes: 0.5 });
  } else {
    await chrome.storage.session.remove(SESSION_JOIN);
    await chrome.alarms.clear(PAIRING_ALARM);
  }
}

async function setPairingProblem(code: string | null): Promise<void> {
  if (code === null) await chrome.storage.session.remove(SESSION_JOIN_PROBLEM);
  else await chrome.storage.session.set({ [SESSION_JOIN_PROBLEM]: code });
}

/** The approval arrived but the password is gone: no poll until the popup sends it. */
let awaitingPassword = false;
let pairingLoop: Promise<void> | undefined;

const pause = (ms: number) =>
  new Promise<void>((resolve) => {
    setTimeout(resolve, ms);
  });

/** One loop at a time. Each round's fetch and storage calls keep the worker alive meanwhile. */
function pollPairing(): void {
  if (pairingLoop || awaitingPassword) return;
  pairingLoop = (async () => {
    for (;;) {
      const generation = lockGeneration;
      const e = await getEngine();
      if (e.pairingJoinState().state !== 'joined') {
        await saveJoin(e);
        return;
      }
      try {
        const result = await e.pairingWait();
        await setPairingProblem(null);
        if (result.state === 'enrolled') {
          await rememberUnlocked(e, generation);
          await saveJoin(e);
          return;
        }
      } catch (error) {
        const code = errorPayload(error).code;
        await settleVaultError(code);
        if (code === 'password_required') awaitingPassword = true;
        else await setPairingProblem(code);
        await saveJoin(e);
        if (!PAIRING_RETRY.has(code)) return;
      }
      await pause(PAIRING_POLL_MS);
    }
  })()
    .catch(() => undefined)
    .finally(() => {
      pairingLoop = undefined;
    });
}

async function resumePairing(): Promise<void> {
  if ((await chrome.storage.session.get(SESSION_JOIN))[SESSION_JOIN] !== undefined) pollPairing();
}

async function pairingView(): Promise<PairingView> {
  const problem = (await chrome.storage.session.get(SESSION_JOIN_PROBLEM))[SESSION_JOIN_PROBLEM];
  const view = { problem: typeof problem === 'string' ? problem : null };
  if (await isUnlocked()) return { state: 'enrolled', needsPassword: false, problem: null };
  const join = (await getEngine()).pairingJoinState();
  if (join.state !== 'joined') return { ...view, state: 'none', needsPassword: false };
  pollPairing();
  return { ...view, state: 'joined', needsPassword: join.needsPassword };
}

/** Settle a lock or a removal before replying, so the page's next status read sees it. */
async function settleVaultError(code: string): Promise<void> {
  if (code === 'device_revoked') await forget();
  else if (code === 'session_expired') await lock();
}

async function setServer(text: string): Promise<SetServerResult> {
  const origin = fillableOrigin(text);
  if (!origin || origin !== text.replace(/\/+$/, '')) return 'not_an_origin';
  // A device already belongs to one server; it has to be forgotten before another is set.
  const existing = await serverOrigin();
  if (existing && existing !== origin) {
    const store = await DeviceStore.open();
    if (await store.device()) return 'device_exists';
  }
  // The options page asked for the permission; the worker only checks it was granted.
  if (!(await chrome.permissions.contains({ origins: [`${origin}/*`] }))) return 'no_permission';
  await lock();
  await chrome.storage.local.set({ [LOCAL_SERVER]: origin });
  return 'saved';
}

// ---- Inline icon (extension-inline-autofill.md, phase A: option I1) ----

const LOCAL_INLINE = 'inlineEnabled';
const INLINE_SCRIPT = 'ruvee-inline';

async function inlineEnabled(): Promise<boolean> {
  return (await chrome.storage.local.get(LOCAL_INLINE))[LOCAL_INLINE] === true;
}

/**
 * Makes the registered content script match the setting and the permission: registered only while
 * inline fill is on **and** the browser still grants the host permission. A permission withdrawn
 * from the browser's own settings turns inline fill off.
 */
async function reconcileInline(): Promise<void> {
  const granted = await chrome.permissions.contains({ origins: [...INLINE_ORIGINS] });
  const wanted = (await inlineEnabled()) && granted;
  if (!granted) await chrome.storage.local.remove(LOCAL_INLINE);
  const registered =
    (await chrome.scripting.getRegisteredContentScripts({ ids: [INLINE_SCRIPT] })).length > 0;
  if (wanted && !registered)
    await chrome.scripting.registerContentScripts([
      {
        id: INLINE_SCRIPT,
        js: ['content.js'],
        matches: [...INLINE_ORIGINS],
        allFrames: false,
        runAt: 'document_idle',
        world: 'ISOLATED',
        persistAcrossSessions: true,
      },
    ]);
  if (!wanted && registered)
    await chrome.scripting.unregisterContentScripts({ ids: [INLINE_SCRIPT] });
}

async function setInline(enabled: boolean): Promise<SetInlineResult> {
  // The options page asked for the permission in the user's click; the worker only checks it.
  if (enabled && !(await chrome.permissions.contains({ origins: [...INLINE_ORIGINS] })))
    return 'no_permission';
  if (enabled) await chrome.storage.local.set({ [LOCAL_INLINE]: true });
  else await chrome.storage.local.remove(LOCAL_INLINE);
  await reconcileInline();
  return 'saved';
}

let lastInlineOpen = 0;
const INLINE_OPEN_INTERVAL_MS = 1000;

/**
 * The user clicked the inline icon. Opens the toolbar popup, where the choice is made (§2, I1).
 * Nothing about the vault is read or returned: the reply is the same whatever the vault holds, so
 * the page learns nothing from it (§4). A content-script message never counts as activity for
 * auto-lock and never reaches the vault channel.
 */
async function inlineOpen(tabId: number, windowId: number | undefined, origin: string) {
  if (!(await inlineEnabled())) return;
  // The browser's view of the tab, read again: the page may have navigated since it sent this.
  const tab = await chrome.tabs.get(tabId).catch(() => undefined);
  if (!tab?.active || fillableOrigin(tab.url) !== origin) return;
  const now = Date.now();
  if (now - lastInlineOpen < INLINE_OPEN_INTERVAL_MS) return;
  lastInlineOpen = now;
  try {
    await chrome.action.openPopup(windowId === undefined ? undefined : { windowId });
  } catch {
    // No popup could be opened (an unfocused window, a browser without the API): mark the
    // toolbar button for this tab instead. The user opens it, as with manual fill.
    await chrome.action.setBadgeBackgroundColor({ tabId, color: '#6d4aff' });
    await chrome.action.setBadgeText({ tabId, text: '•' });
  }
}

async function handle(request: ExtensionRequest): Promise<unknown> {
  switch (request.kind) {
    case 'status': {
      const status: Status = { serverOrigin: await serverOrigin(), unlocked: await isUnlocked() };
      return status;
    }
    case 'setServer':
      return setServer(request.origin);
    case 'lock':
      await lock();
      return true;
    case 'candidates':
      return candidates(request.tabId);
    case 'fill':
      return fill(request.tabId, request.itemId);
    case 'pairing':
      return pairingView();
    case 'inlineSettings': {
      const settings: InlineSettings = { enabled: await inlineEnabled() };
      return settings;
    }
    case 'setInline':
      return setInline(request.enabled);
    case 'vault': {
      const generation = lockGeneration;
      const e = await getEngine();
      const pairing = ['login', 'pairingJoin', 'pairingWait'].includes(request.method);
      if (pairing) awaitingPassword = false;
      let result: unknown;
      try {
        result = await dispatch(e, request.method, request.params);
      } catch (error) {
        const code = errorPayload(error).code;
        await settleVaultError(code);
        if (pairing) {
          if (code === 'password_required') awaitingPassword = request.method === 'pairingWait';
          await saveJoin(e);
        }
        throw error;
      }
      if (pairing) {
        if (request.method !== 'pairingWait') await setPairingProblem(null);
        await saveJoin(e);
        pollPairing();
      }
      const enrolled =
        request.method === 'unlock' ||
        (request.method === 'pairingWait' &&
          (result as { state?: string } | undefined)?.state === 'enrolled');
      if (enrolled) await rememberUnlocked(e, generation);
      if (request.method === 'logout') await forget();
      // A sync that found the session gone reports it in its status rather than throwing.
      if (
        request.method === 'sync' &&
        (result as { state?: string } | undefined)?.state === 'session_expired'
      )
        await lock();
      return result;
    }
  }
}

/** Only this extension's own pages; content scripts and other extensions are dropped (E-03). */
function trusted(sender: chrome.runtime.MessageSender): boolean {
  return sender.id === chrome.runtime.id && sender.origin === self.location.origin;
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!trusted(sender)) {
    // The separate content-script channel: one message kind, an empty reply, no vault access.
    const target = inlineTarget(sender, chrome.runtime.id, self.location.origin);
    if (!target || !contentRequestSchema.safeParse(message).success) return undefined;
    inlineOpen(target.tabId, target.windowId, target.origin)
      .catch(() => undefined)
      .finally(() => {
        sendResponse(null);
      });
    return true;
  }
  const parsed = requestSchema.safeParse(message);
  if (!parsed.success) {
    sendResponse({ ok: false, code: 'internal' } satisfies ExtensionResponse);
    return undefined;
  }
  lockIfIdle()
    .then(() => chrome.storage.session.set({ [SESSION_ACTIVITY]: Date.now() }))
    .then(() => handle(parsed.data))
    .then(
      (result) => {
        sendResponse({ ok: true, result } satisfies ExtensionResponse);
      },
      (error: unknown) => {
        sendResponse({ ok: false, ...errorPayload(error) } satisfies ExtensionResponse);
      },
    );
  return true;
});

void chrome.storage.session.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' });
// Chrome's shortest alarm period is 30 seconds; the test build uses it so its test is quick.
void chrome.alarms.create('autolock', { periodInMinutes: __RUVEE_TEST__ ? 0.5 : 1 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'autolock') void lockIfIdle();
  if (alarm.name === PAIRING_ALARM) void resumePairing();
});
// A worker started again (by the pairing alarm, or any event) goes on with a stored join.
void resumePairing();
void reconcileInline().catch(() => undefined);
chrome.permissions.onRemoved.addListener(() => {
  void reconcileInline().catch(() => undefined);
});
