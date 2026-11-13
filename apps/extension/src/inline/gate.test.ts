import { requestSchema } from '../messages';
import { contentRequestSchema, inlineTarget, type InlineSender } from './gate';

const ID = 'ikjjmgfofphmclnkphkceboclijkfkbd';
const EXT = `chrome-extension://${ID}`;
const PAGE = 'https://login.example';

type Over = { [K in keyof InlineSender]?: InlineSender[K] | undefined };
/** Chrome leaves a field out when it does not apply; `undefined` here means "left out". */
const sender = (over: Over = {}): InlineSender => {
  const s: Record<string, unknown> = {
    id: ID,
    origin: PAGE,
    frameId: 0,
    tab: { id: 7, url: `${PAGE}/sign-in?next=/`, windowId: 3 },
    ...over,
  };
  return Object.fromEntries(Object.entries(s).filter(([, v]) => v !== undefined));
};

describe('the inline channel: who may ask to open the popup (E-15, E-20)', () => {
  it('accepts this extension’s content script in the top frame of a fillable page', () => {
    expect(inlineTarget(sender(), ID, EXT)).toEqual({ tabId: 7, windowId: 3, origin: PAGE });
  });

  it('refuses another extension, and this extension’s own pages', () => {
    expect(inlineTarget(sender({ id: 'otherextensionid' }), ID, EXT)).toBeNull();
    expect(inlineTarget(sender({ origin: EXT }), ID, EXT)).toBeNull();
    expect(inlineTarget(sender({ origin: undefined }), ID, EXT)).toBeNull();
  });

  it('refuses every frame but the top one, even of the same origin', () => {
    expect(inlineTarget(sender({ frameId: 3 }), ID, EXT)).toBeNull();
    expect(inlineTarget(sender({ frameId: undefined }), ID, EXT)).toBeNull();
  });

  it('refuses a sender whose origin is not the tab’s (a framed page, a navigation)', () => {
    expect(
      inlineTarget(sender({ tab: { id: 7, url: 'https://other.example/', windowId: 3 } }), ID, EXT),
    ).toBeNull();
    expect(
      inlineTarget(
        sender({ tab: { id: 7, url: 'https://login.example:8443/', windowId: 3 } }),
        ID,
        EXT,
      ),
    ).toBeNull();
  });

  it('refuses pages that are never filled: plain HTTP, URLs with credentials, no tab', () => {
    expect(
      inlineTarget(
        sender({ origin: 'http://login.example', tab: { id: 7, url: 'http://login.example/' } }),
        ID,
        EXT,
      ),
    ).toBeNull();
    expect(
      inlineTarget(sender({ tab: { id: 7, url: 'https://user:pw@login.example/' } }), ID, EXT),
    ).toBeNull();
    expect(inlineTarget(sender({ tab: undefined }), ID, EXT)).toBeNull();
    expect(inlineTarget(sender({ tab: { url: `${PAGE}/` } }), ID, EXT)).toBeNull();
  });
});

describe('the inline message schema', () => {
  it('has two messages: open (empty) and capture (username and password only)', () => {
    expect(contentRequestSchema.safeParse({ kind: 'inlineOpen' }).success).toBe(true);
    const capture = { kind: 'inlineCapture', username: 'me', password: 'synthetic-pw' };
    expect(contentRequestSchema.safeParse(capture).success).toBe(true);
    expect(contentRequestSchema.safeParse({ ...capture, username: '' }).success).toBe(true);
    for (const forged of [
      // E-17: the origin, tab or item of a save always comes from the browser, never the page.
      { ...capture, origin: 'https://bank.example' },
      { ...capture, url: 'https://bank.example/login' },
      { ...capture, tabId: 7 },
      { ...capture, itemId: '00000000-0000-4000-8000-000000000000' },
      { ...capture, password: '' },
      { ...capture, password: 'x'.repeat(1025) },
      { ...capture, username: 'x'.repeat(501) },
      { kind: 'inlineCapture', password: 'synthetic-pw' },
    ])
      expect(contentRequestSchema.safeParse(forged).success, JSON.stringify(forged)).toBe(false);
    for (const forged of [
      { kind: 'inlineOpen', origin: PAGE },
      { kind: 'inlineOpen', tabId: 7 },
      { kind: 'fill', tabId: 7, itemId: '00000000-0000-4000-8000-000000000000' },
      { kind: 'candidates', tabId: 7 },
      { kind: 'vault', method: 'phase' },
      { kind: 'vault', method: 'unlock', params: { password: 'x' } },
      { kind: 'setInline', enabled: true },
      { kind: 'lock' },
      'inlineOpen',
      null,
    ])
      expect(contentRequestSchema.safeParse(forged).success, JSON.stringify(forged)).toBe(false);
  });

  it('is not part of the extension pages’ channel, and theirs is not part of it', () => {
    expect(requestSchema.safeParse({ kind: 'inlineOpen' }).success).toBe(false);
    expect(
      requestSchema.safeParse({ kind: 'inlineCapture', username: 'me', password: 'pw' }).success,
    ).toBe(false);
    for (const kind of ['pendingSave', 'savePending', 'dismissPending'])
      expect(contentRequestSchema.safeParse({ kind, tabId: 7 }).success, kind).toBe(false);
    expect(contentRequestSchema.safeParse({ kind: 'status' }).success).toBe(false);
  });
});
