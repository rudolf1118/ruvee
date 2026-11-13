// @vitest-environment jsdom

/**
 * The inline content script on a page (extension-inline-autofill.md §4, §5.1). jsdom cannot make
 * a trusted click, so the click that opens the popup is covered by the browser test; here: what the
 * page can and cannot reach, and that the script asks the worker nothing on its own.
 */

const sendMessage = vi.fn(() => Promise.resolve(null));
const shadowRoots: ShadowRoot[] = [];

beforeAll(async () => {
  vi.stubGlobal('chrome', { runtime: { sendMessage } });
  // jsdom has neither layout nor `checkVisibility`; every field gets a usable box.
  HTMLElement.prototype.checkVisibility = () => true;
  HTMLElement.prototype.getBoundingClientRect = () =>
    ({ left: 10, top: 10, right: 210, bottom: 40, width: 200, height: 30 }) as DOMRect;
  // Only to reach the closed shadow root from this test, as the page never can.
  const attach = Object.getOwnPropertyDescriptor(Element.prototype, 'attachShadow')?.value as (
    this: Element,
    init: ShadowRootInit,
  ) => ShadowRoot;
  HTMLElement.prototype.attachShadow = function (init) {
    const root = attach.call(this, init);
    shadowRoots.push(root);
    return root;
  };
  document.body.innerHTML = `<form><input id="user" type="email"><input id="pw" type="password"></form>`;
  await import('./content');
});

const hosts = () => Array.from(document.querySelectorAll('ruvee-inline-icon'));

describe('the inline content script', () => {
  it('puts one icon on the password field and one on the username field', () => {
    expect(hosts()).toHaveLength(2);
    expect(shadowRoots).toHaveLength(2);
  });

  it('keeps its button out of the page’s reach (closed shadow root)', () => {
    for (const host of hosts()) expect(host.shadowRoot).toBeNull();
  });

  it('asks the worker nothing on its own: no state, no matches, no origin', () => {
    expect(sendMessage).not.toHaveBeenCalled();
  });

  it('ignores clicks the page makes (untrusted events), on the icon or its button', () => {
    for (const host of hosts()) host.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    for (const root of shadowRoots) root.querySelector('button')?.click();
    expect(sendMessage).not.toHaveBeenCalled();
  });

  it('puts the icon back after the page removes it, and removes it with the field', async () => {
    hosts()[0]?.remove();
    document.body.append(document.createElement('div'));
    await vi.waitFor(() => {
      expect(hosts()).toHaveLength(2);
    });
    document.querySelector('form')?.remove();
    await vi.waitFor(() => {
      expect(hosts()).toHaveLength(0);
    });
  });
});
