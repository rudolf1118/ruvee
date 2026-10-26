// @vitest-environment jsdom
import { fillPage } from './fill';

const ORIGIN = 'http://localhost:3000';

const box = (left: number, top: number, width = 100, height = 20) =>
  ({ left, top, width, height }) as DOMRect;

/**
 * jsdom lays nothing out: every input gets its own box in a column, and the hit test returns the
 * input whose box holds the point, unless a test says what is on top.
 */
function page(html: string, onTop?: (x: number, y: number) => Element | null) {
  document.body.innerHTML = html;
  const inputs = Array.from(document.querySelectorAll('input'));
  inputs.forEach((el, n) => {
    el.getBoundingClientRect = () => box(10, 10 + n * 30);
  });
  Element.prototype.scrollIntoView = () => undefined;
  document.elementFromPoint = (x: number, y: number) =>
    onTop
      ? onTop(x, y)
      : (inputs.find((el) => {
          const b = el.getBoundingClientRect();
          return x >= b.left && x < b.left + b.width && y >= b.top && y < b.top + b.height;
        }) ?? null);
}

const value = (id: string) => (document.getElementById(id) as HTMLInputElement).value;

describe('the injected fill function', () => {
  it('fills the password and the username field before it, without submitting', () => {
    page(`<form onsubmit="throw new Error('submitted')">
      <input id="search" type="search">
      <input id="user" type="email"><input id="pw" type="password"></form>`);
    const events: string[] = [];
    document.getElementById('pw')?.addEventListener('input', () => events.push('input'));
    expect(fillPage(ORIGIN, 'someone@mail.example', 'synthetic-pw')).toBe('filled');
    expect(value('user')).toBe('someone@mail.example');
    expect(value('pw')).toBe('synthetic-pw');
    expect(value('search')).toBe('');
    expect(events).toEqual(['input']);
  });

  it('refuses when the page origin is not the one the extension checked', () => {
    page('<input id="pw" type="password">');
    expect(fillPage('https://mail.example', 'u', 'synthetic-pw')).toBe('origin_changed');
    expect(value('pw')).toBe('');
  });

  it('skips hidden, disabled and read-only fields, and fields of another form', () => {
    page(`
      <form><input id="other-user" type="text"></form>
      <form>
        <input id="hidden-pw" type="password" style="display:none">
        <input id="faded-pw" type="password" style="opacity:0">
        <input id="ro-pw" type="password" readonly>
        <input id="user" type="text"><input id="pw" type="password">
      </form>`);
    expect(fillPage(ORIGIN, 'someone', 'synthetic-pw')).toBe('filled');
    for (const id of ['hidden-pw', 'faded-pw', 'ro-pw', 'other-user']) expect(value(id)).toBe('');
    expect(value('pw')).toBe('synthetic-pw');
    expect(value('user')).toBe('someone');
  });

  it('REVIEW R18 (regression): skips fields hidden by an ancestor, off screen, tiny or covered', () => {
    page(`<form>
      <div style="opacity:0"><input id="ancestor-faded" type="password"></div>
      <div style="opacity:0.3"><div style="opacity:0.9"><input id="mostly-faded" type="password"></div></div>
      <div style="visibility:hidden"><input id="ancestor-hidden" type="password"></div>
      <input id="tiny" type="password"><input id="offscreen" type="password">
      <input id="covered" type="password"></form>`);
    const el = (id: string) => document.getElementById(id) as HTMLInputElement;
    el('tiny').getBoundingClientRect = () => box(10, 200, 1, 1);
    el('offscreen').getBoundingClientRect = () => box(-9999, 230);
    // Something else is on top of this one at its centre (an overlay, or a clipping ancestor).
    const overlay = document.createElement('div');
    const hit = document.elementFromPoint.bind(document);
    document.elementFromPoint = (x, y) => {
      const under = hit(x, y);
      return under === el('covered') ? overlay : under;
    };
    // Before: every one of these was filled.
    expect(fillPage(ORIGIN, 'u', 'synthetic-pw')).toBe('no_password_field');
    for (const id of [
      'ancestor-faded',
      'mostly-faded',
      'ancestor-hidden',
      'tiny',
      'offscreen',
      'covered',
    ])
      expect(value(id), id).toBe('');
  });

  it('fills a visible field next to hidden decoys, and refuses when nothing is on top', () => {
    page(`<form><div style="opacity:0"><input id="decoy" type="password"></div>
      <input id="pw" type="password"></form>`);
    expect(fillPage(ORIGIN, '', 'synthetic-pw')).toBe('filled');
    expect(value('decoy')).toBe('');
    expect(value('pw')).toBe('synthetic-pw');
    page('<input id="pw" type="password">', () => null);
    expect(fillPage(ORIGIN, '', 'synthetic-pw')).toBe('no_password_field');
  });

  it('reports a page without a usable password field', () => {
    page('<input type="text"><input type="password" disabled>');
    expect(fillPage(ORIGIN, 'u', 'synthetic-pw')).toBe('no_password_field');
  });

  it('uses no outside references, so it survives serialization', () => {
    const source = fillPage.toString();
    // Rebuilt from its source alone, as chrome.scripting does, it still works.
    // eslint-disable-next-line @typescript-eslint/no-implied-eval, @typescript-eslint/no-unsafe-call -- test-only stand-in for chrome.scripting's serialization
    const rebuilt = new Function(`return (${source})`)() as typeof fillPage;
    page('<input id="pw" type="password">');
    expect(rebuilt(ORIGIN, '', 'synthetic-pw')).toBe('filled');
    expect(value('pw')).toBe('synthetic-pw');
  });
});
