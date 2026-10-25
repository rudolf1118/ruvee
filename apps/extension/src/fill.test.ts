// @vitest-environment jsdom
import { fillPage } from './fill';

const ORIGIN = 'http://localhost:3000';

function page(html: string) {
  document.body.innerHTML = html;
  // jsdom lays nothing out; give every input a size so visibility depends on styles only.
  for (const el of Array.from(document.querySelectorAll('input')))
    el.getBoundingClientRect = () => ({ width: 100, height: 20 }) as DOMRect;
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
