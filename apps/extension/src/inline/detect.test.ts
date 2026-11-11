// @vitest-environment jsdom
import { inlineFields } from './detect';

const ids = () => inlineFields(document).map((el) => el.id);

describe('fields that get the inline icon', () => {
  it('marks a password field and the username field before it in the same form', () => {
    document.body.innerHTML = `<form><input id="search" type="search">
      <input id="user" type="email"><input id="pw" type="password"></form>`;
    expect(ids().sort()).toEqual(['pw', 'user']);
  });

  it('marks nothing on a page without a password field', () => {
    document.body.innerHTML = `<form><input id="q" type="text"><input id="mail" type="email"></form>`;
    expect(ids()).toEqual([]);
  });

  it('marks both password fields of a sign-up or change-password form', () => {
    document.body.innerHTML = `<form><input id="user" type="text">
      <input id="pw" type="password" autocomplete="new-password">
      <input id="again" type="password" autocomplete="new-password"></form>`;
    expect(ids().sort()).toEqual(['again', 'pw', 'user']);
  });

  it('does not take a username field from another form', () => {
    document.body.innerHTML = `<form><input id="newsletter" type="email"></form>
      <form><input id="pw" type="password"></form>`;
    expect(ids()).toEqual(['pw']);
  });

  it('skips disabled and read-only fields', () => {
    document.body.innerHTML = `<form><input id="user" type="text" readonly>
      <input id="pw" type="password" disabled></form>`;
    expect(ids()).toEqual([]);
  });

  it('skips fields in shadow roots and frames, which a fill never reaches', () => {
    document.body.innerHTML = `<div id="host"></div><iframe srcdoc="<input type=password>"></iframe>`;
    const host = document.getElementById('host');
    const root = host?.attachShadow({ mode: 'open' });
    if (root) root.innerHTML = `<input id="shadow-pw" type="password">`;
    expect(ids()).toEqual([]);
  });
});
