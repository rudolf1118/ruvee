// @vitest-environment jsdom
import { captureFrom, submitControl } from './capture';

const el = (id: string) => {
  const found = document.getElementById(id);
  if (!found) throw new Error(id);
  return found;
};

function form(html: string, values: Record<string, string>) {
  document.body.innerHTML = html;
  for (const [id, value] of Object.entries(values)) (el(id) as HTMLInputElement).value = value;
}

describe('what a sign-in submits (phase B)', () => {
  it('takes the password and the username field before it, in the submitted form', () => {
    form(
      `<form><input id="q" type="search"><input id="user" type="email"><input id="pw" type="password"><button id="go">Sign in</button></form>`,
      { q: 'shoes', user: ' someone@mail.example ', pw: 'synthetic-pw' },
    );
    expect(captureFrom(el('go'))).toEqual({
      username: 'someone@mail.example',
      password: 'synthetic-pw',
    });
  });

  it('takes nothing from another form on the page', () => {
    form(
      `<form><input id="news" type="email"><input id="other-pw" type="password"></form>
       <form><input id="user" type="text"><input id="pw" type="password"><button id="go"></button></form>`,
      { news: 'news@mail.example', 'other-pw': 'other-secret', user: 'me', pw: 'mine' },
    );
    expect(captureFrom(el('go'))).toEqual({ username: 'me', password: 'mine' });
  });

  it('offers nothing without a password, or with two different ones (a change: phase C)', () => {
    form(
      `<form><input id="user" type="text"><input id="pw" type="password"><button id="go"></button></form>`,
      {
        user: 'me',
      },
    );
    expect(captureFrom(el('go'))).toBeNull();
    form(
      `<form><input id="old" type="password"><input id="new" type="password"><button id="go"></button></form>`,
      { old: 'old-secret', new: 'new-secret' },
    );
    expect(captureFrom(el('go'))).toBeNull();
  });

  it('accepts a sign-up form whose two password fields agree', () => {
    form(
      `<form><input id="user" type="email"><input id="pw" type="password"><input id="again" type="password"><button id="go"></button></form>`,
      { user: 'new@mail.example', pw: 'fresh-secret', again: 'fresh-secret' },
    );
    expect(captureFrom(el('go'))).toEqual({
      username: 'new@mail.example',
      password: 'fresh-secret',
    });
  });

  it('works for fields in no form, ignoring fields that are in one', () => {
    form(
      `<form><input id="in-form" type="password"></form>
       <div><input id="user" type="text"><input id="pw" type="password"><div id="go" role="button">Log in</div></div>`,
      { 'in-form': 'form-secret', user: 'me', pw: 'loose-secret' },
    );
    expect(captureFrom(el('go'))).toEqual({ username: 'me', password: 'loose-secret' });
  });

  it('refuses values longer than an item can hold', () => {
    form(`<form><input id="pw" type="password"><button id="go"></button></form>`, {
      pw: 'x'.repeat(1025),
    });
    expect(captureFrom(el('go'))).toBeNull();
  });
});

describe('which clicks count as submitting', () => {
  it('a submit button or input in a form, and its content', () => {
    document.body.innerHTML = `<form><button id="b"><span id="label">Sign in</span></button>
      <input id="s" type="submit"><input id="img" type="image">
      <button id="plain" type="button">Show</button><button id="reset" type="reset"></button>
      <input id="text" type="text"><div id="role" role="button"></div></form>`;
    expect(submitControl(el('label'))?.id).toBe('b');
    expect(submitControl(el('s'))?.id).toBe('s');
    expect(submitControl(el('img'))?.id).toBe('img');
    for (const id of ['plain', 'reset', 'text', 'role'])
      expect(submitControl(el(id)), id).toBeNull();
  });

  it('any button outside a form (pages that sign in with a script)', () => {
    document.body.innerHTML = `<button id="b" type="button">Continue</button>
      <input id="i" type="button"><div id="r" role="button"></div><p id="p"></p>`;
    expect(submitControl(el('b'))?.id).toBe('b');
    expect(submitControl(el('i'))?.id).toBe('i');
    expect(submitControl(el('r'))?.id).toBe('r');
    expect(submitControl(el('p'))).toBeNull();
    expect(submitControl(null)).toBeNull();
  });
});
