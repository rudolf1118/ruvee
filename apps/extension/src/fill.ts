/**
 * The function injected into the page's top frame for one manual fill (extension-design.md §4).
 * `chrome.scripting` serializes it, so it must be self-contained: no imports, no closures. It
 * returns only a status, never page content.
 */
export type FillResult = 'filled' | 'origin_changed' | 'no_password_field' | 'not_top_frame';

export function fillPage(expectedOrigin: string, username: string, password: string): FillResult {
  // The page may have navigated after the extension checked the tab: check again, here.
  if (window.location.origin !== expectedOrigin) return 'origin_changed';
  if (window.top !== window) return 'not_top_frame';

  const visible = (el: HTMLInputElement) => {
    if (el.disabled || el.readOnly) return false;
    const style = window.getComputedStyle(el);
    if (style.display === 'none' || style.visibility === 'hidden' || Number(style.opacity) === 0)
      return false;
    const box = el.getBoundingClientRect();
    return box.width > 0 && box.height > 0;
  };
  const inputs = Array.from(document.querySelectorAll('input')).filter(visible);
  const passwordField = inputs.find((el) => el.type === 'password');
  if (!passwordField) return 'no_password_field';

  // The username goes into the nearest text or email field before the password, in the same form.
  const candidates = inputs.filter(
    (el) =>
      ['text', 'email', ''].includes(el.type) &&
      el.form === passwordField.form &&
      el.compareDocumentPosition(passwordField) === Node.DOCUMENT_POSITION_FOLLOWING,
  );
  const usernameField = candidates.at(-1);

  const set = (el: HTMLInputElement, value: string) => {
    el.focus();
    // The native setter, so frameworks that track the value see the change.
    // eslint-disable-next-line @typescript-eslint/unbound-method -- called with `el` as `this` below
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
    if (setter) setter.call(el, value);
    else el.value = value;
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  };
  if (usernameField && username !== '') set(usernameField, username);
  set(passwordField, password);
  return 'filled';
}
