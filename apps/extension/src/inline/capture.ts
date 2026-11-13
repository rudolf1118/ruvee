/**
 * What a sign-in gesture submits (extension-inline-autofill.md §5.2, phase B). Called by the
 * content script on the user's own click on a submit control, or Enter in a field. Not on the
 * `submit` event: a page's `requestSubmit()` or `button.click()` fires a submit event that
 * Chrome marks as trusted, so it proves nothing about the user.
 *
 * The scope is the form of the element the user acted on, or the whole document when it is in
 * no form. A capture needs one non-empty password; several different passwords (a change of
 * password) are left to phase C, so nothing is captured.
 */

/** Item limits (packages/vault item-schema): a longer value could not be saved anyway. */
export const CAPTURE_LIMITS = { username: 500, password: 1024 } as const;

export interface Capture {
  readonly username: string;
  readonly password: string;
}

const SUBMIT_INPUT_TYPES = new Set(['submit', 'image']);

/** The control the user clicked, if it submits: a submit button in a form, any button outside one. */
export function submitControl(target: EventTarget | null): HTMLElement | null {
  if (!(target instanceof Element)) return null;
  const control = target.closest<HTMLElement>('button, input, [role="button"]');
  if (!control) return null;
  if (control instanceof HTMLButtonElement)
    return control.type === 'submit' || !control.form ? control : null;
  if (control instanceof HTMLInputElement)
    return SUBMIT_INPUT_TYPES.has(control.type) || (control.type === 'button' && !control.form)
      ? control
      : null;
  return control.closest('form') ? null : control;
}

function scopeOf(el: Element): ParentNode {
  const form = el instanceof HTMLInputElement || el instanceof HTMLButtonElement ? el.form : null;
  return form ?? el.closest('form') ?? el.ownerDocument;
}

/** The username and password in the scope of `el`, or null when there is nothing to offer. */
export function captureFrom(el: Element): Capture | null {
  const scope = scopeOf(el);
  const inputs = Array.from(scope.querySelectorAll('input')).filter(
    (i) => !i.disabled && (scope !== i.ownerDocument || !i.form),
  );
  const passwords = inputs.filter((i) => i.type === 'password' && i.value !== '');
  const first = passwords[0];
  if (!first) return null;
  if (passwords.some((p) => p.value !== first.value)) return null;
  const username =
    inputs
      .filter(
        (i) =>
          ['text', 'email', ''].includes(i.type) &&
          i.compareDocumentPosition(first) === Node.DOCUMENT_POSITION_FOLLOWING,
      )
      .at(-1)
      ?.value.trim() ?? '';
  if (first.value.length > CAPTURE_LIMITS.password || username.length > CAPTURE_LIMITS.username)
    return null;
  return { username, password: first.value };
}
