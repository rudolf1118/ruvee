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

  // Review R18: a field is filled only if the user can see it. Its own style is not enough: an
  // ancestor can hide it (opacity, visibility, display), move it off screen, clip it to nothing
  // or cover it. Kept inline: the function is serialized and must not use module constants.
  const MIN_OPACITY = 0.5;
  const MIN_SIZE = 8;
  const onScreen = (box: DOMRect) => {
    const x = box.left + box.width / 2;
    const y = box.top + box.height / 2;
    return x >= 0 && y >= 0 && x < window.innerWidth && y < window.innerHeight;
  };
  // Follow-up review F-9: `filter: opacity()` fades like `opacity`; a clip path or the legacy
  // `clip` can cut a field away without changing its box; text in a transparent colour is
  // invisible however the box looks.
  const filterOpacity = (filter: string) => {
    let factor = 1;
    for (const m of filter.matchAll(/opacity\(\s*([\d.]+)(%?)\s*\)/g))
      factor *= Number(m[1]) / (m[2] === '%' ? 100 : 1);
    return factor;
  };
  const transparent = (color: string) =>
    color === 'transparent' || /^rgba\(.*,\s*0(\.0+)?\s*\)$/.test(color.replace(/\s+/g, ' '));
  const visible = (el: HTMLInputElement) => {
    if (el.disabled || el.readOnly) return false;
    if (transparent(window.getComputedStyle(el).color)) return false;
    let opacity = 1;
    for (let node: Element | null = el; node; node = node.parentElement) {
      const style = window.getComputedStyle(node);
      if (style.display === 'none' || style.visibility === 'hidden') return false;
      if (style.visibility === 'collapse') return false;
      const clipPath = style.getPropertyValue('clip-path');
      if (clipPath !== '' && clipPath !== 'none') return false;
      const clip = style.getPropertyValue('clip');
      if (clip !== '' && clip !== 'auto') return false;
      opacity *= style.opacity === '' ? 1 : Number(style.opacity);
      opacity *= filterOpacity(style.getPropertyValue('filter'));
    }
    if (!(opacity >= MIN_OPACITY)) return false;
    let box = el.getBoundingClientRect();
    if (box.width < MIN_SIZE || box.height < MIN_SIZE) return false;
    // A field below the fold is scrolled to; one placed outside the page stays outside.
    if (!onScreen(box)) {
      el.scrollIntoView({ block: 'center', inline: 'center' });
      box = el.getBoundingClientRect();
      if (!onScreen(box)) return false;
    }
    // The topmost element at its centre must be the field: not clipped away, not covered. An
    // overlay with `pointer-events: none` is invisible to hit testing (F-9), so for this one test
    // every element takes part, through a style sheet the page's mutation observers do not see.
    let sheet: CSSStyleSheet | undefined;
    if (typeof CSSStyleSheet !== 'undefined' && 'adoptedStyleSheets' in document) {
      sheet = new CSSStyleSheet();
      sheet.replaceSync('* { pointer-events: auto !important; }');
      document.adoptedStyleSheets = [...document.adoptedStyleSheets, sheet];
    }
    try {
      const hit = document.elementFromPoint(box.left + box.width / 2, box.top + box.height / 2);
      return hit !== null && (hit === el || el.contains(hit));
    } finally {
      if (sheet)
        document.adoptedStyleSheets = document.adoptedStyleSheets.filter((s) => s !== sheet);
    }
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
