/**
 * Which fields get the inline icon (extension-inline-autofill.md §5.1, phase A). The same fields
 * the fill function would consider (fill.ts): password inputs in the top document, and the
 * nearest text or email input before each one in the same form. Fields inside shadow roots or
 * frames are skipped, because a fill never reaches them. Layout is not looked at here; the
 * content script hides an icon whose field is not on screen.
 */
export function inlineFields(doc: Document): HTMLInputElement[] {
  const inputs = Array.from(doc.querySelectorAll('input')).filter(
    (el) => !el.disabled && !el.readOnly,
  );
  const fields = new Set<HTMLInputElement>();
  for (const password of inputs.filter((el) => el.type === 'password')) {
    fields.add(password);
    const username = inputs
      .filter(
        (el) =>
          ['text', 'email', ''].includes(el.type) &&
          el.form === password.form &&
          el.compareDocumentPosition(password) === Node.DOCUMENT_POSITION_FOLLOWING,
      )
      .at(-1);
    if (username) fields.add(username);
  }
  return [...fields];
}
