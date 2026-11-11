/** How long a copied secret stays on the clipboard (sync-protocol §Memory and lock, T-26). */
export const CLIPBOARD_CLEAR_MS = 30_000;

let lastCopy: { timer: ReturnType<typeof setTimeout> } | null = null;

/**
 * Copies a value and clears the clipboard after 30 seconds. Browsers do not let a page check
 * what the clipboard holds without a permission prompt, so clearing is best effort: it may
 * overwrite something the user copied since, and it fails silently if the page lost focus.
 */
export async function copySecret(value: string): Promise<void> {
  await navigator.clipboard.writeText(value);
  if (lastCopy) clearTimeout(lastCopy.timer);
  lastCopy = {
    timer: setTimeout(() => {
      void clearClipboard();
    }, CLIPBOARD_CLEAR_MS),
  };
}

/** Called when the vault locks, if Ruvee copied something. */
export async function clearClipboard(): Promise<void> {
  if (!lastCopy) return;
  clearTimeout(lastCopy.timer);
  lastCopy = null;
  try {
    await navigator.clipboard.writeText('');
  } catch {
    // The page may not have focus; nothing more can be done from here.
  }
}
