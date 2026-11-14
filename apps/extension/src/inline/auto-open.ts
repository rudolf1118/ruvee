/**
 * When the worker opens the popup by itself to offer saving a login (extension-inline-autofill.md
 * §5.2a). The popup is browser UI the page cannot draw over (option I1); this only decides
 * whether to call `chrome.action.openPopup()` or to leave the "+" badge alone.
 *
 * Spike, Chromium 156 (2026-11-12): with no user gesture the popup opens when the target window is
 * focused; it fails when a popup is already open, when another window is focused or the window is
 * minimized. If the capture's tab is not the active one, it opens for whichever tab is, so that
 * case is refused here. Versions before 156 were not tried.
 */

/** At most one automatic popup per tab while its capture can live (CAPTURE_TTL_MS). */
export const AUTO_OPEN_PER_TAB_MS = 5 * 60_000;
/** And at most one in the whole browser per this interval, however many tabs sign in. */
export const AUTO_OPEN_ANY_MS = __RUVEE_TEST__ ? 3_000 : 30_000;

export interface AutoOpenState {
  /** The user's setting (options page); off unless turned on. */
  readonly enabled: boolean;
  readonly nowMs: number;
  /** When the popup was last opened by itself, in any tab; undefined if never. */
  readonly lastAnyMs: number | undefined;
  /** When it was last opened by itself for this tab; undefined if never. */
  readonly lastForTabMs: number | undefined;
  /** The capture's tab is the active tab of its window. */
  readonly tabActive: boolean;
  /** That window is the focused one. */
  readonly windowFocused: boolean;
}

/** Why the popup is or is not opened by itself; recorded for hand checks (§8.3). */
export type AutoOpenDecision =
  'open' | 'off' | 'tab_not_active' | 'window_not_focused' | 'limit_any' | 'limit_tab';

export function autoOpenDecision(s: AutoOpenState): AutoOpenDecision {
  if (!s.enabled) return 'off';
  if (!s.tabActive) return 'tab_not_active';
  if (!s.windowFocused) return 'window_not_focused';
  if (s.lastAnyMs !== undefined && s.nowMs - s.lastAnyMs < AUTO_OPEN_ANY_MS) return 'limit_any';
  if (s.lastForTabMs !== undefined && s.nowMs - s.lastForTabMs < AUTO_OPEN_PER_TAB_MS)
    return 'limit_tab';
  return 'open';
}

export function shouldAutoOpen(s: AutoOpenState): boolean {
  return autoOpenDecision(s) === 'open';
}
