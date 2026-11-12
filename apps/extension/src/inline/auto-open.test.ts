import {
  AUTO_OPEN_ANY_MS,
  AUTO_OPEN_PER_TAB_MS,
  shouldAutoOpen,
  type AutoOpenState,
} from './auto-open';

const NOW = 10_000_000;
const base: AutoOpenState = {
  enabled: true,
  nowMs: NOW,
  lastAnyMs: undefined,
  lastForTabMs: undefined,
  tabActive: true,
  windowFocused: true,
};

describe('opening the popup by itself for a save offer', () => {
  it('opens for a new capture in the active tab of the focused window', () => {
    expect(shouldAutoOpen(base)).toBe(true);
  });

  it('never when the user turned it off', () => {
    expect(shouldAutoOpen({ ...base, enabled: false })).toBe(false);
  });

  it('never for a tab that is not in front, or a window without focus (the badge is the offer)', () => {
    // Chromium would open the popup for whichever tab is active, not the capture's.
    expect(shouldAutoOpen({ ...base, tabActive: false })).toBe(false);
    expect(shouldAutoOpen({ ...base, windowFocused: false })).toBe(false);
  });

  it('once per tab while a capture can live, however often the page makes the user submit', () => {
    expect(shouldAutoOpen({ ...base, lastForTabMs: NOW - 1 })).toBe(false);
    expect(shouldAutoOpen({ ...base, lastForTabMs: NOW - AUTO_OPEN_PER_TAB_MS + 1 })).toBe(false);
    expect(shouldAutoOpen({ ...base, lastForTabMs: NOW - AUTO_OPEN_PER_TAB_MS })).toBe(true);
  });

  it('at most once per interval across all tabs', () => {
    expect(shouldAutoOpen({ ...base, lastAnyMs: NOW - AUTO_OPEN_ANY_MS + 1 })).toBe(false);
    expect(shouldAutoOpen({ ...base, lastAnyMs: NOW - AUTO_OPEN_ANY_MS })).toBe(true);
    expect(AUTO_OPEN_ANY_MS).toBe(30_000);
  });
});
