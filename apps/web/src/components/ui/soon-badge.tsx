/**
 * Dashed "Soon" marker the design uses for features that are not built yet.
 * Visual only: pair it with screen reader text such as "(not available yet)".
 */
export function SoonBadge() {
  return (
    <span
      aria-hidden="true"
      className="inline-flex h-[18px] shrink-0 items-center rounded-full border border-dashed border-line-dashed bg-canvas px-1.5 text-[11px] font-medium text-ink-muted"
    >
      Soon
    </span>
  );
}
