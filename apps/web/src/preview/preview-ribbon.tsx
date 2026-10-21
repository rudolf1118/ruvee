import { FIXTURE_MARKER } from './fixtures';

export function PreviewRibbon() {
  return (
    <div
      role="note"
      data-fixture={FIXTURE_MARKER}
      className="flex shrink-0 flex-wrap items-center gap-x-2.5 gap-y-1 bg-ribbon px-4 py-[7px] text-small text-white"
    >
      <span className="rounded-full bg-brand px-2 py-px font-bold">Development preview</span>
      <span>
        Synthetic data in memory only. Nothing is saved, encrypted or synced. Don&apos;t enter real
        information.
      </span>
    </div>
  );
}
