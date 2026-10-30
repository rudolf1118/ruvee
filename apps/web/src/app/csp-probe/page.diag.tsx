import { Probe } from '@/diagnostics/probe';

/**
 * Diagnostics-only route (`page.diag.tsx`). It exists only in `scripts/build-diagnostics.mjs`
 * builds, which export to `out-diagnostics/`; the ordinary export never contains it.
 */
export default function CspProbePage() {
  return (
    <main className="flex min-h-dvh items-center justify-center p-6">
      <section className="flex w-full max-w-[640px] flex-col gap-4 rounded-[18px] border border-line bg-surface p-8">
        <h1 className="text-heading leading-tight font-bold tracking-tight-title">CSP probe</h1>
        <p className="text-body text-ink-muted">
          Diagnostics build only. Loads <code className="font-mono">@ruvee/crypto</code> and{' '}
          <code className="font-mono">@serenity-kit/opaque</code> in workers under the production
          Content Security Policy. Synthetic data only.
        </p>
        <h2 className="text-body font-semibold">@ruvee/crypto</h2>
        <Probe name="crypto" />
        <h2 className="text-body font-semibold">@serenity-kit/opaque</h2>
        <Probe name="opaque" />
      </section>
    </main>
  );
}
