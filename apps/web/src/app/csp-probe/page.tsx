import { Probe } from '@/csp-probe/probe';

export default function CspProbePage() {
  return (
    <main className="flex min-h-dvh items-center justify-center p-6">
      <section className="flex w-full max-w-[520px] flex-col gap-4 rounded-[18px] border border-line bg-surface p-8">
        <h1 className="text-heading leading-tight font-bold tracking-tight-title">CSP probe</h1>
        <p className="text-body text-ink-muted">
          Development spike. Loads <code className="font-mono">@ruvee/crypto</code> in a worker
          under the production Content Security Policy. Synthetic data only.
        </p>
        <Probe />
      </section>
    </main>
  );
}
