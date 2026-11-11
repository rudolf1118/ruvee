import { Logo } from '@/components/ui/logo';

export default function NotFoundPage() {
  return (
    <main className="flex min-h-dvh items-center justify-center p-6">
      <section className="flex w-full max-w-[520px] flex-col gap-5 rounded-[18px] border border-line bg-surface p-8">
        <Logo />
        <div className="flex flex-col gap-2">
          <h1 className="text-heading leading-tight font-bold tracking-tight-title">
            Page not found
          </h1>
          <p className="text-body-lg text-ink-muted">That address is not part of this build.</p>
        </div>
      </section>
    </main>
  );
}
