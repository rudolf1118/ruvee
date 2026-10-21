import Link from 'next/link';
import { Logo } from '@/components/ui/logo';

const showPreviewLink = process.env.NODE_ENV !== 'production';

export default function HomePage() {
  return (
    <main className="flex min-h-dvh items-center justify-center p-6">
      <section className="flex w-full max-w-[520px] flex-col gap-5 rounded-[18px] border border-line bg-surface p-8">
        <Logo />
        <div className="flex flex-col gap-2">
          <h1 className="text-heading leading-tight font-bold tracking-tight-title">
            Ruvee is in early development
          </h1>
          <p className="text-body-lg text-ink-muted">
            This build contains the project foundation only. There is no working vault, account,
            encryption or sync yet, so don&apos;t use it to store anything.
          </p>
        </div>
        {showPreviewLink ? (
          <Link
            href="/preview"
            className="inline-flex h-10 items-center justify-center self-start rounded-control border border-brand bg-brand px-4 font-semibold text-white hover:border-brand-hover hover:bg-brand-hover"
          >
            Open the interface preview
          </Link>
        ) : null}
      </section>
    </main>
  );
}
