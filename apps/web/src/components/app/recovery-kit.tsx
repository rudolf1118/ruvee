import type { RecoveryKitView } from '@ruvee/vault';
import { Button } from '../ui/button';

/** The Recovery Kit as shown once at setup and after every recovery (account-recovery.md §2). */
export function RecoveryKitPanel({ kit, onSaved }: { kit: RecoveryKitView; onSaved: () => void }) {
  return (
    <>
      <div className="flex flex-col gap-3 rounded-menu border border-line bg-canvas p-4">
        <div className="text-label font-semibold text-ink-muted">Recovery Key</div>
        <div data-testid="recovery-key" className="font-mono text-body-lg break-words select-all">
          {kit.recoveryKey}
        </div>
        <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-small">
          <dt className="text-ink-muted">Username</dt>
          <dd>{kit.username}</dd>
          <dt className="text-ink-muted">Server</dt>
          <dd className="break-all">{kit.serverOrigin}</dd>
          <dt className="text-ink-muted">Created</dt>
          <dd>{new Date(kit.createdAtMs).toLocaleString()}</dd>
          <dt className="text-ink-muted">Kit id</dt>
          <dd className="font-mono">{kit.recoveryKeyIdShort}</dd>
        </dl>
      </div>
      <p className="text-small text-ink-muted">
        Write it down or print this page, and keep it somewhere safe, like where you keep your
        passport. Ruvee never stores it and can&apos;t show it again.
      </p>
      <div className="flex flex-wrap justify-between gap-2">
        <Button
          onClick={() => {
            window.print();
          }}
        >
          Print
        </Button>
        <Button variant="primary" onClick={onSaved}>
          I&apos;ve saved it
        </Button>
      </div>
    </>
  );
}
