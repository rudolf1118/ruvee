'use client';

import { type Ref, useEffect, useState } from 'react';
import type { ConflictView, ItemDetail as Detail } from '@/vault/protocol';
import { VaultClientError, type VaultClient } from '@/vault/client';
import { Button } from '../ui/button';
import { cx } from '../ui/cx';
import {
  ChevronLeftIcon,
  CopyIcon,
  EyeIcon,
  EyeOffIcon,
  PencilIcon,
  StarIcon,
  TrashIcon,
} from '../ui/icons';
import { Tag } from '../ui/tag';
import { ItemAvatar } from '../vault/item-avatar';
import { KIND_LABELS } from '../vault/filter';
import { copySecret } from './clipboard';
import { Notice } from './fields';
import { messageFor } from './messages';
import { relativeTime, safeHref } from './view-model';

const MASK = '••••••••••••';

function Row({
  label,
  children,
  actions,
}: {
  label: string;
  children: React.ReactNode;
  actions?: React.ReactNode;
}) {
  return (
    <div className="flex flex-wrap items-start gap-3 border-t border-line-soft py-3.5">
      <div className="min-w-[220px] flex-1">
        <div className="mb-[3px] text-label font-semibold text-ink-muted">{label}</div>
        <div className="text-body-lg break-words whitespace-pre-line">{children}</div>
      </div>
      {actions ? <div className="flex shrink-0 gap-1.5">{actions}</div> : null}
    </div>
  );
}

function CopyButton({ label, value }: { label: string; value: () => Promise<string> }) {
  const [copied, setCopied] = useState(false);
  return (
    <Button
      size="sm"
      icon={<CopyIcon size={15} />}
      aria-label={`Copy ${label.toLowerCase()}`}
      onClick={() => {
        void value()
          .then(copySecret)
          .then(() => {
            setCopied(true);
            setTimeout(() => {
              setCopied(false);
            }, 1500);
          });
      }}
    >
      <span aria-live="polite">{copied ? 'Copied' : 'Copy'}</span>
    </Button>
  );
}

/** Explains a sync conflict and offers the three outcomes of sync-protocol §6. */
function ConflictBanner({
  client,
  itemId,
  onResolved,
}: {
  client: VaultClient;
  itemId: string;
  onResolved: () => void;
}) {
  const [view, setView] = useState<ConflictView | null>(null);
  useEffect(() => {
    void client.call('conflict', { id: itemId }).then(setView, () => undefined);
  }, [client, itemId]);
  if (!view) return null;
  const resolve = (choice: 'mine' | 'theirs' | 'both') => {
    void client.call('resolveConflict', { id: itemId, choice }).then(onResolved, () => undefined);
  };
  const text =
    view.kind === 'edited_on_both'
      ? 'This item was edited on this device and on another device. The other version is shown below; your version was kept as a draft.'
      : view.kind === 'deleted_elsewhere'
        ? 'You edited this item, but it was permanently deleted on another device.'
        : 'You deleted this item, but it was changed on another device afterwards.';
  return (
    <div
      role="alert"
      className="flex flex-col gap-3 rounded-menu border border-caution-line bg-caution-wash px-4 py-3 text-caution-strong"
    >
      <div className="font-semibold">Changed on two devices</div>
      <p className="text-body">{text}</p>
      {view.local ? (
        <p className="text-small">
          This device&apos;s version: <strong>{view.local.title}</strong>
          {view.local.username ? ` · ${view.local.username}` : ''}
        </p>
      ) : null}
      <div className="flex flex-wrap gap-2">
        {view.kind === 'edited_on_both' ? (
          <>
            <Button
              size="sm"
              variant="primary"
              onClick={() => {
                resolve('mine');
              }}
            >
              Keep this device&apos;s version
            </Button>
            <Button
              size="sm"
              onClick={() => {
                resolve('theirs');
              }}
            >
              Keep the other version
            </Button>
            <Button
              size="sm"
              onClick={() => {
                resolve('both');
              }}
            >
              Keep both
            </Button>
          </>
        ) : view.kind === 'deleted_elsewhere' ? (
          <>
            <Button
              size="sm"
              variant="primary"
              onClick={() => {
                resolve('mine');
              }}
            >
              Restore as a new item
            </Button>
            <Button
              size="sm"
              onClick={() => {
                resolve('theirs');
              }}
            >
              Discard my changes
            </Button>
          </>
        ) : (
          <>
            <Button
              size="sm"
              variant="primary"
              onClick={() => {
                resolve('theirs');
              }}
            >
              Keep the changed item
            </Button>
            <Button
              size="sm"
              variant="danger"
              onClick={() => {
                resolve('mine');
              }}
            >
              Delete it again
            </Button>
          </>
        )}
      </div>
    </div>
  );
}

export function LiveItemDetail({
  client,
  itemId,
  version,
  readOnly,
  headingRef,
  vaultName,
  onBack,
  onTag,
  onEdit,
  onChanged,
}: {
  client: VaultClient;
  itemId: string;
  /** Changes whenever the item list changes, so the detail reloads. */
  version: number;
  readOnly: boolean;
  headingRef: Ref<HTMLHeadingElement>;
  vaultName: string;
  onBack: () => void;
  onTag: (tag: string) => void;
  onEdit: (detail: Detail) => void;
  onChanged: () => void;
}) {
  const [detail, setDetail] = useState<Detail | null>(null);
  const [revealed, setRevealed] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);

  // Keyed by item id in the parent, so revealed and confirm state reset per item.
  useEffect(() => {
    void client.call('detail', { id: itemId }).then(setDetail, () => {
      setDetail(null);
    });
  }, [client, itemId, version]);

  if (!detail) return null;

  const act = (task: Promise<unknown>) => {
    setError(null);
    task.then(onChanged, (e: unknown) => {
      setError(e instanceof VaultClientError ? messageFor(e.code) : messageFor('internal'));
    });
  };
  const secret = () => client.call('secret', { id: itemId });
  const href = detail.urls[0] ? safeHref(detail.urls[0]) : null;

  return (
    <article className="mx-auto flex max-w-[760px] flex-col gap-4">
      <Button
        variant="link"
        className="-ml-2 self-start md:hidden"
        icon={<ChevronLeftIcon size={18} />}
        onClick={onBack}
      >
        Back to items
      </Button>

      {detail.conflict ? (
        <ConflictBanner client={client} itemId={itemId} onResolved={onChanged} />
      ) : null}

      {detail.trashed ? (
        <div
          role="note"
          className="flex flex-wrap items-center gap-3 rounded-menu border border-caution-line bg-caution-wash px-4 py-3 text-caution-strong"
        >
          <TrashIcon size={18} />
          <span className="min-w-[200px] flex-1">
            {confirmDelete
              ? 'Delete this item permanently? It is removed from every device on their next sync. Copies in old backups or already-synced devices are not affected.'
              : 'This item is in Trash. Restore it to use it again, or delete it permanently.'}
          </span>
          {confirmDelete ? (
            <>
              <Button
                size="sm"
                onClick={() => {
                  setConfirmDelete(false);
                }}
              >
                Cancel
              </Button>
              <Button
                variant="danger"
                size="sm"
                onClick={() => {
                  act(client.call('purge', { id: itemId }));
                }}
              >
                Delete permanently
              </Button>
            </>
          ) : (
            <>
              <Button
                variant="primary"
                size="sm"
                {...(readOnly ? { unavailable: true } : {})}
                onClick={() => {
                  act(client.call('restore', { id: itemId }));
                }}
              >
                Restore
              </Button>
              <Button
                variant="danger"
                size="sm"
                {...(readOnly ? { unavailable: true } : {})}
                onClick={() => {
                  setConfirmDelete(true);
                }}
              >
                Delete permanently
              </Button>
            </>
          )}
        </div>
      ) : null}

      {error ? <Notice>{error}</Notice> : null}

      <div className="rounded-card border border-line bg-surface p-6 shadow-card">
        <div className="flex flex-wrap items-start gap-4">
          <ItemAvatar kind={detail.type} title={detail.title} size="lg" />
          <div className="min-w-[200px] flex-1">
            <h2
              ref={headingRef}
              tabIndex={-1}
              className="text-heading leading-tight font-bold tracking-tight-title focus:outline-none"
            >
              {detail.title}
            </h2>
            <div className="mt-1.5 flex flex-wrap items-center gap-2 text-small text-ink-muted">
              <span>{KIND_LABELS[detail.type]}</span>
              <span aria-hidden="true">·</span>
              <span className="inline-flex items-center rounded-full bg-subtle px-2 py-px font-semibold text-ink-secondary">
                {vaultName}
              </span>
              <span aria-hidden="true">·</span>
              <span>Edited {relativeTime(detail.updatedAtMs)}</span>
              {detail.pending ? (
                <>
                  <span aria-hidden="true">·</span>
                  <span className="font-semibold text-caution-strong">Waiting to sync</span>
                </>
              ) : null}
            </div>
          </div>
          {detail.trashed || readOnly ? null : (
            <div className="flex flex-wrap gap-2">
              <Button
                aria-pressed={detail.favorite}
                onClick={() => {
                  act(client.call('setFavorite', { id: itemId, favorite: !detail.favorite }));
                }}
                icon={
                  <StarIcon
                    size={16}
                    filled={detail.favorite}
                    className={cx(detail.favorite && 'text-brand')}
                  />
                }
              >
                {detail.favorite ? 'Favorite' : 'Add to Favorites'}
              </Button>
              <Button
                icon={<PencilIcon size={16} />}
                onClick={() => {
                  onEdit(detail);
                }}
              >
                Edit
              </Button>
              <Button
                variant="danger"
                icon={<TrashIcon size={16} />}
                onClick={() => {
                  act(client.call('trash', { id: itemId }));
                }}
              >
                Move to Trash
              </Button>
            </div>
          )}
        </div>

        <div className="mt-5">
          {detail.type === 'login' ? (
            <>
              {detail.username ? (
                <Row
                  label="Username"
                  actions={
                    <CopyButton label="Username" value={() => Promise.resolve(detail.username)} />
                  }
                >
                  {detail.username}
                </Row>
              ) : null}
              {detail.hasPassword ? (
                <Row
                  label="Password"
                  actions={
                    <>
                      <Button
                        size="sm"
                        aria-pressed={revealed !== null}
                        icon={revealed === null ? <EyeIcon size={15} /> : <EyeOffIcon size={15} />}
                        aria-label={revealed === null ? 'Reveal password' : 'Hide password'}
                        onClick={() => {
                          if (revealed !== null) setRevealed(null);
                          else void secret().then(setRevealed);
                        }}
                      >
                        {revealed === null ? 'Reveal' : 'Hide'}
                      </Button>
                      <CopyButton label="Password" value={secret} />
                    </>
                  }
                >
                  <span className={cx('font-mono', revealed === null && 'tracking-[0.08em]')}>
                    {revealed ?? (
                      <>
                        <span aria-hidden="true">{MASK}</span>
                        <span className="sr-only">Hidden</span>
                      </>
                    )}
                  </span>
                </Row>
              ) : null}
              {detail.urls.length > 0 ? (
                <Row
                  label="Website"
                  actions={
                    <CopyButton
                      label="Website"
                      value={() => Promise.resolve(detail.urls[0] ?? '')}
                    />
                  }
                >
                  {href ? (
                    <a
                      href={href}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-brand-text underline"
                    >
                      {detail.urls[0]}
                    </a>
                  ) : (
                    detail.urls[0]
                  )}
                </Row>
              ) : null}
              {detail.notes ? <Row label="Notes">{detail.notes}</Row> : null}
            </>
          ) : (
            <Row label="Note">
              {detail.noteText || <span className="text-ink-muted">Empty note</span>}
            </Row>
          )}

          <div className="flex flex-wrap gap-4 border-t border-line-soft pt-3.5">
            <div className="min-w-[220px] flex-1">
              <div className="mb-1.5 text-label font-semibold text-ink-muted">Tags</div>
              {detail.tags.length > 0 ? (
                <div className="flex flex-wrap gap-1.5">
                  {detail.tags.map((tag) => (
                    <Tag
                      key={tag}
                      aria-label={`Show items tagged ${tag}`}
                      onClick={() => {
                        onTag(tag);
                      }}
                    >
                      {tag}
                    </Tag>
                  ))}
                </div>
              ) : (
                <span className="text-body text-ink-muted">No tags</span>
              )}
            </div>
            <div className="min-w-[160px]">
              <div className="mb-1.5 text-label font-semibold text-ink-muted">Vault</div>
              <div className="text-body-lg">{vaultName}</div>
            </div>
          </div>
        </div>
      </div>
    </article>
  );
}
