import type { Ref } from 'react';
import { Button } from '../ui/button';
import { ChevronLeftIcon, CopyIcon, EyeIcon, PencilIcon, StarIcon, TrashIcon } from '../ui/icons';
import { LogoMark } from '../ui/logo';
import { Tag } from '../ui/tag';
import { cx } from '../ui/cx';
import { KIND_LABELS } from './filter';
import { ItemAvatar } from './item-avatar';
import type { ItemField, VaultItemView } from './types';

interface ItemDetailProps {
  item: VaultItemView;
  vaultName: string;
  onTag: (tag: string) => void;
  onBack: () => void;
  headingRef: Ref<HTMLHeadingElement>;
}

function FieldRow({ field }: { field: ItemField }) {
  const lower = field.label.toLowerCase();
  return (
    <div className="flex flex-wrap items-start gap-3 border-t border-line-soft py-3.5">
      <div className="min-w-[220px] flex-1">
        <div className="mb-[3px] text-label font-semibold text-ink-muted">{field.label}</div>
        <div
          className={cx(
            'text-body-lg break-words whitespace-pre-line',
            field.mono && 'font-mono',
            field.concealed && 'tracking-[0.08em]',
          )}
        >
          {field.concealed ? (
            <>
              <span aria-hidden="true">{field.display}</span>
              <span className="sr-only">Hidden</span>
            </>
          ) : (
            field.display
          )}
        </div>
      </div>
      <div className="flex shrink-0 gap-1.5">
        {field.concealed ? (
          <Button
            size="sm"
            unavailable
            title="Not available yet"
            icon={<EyeIcon size={15} />}
            aria-label={`Reveal ${lower} (not available yet)`}
          >
            Reveal
          </Button>
        ) : null}
        {field.copyable === false ? null : (
          <Button
            size="sm"
            unavailable
            title="Not available yet"
            icon={<CopyIcon size={15} />}
            aria-label={`Copy ${lower} (not available yet)`}
          >
            Copy
          </Button>
        )}
      </div>
    </div>
  );
}

export function ItemDetail({ item, vaultName, onTag, onBack, headingRef }: ItemDetailProps) {
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

      {item.trashed ? (
        <div
          role="note"
          className="flex flex-wrap items-center gap-3 rounded-menu border border-caution-line bg-caution-wash px-4 py-3 text-caution-strong"
        >
          <TrashIcon size={18} />
          <span className="min-w-[200px] flex-1">
            This item is in Trash. Restore it to use it again, or delete it permanently.
          </span>
          <Button variant="primary" size="sm" unavailable title="Not available yet">
            Restore
          </Button>
          <Button variant="danger" size="sm" unavailable title="Not available yet">
            Delete permanently
          </Button>
        </div>
      ) : null}

      <div className="rounded-card border border-line bg-surface p-6 shadow-card">
        <div className="flex flex-wrap items-start gap-4">
          <ItemAvatar kind={item.kind} title={item.title} size="lg" />
          <div className="min-w-[200px] flex-1">
            <h2
              ref={headingRef}
              tabIndex={-1}
              className="text-heading leading-tight font-bold tracking-tight-title focus:outline-none"
            >
              {item.title}
            </h2>
            <div className="mt-1.5 flex flex-wrap items-center gap-2 text-small text-ink-muted">
              <span>{KIND_LABELS[item.kind]}</span>
              <span aria-hidden="true">·</span>
              <span className="inline-flex items-center rounded-full bg-subtle px-2 py-px font-semibold text-ink-secondary">
                {vaultName}
              </span>
              <span aria-hidden="true">·</span>
              <span>{item.edited}</span>
            </div>
          </div>
          {item.trashed ? null : (
            <div className="flex flex-wrap gap-2">
              <Button
                unavailable
                title="Not available yet"
                icon={
                  <StarIcon
                    size={16}
                    filled={item.favorite}
                    className={cx(item.favorite && 'text-brand')}
                  />
                }
              >
                {item.favorite ? 'Favorite' : 'Add to Favorites'}
              </Button>
              <Button unavailable title="Not available yet" icon={<PencilIcon size={16} />}>
                Edit
              </Button>
              <Button
                variant="danger"
                unavailable
                title="Not available yet"
                icon={<TrashIcon size={16} />}
              >
                Move to Trash
              </Button>
            </div>
          )}
        </div>

        <div className="mt-5">
          {item.fields.map((field) => (
            <FieldRow key={field.label} field={field} />
          ))}

          <div className="flex flex-wrap gap-4 border-t border-line-soft pt-3.5">
            <div className="min-w-[220px] flex-1">
              <div className="mb-1.5 text-label font-semibold text-ink-muted">Tags</div>
              {item.tags.length > 0 ? (
                <div className="flex flex-wrap gap-1.5">
                  {item.tags.map((tag) => (
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

export function NoItemSelected() {
  return (
    <div className="flex h-full min-h-80 flex-col items-center justify-center gap-2 text-center text-ink-muted">
      <LogoMark size={40} tone="soft" />
      <div className="text-body-lg font-semibold text-ink">No item selected</div>
      <div className="text-body">Choose an item from the list to see its details.</div>
    </div>
  );
}
