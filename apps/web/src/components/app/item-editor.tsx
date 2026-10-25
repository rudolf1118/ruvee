'use client';

import { type SubmitEvent, useEffect, useRef, useState } from 'react';
import { ITEM_LIMITS, parseTags } from '@ruvee/vault';
import type { ItemDetail, ItemDraft, ItemSummary, ItemType } from '@ruvee/vault';
import { VaultClientError, type VaultClient } from '@/vault/client';
import { Button } from '../ui/button';
import { cx } from '../ui/cx';
import { ChevronLeftIcon, DiceIcon } from '../ui/icons';
import { Notice, PasswordField, TextArea, TextField } from './fields';
import { messageFor } from './messages';
import { PERSONAL_VAULT } from './view-model';

interface Errors {
  title?: string;
  url?: string;
  password?: string;
  tags?: string;
}

function validate(draft: ItemDraft, tagsText: string): Errors {
  const errors: Errors = {};
  if (!draft.title.trim()) errors.title = 'Add a title so you can find this item later.';
  else if (draft.title.length > ITEM_LIMITS.title)
    errors.title = `Use at most ${ITEM_LIMITS.title} characters.`;
  if (draft.type === 'login') {
    const url = draft.urls[0]?.trim() ?? '';
    if (url && !/^[a-z][a-z0-9+.-]*:\/\/\S+$/i.test(url))
      errors.url = 'Enter a web address like https://example.com.';
    if (draft.password.length > ITEM_LIMITS.password)
      errors.password = `Use at most ${ITEM_LIMITS.password} characters.`;
  }
  const tags = parseTags(tagsText);
  if (tags.length > ITEM_LIMITS.tags || tags.some((t) => t.length > ITEM_LIMITS.tag))
    errors.tags = `Use at most ${ITEM_LIMITS.tags} tags of ${ITEM_LIMITS.tag} characters.`;
  return errors;
}

/** The design's "New login" form, also used for editing and for secure notes. */
export function ItemEditor({
  client,
  existing,
  onCancel,
  onSaved,
}: {
  client: VaultClient;
  existing: ItemDetail | null;
  onCancel: () => void;
  onSaved: (item: ItemSummary) => void;
}) {
  const [type, setType] = useState<ItemType>(existing?.type ?? 'login');
  const [title, setTitle] = useState(existing?.title ?? '');
  const [url, setUrl] = useState(existing?.urls[0] ?? '');
  const [username, setUsername] = useState(existing?.username ?? '');
  const [password, setPassword] = useState('');
  const [notes, setNotes] = useState(existing?.notes ?? '');
  const [noteText, setNoteText] = useState(existing?.noteText ?? '');
  const [tagsText, setTagsText] = useState(existing?.tags.join(', ') ?? '');
  const [favorite, setFavorite] = useState(existing?.favorite ?? false);
  const [errors, setErrors] = useState<Errors>({});
  const [failure, setFailure] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const headingRef = useRef<HTMLHeadingElement>(null);

  // The stored password is fetched from the worker only when the editor opens for it.
  useEffect(() => {
    headingRef.current?.focus();
    if (existing?.hasPassword)
      void client.call('secret', { id: existing.id }).then(setPassword, () => undefined);
  }, [client, existing]);

  const draft: ItemDraft = {
    ...(existing ? { id: existing.id } : {}),
    type,
    title,
    username,
    password,
    urls: url.trim() ? [url.trim(), ...(existing?.urls.slice(1) ?? [])] : [],
    notes,
    noteText,
    tags: parseTags(tagsText),
    favorite,
  };

  const submit = (event: SubmitEvent) => {
    event.preventDefault();
    const found = validate(draft, tagsText);
    setErrors(found);
    if (Object.keys(found).length > 0 || busy) return;
    setBusy(true);
    setFailure(null);
    client.call('save', { draft }).then(
      (saved) => {
        setPassword('');
        onSaved(saved);
      },
      (e: unknown) => {
        setFailure(e instanceof VaultClientError ? messageFor(e.code) : messageFor('internal'));
        setBusy(false);
      },
    );
  };

  const errorCount = Object.keys(errors).length;
  const heading = existing
    ? `Edit ${existing.title}`
    : type === 'login'
      ? 'New login'
      : 'New secure note';

  return (
    <form onSubmit={submit} noValidate className="mx-auto flex max-w-[760px] flex-col gap-4">
      <Button
        variant="link"
        className="-ml-2 self-start md:hidden"
        icon={<ChevronLeftIcon size={18} />}
        onClick={onCancel}
      >
        Back to items
      </Button>
      <div className="flex flex-col gap-5 rounded-card border border-line bg-surface p-6 shadow-card">
        <div>
          <div className="text-small font-semibold text-ink-muted">
            {existing ? 'Edit item' : 'New item'}
          </div>
          <h2
            ref={headingRef}
            tabIndex={-1}
            className="text-heading leading-tight font-bold tracking-tight-title focus:outline-none"
          >
            {heading}
          </h2>
        </div>

        {existing ? null : (
          <div role="radiogroup" aria-label="Item type" className="flex gap-1.5">
            {(['login', 'note'] as const).map((t) => (
              <button
                key={t}
                type="button"
                role="radio"
                aria-checked={type === t}
                onClick={() => {
                  setType(t);
                }}
                className={cx(
                  'h-8 cursor-pointer rounded-full border px-3 text-small font-semibold',
                  type === t
                    ? 'border-brand bg-brand-soft text-brand-strong'
                    : 'border-line-button bg-surface hover:bg-subtle',
                )}
              >
                {t === 'login' ? 'Login' : 'Secure note'}
              </button>
            ))}
          </div>
        )}

        {errorCount > 0 ? (
          <Notice>
            Fix {errorCount} {errorCount === 1 ? 'field' : 'fields'} before saving.
          </Notice>
        ) : null}

        <TextField
          label="Title (required)"
          value={title}
          maxLength={ITEM_LIMITS.title}
          placeholder={type === 'login' ? 'e.g. Lumen Mail' : 'e.g. Home Wi-Fi'}
          onChange={(e) => {
            setTitle(e.target.value);
          }}
          error={errors.title}
        />

        {type === 'login' ? (
          <>
            <TextField
              label="Website"
              value={url}
              inputMode="url"
              autoComplete="off"
              maxLength={ITEM_LIMITS.url}
              placeholder="https://"
              onChange={(e) => {
                setUrl(e.target.value);
              }}
              error={errors.url}
            />
            <TextField
              label="Username or email"
              value={username}
              autoComplete="off"
              maxLength={ITEM_LIMITS.username}
              onChange={(e) => {
                setUsername(e.target.value);
              }}
            />
            <PasswordField
              label="Password"
              value={password}
              autoComplete="new-password"
              maxLength={ITEM_LIMITS.password}
              onChange={(e) => {
                setPassword(e.target.value);
              }}
              error={errors.password}
              extraTrailing={
                <Button unavailable title="Not available yet" icon={<DiceIcon size={16} />}>
                  Generate
                </Button>
              }
            />
            <TextArea
              label="Notes"
              value={notes}
              maxLength={ITEM_LIMITS.notes}
              onChange={(e) => {
                setNotes(e.target.value);
              }}
            />
          </>
        ) : (
          <TextArea
            label="Note"
            value={noteText}
            rows={8}
            maxLength={ITEM_LIMITS.noteText}
            onChange={(e) => {
              setNoteText(e.target.value);
            }}
          />
        )}

        <TextField
          label="Tags"
          value={tagsText}
          onChange={(e) => {
            setTagsText(e.target.value);
          }}
          hint="Separate tags with commas, like work, travel."
          error={errors.tags}
        />

        <div className="flex flex-wrap items-center gap-4">
          <div className="text-small">
            <span className="font-semibold">Vault:</span> {PERSONAL_VAULT.name}
          </div>
          <label className="flex items-center gap-2 text-body">
            <input
              type="checkbox"
              className="size-4 accent-brand"
              checked={favorite}
              onChange={(e) => {
                setFavorite(e.target.checked);
              }}
            />
            Add to Favorites
          </label>
        </div>

        {failure ? <Notice>{failure}</Notice> : null}

        <div className="flex justify-end gap-2 border-t border-line-soft pt-4">
          <Button variant="ghost" onClick={onCancel}>
            Cancel
          </Button>
          <Button variant="primary" type="submit" aria-disabled={busy || undefined}>
            {busy ? 'Saving…' : 'Save'}
          </Button>
        </div>
      </div>
    </form>
  );
}
