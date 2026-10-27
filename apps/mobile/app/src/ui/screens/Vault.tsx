import type { ConflictView, ItemDetail, ItemDraft, ItemSummary, SyncStatus } from '@ruvee/vault';
import { useEffect, useMemo, useState } from 'react';
import { FlatList, Pressable, StyleSheet, Text, TextInput, View } from 'react-native';
import { UiError, type VaultApp } from '../../vault/useVaultApp';
import { Banner, Body, Button, Field, Heading, Screen } from '../kit';
import { messageFor } from '../messages';
import { color, radius } from '../theme';

function errorText(e: unknown): string {
  return e instanceof UiError ? messageFor(e.code, e.retryAfterSeconds) : messageFor('internal');
}

const SYNC_LABEL: Record<SyncStatus['state'], string> = {
  synced: 'Synced',
  syncing: 'Syncing…',
  offline: 'Offline: changes are saved on this device and sync later',
  pending: 'Changes waiting to sync',
  session_expired: 'Session ended: unlock again to sync',
  integrity_error: "Read-only: the server's copy didn't pass Ruvee's checks",
  maintenance: 'The server is being restored: read-only',
  reopening: 'The server waits to be reopened: read-only',
};

const NOTICE: Record<NonNullable<VaultApp['notice']>, string> = {
  device_key_missing: messageFor('device_key_missing'),
  migration_required: messageFor('migration_required'),
  login_failed:
    'The server did not accept your password for this device. Your local copy works offline.',
  offline: "Can't reach the server. Your local copy works offline.",
  rate_limited: messageFor('rate_limited'),
  maintenance: messageFor('server_maintenance'),
  reopening: messageFor('server_reopening'),
  device_unknown: 'The server does not know this device. Your local copy works offline.',
};

type Mode =
  | { readonly name: 'list' }
  | { readonly name: 'item'; readonly id: string }
  | { readonly name: 'edit'; readonly draft: ItemDraft };

export function VaultScreen({ app }: { app: VaultApp }) {
  const [mode, setMode] = useState<Mode>({ name: 'list' });
  if (mode.name === 'item')
    return (
      <ItemScreen
        app={app}
        id={mode.id}
        onBack={() => {
          setMode({ name: 'list' });
        }}
        onEdit={(draft) => {
          setMode({ name: 'edit', draft });
        }}
      />
    );
  if (mode.name === 'edit')
    return (
      <EditScreen
        app={app}
        draft={mode.draft}
        onDone={(id) => {
          setMode(id ? { name: 'item', id } : { name: 'list' });
        }}
      />
    );
  return (
    <ListScreen
      app={app}
      onOpen={(id) => {
        setMode({ name: 'item', id });
      }}
      onAdd={(type) => {
        setMode({ name: 'edit', draft: emptyDraft(type) });
      }}
    />
  );
}

function emptyDraft(type: ItemDraft['type']): ItemDraft {
  return {
    type,
    title: '',
    username: '',
    password: '',
    urls: [],
    notes: '',
    noteText: '',
    tags: [],
    favorite: false,
  };
}

function ListScreen({
  app,
  onOpen,
  onAdd,
}: {
  app: VaultApp;
  onOpen: (id: string) => void;
  onAdd: (type: ItemDraft['type']) => void;
}) {
  const [query, setQuery] = useState('');
  const [syncing, setSyncing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    return app.items
      .filter((i) => !i.trashed)
      .filter(
        (i) => !q || i.title.toLowerCase().includes(q) || i.subtitle.toLowerCase().includes(q),
      )
      .slice()
      .sort((a, b) => a.title.localeCompare(b.title));
  }, [app.items, query]);
  const sync = app.sync;
  const conflicts = app.items.filter((i) => i.conflict !== null).length;

  return (
    <Screen scroll={false}>
      <View style={s.header}>
        <Heading>All items</Heading>
        <Pressable testID="vault-lock" accessibilityRole="button" onPress={app.lock}>
          <Text style={s.link}>Lock</Text>
        </Pressable>
      </View>
      {sync ? (
        <Text
          testID="sync-status"
          style={[s.sync, sync.state === 'synced' ? s.syncOk : s.syncWarn]}
        >
          {SYNC_LABEL[sync.state]}
          {sync.pendingCount > 0 ? ` · ${String(sync.pendingCount)} pending` : ''}
        </Text>
      ) : null}
      {app.notice ? (
        <Banner tone="caution" testID="session-notice">
          {NOTICE[app.notice]}
        </Banner>
      ) : null}
      {conflicts > 0 ? (
        <Banner tone="caution" testID="conflict-banner">
          {conflicts === 1 ? '1 item was' : `${String(conflicts)} items were`} changed here and on
          another device. Open it to choose which version to keep.
        </Banner>
      ) : null}
      {error ? <Banner tone="danger">{error}</Banner> : null}
      <TextInput
        testID="vault-search"
        accessibilityLabel="Search"
        placeholder="Search"
        placeholderTextColor={color.inkMuted}
        value={query}
        onChangeText={setQuery}
        style={s.search}
        autoCorrect={false}
      />
      <Text testID="item-count" style={s.count}>
        {visible.length === 1 ? '1 item' : `${String(visible.length)} items`}
      </Text>
      <FlatList
        style={s.list}
        data={visible}
        keyExtractor={(i) => i.id}
        renderItem={({ item }) => <Row item={item} onPress={() => onOpen(item.id)} />}
        ListEmptyComponent={<Body muted>No items yet.</Body>}
      />
      <View style={s.actions}>
        <View style={s.action}>
          <Button title="New login" testID="add-login" onPress={() => onAdd('login')} />
        </View>
        <View style={s.action}>
          <Button
            title="New note"
            testID="add-note"
            kind="secondary"
            onPress={() => onAdd('note')}
          />
        </View>
      </View>
      <View style={s.actions}>
        <View style={s.action}>
          <Button
            title="Sync now"
            testID="vault-sync"
            kind="secondary"
            busy={syncing}
            onPress={() => {
              setSyncing(true);
              setError(null);
              app.syncNow().then(
                () => {
                  setSyncing(false);
                },
                (e: unknown) => {
                  setError(errorText(e));
                  setSyncing(false);
                },
              );
            }}
          />
        </View>
        <View style={s.action}>
          <Button
            title="Log out"
            testID="vault-logout"
            kind="secondary"
            onPress={() => void app.logout().catch(() => undefined)}
          />
        </View>
      </View>
    </Screen>
  );
}

function Row({ item, onPress }: { item: ItemSummary; onPress: () => void }) {
  return (
    <Pressable
      testID={`item-${item.title}`}
      accessibilityRole="button"
      accessibilityLabel={item.title}
      onPress={onPress}
      style={({ pressed }) => [s.row, pressed && s.rowPressed]}
    >
      <Text style={s.rowType}>{item.type === 'login' ? 'Login' : 'Note'}</Text>
      <View style={s.rowBody}>
        <Text style={s.rowTitle} numberOfLines={1}>
          {item.title}
        </Text>
        {item.subtitle ? (
          <Text style={s.rowSubtitle} numberOfLines={1}>
            {item.subtitle}
          </Text>
        ) : null}
      </View>
      {item.conflict ? (
        <Text style={s.flag}>Conflict</Text>
      ) : item.pending ? (
        <Text style={s.flag}>Pending</Text>
      ) : null}
    </Pressable>
  );
}

function ItemScreen({
  app,
  id,
  onBack,
  onEdit,
}: {
  app: VaultApp;
  id: string;
  onBack: () => void;
  onEdit: (draft: ItemDraft) => void;
}) {
  const [item, setItem] = useState<ItemDetail | null>(null);
  const [conflict, setConflict] = useState<ConflictView | null>(null);
  const [secret, setSecret] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const summary = app.items.find((i) => i.id === id);

  useEffect(() => {
    let alive = true;
    app.detail(id).then(
      (d) => {
        if (alive) setItem(d);
      },
      (e: unknown) => {
        if (alive) setError(errorText(e));
      },
    );
    if (summary?.conflict)
      app.conflict(id).then(
        (c) => {
          if (alive) setConflict(c);
        },
        () => undefined,
      );
    else setConflict(null);
    return () => {
      alive = false;
    };
  }, [app, id, summary?.conflict, summary?.updatedAtMs]);

  // The revealed password lives only in this screen's state and goes when it closes.
  useEffect(() => () => setSecret(null), []);

  const edit = async () => {
    if (!item) return;
    const password = item.type === 'login' && item.hasPassword ? await app.secret(id) : '';
    onEdit({
      id,
      type: item.type,
      title: item.title,
      username: item.username,
      password,
      urls: item.urls,
      notes: item.notes,
      noteText: item.noteText,
      tags: item.tags,
      favorite: item.favorite,
    });
  };

  const resolve = (choice: 'mine' | 'theirs' | 'both') => {
    app.resolveConflict(id, choice).then(
      () => {
        setConflict(null);
        if (choice === 'both') onBack();
      },
      (e: unknown) => {
        setError(errorText(e));
      },
    );
  };

  return (
    <Screen>
      <Pressable testID="item-back" accessibilityRole="button" onPress={onBack}>
        <Text style={s.link}>‹ All items</Text>
      </Pressable>
      {error ? <Banner tone="danger">{error}</Banner> : null}
      {item ? (
        <>
          <Heading>{item.title}</Heading>
          {conflict ? (
            <View style={s.card} testID="conflict-panel">
              <Banner tone="caution">
                This item was changed here and on another device. This device has “
                {conflict.local?.title ?? 'deleted'}”; the other version is “
                {conflict.remote?.title ?? 'deleted'}”.
              </Banner>
              <Button
                title="Keep this device's version"
                testID="conflict-mine"
                onPress={() => resolve('mine')}
              />
              <Button
                title="Keep the other version"
                testID="conflict-theirs"
                kind="secondary"
                onPress={() => resolve('theirs')}
              />
              <Button
                title="Keep both"
                testID="conflict-both"
                kind="secondary"
                onPress={() => resolve('both')}
              />
            </View>
          ) : null}
          {item.type === 'login' ? (
            <View style={s.card}>
              <Detail label="Username" value={item.username} testID="detail-username" />
              <Detail label="Website" value={item.urls.join('\n')} testID="detail-url" />
              <View style={s.detail}>
                <Text style={s.detailLabel}>Password</Text>
                <Text testID="detail-password" style={s.detailValue} selectable={false}>
                  {secret ?? (item.hasPassword ? '••••••••••' : '')}
                </Text>
                {item.hasPassword ? (
                  <Pressable
                    testID={secret ? 'hide-password' : 'reveal-password'}
                    accessibilityRole="button"
                    onPress={() => {
                      if (secret) setSecret(null);
                      else app.secret(id).then(setSecret, (e: unknown) => setError(errorText(e)));
                    }}
                  >
                    <Text style={s.link}>{secret ? 'Hide' : 'Reveal'}</Text>
                  </Pressable>
                ) : null}
              </View>
              {item.notes ? (
                <Detail label="Notes" value={item.notes} testID="detail-notes" />
              ) : null}
            </View>
          ) : (
            <View style={s.card}>
              <Detail label="Note" value={item.noteText} testID="detail-note" />
            </View>
          )}
          <Button
            title="Edit"
            testID="item-edit"
            kind="secondary"
            onPress={() => void edit().catch((e: unknown) => setError(errorText(e)))}
          />
        </>
      ) : (
        <Body muted>Loading…</Body>
      )}
    </Screen>
  );
}

function Detail({ label, value, testID }: { label: string; value: string; testID: string }) {
  return (
    <View style={s.detail}>
      <Text style={s.detailLabel}>{label}</Text>
      <Text testID={testID} style={s.detailValue}>
        {value}
      </Text>
    </View>
  );
}

/**
 * Item fields are excluded from the system Autofill service (`importantForAutofill="no"`), so
 * another password manager or Google Autofill is never offered an item's username or password
 * to save. The master-password fields keep the platform default.
 */
function EditScreen({
  app,
  draft,
  onDone,
}: {
  app: VaultApp;
  draft: ItemDraft;
  onDone: (id?: string) => void;
}) {
  const [title, setTitle] = useState(draft.title);
  const [username, setUsername] = useState(draft.username);
  const [password, setPassword] = useState(draft.password);
  const [url, setUrl] = useState(draft.urls.join(', '));
  const [notes, setNotes] = useState(draft.notes);
  const [noteText, setNoteText] = useState(draft.noteText);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const login = draft.type === 'login';

  const save = () => {
    setBusy(true);
    setError(null);
    const next: ItemDraft = {
      ...draft,
      title: title.trim(),
      username: login ? username : '',
      password: login ? password : '',
      urls: login
        ? url
            .split(',')
            .map((u) => u.trim())
            .filter(Boolean)
        : [],
      notes: login ? notes : '',
      noteText: login ? '' : noteText,
    };
    app.save(next).then(
      (summary) => {
        onDone(summary.id);
      },
      (e: unknown) => {
        setError(errorText(e));
        setBusy(false);
      },
    );
  };

  return (
    <Screen>
      <Heading>{draft.id ? 'Edit item' : login ? 'New login' : 'New secure note'}</Heading>
      <Field
        label="Title (required)"
        testID="edit-title"
        importantForAutofill="no"
        value={title}
        onChangeText={setTitle}
      />
      {login ? (
        <>
          <Field
            label="Website"
            testID="edit-url"
            importantForAutofill="no"
            value={url}
            onChangeText={setUrl}
            autoCapitalize="none"
            keyboardType="url"
          />
          <Field
            label="Username or email"
            testID="edit-username"
            importantForAutofill="no"
            value={username}
            onChangeText={setUsername}
            autoCapitalize="none"
          />
          <Field
            label="Password"
            testID="edit-password"
            importantForAutofill="no"
            value={password}
            onChangeText={setPassword}
            secureTextEntry
            autoCapitalize="none"
          />
          <Field
            label="Notes"
            testID="edit-notes"
            importantForAutofill="no"
            value={notes}
            onChangeText={setNotes}
            multiline
          />
        </>
      ) : (
        <Field
          label="Note"
          testID="edit-note-text"
          importantForAutofill="no"
          value={noteText}
          onChangeText={setNoteText}
          multiline
        />
      )}
      {error ? (
        <Banner tone="danger" testID="edit-error">
          {error}
        </Banner>
      ) : null}
      <Button title="Save" testID="edit-save" busy={busy} disabled={!title.trim()} onPress={save} />
      <Button
        title="Cancel"
        testID="edit-cancel"
        kind="secondary"
        onPress={() => onDone(draft.id)}
      />
    </Screen>
  );
}

const s = StyleSheet.create({
  header: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' },
  link: { color: color.brandText, fontSize: 16, fontWeight: '600' },
  sync: { fontSize: 14 },
  syncOk: { color: color.inkMuted },
  syncWarn: { color: color.cautionStrong },
  search: {
    backgroundColor: color.surface,
    borderColor: color.lineInput,
    borderWidth: 1,
    borderRadius: radius.control,
    paddingHorizontal: 12,
    paddingVertical: 9,
    fontSize: 16,
    color: color.ink,
  },
  count: { color: color.inkMuted, fontSize: 13 },
  list: { flex: 1 },
  row: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
    backgroundColor: color.surface,
    borderRadius: radius.row,
    borderColor: color.line,
    borderWidth: 1,
    padding: 12,
    marginBottom: 8,
  },
  rowPressed: { backgroundColor: color.subtle },
  rowType: { width: 44, color: color.brandText, fontSize: 12, fontWeight: '700' },
  rowBody: { flex: 1 },
  rowTitle: { fontSize: 16, fontWeight: '600', color: color.ink },
  rowSubtitle: { fontSize: 13, color: color.inkMuted },
  flag: { fontSize: 12, color: color.cautionStrong, fontWeight: '600' },
  actions: { flexDirection: 'row', gap: 10 },
  action: { flex: 1 },
  card: {
    backgroundColor: color.surface,
    borderRadius: radius.card,
    borderColor: color.line,
    borderWidth: 1,
    padding: 14,
    gap: 12,
  },
  detail: { gap: 4 },
  detailLabel: { fontSize: 13, color: color.inkMuted, fontWeight: '600' },
  detailValue: { fontSize: 16, color: color.ink },
});
