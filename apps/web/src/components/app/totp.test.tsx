import { act, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ItemDetail, ItemDraft, ItemSummary, TotpView } from '@ruvee/vault';
import type { VaultClient } from '@/vault/client';
import { ItemEditor } from './item-editor';
import { formatCode, TotpRow } from './totp';

/** The web vault's authenticator UI (D-35, totp-authenticator.md §3 and §5; T2). */

const SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

function editorClient() {
  const drafts: ItemDraft[] = [];
  const client = {
    call: (method: string, params?: { draft: ItemDraft }) => {
      if (method === 'save' && params) drafts.push(params.draft);
      if (method === 'secret') return Promise.resolve('synthetic-stored-password');
      return Promise.resolve({ id: 'synthetic-item', title: 'x' } as unknown as ItemSummary);
    },
  } as unknown as VaultClient;
  return { client, drafts };
}

const existing = (hasTotp: boolean): ItemDetail => ({
  id: 'synthetic-item',
  type: 'login',
  title: 'Synthetic Mail',
  subtitle: '',
  favorite: false,
  trashed: false,
  tags: [],
  urls: ['https://mail.example'],
  updatedAtMs: 1,
  pending: false,
  conflict: null,
  username: 'someone@mail.example',
  hasPassword: true,
  hasTotp,
  notes: '',
  noteText: '',
  createdAtMs: 1,
});

describe('authenticator in the item editor', () => {
  it('shows the trade-off, refuses a bad key, and saves a pasted link with a preview code', async () => {
    const user = userEvent.setup();
    const { client, drafts } = editorClient();
    render(
      <ItemEditor client={client} existing={null} onCancel={() => undefined} onSaved={vi.fn()} />,
    );
    await user.click(screen.getByRole('button', { name: 'Add authenticator' }));
    expect(screen.getByText(/has both your\s+password and your second factor/)).toBeVisible();
    expect(screen.getByText(/your email, your Ruvee server and your bank/)).toBeVisible();

    const input = screen.getByLabelText('Setup key or otpauth:// link');
    await user.type(input, 'not a key!');
    expect(screen.getByText(/only the letters A to Z and the digits 2 to 7/)).toBeVisible();
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(drafts).toEqual([]);

    await user.clear(input);
    const uri = `otpauth://totp/Synthetic%20Corp:alice?secret=${SECRET}&issuer=Synthetic%20Corp`;
    await user.click(input);
    await user.paste(uri);
    // The issuer and account fill the empty title and username.
    expect(screen.getByLabelText('Title (required)')).toHaveValue('Synthetic Corp');
    expect(screen.getByLabelText('Username or email')).toHaveValue('alice');
    expect(await screen.findByText(/^\d{3} \d{3}$/)).toBeVisible();

    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(drafts).toHaveLength(1);
    expect(drafts[0]?.totp).toBe(uri);
  });

  it('never sends the secret back for an ordinary edit, and removes it only on request', async () => {
    const user = userEvent.setup();
    const { client, drafts } = editorClient();
    const view = render(
      <ItemEditor
        key="edit"
        client={client}
        existing={existing(true)}
        onCancel={() => undefined}
        onSaved={vi.fn()}
      />,
    );
    expect(screen.getByText(/Set up\. Codes are shown on the item/)).toBeVisible();
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(drafts[0]).not.toHaveProperty('totp');

    view.rerender(
      <ItemEditor
        key="remove"
        client={client}
        existing={existing(true)}
        onCancel={() => undefined}
        onSaved={vi.fn()}
      />,
    );
    await user.click(screen.getByRole('button', { name: 'Remove' }));
    expect(screen.getByText(/may be locked out/)).toBeVisible();
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(drafts[1]?.totp).toBeNull();
  });

  it('a note never carries an authenticator', async () => {
    const user = userEvent.setup();
    const { client, drafts } = editorClient();
    render(
      <ItemEditor client={client} existing={null} onCancel={() => undefined} onSaved={vi.fn()} />,
    );
    await user.click(screen.getByRole('button', { name: 'Add authenticator' }));
    await user.type(screen.getByLabelText('Setup key or otpauth:// link'), SECRET);
    await user.click(screen.getByRole('radio', { name: 'Secure note' }));
    await user.type(screen.getByLabelText('Title (required)'), 'Synthetic note');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(drafts[0]).not.toHaveProperty('totp');
  });
});

describe('authenticator code on the item', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  function rowClient(view: TotpView) {
    const calls: string[] = [];
    const client = {
      call: (method: string) => {
        calls.push(method);
        return Promise.resolve(view);
      },
    } as unknown as VaultClient;
    return { client, calls };
  }

  it('shows the grouped code, the seconds left, and copies a fresh code', async () => {
    vi.useFakeTimers({ toFake: ['Date', 'setInterval', 'clearInterval'] });
    vi.setSystemTime(1_000_000);
    const writeText = vi.fn(() => Promise.resolve());
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    const { client, calls } = rowClient({
      code: '123456',
      nextCode: '654321',
      digits: 6,
      period: 30,
      validUntilMs: 1_020_000,
      clockSkewMs: 29_000,
    });
    render(<TotpRow client={client} itemId="synthetic-item" />);
    expect(await screen.findByText('123 456')).toBeVisible();
    expect(screen.getByText('20s')).toBeVisible();
    expect(screen.queryByText(/Next:/)).toBeNull();
    expect(screen.queryByText(/clock is about/)).toBeNull();

    // In the last five seconds the next code is shown beside it.
    act(() => {
      vi.setSystemTime(1_016_000);
      vi.advanceTimersByTime(1000);
    });
    expect(screen.getByText('654 321')).toBeVisible();

    act(() => {
      screen.getByRole('button', { name: 'Copy authenticator code' }).click();
    });
    await vi.waitFor(() => {
      expect(writeText).toHaveBeenCalledWith('123456');
    });
    // Copy asks the worker again rather than reusing the shown value.
    expect(calls.filter((c) => c === 'totp').length).toBeGreaterThanOrEqual(2);
  });

  it('warns when the device clock is more than 30 seconds off', async () => {
    const { client } = rowClient({
      code: '12345678',
      nextCode: '87654321',
      digits: 8,
      period: 30,
      validUntilMs: Date.now() + 20_000,
      clockSkewMs: -31_000,
    });
    render(<TotpRow client={client} itemId="synthetic-item" />);
    expect(await screen.findByText('1234 5678')).toBeVisible();
    expect(screen.getByText(/clock is about 31 seconds\s+behind/)).toBeVisible();
  });

  it('groups 6, 7 and 8 digits', () => {
    expect(formatCode('123456')).toBe('123 456');
    expect(formatCode('1234567')).toBe('123 4567');
    expect(formatCode('12345678')).toBe('1234 5678');
  });
});
