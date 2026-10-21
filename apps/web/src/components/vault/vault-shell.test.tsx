import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { previewItems, previewVaults } from '@/preview/fixtures';
import { VaultShell } from './vault-shell';

function renderShell() {
  const user = userEvent.setup();
  render(<VaultShell items={previewItems} vaults={previewVaults} initialSelectedId="i1" />);
  return user;
}

function rows() {
  return within(screen.getByRole('list', { name: /items/i })).getAllByRole('button');
}

beforeAll(() => {
  // jsdom has no matchMedia; the shell only uses it to pick focus targets.
  window.matchMedia = ((query: string) => ({
    matches: false,
    media: query,
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
  })) as unknown as typeof window.matchMedia;
});

describe('VaultShell', () => {
  it('renders navigation, the item list and the selected item', () => {
    renderShell();
    expect(screen.getAllByRole('navigation', { name: 'Vault navigation' })).toHaveLength(1);
    expect(screen.getByRole('heading', { level: 1, name: 'All items' })).toBeInTheDocument();
    expect(screen.getByText('14 items in all vaults')).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 2, name: 'Lumen Mail' })).toBeInTheDocument();
  });

  it('filters by search and announces the result count', async () => {
    const user = renderShell();
    await user.type(screen.getByRole('searchbox', { name: 'Search items' }), 'kes');
    expect(rows().map((row) => row.textContent)).toEqual([
      expect.stringContaining('Kestrel Air'),
      expect.stringContaining('Kestrel Rewards Card'),
    ]);
    expect(screen.getByRole('status')).toHaveTextContent('2 results for “kes”');
  });

  it('shows the no-results state with a working clear action', async () => {
    const user = renderShell();
    await user.type(screen.getByRole('searchbox', { name: 'Search items' }), 'zebra');
    expect(screen.getByRole('heading', { name: 'No items match “zebra”' })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Clear search' }));
    expect(rows()).toHaveLength(14);
  });

  it('moves focus between rows with arrow keys', async () => {
    const user = renderShell();
    const [first, second] = rows();
    first?.focus();
    await user.keyboard('{ArrowDown}');
    expect(second).toHaveFocus();
    await user.keyboard('{End}');
    expect(rows().at(-1)).toHaveFocus();
    await user.keyboard('{Home}');
    expect(first).toHaveFocus();
  });

  it('selects an item and filters by its tag', async () => {
    const user = renderShell();
    await user.click(screen.getByRole('button', { name: /Kestrel Air/ }));
    expect(screen.getByRole('heading', { level: 2, name: 'Kestrel Air' })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Show items tagged travel' }));
    expect(rows()).toHaveLength(2);
    expect(screen.getByRole('button', { name: 'Clear tag filter travel' })).toBeInTheDocument();
  });

  it('never shows secret values and marks unbuilt actions as unavailable', () => {
    renderShell();
    const detail = screen.getByRole('region', { name: 'Item details' });
    expect(within(detail).getByText('••••••••••••')).toBeInTheDocument();
    for (const name of [/^Reveal password/, /^Copy password/, /^Edit/, /^Move to Trash/]) {
      expect(within(detail).getByRole('button', { name })).toHaveAttribute('aria-disabled', 'true');
    }
    expect(screen.getByRole('button', { name: /Add item \(not available yet\)/ })).toHaveAttribute(
      'aria-disabled',
      'true',
    );
    for (const name of ['Security', 'Password generator', 'Settings', 'Lock now']) {
      expect(screen.getByRole('button', { name: `${name} (not available yet)` })).toHaveAttribute(
        'aria-disabled',
        'true',
      );
    }
  });

  it('does not claim the data is synced', () => {
    renderShell();
    expect(screen.queryByText(/^Synced$/)).not.toBeInTheDocument();
    expect(screen.getByText('Sync not set up')).toBeInTheDocument();
  });

  it('switches vaults from a keyboard-operable menu', async () => {
    const user = renderShell();
    const trigger = screen.getByRole('button', { name: /Vault All vaults/ });
    await user.click(trigger);
    const menu = screen.getByRole('menu', { name: 'Choose a vault' });
    expect(within(menu).getByRole('menuitemradio', { name: /All vaults/ })).toHaveFocus();
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('menu')).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();

    await user.click(trigger);
    await user.click(screen.getByRole('menuitemradio', { name: /Side projects/ }));
    expect(screen.getByRole('heading', { name: 'Side projects is empty' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Add a login/ })).toHaveAttribute(
      'aria-disabled',
      'true',
    );
  });

  it('shows the trashed item banner in Trash', async () => {
    const user = renderShell();
    await user.click(screen.getByRole('button', { name: /^Trash/ }));
    expect(screen.getByRole('heading', { level: 1, name: 'Trash' })).toBeInTheDocument();
    expect(screen.getByText(/This item is in Trash/)).toBeInTheDocument();
  });
});
