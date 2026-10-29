import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ItemSummary } from '@ruvee/vault';
import type { VaultClient } from '@/vault/client';
import { ItemEditor } from './item-editor';

/**
 * Follow-up review F-20: a save that finishes after the user moved on to another editor must not
 * close that editor (and discard what is typed there). The save itself still happens.
 */
function deferredClient() {
  let finish: (saved: ItemSummary) => void = () => undefined;
  const calls: string[] = [];
  const client = {
    call: (method: string) => {
      calls.push(method);
      return new Promise<ItemSummary>((resolve) => {
        finish = resolve;
      });
    },
  } as unknown as VaultClient;
  return {
    client,
    calls,
    finish: (saved: ItemSummary) => {
      finish(saved);
    },
  };
}

const saved = { id: 'synthetic-item', title: 'Synthetic' } as unknown as ItemSummary;

describe('ItemEditor (F-20)', () => {
  it('a save that finishes after this editor was replaced does not report to its old owner', async () => {
    const user = userEvent.setup();
    const { client, calls, finish } = deferredClient();
    const onSaved = vi.fn();
    const first = render(
      <ItemEditor
        key="first"
        client={client}
        existing={null}
        onCancel={() => undefined}
        onSaved={onSaved}
      />,
    );
    await user.type(screen.getByLabelText('Title (required)'), 'Synthetic first');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(calls).toEqual(['save']);
    // The user opens another editor before the save answers.
    first.rerender(
      <ItemEditor
        key="second"
        client={client}
        existing={null}
        onCancel={() => undefined}
        onSaved={vi.fn()}
      />,
    );
    await user.type(screen.getByLabelText('Title (required)'), 'Typed in the second editor');
    finish(saved);
    await new Promise((r) => setTimeout(r, 0));
    expect(onSaved).not.toHaveBeenCalled();
    expect(screen.getByLabelText('Title (required)')).toHaveValue('Typed in the second editor');
  });

  it('a save that finishes while its editor is open reports as before', async () => {
    const user = userEvent.setup();
    const { client, finish } = deferredClient();
    const onSaved = vi.fn();
    render(
      <ItemEditor client={client} existing={null} onCancel={() => undefined} onSaved={onSaved} />,
    );
    await user.type(screen.getByLabelText('Title (required)'), 'Synthetic only');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    finish(saved);
    await new Promise((r) => setTimeout(r, 0));
    expect(onSaved).toHaveBeenCalledWith(saved);
  });
});
