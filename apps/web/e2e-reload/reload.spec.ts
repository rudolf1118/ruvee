import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { type BrowserContext, expect, type Page, test } from '@playwright/test';
import pg from 'pg';
import { STATE_FILE } from '../playwright.reload.config';

/**
 * D-34 web reload tickets in a real browser against the real API (web-reload-unlock.md §7,
 * INV-25): a reload stays unlocked without the password; lock, logout, auto-lock, the idle limit
 * and 3 minutes without a heartbeat each end the ticket, and the next load asks for the password.
 * The spec ages ticket rows in the stack's throwaway database instead of waiting. Synthetic data
 * only.
 */

const USERNAME = 'synthetic-reload-owner';
const MASTER = 'synthetic reload harbor lantern 71';
const NOTE = 'Synthetic Reload Note';
const KEY = 'ruvee-reload-ticket';

interface Ticket {
  ticketId: string;
  tabHalf: string;
  envelope: string;
}

function state(): { bootstrapToken: string; database: string } {
  return JSON.parse(readFileSync(STATE_FILE, 'utf8')) as {
    bootstrapToken: string;
    database: string;
  };
}

/** A statement on the stack's own throwaway database, as its administrator. */
async function sql<T extends pg.QueryResultRow>(text: string): Promise<T[]> {
  const url = new URL(process.env.RUVEE_E2E_ADMIN_DATABASE_URL ?? '');
  url.pathname = `/${state().database}`;
  const client = new pg.Client({ connectionString: url.toString() });
  await client.connect();
  try {
    return (await client.query<T>(text)).rows;
  } finally {
    await client.end();
  }
}

const ticketRows = () => sql<{ id_hash: Buffer }>('SELECT id_hash FROM reload_tickets');

function stored(page: Page): Promise<Ticket | null> {
  return page.evaluate((key) => {
    const text = sessionStorage.getItem(key);
    return text === null ? null : (JSON.parse(text) as Ticket);
  }, KEY);
}

/** Waits until the tab holds a ticket other than `previous`, and returns it. */
async function nextTicket(page: Page, previous?: string): Promise<Ticket> {
  await expect
    .poll(
      async () => {
        const id = (await stored(page))?.ticketId;
        return id !== undefined && id !== previous;
      },
      { timeout: 15_000 },
    )
    .toBe(true);
  const ticket = await stored(page);
  if (!ticket) throw new Error('no ticket');
  return ticket;
}

const unlocked = (page: Page) =>
  expect(page.getByRole('heading', { level: 1, name: 'All items' })).toBeVisible({
    timeout: 30_000,
  });
const locked = (page: Page) =>
  expect(page.getByRole('heading', { name: 'Your vault is locked' })).toBeVisible({
    timeout: 30_000,
  });

async function unlock(page: Page) {
  await page.getByRole('textbox', { name: 'Master password', exact: true }).fill(MASTER);
  await page.getByRole('button', { name: 'Unlock' }).click();
  await unlocked(page);
}

/** A new tab whose sessionStorage starts with `ticket`, as a session restore would bring back. */
async function restoredTab(context: BrowserContext, ticket: Ticket): Promise<Page> {
  const page = await context.newPage();
  await page.addInitScript(
    ([key, value]) => {
      if (sessionStorage.getItem('spec-restored') === null) {
        sessionStorage.setItem('spec-restored', '1');
        sessionStorage.setItem(key, value);
      }
    },
    [KEY, JSON.stringify(ticket)] as const,
  );
  await page.goto('/');
  return page;
}

test.describe.configure({ mode: 'serial' });

test('reload tickets: resume, single use, lock, logout, closed tab, idle, auto-lock, heartbeat', async ({
  browser,
}) => {
  test.setTimeout(300_000);
  const context = await browser.newContext();
  const bodies: string[] = [];
  context.on('request', (request) => {
    const body = request.postData();
    if (body) bodies.push(body);
  });
  let page = await context.newPage();

  // ---- Setup: the first unlock issues a ticket ----
  await page.goto('/');
  await page.getByRole('button', { name: 'Create an account' }).click();
  await page.getByLabel('Setup token').fill(state().bootstrapToken);
  await page.getByLabel('Username').fill(USERNAME);
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByRole('textbox', { name: 'Master password', exact: true }).fill(MASTER);
  await page.getByRole('textbox', { name: 'Type it again', exact: true }).fill(MASTER);
  await page.getByRole('checkbox').check();
  await page.getByRole('button', { name: 'Continue' }).click();
  const kit = (await page.getByTestId('recovery-key').innerText()).trim();
  await page.getByRole('button', { name: "I've saved it" }).click();
  await page.getByLabel('Recovery Key').fill(kit);
  await page.getByRole('button', { name: 'Finish setup' }).click();
  await unlocked(page);
  await page.getByRole('button', { name: 'Add item' }).click();
  await page.getByRole('radio', { name: 'Secure note' }).click();
  await page.getByLabel('Title (required)').fill(NOTE);
  await page.getByLabel('Note').fill('synthetic reload body');
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByRole('heading', { level: 2, name: NOTE })).toBeVisible();

  let ticket = await nextTicket(page);
  expect(Object.keys(ticket).sort()).toEqual(['envelope', 'tabHalf', 'ticketId']);
  // The server keeps only SHA-256 of the ticket id.
  const rows = await ticketRows();
  expect(rows).toHaveLength(1);
  expect(rows[0]?.id_hash).toEqual(
    createHash('sha256').update(Buffer.from(ticket.ticketId, 'base64url')).digest(),
  );

  // ---- A reload stays unlocked without the password, and the ticket is replaced ----
  await page.reload();
  await unlocked(page);
  await expect(page.getByRole('button', { name: new RegExp(NOTE) })).toBeVisible();
  const afterReload = await nextTicket(page, ticket.ticketId);
  // Single use: the old ticket is gone; one row, the new one.
  expect(await ticketRows()).toHaveLength(1);
  // The tab half and the sealed AK never went to the server (INV-01).
  for (const t of [ticket, afterReload]) {
    expect(bodies.join('\n')).not.toContain(t.tabHalf);
    expect(bodies.join('\n')).not.toContain(t.envelope);
  }
  ticket = afterReload;

  // ---- A heartbeat moves the 3-minute limit (page clock, real server) ----
  await page.clock.install();
  await page.reload();
  await unlocked(page);
  await nextTicket(page, ticket.ticketId);
  await sql(`UPDATE reload_tickets SET expires_at = now() + interval '20 seconds'`);
  await page.clock.fastForward('01:05');
  await expect
    .poll(
      async () =>
        (
          await sql<{ left: number }>(
            `SELECT extract(epoch FROM expires_at - now())::float AS left FROM reload_tickets`,
          )
        )[0]?.left ?? 0,
      { timeout: 15_000 },
    )
    .toBeGreaterThan(150);

  // ---- Auto-lock in the page (D-10) ends it; the next load asks for the password ----
  await page.clock.fastForward('16:00');
  await locked(page);
  expect(await stored(page)).toBeNull();
  await expect.poll(async () => (await ticketRows()).length, { timeout: 15_000 }).toBe(0);
  await page.reload();
  await locked(page);
  await page.close();
  page = await context.newPage();
  await page.goto('/');
  await locked(page);
  await unlock(page);
  await nextTicket(page);

  // ---- Lock now ends it ----
  await page.getByRole('button', { name: 'Lock now' }).click();
  await locked(page);
  expect(await stored(page)).toBeNull();
  await expect.poll(async () => (await ticketRows()).length, { timeout: 15_000 }).toBe(0);
  await page.reload();
  await locked(page);

  // ---- The idle limit on the server ends it even when the page did not lock ----
  await unlock(page);
  await nextTicket(page);
  await sql(
    `UPDATE reload_tickets SET created_at = now() - interval '20 minutes',
                               idle_expires_at = now() - interval '1 second'`,
  );
  await page.reload();
  await locked(page);
  expect(await stored(page)).toBeNull();

  // ---- A closed tab: inside the 3 minutes a restored copy resumes (the stated window) ----
  await unlock(page);
  ticket = await nextTicket(page);
  await page.close();
  page = await restoredTab(context, ticket);
  await unlocked(page);
  ticket = await nextTicket(page, ticket.ticketId);

  // ---- ... and after 3 minutes without a heartbeat it does not ----
  await page.close();
  await sql(
    `UPDATE reload_tickets SET created_at = now() - interval '10 minutes',
                               expires_at = now() - interval '1 second'`,
  );
  page = await restoredTab(context, ticket);
  await locked(page);
  expect(await stored(page)).toBeNull();

  // ---- The API unreachable at load: the lock screen; the password still works offline ----
  await unlock(page);
  await nextTicket(page);
  await context.route('**/api/v1/reload-tickets/redeem', (route) => route.abort());
  await page.reload();
  await locked(page);
  await context.unroute('**/api/v1/reload-tickets/redeem');
  await unlock(page);
  await nextTicket(page);

  // ---- Logout ends it on the server at once ----
  await page.getByRole('button', { name: 'Log out' }).click();
  await locked(page);
  expect(await stored(page)).toBeNull();
  expect(await ticketRows()).toHaveLength(0);
  await page.reload();
  await locked(page);

  await context.close();
});
