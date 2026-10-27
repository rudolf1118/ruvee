// The web app in Chromium (Playwright), driven through its real UI on the static export: the
// same build, headers and CSP a user gets. It plays "a device you already use".

import { chromium, type Browser, type Page } from 'playwright-core';

export class WebDevice {
  private readonly browser: Browser;
  readonly page: Page;

  private constructor(browser: Browser, page: Page) {
    this.browser = browser;
    this.page = page;
  }

  static async open(origin: string): Promise<WebDevice> {
    const browser = await chromium.launch({
      headless: true,
      ...(process.env.PLAYWRIGHT_CHANNEL ? { channel: process.env.PLAYWRIGHT_CHANNEL } : {}),
    });
    const context = await browser.newContext({
      baseURL: origin,
      viewport: { width: 1440, height: 900 },
    });
    const page = await context.newPage();
    page.setDefaultTimeout(30_000);
    await page.goto('/');
    return new WebDevice(browser, page);
  }

  async createAccount(p: {
    bootstrapToken: string;
    username: string;
    password: string;
  }): Promise<string> {
    const a = this.page;
    await a.getByRole('button', { name: 'Create an account' }).click();
    await a.getByLabel('Setup token').fill(p.bootstrapToken);
    await a.getByLabel('Username').fill(p.username);
    await a.getByRole('button', { name: 'Continue' }).click();
    await a.getByRole('textbox', { name: 'Master password', exact: true }).fill(p.password);
    await a.getByRole('textbox', { name: 'Type it again', exact: true }).fill(p.password);
    await a.getByRole('checkbox').check();
    await a.getByRole('button', { name: 'Continue' }).click();
    const kit = (await a.getByTestId('recovery-key').innerText()).trim();
    await a.getByRole('button', { name: "I've saved it" }).click();
    await a.getByLabel('Recovery Key').fill(kit);
    await a.getByRole('button', { name: 'Finish setup' }).click();
    await a.getByRole('heading', { level: 1, name: 'All items' }).waitFor({ timeout: 60_000 });
    return kit;
  }

  async addLogin(p: {
    title: string;
    url: string;
    username: string;
    password: string;
  }): Promise<void> {
    const a = this.page;
    await a.getByRole('button', { name: 'Add item' }).click();
    await a.getByLabel('Title (required)').fill(p.title);
    await a.getByLabel('Website').fill(p.url);
    await a.getByLabel('Username or email').fill(p.username);
    await a.getByRole('textbox', { name: 'Password', exact: true }).fill(p.password);
    await a.getByRole('button', { name: 'Save' }).click();
    await a.getByRole('heading', { level: 2, name: p.title }).waitFor();
  }

  async addNote(p: { title: string; text: string }): Promise<void> {
    const a = this.page;
    await a.getByRole('button', { name: 'Add item' }).click();
    await a.getByRole('radio', { name: 'Secure note' }).click();
    await a.getByLabel('Title (required)').fill(p.title);
    await a.getByLabel('Note').fill(p.text);
    await a.getByRole('button', { name: 'Save' }).click();
    await a.getByRole('heading', { level: 2, name: p.title }).waitFor();
  }

  row(title: string | RegExp) {
    return this.page.locator('#item-list').getByRole('button', { name: title });
  }

  async renameItem(from: string | RegExp, to: string): Promise<void> {
    const a = this.page;
    await this.row(from).click();
    await a.getByRole('button', { name: 'Edit' }).click();
    await a.getByLabel('Title (required)').fill(to);
    await a.getByRole('button', { name: 'Save' }).click();
    await a.getByRole('heading', { level: 2, name: to }).waitFor();
    await this.waitSynced();
  }

  async waitSynced(): Promise<void> {
    await this.page.getByRole('status').filter({ hasText: 'Synced' }).waitFor({ timeout: 30_000 });
  }

  async syncNow(): Promise<void> {
    await this.page.getByRole('button', { name: 'Sync now' }).click();
  }

  /** Starts a pairing on this device and returns the code to type on the new device. */
  async startPairing(): Promise<string> {
    const a = this.page;
    await a.getByRole('button', { name: 'Devices' }).click();
    await a.getByRole('button', { name: 'Add a device' }).click();
    const box = a.getByTestId('pairing-code');
    await box.filter({ hasText: /^PC1-/ }).waitFor();
    return (await box.innerText()).trim();
  }

  async approvePairing(platformName: string): Promise<void> {
    const a = this.page;
    await a.getByText(new RegExp(`Approve a new\\s+${platformName}`)).waitFor({ timeout: 60_000 });
    await a.getByRole('button', { name: 'Approve' }).click();
    await a.getByText('The new device was added.').waitFor();
    await a.getByRole('button', { name: 'Done' }).click();
  }

  async openItems(): Promise<void> {
    await this.page.getByRole('button', { name: 'All items' }).first().click();
  }

  async changePassword(current: string, next: string): Promise<void> {
    const a = this.page;
    await a.getByRole('button', { name: 'Security', exact: true }).click();
    await a.getByRole('textbox', { name: 'Current master password', exact: true }).fill(current);
    await a.getByRole('textbox', { name: 'New master password', exact: true }).fill(next);
    await a.getByRole('textbox', { name: 'Type the new password again', exact: true }).fill(next);
    await a.getByRole('button', { name: 'Change password' }).click();
    await a.getByText('Your master password was changed.').waitFor({ timeout: 60_000 });
  }

  /** Removes the one device added by pairing, as "no longer used" (the default reason). */
  async removePairedDevice(password: string): Promise<void> {
    const a = this.page;
    await a.getByRole('button', { name: 'Devices' }).click();
    const device = a.getByRole('listitem').filter({ hasText: 'added with a pairing code' });
    await device.getByRole('button', { name: /^Remove/ }).click();
    await a.getByRole('textbox', { name: 'Master password', exact: true }).fill(password);
    await a.getByRole('button', { name: 'Remove device' }).click();
    await a.getByText(/^Removed/).waitFor({ timeout: 60_000 });
  }

  async close(): Promise<void> {
    await this.browser.close();
  }
}
