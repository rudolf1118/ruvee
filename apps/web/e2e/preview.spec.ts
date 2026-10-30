import AxeBuilder from '@axe-core/playwright';
import { expect, type Page, test } from '@playwright/test';

async function openPreview(page: Page) {
  await page.goto('/preview');
  await expect(page.getByRole('note').filter({ hasText: 'Development preview' })).toBeVisible();
}

test('has no detectable accessibility violations', async ({ page }) => {
  await openPreview(page);
  const results = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21aa'])
    .analyze();
  expect(results.violations.map((v) => `${v.id}: ${v.help}`)).toEqual([]);
});

test('opens on the welcome screen, marked as an unreviewed development build', async ({ page }) => {
  await page.goto('/');
  await expect(
    page.getByRole('heading', { name: 'Keep every password in one calm, safe place.' }),
  ).toBeVisible();
  await expect(page.getByText('Development build, not reviewed.')).toBeVisible();
  await expect(page.getByRole('link', { name: 'Open the interface preview' })).toBeVisible();
});

test.describe('desktop layout', () => {
  test.skip(({ isMobile }) => isMobile, 'desktop only');

  test('shows navigation, list and detail side by side', async ({ page }) => {
    await openPreview(page);
    await expect(page.getByRole('navigation', { name: 'Vault navigation' })).toBeVisible();
    await expect(page.getByRole('heading', { level: 1, name: 'All items' })).toBeVisible();
    await expect(page.getByRole('heading', { level: 2, name: 'Lumen Mail' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Open navigation' })).toBeHidden();
  });

  test('supports keyboard navigation with a visible focus ring', async ({ page }) => {
    await openPreview(page);
    await page.keyboard.press('Tab');
    const skip = page.getByRole('link', { name: 'Skip to items' });
    await expect(skip).toBeFocused();
    await expect(skip).toBeVisible();

    const search = page.getByRole('searchbox', { name: 'Search items' });
    await search.focus();
    await search.press('ArrowDown');
    const firstRow = page.getByRole('button', { name: /^Brightline Energy/ });
    await expect(firstRow).toBeFocused();
    const outline = await firstRow.evaluate((el) => getComputedStyle(el).outlineStyle);
    expect(outline).not.toBe('none');

    await page.keyboard.press('ArrowDown');
    await page.keyboard.press('Enter');
    await expect(page.getByRole('heading', { level: 2, name: 'Cobalt Code' })).toBeVisible();
  });
});

test.describe('mobile layout', () => {
  test.skip(({ isMobile }) => !isMobile, 'mobile only');

  test('moves between list and detail screens', async ({ page }) => {
    await openPreview(page);
    await expect(page.getByRole('region', { name: 'Item details' })).toBeHidden();
    await page.getByRole('button', { name: /^Kestrel Air/ }).click();
    const heading = page.getByRole('heading', { level: 2, name: 'Kestrel Air' });
    await expect(heading).toBeVisible();
    await expect(heading).toBeFocused();
    await expect(page.getByRole('region', { name: 'Items' })).toBeHidden();

    await page.getByRole('button', { name: 'Back to items' }).click();
    await expect(page.getByRole('button', { name: /^Kestrel Air/ })).toBeFocused();
  });

  test('opens navigation in a drawer that Escape closes', async ({ page }) => {
    await openPreview(page);
    const open = page.getByRole('button', { name: 'Open navigation' });
    await open.click();
    const drawer = page.getByRole('dialog', { name: 'Navigation' });
    await expect(drawer).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(drawer).toBeHidden();
    await expect(open).toBeFocused();

    await open.click();
    await drawer.getByRole('button', { name: /^Payment cards/ }).click();
    await expect(drawer).toBeHidden();
    await expect(page.getByRole('heading', { level: 1, name: 'Payment cards' })).toBeVisible();
  });
});
