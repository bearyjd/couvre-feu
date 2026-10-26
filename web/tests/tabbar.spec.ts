import { test, expect, enroll } from './browser-fixture.ts';

const bar = (page: import('@playwright/test').Page) => page.locator('.tablist');

test('sign-in screen shows no tab bar', async ({ page, demo }) => {
  await page.goto(demo.origin);
  await expect(page.locator('#auth-view')).toBeVisible();
  await expect(page.locator('.tabbar')).toBeHidden();
  await expect(page.getByRole('tab')).toHaveCount(0);
});

test('default overview keeps every section visible; tabs switch groups and set aria state', async ({ page, demo }) => {
  await enroll(page, demo, 'bryn');
  await expect(bar(page)).toBeVisible();
  await expect(page.getByRole('tab', { name: 'Overview' })).toHaveAttribute('aria-selected', 'true');
  await expect(page.locator('#people')).toBeVisible();
  await expect(page.locator('#schedule-editor')).toBeVisible();
  await page.getByRole('tab', { name: 'Schedules' }).click();
  await expect(page.getByRole('tab', { name: 'Schedules' })).toHaveAttribute('aria-selected', 'true');
  await expect(page.getByRole('tab', { name: 'Overview' })).toHaveAttribute('aria-selected', 'false');
  await expect(page.locator('#schedule-editor')).toBeVisible();
  await expect(page.locator('#people')).toBeHidden();
  await expect(page.locator('#parent-alerts')).toBeHidden();
  await page.getByRole('tab', { name: /^Activity/ }).click();
  await expect(page.locator('#operational-alerts')).toBeVisible();
  await expect(page.locator('#schedule-editor')).toBeHidden();
  // The bar never covers the footer: the last content can scroll fully clear of it.
  await page.locator('footer').scrollIntoViewIfNeeded();
  const [barTop, footerBottom] = await Promise.all([page.locator('.tabbar').evaluate((el) => el.getBoundingClientRect().top), page.locator('footer').evaluate((el) => el.getBoundingClientRect().bottom)]);
  expect(footerBottom).toBeLessThanOrEqual(barTop + 1);
});

test('arrow, Home and End keys move between tabs with roving tabindex', async ({ page, demo }) => {
  await enroll(page, demo, 'bryn');
  await page.getByRole('tab', { name: 'Overview' }).focus();
  await page.keyboard.press('ArrowRight');
  await expect(page.getByRole('tab', { name: 'Schedules' })).toBeFocused();
  await expect(page.getByRole('tab', { name: 'Schedules' })).toHaveAttribute('aria-selected', 'true');
  await expect(page.getByRole('tab', { name: 'Schedules' })).toHaveAttribute('tabindex', '0');
  await expect(page.getByRole('tab', { name: 'Overview' })).toHaveAttribute('tabindex', '-1');
  await page.keyboard.press('End');
  await expect(page.getByRole('tab', { name: 'Devices' })).toBeFocused();
  await page.keyboard.press('ArrowRight');
  await expect(page.getByRole('tab', { name: 'Overview' })).toBeFocused();
  await page.keyboard.press('ArrowLeft');
  await expect(page.getByRole('tab', { name: 'Devices' })).toHaveAttribute('aria-selected', 'true');
});

test('last tab is remembered for the session and deep links select a tab', async ({ page, demo }) => {
  await enroll(page, demo, 'bryn');
  await page.getByRole('tab', { name: 'Requests' }).click();
  await expect(page.locator('#people')).toBeHidden();
  await page.goto(demo.origin);
  await expect(page.locator('#status-view')).toBeVisible();
  await expect(page.getByRole('tab', { name: 'Requests' })).toHaveAttribute('aria-selected', 'true');
  await page.goto(`${demo.origin}/#devices`);
  await page.reload();
  await expect(page.getByRole('tab', { name: 'Devices' })).toHaveAttribute('aria-selected', 'true');
});

test('tabpanel wraps the content groups outside the tablist and every tab controls it', async ({ page, demo }) => {
  await enroll(page, demo, 'bryn');
  const panel = page.getByRole('tabpanel');
  await expect(panel).toHaveCount(1);
  await expect(panel).toHaveAttribute('id', 'tab-panel');
  await expect(panel.locator('.tablist')).toHaveCount(0);
  await expect(panel.locator('#people')).toHaveCount(1);
  for (const tab of await page.getByRole('tab').all()) await expect(tab).toHaveAttribute('aria-controls', 'tab-panel');
  await expect(page.locator('nav')).toHaveCount(0);
  await page.getByRole('tab', { name: 'Schedules' }).click();
  await expect(panel).toHaveAttribute('aria-labelledby', 'tab-schedules');
  await expect(page.getByRole('tablist', { name: 'Sections' })).toBeVisible();
});

test('a tab with no visible sections shows an empty-state message instead of a blank page', async ({ page, demo }) => {
  await enroll(page, demo, 'bryn');
  await page.getByRole('tab', { name: 'Requests' }).click();
  await page.evaluate(() => document.querySelectorAll('#tab-panel [data-tab-group="requests"]').forEach((node) => { (node as HTMLElement).hidden = true; }));
  await expect(page.locator('#tab-empty')).toBeVisible();
  await expect(page.locator('#tab-empty')).toContainText('Nothing to show here yet');
  await page.evaluate(() => document.querySelectorAll('#tab-panel [data-tab-group="requests"]').forEach((node) => { (node as HTMLElement).hidden = false; }));
  await expect(page.locator('#tab-empty')).toBeHidden();
  await page.getByRole('tab', { name: 'Overview' }).click();
  await expect(page.locator('#tab-empty')).toBeHidden();
});

test('signing out forgets the remembered tab and the next sign-in starts on Overview', async ({ page, demo }) => {
  await enroll(page, demo, 'bryn');
  await page.getByRole('tab', { name: 'Devices' }).click();
  expect(await page.evaluate(() => sessionStorage.getItem('cf-tab'))).toBe('devices');
  await page.getByRole('button', { name: 'Sign out', exact: true }).click();
  await expect(page.locator('#auth-view')).toBeVisible();
  expect(await page.evaluate(() => sessionStorage.getItem('cf-tab'))).toBeNull();
  expect(await page.evaluate(() => location.hash)).toBe('');
  await page.getByRole('button', { name: 'Sign in with a passkey' }).click();
  await expect(page.locator('#status-view')).toBeVisible();
  await expect(page.getByRole('tab', { name: 'Overview' })).toHaveAttribute('aria-selected', 'true');
  await expect(page.locator('#people')).toBeVisible();
});

test('destructive buttons carry data-risk="destructive"', async ({ page, demo }) => {
  await enroll(page, demo, 'bryn');
  await page.getByRole('tab', { name: 'Devices' }).click();
  await expect(page.getByRole('button', { name: /^Remove my passkey/ })).toHaveAttribute('data-risk', 'destructive');
  const unmarked = await page.evaluate(() => [...document.querySelectorAll('.button[aria-label^="Remove"], .button[aria-label^="Disable"]')].filter((b) => b.getAttribute('data-risk') !== 'destructive').length);
  expect(unmarked).toBe(0);
  await expect(page.locator('[data-risk="destructive"]').first()).toBeVisible();
});

test('hashchange on a live page switches tabs', async ({ page, demo }) => {
  await enroll(page, demo, 'bryn');
  await page.evaluate(() => { location.hash = '#activity'; });
  await expect(page.getByRole('tab', { name: /^Activity/ })).toHaveAttribute('aria-selected', 'true');
  await expect(page.locator('#people')).toBeHidden();
  await page.evaluate(() => { location.hash = '#devices'; });
  await expect(page.getByRole('tab', { name: 'Devices' })).toHaveAttribute('aria-selected', 'true');
});

test('at 900px and wider the bar is hidden and nothing is filtered even after choosing a tab', async ({ page, demo }) => {
  await enroll(page, demo, 'bryn');
  await page.getByRole('tab', { name: 'Devices' }).click();
  await page.setViewportSize({ width: 1000, height: 900 });
  await expect(page.locator('.tabbar')).toBeHidden();
  await expect(page.locator('#people')).toBeVisible();
  await expect(page.locator('#schedule-editor')).toBeVisible();
  await expect(page.locator('#operational-alerts')).toBeVisible();
  await expect(page.locator('#tab-empty')).toBeHidden();
});
