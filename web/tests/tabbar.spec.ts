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
