import { test, expect, enroll } from './browser-fixture.ts';
import type { Page } from '@playwright/test';

const banner = (page: Page) => page.locator('#service-down');
const probe = (page: Page) => page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')));
const noScroll = (page: Page) => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth);

test.use({ viewport: { width: 390, height: 844 } });
test.afterEach(async ({ page }) => { await page.unrouteAll({ behavior: 'wait' }); });

test('a stopped service shows the unreachable banner, never Offline, and Retry recovers after restart', async ({ page, demo }) => {
  await enroll(page, demo);
  await expect(banner(page)).toBeHidden();
  await demo.stopService();
  await probe(page);
  await expect(banner(page)).toBeVisible();
  await expect(banner(page)).toContainText(/Couvre-feu is not responding \(since \d{1,2}:\d{2}[^)]*\)\. Your phone is online\. Nothing was changed\./);
  await expect(banner(page)).not.toContainText(/offline/i);
  await expect(page.locator('#connection')).not.toContainText(/offline/i);
  await expect(page.locator('#connection')).toContainText('read-only snapshot');
  await expect(page.locator('[data-person="alex"]')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Pause Alex (fictional)', exact: true })).toBeDisabled();
  for (const id of ['#service-down', '#connection', '#notice']) expect(await page.locator(id).innerText()).not.toMatch(/\b50[0-9]\b|offline/i);
  await demo.startService();
  await page.getByRole('button', { name: 'Retry' }).click();
  await expect(banner(page)).toBeHidden();
  await expect(page.locator('#connection')).toContainText('Connected');
  await expect(page.getByRole('button', { name: 'Pause Alex (fictional)', exact: true })).toBeEnabled();
});

test('a browser offline event still says Offline and shows no banner', async ({ page, context, demo }) => {
  await enroll(page, demo);
  await context.setOffline(true);
  await expect(page.locator('#connection')).toContainText('Offline · read-only snapshot');
  await expect(banner(page)).toBeHidden();
  await context.setOffline(false);
  await expect(page.locator('#connection')).toContainText('Connected');
});

test('a request that fails because the phone lost its connection mid-flight says Offline, not the banner', async ({ page, demo }) => {
  await enroll(page, demo);
  await page.route('**/people', async (route) => {
    await page.evaluate(() => Object.defineProperty(navigator, 'onLine', { configurable: true, get: () => false }));
    await route.abort('internetdisconnected');
  });
  await probe(page);
  await expect(page.locator('#connection')).toContainText('Offline · read-only snapshot');
  await expect(banner(page)).toBeHidden();
});

test('a 502 from the proxy path shows the banner and clears itself when the service answers', async ({ page, demo }) => {
  await enroll(page, demo);
  let broken = true;
  await page.route('**/people', async (route) => {
    if (broken) await route.fulfill({ status: 502, contentType: 'text/html', body: '<html><body>502 Bad Gateway</body></html>' });
    else await route.continue();
  });
  await probe(page);
  await expect(banner(page)).toBeVisible();
  await expect(banner(page)).toContainText('Couvre-feu is not responding');
  await expect(page.locator('#connection')).not.toContainText(/offline/i);
  await expect(banner(page).locator('details')).toContainText('502'); // status only inside the Details disclosure
  await expect(banner(page).locator('p').first()).not.toContainText('502');
  broken = false;
  await probe(page);
  await expect(banner(page)).toBeHidden();
});

test('the since-time is when the failure first happened and is not reset by retries', async ({ page, demo }) => {
  await enroll(page, demo);
  await demo.stopService();
  await probe(page);
  await expect(banner(page)).toBeVisible();
  const first = await banner(page).getAttribute('data-since');
  expect(first).toMatch(/^\d+$/);
  await page.waitForTimeout(1200); // timeout-ok: lets the second-resolution since stamp move if a retry wrongly reset it
  await page.getByRole('button', { name: 'Retry' }).click();
  await expect(page.getByRole('button', { name: 'Retry' })).toBeEnabled();
  await page.waitForTimeout(1200); // timeout-ok: same, second retry
  await page.getByRole('button', { name: 'Retry' }).click();
  await expect(page.getByRole('button', { name: 'Retry' })).toBeEnabled();
  expect(await banner(page).getAttribute('data-since')).toBe(first);
});

test('the banner fits 390 px with a 44 px Retry target, keeps focus and uses a status role', async ({ page, demo }) => {
  await enroll(page, demo);
  await demo.stopService();
  await page.locator('#main').focus();
  await probe(page);
  await expect(banner(page)).toBeVisible();
  expect(await noScroll(page)).toBe(true);
  expect(await banner(page).getAttribute('role')).toBe('status');
  const box = await page.getByRole('button', { name: 'Retry' }).boundingBox();
  expect(box!.height).toBeGreaterThanOrEqual(44);
  expect(box!.width).toBeGreaterThanOrEqual(44);
  expect(await page.evaluate(() => document.activeElement?.id)).toBe('main');
});
