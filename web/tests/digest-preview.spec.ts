import { test, expect, signIn } from './bulk-fixture.ts';
import type { Page } from '@playwright/test';
import { readFile } from 'node:fs/promises';

const MAC_PATTERN = /[0-9a-f]{2}(:[0-9a-f]{2}){5}/i;
const panel = (page: Page) => page.locator('#digest-preview-panel');
// Sunday 2026-11-15 18:00 and Sunday 2026-11-22 18:00 in America/New_York (EST, UTC-5).
const PERIOD = { start: 1794783600, end: 1795388400 };
const BODY = { period: PERIOD, counts: { requests: 7, grants: 4, pauses: 2 }, blockedLookups: { firstDay: '2026-11-15', lastDay: '2026-11-21', count: 31, daysCounted: 3 } };
const json = (body: unknown, status = 200) => ({ status, contentType: 'application/json', headers: { 'Cache-Control': 'no-store' }, body: JSON.stringify(body) });
const counts = (page: Page) => panel(page).locator('[data-count]');

test('admin sees the period in New York time, three counts and the partial blocked-lookup coverage', async ({ page, integration: f }) => {
  f.config.digestPreview = { enabled: true };
  await page.route('**/digest/preview', (route) => route.fulfill(json(BODY)));
  await signIn(page, f, 'operator');
  await page.locator('#tab-more').click();
  await expect(panel(page).getByRole('heading', { name: 'Weekly digest preview' })).toBeVisible();
  await expect(panel(page).locator('[data-period]')).toContainText('Last full week:');
  await expect(panel(page).locator('[data-period]')).toContainText('Nov 15');
  await expect(panel(page).locator('[data-period]')).toContainText('Nov 22');
  await expect(panel(page).locator('[data-period]')).toContainText('6:00');
  await expect(panel(page).locator('[data-count="requests"]')).toHaveText('7');
  await expect(panel(page).locator('[data-count="grants"]')).toHaveText('4');
  await expect(panel(page).locator('[data-count="pauses"]')).toHaveText('2');
  await expect(panel(page).locator('[data-blocked]')).toHaveText('Blocked website lookups: 31 (2026-11-15 to 2026-11-21) 3 of 7 days counted');
  await expect(page.locator('#more-jump a[data-target="#digest-preview-panel"]')).toBeVisible();
});

test('full coverage drops the "of 7" qualifier; a body without blockedLookups shows no blocked line', async ({ page, integration: f }) => {
  f.config.digestPreview = { enabled: true };
  let body: unknown = { ...BODY, blockedLookups: { ...BODY.blockedLookups, daysCounted: 7 } };
  await page.route('**/digest/preview', (route) => route.fulfill(json(body)));
  await signIn(page, f, 'operator');
  await page.locator('#tab-more').click();
  await expect(panel(page).locator('[data-blocked]')).toHaveText('Blocked website lookups: 31 (2026-11-15 to 2026-11-21)');
  body = { period: PERIOD, counts: BODY.counts };
  await page.reload();
  await page.locator('#tab-more').click();
  await expect(counts(page)).toHaveCount(3);
  await expect(panel(page).locator('[data-blocked]')).toHaveCount(0);
  await expect(panel(page)).not.toContainText('Blocked website lookups');
});

test('a real 200 with zero counts shows 0 for all three', async ({ page, integration: f }) => {
  f.config.digestPreview = { enabled: true };
  await signIn(page, f, 'operator');
  await page.locator('#tab-more').click();
  for (const name of ['requests', 'grants', 'pauses']) await expect(panel(page).locator(`[data-count="${name}"]`)).toHaveText('0');
  await expect(panel(page)).not.toContainText('unavailable');
});

test('503 shows unavailable with no counts, and Try again refetches then shows data', async ({ page, integration: f }) => {
  f.config.digestPreview = { enabled: true };
  let fail = true;
  await page.route('**/digest/preview', (route) => route.fulfill(fail ? json({ error: { code: 'digest_preview_unavailable' } }, 503) : json(BODY)));
  await signIn(page, f, 'operator');
  await page.locator('#tab-more').click();
  await expect(panel(page).getByRole('status')).toContainText('Digest preview unavailable');
  await expect(counts(page)).toHaveCount(0);
  await expect(panel(page)).not.toContainText(/\b0\b/);
  fail = false;
  await panel(page).getByRole('button', { name: 'Try again' }).click();
  await expect(panel(page).locator('[data-count="requests"]')).toHaveText('7');
});

test('flag off: the request is a 404, the panel stays hidden, no error is shown', async ({ page, integration: f }) => {
  const statuses: number[] = [];
  page.on('response', (r) => { if (new URL(r.url()).pathname === '/digest/preview') statuses.push(r.status()); });
  await signIn(page, f, 'operator');
  await page.locator('#tab-more').click();
  await expect.poll(() => statuses).toEqual([404]);
  await expect(panel(page)).toBeHidden();
  await expect(page.locator('#more-jump a[data-target="#digest-preview-panel"]')).toBeHidden();
  await expect(page.getByText('Digest preview unavailable')).toHaveCount(0);
});

test('an ordinary parent never requests the preview and sees no panel', async ({ page, integration: f }) => {
  f.config.digestPreview = { enabled: true };
  let requests = 0;
  page.on('request', (r) => { if (new URL(r.url()).pathname === '/digest/preview') requests++; });
  await signIn(page, f, 'parent');
  await page.locator('#tab-more').click();
  await page.waitForTimeout(500);
  expect(requests).toBe(0);
  await expect(panel(page)).toBeHidden();
});

test('sign-out empties and hides the panel and nothing is persisted', async ({ page, integration: f }) => {
  f.config.digestPreview = { enabled: true };
  await page.route('**/digest/preview', (route) => route.fulfill(json(BODY)));
  await signIn(page, f, 'operator');
  await page.locator('#tab-more').click();
  await expect(panel(page).locator('[data-count="requests"]')).toHaveText('7');
  await page.locator('#logout').click();
  await expect(panel(page)).toBeHidden();
  expect(await panel(page).evaluate((n) => n.children.length)).toBe(0);
  const stores = await page.evaluate(async () => ({
    local: JSON.stringify({ ...localStorage }), session: JSON.stringify({ ...sessionStorage }),
  }));
  for (const value of Object.values(stores)) { expect(value).not.toMatch(/digest/i); expect(value).not.toContain('"requests"'); }
});

test('offline hides the panel and coming back online fetches and shows it again', async ({ page, context, integration: f }) => {
  f.config.digestPreview = { enabled: true };
  let fetches = 0;
  await page.route('**/digest/preview', (route) => { fetches++; return route.fulfill(json(BODY)); });
  await signIn(page, f, 'operator');
  await page.locator('#tab-more').click();
  await expect(panel(page).locator('[data-count="requests"]')).toHaveText('7');
  await context.setOffline(true);
  await expect(panel(page)).toBeHidden();
  await context.setOffline(false);
  await expect(panel(page).locator('[data-count="requests"]')).toHaveText('7');
  expect(fetches).toBeGreaterThanOrEqual(2);
});

test('403 hides the panel without an unavailable message', async ({ page, integration: f }) => {
  f.config.digestPreview = { enabled: true };
  await page.route('**/digest/preview', (route) => route.fulfill(json({ error: { code: 'forbidden' } }, 403)));
  await signIn(page, f, 'operator');
  await page.locator('#tab-more').click();
  await page.waitForTimeout(300);
  await expect(panel(page)).toBeHidden();
  await expect(page.getByText('Digest preview unavailable')).toHaveCount(0);
});

test('Try again returns keyboard focus to the panel heading', async ({ page, integration: f }) => {
  f.config.digestPreview = { enabled: true };
  let fail = true;
  await page.route('**/digest/preview', (route) => route.fulfill(fail ? json({ error: { code: 'digest_preview_unavailable' } }, 503) : json(BODY)));
  await signIn(page, f, 'operator');
  await page.locator('#tab-more').click();
  fail = false;
  await panel(page).getByRole('button', { name: 'Try again' }).click();
  await expect(panel(page).locator('[data-count="requests"]')).toHaveText('7');
  await expect(panel(page).locator('#digest-preview-title')).toBeFocused();
});

for (const [name, start, end] of [['spring', '2026-03-01T23:00:00Z', '2026-03-08T22:00:00Z'], ['fall', '2026-10-25T22:00:00Z', '2026-11-01T23:00:00Z']] as const) {
  test(`${name} DST week renders 6:00 PM at both ends in New York time`, async ({ browser, integration: f }) => {
    f.config.digestPreview = { enabled: true };
    const context = await browser.newContext({ timezoneId: 'UTC' });
    const page = await context.newPage();
    const period = { start: Date.parse(start) / 1000, end: Date.parse(end) / 1000 };
    await page.route('**/digest/preview', (route) => route.fulfill(json({ period, counts: BODY.counts })));
    await signIn(page, f, 'operator');
    await page.locator('#tab-more').click();
    await expect(panel(page).locator('[data-period]')).toContainText(/6:00\s?PM to .*6:00\s?PM/);
    await context.close();
  });
}

test('reload then a failing fetch shows only unavailable; the response is no-store', async ({ page, integration: f }) => {
  f.config.digestPreview = { enabled: true };
  await signIn(page, f, 'operator');
  await page.locator('#tab-more').click();
  await expect(panel(page).locator('[data-count="requests"]')).toHaveText('0');
  const headers = page.waitForResponse((r) => new URL(r.url()).pathname === '/digest/preview');
  await page.reload();
  expect((await headers).headers()['cache-control']).toBe('no-store');
  await page.unroute('**/digest/preview');
  await page.route('**/digest/preview', (route) => route.abort('failed'));
  await page.reload();
  await page.locator('#tab-more').click();
  await expect(panel(page).getByRole('status')).toContainText('Digest preview unavailable');
  await expect(counts(page)).toHaveCount(0);
});

test('hostile or extra fields are never drawn: only the allowlisted numbers and no identities or markup', async ({ page, integration: f }) => {
  f.config.digestPreview = { enabled: true };
  const hostile = { ...BODY, child: '<img src=x onerror="window.__xss=1">', mac: '02:10:20:30:40:50', counts: { ...BODY.counts, device: 'Kid phone' } };
  await page.route('**/digest/preview', (route) => route.fulfill(json(hostile)));
  await signIn(page, f, 'operator');
  await page.locator('#tab-more').click();
  await expect(counts(page)).toHaveCount(3);
  const text = await panel(page).innerText();
  expect(text).not.toMatch(MAC_PATTERN);
  expect(text).not.toContain('Kid phone');
  expect(await panel(page).locator('img, script').count()).toBe(0);
  expect(await page.evaluate(() => (window as unknown as { __xss?: number }).__xss)).toBeUndefined();
});

test('malformed body shows unavailable, never zero', async ({ page, integration: f }) => {
  f.config.digestPreview = { enabled: true };
  await page.route('**/digest/preview', (route) => route.fulfill(json({ period: PERIOD, counts: { requests: 'many' } })));
  await signIn(page, f, 'operator');
  await page.locator('#tab-more').click();
  await expect(panel(page).getByRole('status')).toContainText('Digest preview unavailable');
  await expect(counts(page)).toHaveCount(0);
});

test('/digest-preview.js is listed in sw.js ASSETS and served', async ({ page, integration: f }) => {
  const sw = await readFile(new URL('../public/sw.js', import.meta.url), 'utf8');
  expect(sw).toContain("'/digest-preview.js'");
  const response = await page.request.get(`${f.origin}/digest-preview.js`);
  expect(response.status()).toBe(200);
});
