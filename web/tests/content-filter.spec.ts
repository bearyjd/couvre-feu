import { test, expect, enroll } from './browser-fixture.ts';
import type { Page, Route } from '@playwright/test';

// The content filter card (PRP-006 A4). The demo has no filter, so every state is driven by answering GET/PUT /people/:id/filter
// from the test; those tests are labelled MOCK. Nothing here contacts NextDNS or a router.
test.use({ serviceWorkers: 'block' });
test.setTimeout(60000);
test.afterEach(async ({ page }) => { await page.unrouteAll({ behavior: 'wait' }); });

const DESIRED = { categories: ['porn', 'mystery-cat'], services: [], safeSearch: true, youtubeRestrictedMode: false, blockBypass: true, denylist: [], allowlist: [] };
type Mock = { gets: string[]; puts: unknown[]; get: (route: Route) => Promise<void> | void; put?: (route: Route, body: any) => Promise<void> | void };
const record = (state: string, desired = DESIRED) => ({ revision: 1, state, stateAt: 1, desired, note: 'unverified on this router' });
const refuse = (status: number, code: string) => (route: Route) => route.fulfill({ status, json: { error: { code, message: `raw ${code}` } } });

async function mock(page: Page, init: Partial<Mock> & Pick<Mock, 'get'>): Promise<Mock> {
  const m: Mock = { gets: [], puts: [], ...init };
  await page.route((url) => /^\/people\/[a-z_0-9]+\/filter$/.test(url.pathname), async (route) => {
    const request = route.request();
    if (request.method() === 'GET') { m.gets.push(new URL(request.url()).pathname); await m.get(route); return; }
    const body = request.postDataJSON(); m.puts.push(body);
    await (m.put ? m.put(route, body) : route.fulfill({ json: record('pending', body.desired) }));
  });
  return m;
}
const card = (page: Page) => page.locator('#filter-panel [data-filter-person="alex"]');

test('MOCK: a set filter shows its honest state, keeps unknown ids, and saves a tightening without a passkey', async ({ page, demo }) => {
  const m = await mock(page, { get: (route) => (new URL(route.request().url()).pathname.includes('/alex/') ? route.fulfill({ json: record('not_confirmed') }) : refuse(404, 'person_not_found')(route)) });
  await enroll(page, demo);
  await expect(card(page)).toBeVisible();
  await expect(card(page).locator('[data-filter-state]')).toContainText('Not confirmed');
  await expect(card(page).locator('[data-filter-state]')).toContainText('unverified on this router');
  await expect(card(page).locator('[data-filter-field="categories:mystery-cat"]')).toBeChecked();
  await card(page).locator('[data-filter-field="categories:gambling"]').check();
  await card(page).getByRole('button', { name: 'Save changes' }).click();
  await expect(card(page).locator('[data-filter-notice]')).toHaveText('Saved.');
  expect(m.puts).toHaveLength(1);
  expect((m.puts[0] as any).desired.categories.sort()).toEqual(['gambling', 'mystery-cat', 'porn']);
  expect((m.puts[0] as any).stepUp).toBeUndefined();
  await expect(page.locator('#filter-panel [data-filter-person]')).toHaveCount(1); // other children answered 404: no card
});

test('MOCK: a loosening (403 step_up_required) starts the passkey step-up and stops cleanly when it fails', async ({ page, demo }) => {
  let attempts = 0;
  const m = await mock(page, {
    get: (route) => route.fulfill({ json: record('applied') }),
    put: (route, body) => { attempts++; return body.stepUp ? route.fulfill({ json: record('pending', body.desired) }) : refuse(403, 'step_up_required')(route); },
  });
  await page.route('**/step-up/options', (route) => route.fulfill({ status: 500, json: { error: { code: 'x', message: 'x' } } }));
  await enroll(page, demo);
  await card(page).locator('[data-filter-field="categories:porn"]').uncheck();
  await card(page).getByRole('button', { name: 'Save changes' }).click();
  await expect(card(page).locator('[data-filter-notice]')).toHaveText('The filter could not be changed. Nothing changed.');
  expect(attempts).toBe(1);
  expect(m.puts).toHaveLength(1);
});

test('MOCK: feature off (route_not_found) shows nothing and asks once per child', async ({ page, demo }) => {
  const m = await mock(page, { get: refuse(404, 'route_not_found') });
  await enroll(page, demo);
  await page.waitForTimeout(500);
  await expect(page.locator('#filter-panel')).toBeHidden();
  const before = m.gets.length;
  await page.locator('#refresh').click();
  await page.waitForTimeout(500);
  expect(m.gets.length).toBe(before);
});

test('MOCK: an unset child offers a baseline; typed sites are validated and never rendered as markup', async ({ page, demo }) => {
  const m = await mock(page, { get: refuse(404, 'filter_not_set') });
  await enroll(page, demo);
  await expect(card(page)).toBeVisible();
  await expect(card(page).locator('[data-filter-field="categories:porn"]')).toBeChecked();
  const input = card(page).locator('[data-filter-input="denylist"]');
  await input.fill('<img src=x onerror="window.__xss=1">');
  await input.press('Enter');
  await expect(card(page).getByRole('alert').filter({ hasText: 'just the site name' }).first()).toBeVisible();
  await input.fill(' Example.COM ');
  await input.press('Enter');
  await expect(card(page).getByText('example.com', { exact: true })).toBeVisible();
  await card(page).getByRole('button', { name: 'Save filter' }).click();
  await expect(card(page).locator('[data-filter-notice]')).toHaveText('Saved.');
  expect((m.puts[0] as any).desired.denylist).toEqual(['example.com']);
  expect(await page.evaluate(() => (window as any).__xss)).toBeUndefined();
});
