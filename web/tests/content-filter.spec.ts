import { test, expect, enroll } from './browser-fixture.ts';
import type { Page, Route } from '@playwright/test';

// The content filter card (PRP-006 A4). The demo has no filter, so every state is driven by answering GET/PUT /people/:id/filter
// from the test; those tests are labelled MOCK. Nothing here contacts NextDNS or a router.
test.use({ serviceWorkers: 'block' });
test.setTimeout(60000);
test.afterEach(async ({ page }) => { await page.unrouteAll({ behavior: 'wait' }); });

const DESIRED: { categories: string[]; services: string[]; safeSearch: boolean; youtubeRestrictedMode: boolean; blockBypass: boolean; denylist: string[]; allowlist: string[] } = { categories: ['porn', 'mystery-cat'], services: [], safeSearch: true, youtubeRestrictedMode: false, blockBypass: true, denylist: [], allowlist: [] };
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
  await expect(card(page).locator('[data-filter-notice]')).toHaveText('Saved here. NextDNS has not confirmed it yet.');
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
  await expect(card(page).locator('[data-filter-notice]')).toHaveText('Saved here. NextDNS has not confirmed it yet.');
  expect((m.puts[0] as any).desired.denylist).toEqual(['example.com']);
  expect(await page.evaluate(() => (window as any).__xss)).toBeUndefined();
});

const HOSTILE = '<img src=x onerror="window.__xss=1">';
test('MOCK: hostile ids held by the service are rendered as text and kept on save', async ({ page, demo }) => {
  const desired = { ...DESIRED, categories: [HOSTILE, 'porn'], denylist: [HOSTILE] };
  const m = await mock(page, { get: (route) => route.fulfill({ json: record('drift', desired) }) });
  await enroll(page, demo);
  await expect(card(page).locator('[data-filter-state]')).toContainText('Changed elsewhere');
  await expect(card(page).getByText(HOSTILE, { exact: true }).first()).toBeVisible();
  expect(await page.evaluate(() => (window as any).__xss)).toBeUndefined();
  await card(page).locator('[data-filter-field="safeSearch"]').uncheck();
  await card(page).getByRole('button', { name: 'Save changes' }).click();
  await expect(card(page).locator('[data-filter-notice]')).not.toHaveText('');
  expect((m.puts[0] as any).desired.categories).toContain(HOSTILE);
  expect((m.puts[0] as any).desired.denylist).toEqual([HOSTILE]);
});

test('MOCK: a passkey step-up sends the bound challenge, then the proof', async ({ page, demo }) => {
  const seen: any[] = [];
  await mock(page, {
    get: (route) => route.fulfill({ json: record('applied') }),
    put: (route, body) => body.stepUp ? route.fulfill({ json: record('pending', body.desired) }) : refuse(403, 'step_up_required')(route),
  });
  await page.route('**/step-up/options', async (route) => { seen.push(route.request().postDataJSON()); await route.fulfill({ status: 409, json: { error: { code: 'x', message: 'x' } } }); });
  await enroll(page, demo);
  await card(page).locator('[data-filter-field="categories:porn"]').uncheck();
  await card(page).getByRole('button', { name: 'Save changes' }).click();
  await expect(card(page).locator('[data-filter-notice]')).toContainText('Nothing changed');
  expect(seen).toHaveLength(1);
  expect(Object.keys(seen[0]).sort()).toEqual(['action', 'desired', 'person']);
  expect(seen[0].action).toBe('content_filter_set');
  expect(seen[0].person).toBe('alex');
  expect(seen[0].desired.categories).toEqual(['mystery-cat']);
});

test('MOCK: a server error on save does not claim nothing changed, and re-reads the state', async ({ page, demo }) => {
  let reads = 0;
  await mock(page, { get: (route) => { reads++; return route.fulfill({ json: record(reads > 1 ? 'pending' : 'applied') }); }, put: refuse(502, 'bad_gateway') });
  await enroll(page, demo);
  await card(page).locator('[data-filter-field="blockBypass"]').uncheck();
  await card(page).getByRole('button', { name: 'Save changes' }).click();
  await expect(card(page).locator('[data-filter-notice]')).toContainText('Could not confirm your change saved');
  await expect(card(page).locator('[data-filter-notice]')).not.toContainText('Nothing changed');
  await expect(card(page).locator('[data-filter-state]')).toContainText('Sending');
});

test('MOCK: a failing read is not retried on every refresh, and an unsaved edit survives one', async ({ page, demo }) => {
  const m = await mock(page, { get: refuse(500, 'boom') });
  await enroll(page, demo);
  await expect(card(page).getByRole('alert')).toBeVisible();
  const before = m.gets.length;
  await page.locator('#refresh').click(); await page.waitForTimeout(400);
  await page.locator('#refresh').click(); await page.waitForTimeout(400);
  expect(m.gets.length).toBe(before);
  const retry = card(page).getByRole('button', { name: 'Try again' });
  await retry.click();
  await expect.poll(() => m.gets.length).toBeGreaterThan(before);
});

test('MOCK: a site typed but not added is saved if valid, and blocks the save if it is not a site name', async ({ page, demo }) => {
  const m = await mock(page, { get: refuse(404, 'filter_not_set') });
  await enroll(page, demo);
  const input = card(page).locator('[data-filter-input="allowlist"]');
  await input.fill('not a site!');
  await card(page).getByRole('button', { name: 'Save filter' }).click();
  await expect(card(page).locator('[data-filter-notice]')).toContainText('Nothing changed');
  expect(m.puts).toHaveLength(0);
  await input.fill('School.Example.org');
  await card(page).getByRole('button', { name: 'Save filter' }).click();
  await expect(card(page).locator('[data-filter-notice]')).toHaveText('Saved here. NextDNS has not confirmed it yet.');
  expect((m.puts[0] as any).desired.allowlist).toEqual(['school.example.org']);
});

test('MOCK: text typed in a site box survives a refresh', async ({ page, demo }) => {
  await mock(page, { get: (route) => route.fulfill({ json: record('applied') }) });
  await enroll(page, demo);
  const input = card(page).locator('[data-filter-input="denylist"]');
  await input.fill('exam');
  await card(page).locator('[data-filter-field="safeSearch"]').uncheck();
  await input.focus();
  await page.locator('#refresh').click();
  await page.waitForTimeout(600);
  await expect(card(page).locator('[data-filter-input="denylist"]')).toHaveValue('exam');
});

test('MOCK: a typed site survives a failed save and is sent on the next one', async ({ page, demo }) => {
  let fail = true;
  const m = await mock(page, { get: (route) => route.fulfill({ json: record('applied') }), put: (route, body) => fail ? refuse(429, 'content_filter_rate_limited')(route) : route.fulfill({ json: record('pending', body.desired) }) });
  await enroll(page, demo);
  await card(page).locator('[data-filter-input="allowlist"]').fill('keep.example.org');
  await card(page).getByRole('button', { name: 'Save changes' }).click();
  await expect(card(page).locator('[data-filter-notice]')).toContainText('Try again in a minute');
  await expect(card(page).getByText('keep.example.org', { exact: true })).toBeVisible();
  fail = false;
  await card(page).getByRole('button', { name: 'Save changes' }).click();
  await expect(card(page).locator('[data-filter-notice]')).toContainText('Saved here');
  expect((m.puts[1] as any).desired.allowlist).toEqual(['keep.example.org']);
});
