import { test, expect, signIn } from './bulk-fixture.ts';
import type { Page } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { issueOperatorBootstrap } from '../../service/src/auth.ts';

const MAC_PATTERN = /[0-9a-f]{2}(:[0-9a-f]{2}){5}/i;
const panel = (page: Page) => page.locator('#push-settings-panel');
const json = (body: unknown, status = 200) => ({ status, contentType: 'application/json', headers: { 'Cache-Control': 'no-store' }, body: JSON.stringify(body) });
const SETTINGS = { push: { provider: 'ntfy', configured: true, quietHours: { start: '21:00', end: '07:00', zone: 'America/New_York', activeNow: false },
    heldKinds: ['time_request_pending', 'repeated_blocked_attempts'], digest: { audience: 'admins', day: 'sunday', time: '18:00', zone: 'America/New_York' } } };
const open = async (page: Page, f: Parameters<typeof signIn>[1], account: 'operator' | 'parent' = 'operator') => {
  await signIn(page, f, account);
  await page.locator('#tab-more').click();
};

test('admin sees quiet hours, held kinds as plain labels, the digest schedule, provider state and the unverified label', async ({ page, integration: f }) => {
  await page.route('**/push/settings', (route) => route.fulfill(json(SETTINGS)));
  await open(page, f);
  await expect(panel(page).getByRole('heading', { name: 'Notifications' })).toBeVisible();
  await expect(panel(page).locator('[data-quiet]')).toHaveText('9:00 PM to 7:00 AM (New York time). Not quiet right now.');
  await expect(panel(page).locator('[data-held] li')).toHaveText(['Extra-time requests', 'Repeated blocked attempts']);
  await expect(panel(page).locator('[data-digest]')).toHaveText('Sundays at 6:00 PM (New York time), to admins');
  await expect(panel(page).locator('[data-provider]')).toHaveText('ntfy: set up');
  await expect(panel(page).locator('[data-unverified]')).toContainText('unverified on this router/phone');
  await expect(page.locator('#more-jump a[data-target="#push-settings-panel"]')).toBeVisible();
  await expect(panel(page)).not.toContainText(/delivered/i);
});

test('quiet right now and not set up are shown as such', async ({ page, integration: f }) => {
  const body = { push: { ...SETTINGS.push, configured: false, quietHours: { ...SETTINGS.push.quietHours, activeNow: true } } };
  await page.route('**/push/settings', (route) => route.fulfill(json(body)));
  await open(page, f);
  await expect(panel(page).locator('[data-quiet]')).toContainText('Quiet right now.');
  await expect(panel(page).locator('[data-provider]')).toHaveText('ntfy: not set up');
});

test('flag off: the real route is a 404, the panel and its jump link stay hidden, no error shown', async ({ page, integration: f }) => {
  const statuses: number[] = [];
  page.on('response', (r) => { if (new URL(r.url()).pathname === '/push/settings') statuses.push(r.status()); });
  await open(page, f);
  await expect.poll(() => statuses).toEqual([404]);
  await expect(panel(page)).toBeHidden();
  await expect(page.locator('#more-jump a[data-target="#push-settings-panel"]')).toBeHidden();
  await expect(page.getByText('Notification settings unavailable')).toHaveCount(0);
});

test('403 hides the panel without an unavailable message', async ({ page, integration: f }) => {
  await page.route('**/push/settings', (route) => route.fulfill(json({ error: { code: 'admin_required' } }, 403)));
  const answered = page.waitForResponse((r) => new URL(r.url()).pathname === '/push/settings' && r.status() === 403);
  await open(page, f);
  await answered;
  await expect(panel(page)).toBeHidden();
  await expect(page.getByText('Notification settings unavailable')).toHaveCount(0);
});

test('an ordinary parent never requests the settings and sees no panel', async ({ page, integration: f }) => {
  let requests = 0;
  page.on('request', (r) => { if (new URL(r.url()).pathname === '/push/settings') requests++; });
  await open(page, f, 'parent');
  await expect(page.locator('#more-jump')).toBeVisible();
  await expect(page.locator('#more-jump a[data-target="#push-settings-panel"]')).toBeHidden();
  expect(requests).toBe(0);
  await expect(panel(page)).toBeHidden();
});

test('sign-out empties and hides the panel and nothing is persisted', async ({ page, integration: f }) => {
  await page.route('**/push/settings', (route) => route.fulfill(json(SETTINGS)));
  await open(page, f);
  await expect(panel(page).locator('[data-held] li').first()).toBeVisible();
  await page.locator('#logout').click();
  await expect(panel(page)).toBeHidden();
  expect(await panel(page).evaluate((n) => n.children.length)).toBe(0);
  const stores = await page.evaluate(() => ({ local: JSON.stringify({ ...localStorage }), session: JSON.stringify({ ...sessionStorage }) }));
  for (const value of Object.values(stores)) { expect(value).not.toMatch(/push|quiet|ntfy/i); }
});

test('Send test push: POST with the CSRF header and no body, then the honest "Sent to push service"', async ({ page, integration: f }) => {
  await page.route('**/push/settings', (route) => route.fulfill(json(SETTINGS)));
  const seen: { method: string; csrf: string | undefined; body: string | null }[] = [];
  await page.route('**/push/test', (route) => { const r = route.request(); seen.push({ method: r.method(), csrf: r.headers()['x-csrf-token'], body: r.postData() }); return route.fulfill(json({ result: 'sent_to_push_service' })); });
  await open(page, f);
  await panel(page).getByRole('button', { name: 'Send test push' }).click();
  await expect(panel(page).locator('[data-test-status]')).toHaveText('Sent to push service');
  await expect(panel(page)).toContainText('does not prove the phone got it');
  await expect(panel(page)).not.toContainText(/delivered/i);
  expect(seen).toHaveLength(1);
  expect(seen[0].method).toBe('POST');
  expect(seen[0].csrf).toBeTruthy();
  expect(seen[0].body).toBeNull();
});

test('Send test push: a failure tag and no ntfy setup are shown as such', async ({ page, integration: f }) => {
  await page.route('**/push/settings', (route) => route.fulfill(json(SETTINGS)));
  let result = 'push_failed:http_500';
  await page.route('**/push/test', (route) => route.fulfill(json({ result })));
  await open(page, f);
  const button = panel(page).getByRole('button', { name: 'Send test push' });
  await button.click();
  await expect(panel(page).locator('[data-test-status]')).toHaveText('Push failed (http_500)');
  result = 'not_configured';
  await button.click();
  await expect(panel(page).locator('[data-test-status]')).toHaveText('No push set up');
  result = 'push_failed:<img src=x>';
  await button.click();
  await expect(panel(page).locator('[data-test-status]')).toHaveText('Push failed');
  await expect(panel(page).locator('img')).toHaveCount(0);
});

test('Send test push: the cooldown (429) and a network error get plain messages, and the button is usable again', async ({ page, integration: f }) => {
  await page.route('**/push/settings', (route) => route.fulfill(json(SETTINGS)));
  let mode: 'cooldown' | 'abort' = 'cooldown';
  await page.route('**/push/test', (route) => mode === 'cooldown' ? route.fulfill(json({ error: { code: 'push_test_cooldown' } }, 429)) : route.abort('failed'));
  await open(page, f);
  const button = panel(page).getByRole('button', { name: 'Send test push' });
  await button.click();
  await expect(panel(page).locator('[data-test-status]')).toHaveText('Please wait before sending another test');
  mode = 'abort';
  await button.click();
  await expect(panel(page).locator('[data-test-status]')).toHaveText('The test could not be sent');
  await expect(button).toBeEnabled();
});

test('settings 503 shows unavailable, Try again refetches', async ({ page, integration: f }) => {
  let fail = true;
  await page.route('**/push/settings', (route) => route.fulfill(fail ? json({ error: { code: 'x' } }, 503) : json(SETTINGS)));
  await open(page, f);
  await expect(panel(page).getByRole('status')).toContainText('Notification settings unavailable');
  await expect(panel(page).locator('[data-held]')).toHaveCount(0);
  fail = false;
  await panel(page).getByRole('button', { name: 'Try again' }).click();
  await expect(panel(page).locator('[data-held] li').first()).toBeVisible();
});

test('malformed body shows unavailable; hostile or unknown fields are never drawn', async ({ page, integration: f }) => {
  const hostile = { push: { ...SETTINGS.push, url: 'https://ntfy.example/secret-topic', topic: 'secret-topic', mac: '02:10:20:30:40:50',
      heldKinds: ['time_request_pending', '<img src=x onerror="window.__xss=1">'] } };
  await page.route('**/push/settings', (route) => route.fulfill(json(hostile)));
  await open(page, f);
  await expect(panel(page).locator('[data-held] li')).toHaveText(['Extra-time requests', 'Another low-urgency alert type']);
  const text = await panel(page).innerText();
  expect(text).not.toMatch(MAC_PATTERN);
  expect(text).not.toContain('secret-topic');
  expect(text).not.toContain('onerror');
  expect(await panel(page).locator('img, script').count()).toBe(0);
  expect(await page.evaluate(() => (window as unknown as { __xss?: number }).__xss)).toBeUndefined();
  await page.unroute('**/push/settings');
  await page.route('**/push/settings', (route) => route.fulfill(json({ push: { ...SETTINGS.push, quietHours: { start: 'soon' } } })));
  await page.reload();
  await page.locator('#tab-more').click();
  await expect(panel(page).getByRole('status')).toContainText('Notification settings unavailable');
});

test('/push-settings.js is in sw.js ASSETS, in the http.ts allowlist, and served', async ({ page, integration: f }) => {
  const sw = await readFile(new URL('../public/sw.js', import.meta.url), 'utf8');
  expect(sw).toContain("'/push-settings.js'");
  const http = await readFile(new URL('../../service/src/http.ts', import.meta.url), 'utf8');
  expect(http).toContain("'/push-settings.js': ['push-settings.js'");
  const response = await page.request.get(`${f.origin}/push-settings.js`);
  expect(response.status()).toBe(200);
  expect(response.headers()['content-type']).toContain('text/javascript');
});

const reenroll = async (page: Page, f: Parameters<typeof signIn>[1], account: 'operator' | 'parent') => {
  await page.getByLabel('One-use enrollment token').fill(issueOperatorBootstrap(f.store, account, f.now()));
  await page.getByRole('button', { name: 'Create a passkey' }).click();
  await expect(page.locator('#status-view')).toBeVisible();
  await page.locator('#tab-more').click();
};

test('Send test push: focus stays on the button and the status is one persistent role=status node', async ({ page, integration: f }) => {
  await page.route('**/push/settings', (route) => route.fulfill(json(SETTINGS)));
  await page.route('**/push/test', (route) => route.fulfill(json({ result: 'sent_to_push_service' })));
  await open(page, f);
  const button = panel(page).locator('[data-action="test"]'), status = panel(page).locator('[data-test-status]');
  const handle = await status.elementHandle();
  await button.focus();
  await button.press('Enter');
  await expect(status).toHaveText('Sent to push service');
  await expect(button).toBeFocused();
  await expect(button).toBeEnabled();
  expect(await handle!.evaluate((n) => n.isConnected)).toBe(true);
  await expect(panel(page).locator('[role="status"]')).toHaveCount(1);
  await expect(page.locator('#push-settings-panel')).not.toHaveAttribute('aria-live', /.*/);
});

test('Send test push: a double click sends exactly one POST', async ({ page, integration: f }) => {
  await page.route('**/push/settings', (route) => route.fulfill(json(SETTINGS)));
  let posts = 0, release!: () => void;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  await page.route('**/push/test', async (route) => { posts++; await gate; await route.fulfill(json({ result: 'sent_to_push_service' })); });
  await open(page, f);
  const button = panel(page).locator('[data-action="test"]');
  await button.dblclick();
  await expect(button).toBeDisabled();
  release();
  await expect(panel(page).locator('[data-test-status]')).toHaveText('Sent to push service');
  expect(posts).toBe(1);
});

test('an account switch while the settings GET is in flight never draws the stale answer', async ({ page, integration: f }) => {
  let release!: () => void, held = false;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  await page.route('**/push/settings', async (route) => { held = true; await gate; await route.fulfill(json(SETTINGS)).catch(() => undefined); });
  await open(page, f);
  await expect.poll(() => held).toBe(true);
  await page.locator('#logout').click();
  await expect(page.getByLabel('One-use enrollment token')).toBeVisible();
  await reenroll(page, f, 'parent');
  const answered = page.waitForResponse((r) => new URL(r.url()).pathname === '/push/settings');
  release();
  await answered;
  await expect(panel(page)).toBeHidden();
  expect(await panel(page).evaluate((n) => n.children.length)).toBe(0);
});

test('an account switch while the test POST is in flight never draws the stale result', async ({ page, integration: f }) => {
  await page.route('**/push/settings', (route) => route.fulfill(json(SETTINGS)));
  let release!: () => void, held = false;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  await page.route('**/push/test', async (route) => { held = true; await gate; await route.fulfill(json({ result: 'sent_to_push_service' })).catch(() => undefined); });
  await open(page, f);
  await panel(page).locator('[data-action="test"]').click();
  await expect.poll(() => held).toBe(true);
  await page.locator('#logout').click();
  await expect(page.getByLabel('One-use enrollment token')).toBeVisible();
  await reenroll(page, f, 'parent');
  const answered = page.waitForResponse((r) => new URL(r.url()).pathname === '/push/test');
  release();
  await answered;
  await expect(panel(page)).toBeHidden();
  expect(await panel(page).evaluate((n) => n.textContent)).toBe('');
});

test('offline hides the panel, and coming back online fetches the settings again and shows it', async ({ page, context, integration: f }) => {
  let gets = 0;
  await page.route('**/push/settings', (route) => { gets++; return route.fulfill(json(SETTINGS)); });
  await open(page, f);
  await expect(panel(page).locator('[data-held] li').first()).toBeVisible();
  expect(gets).toBe(1);
  await context.setOffline(true);
  await expect(page.locator('#connection')).toContainText('Offline');
  await expect(panel(page)).toBeHidden();
  await context.setOffline(false);
  await expect(page.locator('#connection')).toContainText('Connected');
  await expect(panel(page).locator('[data-held] li').first()).toBeVisible();
  expect(gets).toBe(2);
});

test('a test result that arrives while offline does not redraw the hidden panel', async ({ page, context, integration: f }) => {
  await page.route('**/push/settings', (route) => route.fulfill(json(SETTINGS)));
  let release!: () => void, held = false;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  await page.route('**/push/test', async (route) => { held = true; await gate; await route.fulfill(json({ result: 'sent_to_push_service' })).catch(() => undefined); });
  await open(page, f);
  await panel(page).locator('[data-action="test"]').click();
  await expect.poll(() => held).toBe(true);
  await context.setOffline(true);
  await expect(panel(page)).toBeHidden();
  release();
  await expect.poll(() => panel(page).evaluate((n) => n.children.length)).toBe(0);
  await expect(panel(page)).toBeHidden();
  await context.setOffline(false);
  await expect(panel(page).locator('[data-held] li').first()).toBeVisible();
});
