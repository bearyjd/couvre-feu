import { test, expect, enroll } from './browser-fixture.ts';
import type { Page, Route } from '@playwright/test';
import { INITIAL_POLICY } from '../../service/src/fixtures.ts';
import { policyJSON, normalizePolicy } from '../../shared/src/router-schema.ts';

// The parent ask-for-time card (F3). The demo runs the legacy (no allowance) path, so the states it cannot
// produce on its own (applying, unconfirmed, failed, router errors) are driven by answering the two parent
// routes from the test and are labelled MOCK below. Everything else runs against the real demo service.
test.use({ serviceWorkers: 'block' });
test.setTimeout(60000);

const NOW = Math.floor(Date.now() / 1000);
type Mock = Record<string, unknown>;
const request = (extra: Mock = {}): Mock => ({
  id: '11111111-1111-4111-8111-111111111111', personId: 'alex', minutes: 30, reason: 'finishing homework', state: 'pending',
  createdAt: NOW - 30, expiresAt: NOW + 800, decidedBy: null, decidedAt: null, grantedMinutes: null, allowanceUntil: null,
  code: null, repause: 'none', repauseOverdue: false, repauseError: null, ...extra,
});

/** MOCK: serves GET /time-requests from `current()` and routes the decision POSTs to `onPost`. */
async function mockParentRoutes(page: Page, current: () => Mock[], onPost: (route: Route, action: 'approve' | 'decline') => Promise<void> | void) {
  await page.route((url) => url.pathname === '/time-requests', (route) => route.request().method() === 'GET'
    ? route.fulfill({ json: { links: [{ personId: 'alex', active: false, createdAt: null }], requests: current() } }) : route.fallback());
  await page.route(/\/time-requests\/[0-9a-f-]{36}\/(approve|decline)$/, (route) => onPost(route, route.request().url().endsWith('approve') ? 'approve' : 'decline'));
}
const label = (page: Page, epoch: number) => page.evaluate((value) => new Date(value * 1000).toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' }), epoch);
const clearSchedules = (demo: Parameters<Parameters<typeof test>[2]>[0]['demo']) => {
  const open = policyJSON(normalizePolicy({ ...INITIAL_POLICY, schedules: [] }));
  demo.store.run('UPDATE service_state SET desired_json=? WHERE singleton=1', open);
  demo.router.store.run('UPDATE fake_state SET policy=? WHERE singleton=1', open);
  demo.router.tick();
};

test('MOCK: a pending request lists the child, minutes and reason, with one-tap Grant and Decline named for the child', async ({ page, demo }) => {
  await mockParentRoutes(page, () => [request()], () => {});
  await enroll(page, demo, 'bryn');
  const card = page.locator('.time-request');
  await expect(card).toContainText('Alex (fictional) asks for 30 minutes');
  await expect(card).toContainText('finishing homework');
  const grant = page.getByRole('button', { name: 'Grant 30 minutes for Alex (fictional)' });
  const decline = page.getByRole('button', { name: 'Decline request from Alex (fictional)' });
  await expect(grant).toBeVisible();
  await expect(decline).toBeVisible();
  await expect(grant).toHaveText('Grant 30 min');
  for (const button of [grant, decline]) expect((await button.boundingBox())!.height).toBeGreaterThanOrEqual(44);
  // Focus order: Grant, then Decline.
  await grant.focus();
  await page.keyboard.press('Tab');
  await expect(decline).toBeFocused();
  // Status changes are announced politely.
  await expect(page.locator('#time-requests [aria-live="polite"]')).toHaveCount(1);
  // No domains or device identifiers on the card.
  await expect(page.locator('#time-requests')).not.toContainText(/\.(com|net|org)\b|[0-9a-f]{2}(:[0-9a-f]{2}){5}/i);
});

test('MOCK: a request above the cap is offered at the 60 minute cap', async ({ page, demo }) => {
  await mockParentRoutes(page, () => [request({ minutes: 90 })], () => {});
  await enroll(page, demo, 'bryn');
  await expect(page.getByRole('button', { name: 'Grant 60 minutes for Alex (fictional)' })).toBeVisible();
});

test('MOCK: grant shows Applying until the service confirms, then Granted until the router time, never optimistic', async ({ page, demo }) => {
  let phase: 'pending' | 'approving' | 'approved' = 'pending';
  const until = NOW + 30 * 60;
  const bodies: unknown[] = [];
  await mockParentRoutes(page, () => [request(phase === 'pending' ? {} : phase === 'approving' ? { state: 'approving', grantedMinutes: 30 } : { state: 'approved', grantedMinutes: 30, allowanceUntil: until })],
    (route) => { bodies.push(route.request().postDataJSON()); phase = 'approving'; return route.fulfill({ json: { request: request({ state: 'approving', grantedMinutes: 30 }) } }); });
  await enroll(page, demo, 'bryn');
  await page.getByRole('button', { name: 'Grant 30 minutes for Alex (fictional)' }).click();
  await expect(page.locator('#time-requests')).toContainText('Applying');
  await expect(page.locator('#time-requests')).not.toContainText('Granted until');
  expect(bodies).toEqual([{ minutes: 30 }]);
  phase = 'approved';
  await expect(page.locator('#time-requests')).toContainText(`Granted until ${await label(page, until)}`, { timeout: 15000 });
  await expect(page.locator('#time-requests')).not.toContainText('Applying');
  await expect(page.locator('#time-requests')).toContainText('unverified on this router');
  await expect(page.getByRole('button', { name: 'End extra time for Alex (fictional)' })).toBeVisible();
});

test('MOCK: a grant that could not be applied says Couldn\'t apply with the reason code', async ({ page, demo }) => {
  let failed = false;
  await mockParentRoutes(page, () => [request(failed ? { state: 'apply_failed', grantedMinutes: 30, code: 'grant_not_in_force' } : {})],
    (route) => { failed = true; return route.fulfill({ json: { request: request({ state: 'apply_failed', code: 'grant_not_in_force' }) } }); });
  await enroll(page, demo, 'bryn');
  await page.getByRole('button', { name: 'Grant 30 minutes for Alex (fictional)' }).click();
  await expect(page.locator('#time-requests')).toContainText("Couldn't apply");
  await expect(page.locator('#time-requests')).toContainText('grant_not_in_force');
  await expect(page.locator('#time-requests')).not.toContainText('Granted until');
});

test('MOCK: buttons are disabled while a decision is in flight and a second tap sends nothing', async ({ page, demo }) => {
  let posts = 0;
  let release!: () => void;
  const held = new Promise<void>((resolve) => { release = resolve; });
  await mockParentRoutes(page, () => [request()], async (route) => { posts += 1; await held; await route.fulfill({ status: 409, json: { error: { code: 'request_not_pending', message: 'Already decided.' } } }); });
  await enroll(page, demo, 'bryn');
  const grant = page.getByRole('button', { name: 'Grant 30 minutes for Alex (fictional)' });
  await grant.click();
  await expect(grant).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Decline request from Alex (fictional)' })).toBeDisabled();
  await grant.click({ force: true });
  await page.waitForTimeout(300);
  expect(posts).toBe(1);
  release();
  await expect(page.locator('#time-requests')).toContainText('Already decided');
});

test('MOCK: a hostile reason is shown as plain text only in the parent DOM', async ({ page, demo }) => {
  const hostile = '<img src=x onerror="window.__pwned=1"><script>window.__pwned=2</script>';
  await mockParentRoutes(page, () => [request({ reason: hostile })], () => {});
  await enroll(page, demo, 'bryn');
  await expect(page.locator('.time-request')).toContainText(hostile);
  expect(await page.locator('#time-requests img, #time-requests script').count()).toBe(0);
  expect(await page.evaluate(() => (window as unknown as { __pwned?: number }).__pwned)).toBeUndefined();
});

test('MOCK: a 404 from /time-requests (feature off) hides the card and stops polling', async ({ page, demo }) => {
  let gets = 0;
  await page.route((url) => url.pathname === '/time-requests', (route) => { gets += 1; return route.fulfill({ status: 404, json: { error: { code: 'route_not_found', message: 'Not found.' } } }); });
  await enroll(page, demo, 'bryn');
  await expect.poll(() => gets).toBeGreaterThan(0);
  await expect(page.locator('#time-requests')).toBeHidden();
  const seen = gets;
  await page.waitForTimeout(6500);
  expect(gets).toBe(seen);
  await expect(page.locator('#time-requests')).toBeHidden();
});

test('demo: grant a real request, see Granted until, then End extra time pauses the child', async ({ page, browser, demo }) => {
  clearSchedules(demo);
  await enroll(page, demo, 'bryn');
  await page.getByRole('button', { name: 'Create request link for Alex (fictional)' }).click();
  const url = await page.locator('.request-link input').inputValue();
  const context = await browser.newContext({ serviceWorkers: 'block' });
  try {
    const child = await context.newPage();
    await child.goto(url);
    await child.getByLabel('30 minutes').check();
    await child.getByLabel(/Why\?/).fill('reading');
    await child.getByRole('button', { name: 'Send request' }).click();
    await expect(page.locator('.time-request')).toContainText('Alex (fictional) asks for 30 minutes');
    await page.getByRole('button', { name: 'Grant 30 minutes for Alex (fictional)' }).click();
    await expect(page.locator('#time-requests')).toContainText('Granted until', { timeout: 15000 });
    await expect(page.locator('.time-request')).toHaveCount(0);
    expect(demo.router.observe().policy.pauses).toEqual([]);
    await page.getByRole('button', { name: 'End extra time for Alex (fictional)' }).click();
    await expect.poll(() => demo.router.observe().policy.pauses.length, { timeout: 20000 }).toBe(1);
  } finally { await context.close(); }
});

test('demo: decline a real request', async ({ page, browser, demo }) => {
  await enroll(page, demo, 'bryn');
  await page.getByRole('button', { name: 'Create request link for Alex (fictional)' }).click();
  const url = await page.locator('.request-link input').inputValue();
  const context = await browser.newContext({ serviceWorkers: 'block' });
  try {
    const child = await context.newPage();
    await child.goto(url);
    await child.getByRole('button', { name: 'Send request' }).click();
    await page.getByRole('button', { name: 'Decline request from Alex (fictional)' }).click();
    await expect(page.locator('.time-request-history')).toContainText('declined');
    await expect(page.locator('.time-request')).toHaveCount(0);
    await expect(child.locator('#child-state')).toContainText(/not this time/i, { timeout: 15000 });
  } finally { await context.close(); }
});
