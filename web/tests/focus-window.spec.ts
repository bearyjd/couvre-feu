import { test, expect, enroll } from './browser-fixture.ts';
import type { Page, Route } from '@playwright/test';

// The parent Focus window buttons and chip (F5, web). The demo has no focus route (404), so every state it cannot produce is driven by
// answering the routes from the test; those tests are labelled MOCK. Nothing here contacts a router.
test.use({ serviceWorkers: 'block' });
test.setTimeout(60000);
// Drain handlers before the page goes away, so an in-flight route.fetch is never charged to the next test.
test.afterEach(async ({ page }) => { await page.unrouteAll({ behavior: 'wait' }); });

const NOW = Math.floor(Date.now() / 1000);
const FOCUS_NAME = (minutes: number) => `Start a ${minutes} minute focus window for Alex (fictional)`;
type Mock = {
  op: { state: 'pending' | 'confirmed' | 'failed' | 'unknown' } | null;
  /** Whether GET /people marks Alex's pause as a focus window (person.pauseLabel). */
  label: boolean;
  paused: boolean;
  /** Whether GET /people tells this viewer the focus window is on (the per-viewer focusWindow boolean). */
  feature: boolean;
  post: (route: Route) => Promise<void> | void;
  posts: number;
  bodies: unknown[];
  headers: Record<string, string>[];
};
const operation = (provenance: Record<string, unknown>, state: string) => ({
  source: provenance.source, integrationScope: provenance.integrationScope, id: 'op-focus-1', personId: 'alex', action: 'pause', revision: 5, state, createdAt: NOW, updatedAt: NOW,
  error: state === 'failed' ? 'router_rejected' : null, confirmedAt: state === 'confirmed' ? NOW : null,
});
const refuse = (status: number, code: string) => (route: Route) => route.fulfill({ status, json: { error: { code, message: `raw message for ${code}` } } });

/** MOCK: patches GET /people for Alex and answers POST /people/alex/focus and GET /operations/op-focus-1. */
async function mockFocus(page: Page, init: Partial<Mock> & { post: Mock['post'] }): Promise<Mock> {
  const mock: Mock = { op: null, label: false, paused: false, feature: true, posts: 0, bodies: [], headers: [], ...init };
  await page.route((url) => url.pathname === '/people', async (route) => {
    const response = await route.fetch();
    const body = await response.json();
    const alex = body.people.find((p: { id: string }) => p.id === 'alex');
    alex.effectiveManualPause = mock.paused ? { until: NOW + 1800 } : null;
    alex.pauseLabel = mock.label ? 'focus' : null;
    if (mock.feature) body.focusWindow = true; else delete body.focusWindow;
    if (mock.op) { alex.latestOperation = operation(body, mock.op.state); alex.status = mock.op.state; }
    await route.fulfill({ json: body });
  });
  await page.route((url) => url.pathname === '/people/alex/focus', async (route) => {
    mock.posts += 1; mock.headers.push(route.request().headers()); mock.bodies.push(route.request().postDataJSON());
    await mock.post(route);
  });
  await page.route((url) => url.pathname === '/operations/op-focus-1', async (route) => {
    await route.fulfill({ json: operation({}, mock.op?.state ?? 'pending') });
  });
  return mock;
}
const respondWith = (mockRef: { current?: Mock }, state: 'pending' | 'confirmed' | 'failed' | 'unknown') => async (route: Route) => {
  mockRef.current!.op = { state };
  await route.fulfill({ status: 202, json: { operation: operation({}, state), operationUrl: '/operations/op-focus-1' } });
};
const box = (page: Page) => page.locator('[data-focus-window="alex"]');
const status = (page: Page) => page.locator('[data-focus-status="alex"]');
const RAW = /child_paused|invalid_minutes|revision_conflict|operation_in_progress|route_not_found|router_rejected|raw message|\b[a-z]+_[a-z_]+\b/;

test('MOCK: six named buttons, at least 44px tall, with a polite status region', async ({ page, demo }) => {
  await mockFocus(page, { post: refuse(500, 'x') });
  await enroll(page, demo, 'bryn');
  for (const minutes of [15, 30, 45, 60, 90, 120]) {
    const button = page.getByRole('button', { name: FOCUS_NAME(minutes), exact: true });
    await expect(button).toHaveText(`Focus ${minutes} min`);
    expect((await button.boundingBox())!.height).toBeGreaterThanOrEqual(44);
  }
  await expect(page.locator('[data-focus-minutes]')).toHaveCount(6);
  await expect(status(page)).toHaveAttribute('aria-live', 'polite');
  await expect(box(page)).not.toContainText(RAW);
});

test('MOCK: the buttons follow the per-viewer focusWindow signal: absent when false, present when true', async ({ page, demo }) => {
  const mock = await mockFocus(page, { feature: false, post: refuse(500, 'x') });
  await enroll(page, demo, 'bryn');
  await expect(page.locator('[data-focus-minutes]')).toHaveCount(0);
  await expect(page.locator('[data-focus-window]')).toHaveCount(0);
  mock.feature = true;
  await page.locator('#refresh').click();
  await expect(page.getByRole('button', { name: FOCUS_NAME(15), exact: true })).toBeVisible();
  expect(mock.posts).toBe(0);
});

test('MOCK: a tap sends the minutes once, shows starting until the router confirms, never optimistic', async ({ page, demo }) => {
  const ref: { current?: Mock } = {};
  ref.current = await mockFocus(page, { post: respondWith(ref, 'pending') });
  await enroll(page, demo, 'bryn');
  await page.getByRole('button', { name: FOCUS_NAME(45), exact: true }).click();
  await expect(status(page)).toContainText('Starting');
  await expect(page.getByRole('button', { name: FOCUS_NAME(15), exact: true })).toBeDisabled();
  await expect(page.locator('.badge.focus')).toHaveCount(0);
  await expect.poll(() => ref.current!.posts).toBe(1);
  expect(ref.current.bodies[0]).toEqual({ minutes: 45 });
  expect(ref.current.headers[0]['if-match']).toBeTruthy();
  expect(ref.current.headers[0]['idempotency-key']).toBeTruthy();
  ref.current.op = { state: 'confirmed' };
  await expect(status(page)).toContainText('Waiting for the status', { timeout: 15000 });
  expect(ref.current.posts).toBe(1);
});

test('MOCK: pauseLabel focus shows a Focus chip and Focus until, in place of Paused', async ({ page, demo }) => {
  await mockFocus(page, { paused: true, label: true, post: refuse(500, 'x') });
  await enroll(page, demo, 'bryn');
  await expect(page.locator('[data-person="alex"] .badge.focus')).toHaveText('Focus');
  await expect(page.locator('[data-person="alex"] .reasons')).toContainText('Focus until');
  await expect(page.locator('[data-person="alex"] .reasons')).not.toContainText('Paused until');
  await expect(page.getByRole('button', { name: FOCUS_NAME(15) })).toHaveCount(0);
});

test('MOCK: an ordinary manual pause shows no Focus chip', async ({ page, demo }) => {
  await mockFocus(page, { paused: true, label: false, post: refuse(500, 'x') });
  await enroll(page, demo, 'bryn');
  await expect(page.locator('[data-person="alex"] .badge.focus')).toHaveCount(0);
  await expect(page.locator('[data-person="alex"] .reasons')).toContainText('Paused until');
});

const FAILURES: [string, number, string, RegExp][] = [
  ['paused', 409, 'child_paused', /End the pause first/],
  ['conflict', 409, 'revision_conflict', /status changed.*refreshed/i],
  ['busy', 409, 'operation_in_progress', /still being applied/],
  ['unknown code', 409, 'something_new_and_odd', /could not be started/],
];
for (const [name, httpStatus, code, text] of FAILURES) {
  test(`MOCK: ${name} (${httpStatus}) is explained in plain words with no raw code`, async ({ page, demo }) => {
    const mock = await mockFocus(page, { post: refuse(httpStatus, code) });
    await enroll(page, demo, 'bryn');
    await page.getByRole('button', { name: FOCUS_NAME(30), exact: true }).click();
    await expect(status(page)).toContainText(text);
    await expect(box(page)).not.toContainText(RAW);
    await expect.poll(() => mock.posts).toBe(1);
    await expect(page.getByRole('button', { name: FOCUS_NAME(30), exact: true })).toBeEnabled();
  });
}

test('MOCK: route_not_found hides every focus control without an error', async ({ page, demo }) => {
  const mock = await mockFocus(page, { post: refuse(404, 'route_not_found') });
  await enroll(page, demo, 'bryn');
  await page.getByRole('button', { name: FOCUS_NAME(15), exact: true }).click();
  await expect.poll(() => mock.posts).toBe(1);
  await expect(page.locator('[data-focus-minutes]')).toHaveCount(0);
  await expect(page.locator('#notice')).toBeHidden();
});

test('MOCK: a click that is not an offered length sends nothing', async ({ page, demo }) => {
  const mock = await mockFocus(page, { post: refuse(500, 'x') });
  await enroll(page, demo, 'bryn');
  await page.evaluate(() => {
    const twin = document.querySelector('[data-focus-minutes="15"]')!.cloneNode(true) as HTMLButtonElement;
    twin.dataset.focusMinutes = '50';
    document.querySelector('#people')!.append(twin);
    twin.click();
  });
  await page.evaluate(() => new Promise((resolve) => setTimeout(resolve, 300)));
  expect(mock.posts).toBe(0);
});

test('MOCK: a double tap sends one request', async ({ page, demo }) => {
  let release!: () => void;
  const held = new Promise<void>((resolve) => { release = resolve; });
  const ref: { current?: Mock } = {};
  ref.current = await mockFocus(page, { post: async (route) => { await held; await respondWith(ref, 'pending')(route); } });
  await enroll(page, demo, 'bryn');
  await page.getByRole('button', { name: FOCUS_NAME(15), exact: true }).dblclick();
  await expect(status(page)).toContainText('Starting');
  await expect.poll(() => ref.current!.posts).toBe(1);
  release();
  await page.evaluate(() => new Promise((resolve) => setTimeout(resolve, 300)));
  expect(ref.current.posts).toBe(1);
});

test('MOCK: signing out clears the focus text and controls from the page', async ({ page, demo }) => {
  const ref: { current?: Mock } = {};
  ref.current = await mockFocus(page, { post: respondWith(ref, 'pending') });
  await enroll(page, demo, 'bryn');
  await page.getByRole('button', { name: FOCUS_NAME(15), exact: true }).click();
  await expect(status(page)).toContainText('Starting');
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.locator('#status-view')).toBeHidden();
  await expect(box(page)).toHaveCount(0);
  await expect(page.locator('body')).not.toContainText(/Focus \d+ min|Starting…/);
});
