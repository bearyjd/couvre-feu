import { test, expect, enroll } from './browser-fixture.ts';
import type { Page, Route } from '@playwright/test';

// The parent Reward Time buttons (item 5, web). The demo has no Reward Time route (404), so every state it cannot produce is driven by
// answering the three routes from the test; those tests are labelled MOCK. Nothing here contacts a router.
test.use({ serviceWorkers: 'block' });
test.setTimeout(60000);
// Drain handlers before the page goes away, so an in-flight route.fetch is never charged to the next test.
test.afterEach(async ({ page }) => { await page.unrouteAll({ behavior: 'wait' }); });

const NOW = Math.floor(Date.now() / 1000);
const REWARD_NAME_15 = 'Add 15 minutes of extra time for Alex (fictional)';
const REWARD_NAME_30 = 'Add 30 minutes of extra time for Alex (fictional)';
type Mock = {
  /** Operation the service reports for the last accepted reward; null before any. */
  op: { state: 'pending' | 'confirmed' | 'failed' | 'unknown' } | null;
  allowanceUntil: number | null;
  paused: boolean;
  /** Whether GET /people tells this viewer Reward Time is on (the per-viewer rewardTime boolean). */
  feature: boolean;
  /** Answer for POST /people/alex/reward. */
  post: (route: Route) => Promise<void> | void;
  posts: number;
  /** Reads of GET /operations/op-reward-1 (each is one poll tick). */
  polls: number;
  headers: Record<string, string>[];
};
const operation = (provenance: Record<string, unknown>, state: string) => ({
  source: provenance.source, integrationScope: provenance.integrationScope, id: 'op-reward-1', personId: 'alex', action: 'allow', revision: 5, state, createdAt: NOW, updatedAt: NOW,
  error: state === 'failed' ? 'router_rejected' : null, confirmedAt: state === 'confirmed' ? NOW : null,
});
const refuse = (status: number, code: string) => (route: Route) => route.fulfill({ status, json: { error: { code, message: `raw message for ${code}` } } });

/** MOCK: patches GET /people for Alex and answers POST /people/alex/reward and GET /operations/op-reward-1. */
async function mockReward(page: Page, init: Partial<Mock> & { post: Mock['post'] }): Promise<Mock> {
  const mock: Mock = { op: null, allowanceUntil: null, paused: false, feature: true, posts: 0, polls: 0, headers: [], ...init };
  await page.route((url) => url.pathname === '/people', async (route) => {
    const response = await route.fetch();
    const body = await response.json();
    const alex = body.people.find((p: { id: string }) => p.id === 'alex');
    alex.allowance = mock.allowanceUntil === null ? null : { until: mock.allowanceUntil };
    alex.effectiveManualPause = mock.paused ? { until: 0 } : null;
    if (mock.feature) body.rewardTime = true; else delete body.rewardTime;
    if (mock.op) { alex.latestOperation = operation(body, mock.op.state); alex.status = mock.op.state; }
    await route.fulfill({ json: body });
  });
  await page.route((url) => url.pathname === '/people/alex/reward', async (route) => {
    mock.posts += 1; mock.headers.push(route.request().headers());
    await mock.post(route);
  });
  await page.route((url) => url.pathname === '/operations/op-reward-1', async (route) => {
    mock.polls += 1;
    await route.fulfill({ json: operation({}, mock.op?.state ?? 'pending') });
  });
  return mock;
}
const respondWith = (mockRef: { current?: Mock }, state: 'pending' | 'confirmed' | 'failed' | 'unknown') => async (route: Route) => {
  mockRef.current!.op = { state };
  await route.fulfill({ status: 202, json: { operation: operation({}, state), operationUrl: '/operations/op-reward-1' } });
};
const rewardBox = (page: Page) => page.locator('[data-reward="alex"]');
const status = (page: Page) => page.locator('[data-reward-status="alex"]');
const clock = (page: Page, epoch: number) => page.evaluate((value) => new Date(value * 1000).toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' }), epoch);
const RAW = /reward_cap_exceeded|child_paused|revision_conflict|operation_in_progress|route_not_found|router_rejected|raw message|\b[a-z]+_[a-z_]+\b/;

test('MOCK: reward buttons are named for the child, are at least 44px tall, and have a polite status region', async ({ page, demo }) => {
  const ref: { current?: Mock } = {};
  ref.current = await mockReward(page, { post: refuse(500, 'x') });
  await enroll(page, demo, 'bryn');
  const fifteen = page.getByRole('button', { name: REWARD_NAME_15, exact: true });
  const thirty = page.getByRole('button', { name: REWARD_NAME_30, exact: true });
  await expect(fifteen).toHaveText('Reward +15 min');
  await expect(thirty).toHaveText('Reward +30 min');
  for (const button of [fifteen, thirty]) expect((await button.boundingBox())!.height).toBeGreaterThanOrEqual(44);
  await expect(status(page)).toHaveAttribute('aria-live', 'polite');
  await expect(rewardBox(page)).toContainText('unverified on this router');
  await expect(rewardBox(page)).not.toContainText(RAW);
  await fifteen.focus();
  await page.keyboard.press('Tab');
  await expect(thirty).toBeFocused();
});

test('MOCK: a paused child with no allowance has no reward buttons; with an allowance in force they are offered', async ({ page, demo }) => {
  const mock = await mockReward(page, { paused: true, post: refuse(500, 'x') });
  await enroll(page, demo, 'bryn');
  await expect(page.getByRole('button', { name: 'Resume Alex (fictional) manual pause' })).toBeVisible();
  await expect(page.getByRole('button', { name: REWARD_NAME_15 })).toHaveCount(0);
  mock.allowanceUntil = NOW + 900;
  await page.locator('#refresh').click();
  await expect(page.getByRole('button', { name: REWARD_NAME_15 })).toBeVisible();
});

test('MOCK: applying until the router confirms, then Extra time until the router time, never optimistic', async ({ page, demo }) => {
  const ref: { current?: Mock } = {};
  ref.current = await mockReward(page, { post: respondWith(ref, 'pending') });
  await enroll(page, demo, 'bryn');
  await page.getByRole('button', { name: REWARD_NAME_15, exact: true }).click();
  await expect(status(page)).toContainText('Applying');
  await expect(status(page)).not.toContainText('Extra time until');
  await expect(page.getByRole('button', { name: REWARD_NAME_15, exact: true })).toBeDisabled();
  await expect(page.getByRole('button', { name: REWARD_NAME_30, exact: true })).toBeDisabled();
  await expect.poll(() => ref.current!.posts).toBe(1);
  expect(ref.current.headers[0]['if-match']).toBeTruthy();
  expect(ref.current.headers[0]['idempotency-key']).toBeTruthy();
  const until = Math.floor(Date.now() / 1000) + 900; // router time at the reward is never later than this device's now
  ref.current.allowanceUntil = until; ref.current.op = { state: 'confirmed' };
  await expect(status(page)).toContainText(`Extra time until ${await clock(page, until)}`, { timeout: 15000 });
  await expect(status(page)).toContainText('unverified on this router');
  await expect(page.getByRole('button', { name: REWARD_NAME_15, exact: true })).toBeEnabled();
  await expect(rewardBox(page)).not.toContainText(RAW);
  expect(ref.current.posts).toBe(1);
});

const FAILURES: [string, number, string, RegExp][] = [
  ['cap', 409, 'reward_cap_exceeded', /That would go past the 60 minute limit/],
  ['paused', 409, 'child_paused', /End the pause first/],
  ['conflict', 409, 'revision_conflict', /status changed.*refreshed/i],
  ['busy', 409, 'operation_in_progress', /still being applied/],
  ['unknown code', 409, 'something_new_and_odd', /could not be added/],
  ['server', 503, 'approved_router_observation_required', /could not be added/],
];
for (const [name, httpStatus, code, text] of FAILURES) {
  test(`MOCK: ${name} (${httpStatus}) is explained in plain words with no raw code`, async ({ page, demo }) => {
    const mock = await mockReward(page, { post: refuse(httpStatus, code) });
    await enroll(page, demo, 'bryn');
    await page.getByRole('button', { name: REWARD_NAME_30, exact: true }).click();
    await expect(status(page)).toContainText(text);
    await expect(rewardBox(page)).not.toContainText(RAW);
    await expect(page.locator('body')).not.toContainText(/reward_cap_exceeded|child_paused|raw message/);
    await expect.poll(() => mock.posts).toBe(1);
    // The failed tap is not a state: the buttons work again and focus stayed on the tapped button.
    await expect(page.getByRole('button', { name: REWARD_NAME_30, exact: true })).toBeEnabled();
    await expect(page.getByRole('button', { name: REWARD_NAME_30, exact: true })).toBeFocused();
  });
}

test('MOCK: an operation the router reports as failed is never shown as extra time', async ({ page, demo }) => {
  const ref: { current?: Mock } = {};
  ref.current = await mockReward(page, { post: respondWith(ref, 'pending') });
  await enroll(page, demo, 'bryn');
  await page.getByRole('button', { name: REWARD_NAME_15, exact: true }).click();
  await expect(status(page)).toContainText('Applying');
  ref.current.op = { state: 'failed' };
  await expect(status(page)).toContainText(/did not .*(take effect|confirm)|no extra time/i, { timeout: 15000 });
  await expect(status(page)).not.toContainText('Extra time until');
  await expect(rewardBox(page)).not.toContainText(RAW);
});

test('MOCK: route_not_found (feature off, not the owner) hides every reward control without an error', async ({ page, demo }) => {
  const mock = await mockReward(page, { post: refuse(404, 'route_not_found') });
  await enroll(page, demo, 'bryn');
  await page.getByRole('button', { name: REWARD_NAME_15, exact: true }).click();
  await expect.poll(() => mock.posts).toBe(1);
  await expect(page.locator('[data-reward-minutes]')).toHaveCount(0);
  await expect(page.locator('[data-reward]')).toHaveCount(0);
  await expect(page.locator('#notice')).toBeHidden();
  await expect(page.locator('#people')).not.toContainText(/not found|route_not_found/i);
});

test('MOCK: person_not_found (404) retires only that child\'s controls, as an ordinary refusal', async ({ page, demo }) => {
  const mock = await mockReward(page, { post: refuse(404, 'person_not_found') });
  await enroll(page, demo, 'bryn');
  const others = await page.locator('[data-reward]:not([data-reward="alex"])').count();
  await page.getByRole('button', { name: REWARD_NAME_15, exact: true }).click();
  await expect.poll(() => mock.posts).toBe(1);
  await expect(status(page)).toContainText('not available for this child');
  await expect(page.locator('[data-reward="alex"] [data-reward-minutes]')).toHaveCount(0);
  await expect(rewardBox(page)).not.toContainText(RAW);
  // Not the route-level hide: any other child keeps the controls, and the page shows no error.
  await expect(page.locator('[data-reward]:not([data-reward="alex"])')).toHaveCount(others);
  await expect(page.locator('#notice')).toBeHidden();
});

test('MOCK: the buttons follow the per-viewer rewardTime signal: absent when false, present when true', async ({ page, demo }) => {
  const mock = await mockReward(page, { feature: false, post: refuse(500, 'x') });
  await enroll(page, demo, 'bryn');
  await expect(page.locator('[data-reward-minutes]')).toHaveCount(0);
  await expect(page.locator('[data-reward]')).toHaveCount(0);
  await expect(page.locator('[data-extra-time="alex"]')).toContainText('not turned on');
  mock.feature = true;
  await page.locator('#refresh').click();
  await expect(page.getByRole('button', { name: REWARD_NAME_15, exact: true })).toBeVisible();
  await expect(page.locator('[data-extra-time]')).toHaveCount(0);
  expect(mock.posts).toBe(0);
});

test('MOCK: a click that is not 15 or 30 minutes sends nothing', async ({ page, demo }) => {
  const mock = await mockReward(page, { post: refuse(500, 'x') });
  await enroll(page, demo, 'bryn');
  await page.evaluate(() => {
    const twin = document.querySelector('[data-reward-minutes="15"]')!.cloneNode(true) as HTMLButtonElement;
    twin.dataset.rewardMinutes = '45'; twin.id = 'twin-45';
    document.querySelector('#people')!.append(twin);
    twin.click();
  });
  await page.evaluate(() => new Promise((resolve) => setTimeout(resolve, 300)));
  expect(mock.posts).toBe(0);
  await expect(status(page)).toHaveText('');
});

test('MOCK: a confirmed operation with a stale allowance shows no end time; the post-reward allowance does', async ({ page, demo }) => {
  const ref: { current?: Mock } = {};
  const stale = NOW + 300;
  ref.current = await mockReward(page, { allowanceUntil: stale, post: respondWith(ref, 'pending') });
  await enroll(page, demo, 'bryn');
  await page.getByRole('button', { name: REWARD_NAME_15, exact: true }).click();
  await expect(status(page)).toContainText('waiting for the router'); // the POST has been answered
  ref.current.op = { state: 'confirmed' }; // the router confirmed, but the polled allowance is still the old one
  await expect(status(page)).toContainText('Waiting for it to report the extra time', { timeout: 15000 });
  await expect(status(page)).not.toContainText('Extra time until');
  await page.locator('#refresh').click();
  await expect.poll(() => ref.current!.polls).toBeGreaterThan(0);
  await page.evaluate(() => new Promise((resolve) => setTimeout(resolve, 300)));
  await expect(status(page)).not.toContainText('Extra time until');
  const fresh = Math.max(stale, Math.floor(Date.now() / 1000)) + 900; // old end (or now) + the 15 minutes
  ref.current.allowanceUntil = fresh;
  await page.locator('#refresh').click();
  await expect(status(page)).toContainText(`Extra time until ${await clock(page, fresh)}`);
  await expect(status(page)).toContainText('unverified on this router');
});

test('MOCK: while the operation is pending the page says it is waiting for the router, even if the polled allowance already looks extended', async ({ page, demo }) => {
  const ref: { current?: Mock } = {};
  ref.current = await mockReward(page, { post: respondWith(ref, 'pending') });
  await enroll(page, demo, 'bryn');
  await page.getByRole('button', { name: REWARD_NAME_15, exact: true }).click();
  await expect(status(page)).toContainText('waiting for the router');
  ref.current.allowanceUntil = Math.floor(Date.now() / 1000) + 900;
  await page.locator('#refresh').click(); // /people now reports the extended allowance with the operation still pending
  const seen = ref.current.polls;
  await expect.poll(() => ref.current!.polls, { timeout: 15000 }).toBeGreaterThanOrEqual(seen + 3); // held pending across several poll ticks
  await expect(status(page)).toContainText('waiting for the router');
  await expect(status(page)).not.toContainText('Extra time until');
  await expect(page.locator('[data-reward="alex"]')).not.toContainText('Extra time until');
});

for (const [state, text] of [['unknown', /did not say whether the extra time was applied/], ['conflict', /Extra time was not applied/]] as const) {
  test(`MOCK: an operation the router reports as ${state} is never shown as extra time`, async ({ page, demo }) => {
    const ref: { current?: Mock } = {};
    ref.current = await mockReward(page, { allowanceUntil: Math.floor(Date.now() / 1000) + 4000, post: async (route) => {
      ref.current!.op = { state: state as 'unknown' };
      await route.fulfill({ status: 202, json: { operation: operation({}, state), operationUrl: '/operations/op-reward-1' } });
    } });
    await enroll(page, demo, 'bryn');
    await page.getByRole('button', { name: REWARD_NAME_15, exact: true }).click();
    await expect(status(page)).toContainText(text);
    await expect.poll(() => ref.current!.posts).toBe(1);
    await page.evaluate(() => new Promise((resolve) => setTimeout(resolve, 1000)));
    await expect(status(page)).toContainText(text);
    await expect(status(page)).not.toContainText('Extra time until');
    await expect(rewardBox(page)).not.toContainText(RAW);
  });
}

test('MOCK: a double tap sends one request', async ({ page, demo }) => {
  let release!: () => void;
  const held = new Promise<void>((resolve) => { release = resolve; });
  const ref: { current?: Mock } = {};
  ref.current = await mockReward(page, { post: async (route) => { await held; await respondWith(ref, 'pending')(route); } });
  await enroll(page, demo, 'bryn');
  const button = page.getByRole('button', { name: REWARD_NAME_15, exact: true });
  await button.dblclick();
  await expect(status(page)).toContainText('Applying');
  await expect.poll(() => ref.current!.posts).toBe(1);
  release();
  await expect(status(page)).toContainText('Applying');
  await page.evaluate(() => new Promise((resolve) => setTimeout(resolve, 300)));
  expect(ref.current.posts).toBe(1);
});

test('MOCK: signing out clears the reward text and controls from the page', async ({ page, demo }) => {
  const ref: { current?: Mock } = {};
  ref.current = await mockReward(page, { post: respondWith(ref, 'pending') });
  await enroll(page, demo, 'bryn');
  await page.getByRole('button', { name: REWARD_NAME_15, exact: true }).click();
  await expect(status(page)).toContainText('Applying');
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.locator('#status-view')).toBeHidden();
  await expect(rewardBox(page)).toHaveCount(0);
  await expect(page.locator('body')).not.toContainText(/Extra time|Reward \+|Applying/);
  expect(await page.locator('#people').innerHTML()).toBe('');
});

test('MOCK: a response that arrives after the session ended is ignored', async ({ page, demo }) => {
  let release!: () => void, finished!: () => void;
  const held = new Promise<void>((resolve) => { release = resolve; });
  const done = new Promise<void>((resolve) => { finished = resolve; });
  const ref: { current?: Mock } = {};
  ref.current = await mockReward(page, { post: async (route) => { await held; await respondWith(ref, 'pending')(route); finished(); } });
  await enroll(page, demo, 'bryn');
  await page.getByRole('button', { name: REWARD_NAME_15, exact: true }).click();
  await expect.poll(() => ref.current!.posts).toBe(1);
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.locator('#status-view')).toBeHidden();
  release();
  await done;
  await page.evaluate(() => new Promise((resolve) => setTimeout(resolve, 300)));
  await expect(rewardBox(page)).toHaveCount(0);
  await expect(page.locator('body')).not.toContainText(/Extra time|Reward \+|Applying/);
});

test('MOCK: a different parent signing in sees no earlier status, and a late POST from the first session is ignored', async ({ page, demo }) => {
  let release!: () => void, finished!: () => void;
  const held = new Promise<void>((resolve) => { release = resolve; });
  const done = new Promise<void>((resolve) => { finished = resolve; });
  const ref: { current?: Mock } = {};
  ref.current = await mockReward(page, { post: async (route) => { await held; await respondWith(ref, 'pending')(route); finished(); } });
  await enroll(page, demo, 'bryn');
  await page.getByRole('button', { name: REWARD_NAME_15, exact: true }).click();
  await expect(status(page)).toContainText('Applying');
  await expect.poll(() => ref.current!.posts).toBe(1);
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.locator('#status-view')).toBeHidden();
  await page.getByLabel('One-use enrollment token').fill(demo.token('jd'));
  await page.getByRole('button', { name: 'Create a demo passkey' }).click();
  await expect(page.locator('#status-view')).toBeVisible();
  await expect(page.getByRole('button', { name: REWARD_NAME_15, exact: true })).toBeEnabled();
  await expect(status(page)).toHaveText('');
  await expect(page.locator('[data-reward-busy]')).toHaveCount(0);
  release();
  await done;
  await page.evaluate(() => new Promise((resolve) => setTimeout(resolve, 500)));
  await expect(status(page)).toHaveText('');
  await expect(page.getByRole('button', { name: REWARD_NAME_15, exact: true })).toBeEnabled();
  await expect(page.locator('body')).not.toContainText(/Applying|Your session changed/);
});

test('MOCK: a tap keeps the reward buttons busy (never re-enabled), and a second tap before the redraw is refused by the in-flight guard', async ({ page, demo }) => {
  const ref: { current?: Mock } = {};
  let release!: () => void;
  const held = new Promise<void>((resolve) => { release = resolve; });
  ref.current = await mockReward(page, { post: async (route) => { await held; await respondWith(ref, 'pending')(route); } });
  await enroll(page, demo, 'bryn');
  const result = await page.evaluate(() => {
    const first = document.querySelector<HTMLButtonElement>('[data-reward-minutes="15"][data-person-id="alex"]')!;
    // A copy of the button as it was before the redraw: enabled, and wired to the same handler.
    const stale = first.cloneNode(true) as HTMLButtonElement;
    const observer = new MutationObserver(() => {});
    observer.observe(document.querySelector('#people')!, { subtree: true, attributes: true, attributeFilter: ['disabled'], attributeOldValue: true });
    first.click();
    document.querySelector('#people')!.append(stale); // the redraw replaced the page's buttons; this one stands for a tap that still sees the old, enabled one
    stale.click();
    // Any reward button that lost its disabled attribute, even for an instant, was open to a second tap.
    const reEnabled = observer.takeRecords().filter((record) => (record.target as HTMLElement).matches('[data-reward-minutes]') && record.oldValue !== null).length;
    observer.disconnect();
    const live = [...document.querySelectorAll<HTMLButtonElement>('[data-reward="alex"] [data-reward-minutes]')];
    return { rewardBusy: live.map((b) => b.disabled && b.hasAttribute('data-reward-busy')), reEnabled };
  });
  expect(result.rewardBusy).toEqual([true, true]);
  expect(result.reEnabled).toBe(0);
  await expect.poll(() => ref.current!.posts).toBe(1);
  // The refused second tap must not overwrite the first tap's state: it is still "sending", not "a change is already in progress".
  await page.evaluate(() => new Promise((resolve) => setTimeout(resolve, 300)));
  await expect(status(page)).toContainText('sending the request');
  release();
  await expect(status(page)).toContainText('waiting for the router');
  await page.evaluate(() => new Promise((resolve) => setTimeout(resolve, 300)));
  expect(ref.current.posts).toBe(1);
});
