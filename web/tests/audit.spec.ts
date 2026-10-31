import { test, expect, enroll } from './browser-fixture.ts';
import type { Page, Route } from '@playwright/test';

// The parent Activity log (item 6, web). The demo has no audit log (it is real-router-integration only), so every state is driven by
// answering GET /people (the per-viewer auditLog boolean) and GET /audit... from the test; those tests are labelled MOCK. Nothing here contacts a router.
test.use({ serviceWorkers: 'block' });
test.setTimeout(60000);
// Drain handlers before the page goes away, so an in-flight route.fetch is never charged to the next test.
test.afterEach(async ({ page }) => { await page.unrouteAll({ behavior: 'wait' }); });

const NOW = Math.floor(Date.now() / 1000);
const HOSTILE = '<img src=x onerror="window.__xss=1">';
type Row = { id: number; at: number; actorId: string; actorName: string | null; action: string; personId: string | null; operationId: string | null; result: string };
const row = (id: number, over: Partial<Row> = {}): Row => ({ id, at: NOW - id * 60, actorId: 'bryn', actorName: 'Bryn', action: 'pause', personId: 'alex', operationId: null, result: 'applied', ...over });
type Answer = (route: Route, path: string) => Promise<void> | void;
type Mock = { feature: boolean; answer: Answer; paths: string[] };
const page1 = (rows: Row[], nextBefore: number | null = null): Answer => (route) => route.fulfill({ json: { source: 'synthetic-fake-router', entries: rows, nextBefore } });
const refuse = (status: number, code: string): Answer => (route) => route.fulfill({ status, json: { error: { code, message: `raw message for ${code}` } } });

/** MOCK: patches GET /people with auditLog and answers every /audit path through `answer`. */
async function mockAudit(page: Page, init: Partial<Mock> & { answer: Answer }, rename?: (name: string) => string | null): Promise<Mock> {
  const mock: Mock = { feature: true, paths: [], ...init };
  await page.route((url) => url.pathname === '/people', async (route) => {
    const response = await route.fetch();
    const body = await response.json();
    if (mock.feature) body.auditLog = true; else delete body.auditLog;
    if (rename) for (const person of body.people) person.name = rename(person.name) ?? person.name;
    await route.fulfill({ json: body });
  });
  await page.route((url) => /^\/audit(\/|$)/.test(url.pathname), async (route) => {
    const path = new URL(route.request().url()).pathname;
    mock.paths.push(path);
    await mock.answer(route, path);
  });
  return mock;
}
const panel = (page: Page) => page.locator('#audit-panel');
const items = (page: Page) => panel(page).locator('li.audit-row');
const older = (page: Page) => panel(page).getByRole('button', { name: 'Show older' });
const RAW = /pause_all|resume_all|device_move|grant_approve|reward_add|focus_start|route_not_found|raw message|\b[a-z]+_[a-z_]+\b/;

test('MOCK: rows are newest first with friendly verbs, a child name, local date and time, and honest result wording', async ({ page, demo }) => {
  const rows = [
    row(9, { action: 'pause_all', personId: null, at: NOW - 60 }),
    row(8, { action: 'device_move', actorName: null, actorId: 'jd', result: 'refused' }),
    row(7, { action: 'grant_approve', result: 'failed' }),
    row(6, { action: 'grant_decline' }), row(5, { action: 'grant_end' }), row(4, { action: 'reward_add' }),
    row(3, { action: 'focus_start' }), row(2, { action: 'resume' }), row(1, { action: 'resume_all', personId: null }),
  ];
  await mockAudit(page, { answer: page1(rows) });
  await enroll(page, demo, 'bryn');
  await expect(panel(page).getByRole('heading', { name: 'Activity log' })).toBeVisible();
  await expect(items(page)).toHaveCount(9);
  const verbs = await items(page).locator('[data-what]').allTextContents();
  expect(verbs).toEqual(['Paused everyone', 'Moved a device', 'Approved extra time', 'Declined a request', 'Ended extra time', 'Added reward time', 'Started a focus window', 'Resumed', 'Resumed everyone']);
  await expect(items(page).nth(0).locator('[data-child]')).toHaveText('All children');
  await expect(items(page).nth(1).locator('[data-child]')).toHaveText('Alex (fictional)');
  await expect(items(page).nth(0).locator('[data-who]')).toHaveText('Bryn');
  await expect(items(page).nth(1).locator('[data-who]')).toHaveText('jd'); // no display name: the id is shown
  const when = await page.evaluate((at) => new Date(at * 1000).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }), NOW - 60);
  await expect(items(page).nth(0).locator('time')).toHaveText(when);
  await expect(items(page).nth(0).locator('time')).toHaveAttribute('datetime', new Date((NOW - 60) * 1000).toISOString());
  await expect(items(page).nth(2).locator('[data-result]')).toHaveText('Failed');
  await expect(items(page).nth(1).locator('[data-result]')).toHaveText('Refused');
  const badge = items(page).nth(3).locator('[data-result]');
  await expect(badge).toHaveText('Requested');
  await expect(badge).toHaveAttribute('title', 'Accepted by the service; the router confirms separately');
  await expect(items(page).nth(3)).toContainText('accepted by the service; the router confirms separately'); // also available to screen readers
  await expect(panel(page)).not.toContainText(/\b(done|applied|confirmed|succeeded|success)\b/i);
  await expect(panel(page)).not.toContainText(RAW);
  await expect(panel(page)).toContainText('unverified on this router');
});

test('MOCK: heading, list semantics, polite live status, and 44px buttons', async ({ page, demo }) => {
  await mockAudit(page, { answer: page1([row(2), row(1)], 1) });
  await enroll(page, demo, 'bryn');
  await expect(items(page)).toHaveCount(2);
  await expect(panel(page).getByRole('list', { name: 'Activity log entries' }).getByRole('listitem')).toHaveCount(2);
  await expect(panel(page).locator('[data-audit-status]')).toHaveAttribute('aria-live', 'polite');
  expect((await older(page).boundingBox())!.height).toBeGreaterThanOrEqual(44);
  await expect(panel(page)).toHaveAttribute('aria-labelledby', 'audit-title');
});

test('MOCK: the first page asks for 50 rows; Show older follows nextBefore, appends, and moves focus to the first new row', async ({ page, demo }) => {
  const first = Array.from({ length: 50 }, (_, i) => row(100 - i));
  const second = Array.from({ length: 3 }, (_, i) => row(50 - i, { action: 'resume' }));
  const mock = await mockAudit(page, { answer: (route, path) => (path.endsWith('/before/51') ? page1(second, null)(route, path) : page1(first, 51)(route, path)) });
  await enroll(page, demo, 'bryn');
  await expect(items(page)).toHaveCount(50);
  expect(mock.paths).toEqual(['/audit/limit/50']);
  await older(page).focus();
  await page.keyboard.press('Enter');
  await expect(items(page)).toHaveCount(53);
  expect(mock.paths).toEqual(['/audit/limit/50', '/audit/limit/50/before/51']);
  await expect(older(page)).toHaveCount(0); // nextBefore null: nothing older
  await expect(items(page).nth(50)).toBeFocused();
  await expect(items(page).nth(50).locator('[data-what]')).toHaveText('Resumed');
});

test('MOCK: a double click on Show older sends one request', async ({ page, demo }) => {
  let release!: () => void;
  const held = new Promise<void>((resolve) => { release = resolve; });
  const mock = await mockAudit(page, { answer: async (route, path) => {
    if (path.includes('/before/')) { await held; await page1([row(1, { action: 'resume' })])(route, path); } else await page1([row(3), row(2)], 2)(route, path);
  } });
  await enroll(page, demo, 'bryn');
  await expect(items(page)).toHaveCount(2);
  await older(page).dblclick();
  await expect.poll(() => mock.paths.filter((p) => p.includes('/before/')).length).toBe(1);
  await expect(panel(page).locator('[data-audit-status]')).toContainText('Loading');
  release();
  await expect(items(page)).toHaveCount(3);
  expect(mock.paths.filter((p) => p.includes('/before/'))).toHaveLength(1);
});

test('MOCK: an empty log says so', async ({ page, demo }) => {
  await mockAudit(page, { answer: page1([]) });
  await enroll(page, demo, 'bryn');
  await expect(panel(page)).toContainText('No activity recorded yet.');
  await expect(items(page)).toHaveCount(0);
  await expect(older(page)).toHaveCount(0);
});

test('MOCK: a failed load says Couldn\'t load the log, shows no raw text, and Try again recovers', async ({ page, demo }) => {
  let fail = true;
  await mockAudit(page, { answer: (route, path) => (fail ? refuse(500, 'internal_error')(route, path) : page1([row(1)])(route, path)) });
  await enroll(page, demo, 'bryn');
  await expect(panel(page).locator('[data-audit-status]')).toHaveText("Couldn't load the log.");
  await expect(panel(page)).not.toContainText(/raw message|internal_error/);
  fail = false;
  await panel(page).getByRole('button', { name: 'Try again' }).click();
  await expect(items(page)).toHaveCount(1);
  await expect(panel(page).locator('[data-audit-status]')).not.toContainText("Couldn't");
});

test('MOCK: a failed Show older keeps the rows already shown and offers a retry', async ({ page, demo }) => {
  let fail = true;
  await mockAudit(page, { answer: (route, path) => (path.includes('/before/') ? (fail ? refuse(500, 'x')(route, path) : page1([row(1)])(route, path)) : page1([row(2)], 2)(route, path)) });
  await enroll(page, demo, 'bryn');
  await older(page).click();
  await expect(panel(page).locator('[data-audit-status]')).toHaveText("Couldn't load the log.");
  await expect(items(page)).toHaveCount(1);
  fail = false;
  await older(page).click();
  await expect(items(page)).toHaveCount(2);
});

test('MOCK: a 404 from the log hides the panel (feature off) and is not retried', async ({ page, demo }) => {
  const mock = await mockAudit(page, { answer: refuse(404, 'route_not_found') });
  await enroll(page, demo, 'bryn');
  await expect.poll(() => mock.paths.length).toBe(1);
  await expect(panel(page)).toBeHidden();
  await page.locator('#refresh').click();
  await page.evaluate(() => new Promise((resolve) => setTimeout(resolve, 400)));
  expect(mock.paths).toHaveLength(1);
  await expect(panel(page)).toBeHidden();
  await expect(page.locator('body')).not.toContainText(/Activity log|Couldn't load/);
});

test('MOCK: without the per-viewer auditLog signal the panel is hidden and /audit is never requested', async ({ page, demo }) => {
  const mock = await mockAudit(page, { feature: false, answer: page1([row(1)]) });
  await enroll(page, demo, 'bryn');
  await page.evaluate(() => new Promise((resolve) => setTimeout(resolve, 400)));
  await expect(panel(page)).toBeHidden();
  expect(mock.paths).toEqual([]);
});

test('MOCK: hostile names stay inert text', async ({ page, demo }) => {
  let hostile = false; // the child is renamed only after sign-in, which waits for the real name
  await mockAudit(page, { answer: page1([row(1, { actorName: HOSTILE }), row(2, { actorName: null, actorId: HOSTILE })]) }, () => (hostile ? HOSTILE : null));
  await enroll(page, demo, 'bryn');
  hostile = true;
  await page.locator('#refresh').click();
  await expect(items(page)).toHaveCount(2);
  await expect(items(page).nth(0).locator('[data-who]')).toHaveText(HOSTILE);
  await expect(items(page).nth(1).locator('[data-who]')).toHaveText(HOSTILE);
  await expect(items(page).nth(0).locator('[data-child]')).toHaveText(HOSTILE);
  expect(await panel(page).locator('img').count()).toBe(0);
  expect(await page.evaluate(() => (window as unknown as { __xss?: number }).__xss)).toBeUndefined();
});

test('MOCK: signing out clears the log from the page', async ({ page, demo }) => {
  await mockAudit(page, { answer: page1([row(1)]) });
  await enroll(page, demo, 'bryn');
  await expect(items(page)).toHaveCount(1);
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.locator('#status-view')).toBeHidden();
  await expect(panel(page)).toBeHidden();
  expect(await panel(page).innerHTML()).toBe('');
  await expect(page.locator('body')).not.toContainText(/Activity log|Paused/);
});

test('MOCK: a second parent never sees the first parent\'s rows, and a held response released after the switch is ignored', async ({ page, demo }) => {
  let release!: () => void, finished!: () => void, calls = 0;
  const held = new Promise<void>((resolve) => { release = resolve; });
  const done = new Promise<void>((resolve) => { finished = resolve; });
  await mockAudit(page, { answer: async (route, path) => {
    calls += 1;
    if (calls === 1) { await held; await page1([row(1, { actorName: 'FIRST-PARENT-ROW' })])(route, path); finished(); } else await page1([row(2, { actorName: 'SECOND-PARENT-ROW' })])(route, path);
  } });
  await enroll(page, demo, 'bryn');
  await expect.poll(() => calls).toBe(1);
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.locator('#status-view')).toBeHidden();
  await page.getByLabel('One-use enrollment token').fill(demo.token('jd'));
  await page.getByRole('button', { name: 'Create a demo passkey' }).click();
  await expect(page.locator('#status-view')).toBeVisible();
  await expect(items(page)).toHaveCount(1);
  await expect(items(page).first()).toContainText('SECOND-PARENT-ROW');
  release();
  await done;
  await page.evaluate(() => new Promise((resolve) => setTimeout(resolve, 400)));
  await expect(items(page)).toHaveCount(1);
  await expect(page.locator('body')).not.toContainText('FIRST-PARENT-ROW');
});

test('MOCK: a 404 for one session does not hide the log for the next parent who signs in', async ({ page, demo }) => {
  let calls = 0;
  await mockAudit(page, { answer: (route, path) => { calls += 1; return calls === 1 ? refuse(404, 'route_not_found')(route, path) : page1([row(1)])(route, path); } });
  await enroll(page, demo, 'bryn');
  await expect(panel(page)).toBeHidden();
  await page.getByRole('button', { name: 'Sign out' }).click();
  await page.getByLabel('One-use enrollment token').fill(demo.token('jd'));
  await page.getByRole('button', { name: 'Create a demo passkey' }).click();
  await expect(items(page)).toHaveCount(1);
});
