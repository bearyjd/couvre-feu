import { test, expect, enroll } from './browser-fixture.ts';
import type { Page, Route } from '@playwright/test';

// Review follow-ups for the parent ask-for-time card: honest End notices, session hygiene, focus, reason text, Grant less.
// Routes labelled MOCK answer the parent time-request routes from the test; everything else is the real demo service.
test.use({ serviceWorkers: 'block' });
test.setTimeout(60000);

// Drain every route handler before a test ends, also when an assertion threw: a handler still awaiting route.fetch would
// otherwise be charged to the NEXT test ("route.fetch: Test ended") and hide the real failure behind a misleading one.
test.afterEach(async ({ page }) => { await page.unrouteAll({ behavior: 'wait' }); });

const NOW = Math.floor(Date.now() / 1000);
type Mock = Record<string, unknown>;
const ID = '11111111-1111-4111-8111-111111111111';
const request = (extra: Mock = {}): Mock => ({
  id: ID, personId: 'alex', minutes: 30, reason: 'finishing homework', state: 'pending',
  createdAt: NOW - 30, expiresAt: NOW + 800, decidedBy: null, decidedAt: null, grantedMinutes: null, allowanceUntil: null,
  code: null, repause: 'none', repauseOverdue: false, repauseError: null, ...extra,
});
const activeGrant = (extra: Mock = {}) => request({ state: 'approved', grantedMinutes: 30, allowanceUntil: NOW + 1800, decidedBy: 'bryn', decidedAt: NOW - 10, ...extra });

async function mockList(page: Page, current: () => Mock[]) {
  await page.route((url) => url.pathname === '/time-requests', (route) => route.request().method() === 'GET'
    ? route.fulfill({ json: { links: [{ personId: 'alex', active: false, createdAt: null }], requests: current() } }) : route.fallback());
}
const decisions = (page: Page, onPost: (route: Route, action: 'approve' | 'decline') => Promise<void> | void) =>
  page.route(/\/time-requests\/[0-9a-f-]{36}\/(approve|decline)$/, (route) => onPost(route, route.request().url().endsWith('approve') ? 'approve' : 'decline'));
const endButton = (page: Page) => page.getByRole('button', { name: 'End extra time for Alex (fictional)' });
const card = (page: Page) => page.locator('#time-requests');

test.describe('End extra time is honest about what was sent', () => {
  test('MOCK: a revision conflict (409) does not say Pause requested', async ({ page, demo }) => {
    await mockList(page, () => [activeGrant()]);
    await page.route((url) => url.pathname === '/people/alex/pause', (route) => route.fulfill({ status: 409, json: { error: { code: 'revision_conflict', message: 'Stale.' } } }));
    await enroll(page, demo, 'bryn');
    await endButton(page).click();
    await expect(card(page).locator('.notice')).toContainText("Couldn't send the pause for Alex (fictional)");
    await expect(card(page).locator('.notice')).toContainText('Revision conflict');
    await expect(card(page)).not.toContainText('Pause requested');
  });

  test('MOCK: a server error (500) does not say Pause requested', async ({ page, demo }) => {
    await mockList(page, () => [activeGrant()]);
    await page.route((url) => url.pathname === '/people/alex/pause', (route) => route.fulfill({ status: 500, json: { error: { code: 'boom', message: 'Router busy.' } } }));
    await enroll(page, demo, 'bryn');
    await endButton(page).click();
    await expect(card(page).locator('.notice')).toContainText("Couldn't send the pause for Alex (fictional)");
    await expect(card(page).locator('.notice')).toContainText('Router busy.');
    await expect(card(page)).not.toContainText('Pause requested');
  });

  test('MOCK: lost control (status cannot be refreshed) does not say Pause requested', async ({ page, demo }) => {
    await mockList(page, () => [activeGrant()]);
    await enroll(page, demo, 'bryn');
    await page.route((url) => url.pathname === '/people', (route) => route.abort());
    await endButton(page).click();
    await expect(card(page).locator('.notice')).toContainText("Couldn't send the pause for Alex (fictional)");
    await expect(card(page)).not.toContainText('Pause requested');
  });

  test('MOCK: a changed revision after the refresh does not say Pause requested', async ({ page, demo }) => {
    await mockList(page, () => [activeGrant()]);
    await enroll(page, demo, 'bryn');
    await page.route((url) => url.pathname === '/people', async (route) => {
      const response = await route.fetch();
      const body = await response.json();
      await route.fulfill({ response, json: { ...body, revisionToken: 'changed-under-you' } });
    });
    await endButton(page).click();
    await expect(card(page).locator('.notice')).toContainText("Couldn't send the pause for Alex (fictional)");
    await expect(card(page)).not.toContainText('Pause requested');
  });
});

test.describe('session hygiene', () => {
  test('MOCK: signing out clears reason text, child names and the one-time link from the document', async ({ page, demo }) => {
    await mockList(page, () => [request({ reason: 'private reason text' })]);
    await enroll(page, demo, 'bryn');
    await page.getByRole('button', { name: 'Create request link for Alex (fictional)' }).click();
    await expect(page.locator('.request-link input')).toBeVisible();
    await expect(card(page)).toContainText('private reason text');
    await page.getByRole('button', { name: 'Sign out', exact: true }).click();
    await expect(card(page)).toBeHidden();
    expect(await card(page).evaluate((node) => node.childElementCount)).toBe(0);
    const html = await page.evaluate(() => document.documentElement.outerHTML + [...document.querySelectorAll('input')].map((input) => input.value).join('|'));
    expect(html).not.toContain('private reason text');
    expect(html).not.toContain('/request.html#');
  });

  test('MOCK: a late response issued before a key change is ignored', async ({ page, demo }) => {
    let gets = 0;
    let release!: () => void;
    const held = new Promise<void>((resolve) => { release = resolve; });
    await page.route((url) => url.pathname === '/time-requests', async (route) => {
      if (route.request().method() !== 'GET') return route.fallback();
      gets += 1;
      const mine = gets;
      const links = [{ personId: 'alex', active: false, createdAt: null }];
      if (mine === 1) { await held; return route.fulfill({ json: { links, requests: [request({ reason: 'OLD late reason' })] } }); }
      return route.fulfill({ json: { links, requests: [request({ reason: 'NEW reason' })] } });
    });
    await enroll(page, demo, 'bryn');
    await expect.poll(() => gets).toBe(1);
    await page.getByRole('button', { name: 'Sign out', exact: true }).click();
    await page.getByLabel('One-use enrollment token').fill(demo.token('jd'));
    await page.getByRole('button', { name: 'Create a demo passkey' }).click();
    await expect(card(page)).toContainText('NEW reason');
    const late = page.waitForResponse((r) => new URL(r.url()).pathname === '/time-requests' && r.request().method() === 'GET');
    release();
    await late; // the held OLD response has now been delivered to the page; one frame lets the page act on it
    await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => resolve(null))));
    await expect(card(page)).toContainText('NEW reason');
    await expect(card(page)).not.toContainText('OLD late reason');
  });

  test('MOCK: an owner who signs in after a non-owner 404 gets the card and polling again', async ({ page, demo }) => {
    let off = true, gets = 0;
    await page.route((url) => url.pathname === '/time-requests', (route) => {
      if (route.request().method() !== 'GET') return route.fallback();
      gets += 1;
      return off ? route.fulfill({ status: 404, json: { error: { code: 'route_not_found', message: 'Not found.' } } })
        : route.fulfill({ json: { links: [{ personId: 'alex', active: false, createdAt: null }], requests: [request()] } });
    });
    await enroll(page, demo, 'bryn');
    await expect.poll(() => gets).toBeGreaterThan(0);
    await expect(card(page)).toBeHidden();
    off = false;
    await page.getByRole('button', { name: 'Sign out', exact: true }).click();
    await page.getByLabel('One-use enrollment token').fill(demo.token('jd'));
    await page.getByRole('button', { name: 'Create a demo passkey' }).click();
    await expect(card(page)).toContainText('asks for 30 minutes');
    const seen = gets;
    await expect.poll(() => gets, { timeout: 12000 }).toBeGreaterThan(seen);
  });

  test('MOCK: a double tap on Create link sends one POST', async ({ page, demo }) => {
    await mockList(page, () => []);
    let posts = 0;
    let release!: () => void;
    const held = new Promise<void>((resolve) => { release = resolve; });
    await page.route((url) => url.pathname === '/people/alex/request-link', async (route) => { posts += 1; await held; await route.fallback(); });
    await enroll(page, demo, 'bryn');
    const create = page.getByRole('button', { name: 'Create request link for Alex (fictional)' });
    await create.click();
    await expect(create).toBeDisabled();
    await create.click({ force: true });
    await page.waitForTimeout(300); // negative check (no second POST): there is no event for a request that must not happen
    expect(posts).toBe(1);
    release();
    await expect(page.locator('.request-link input')).toBeVisible();
  });
});

test.describe('status line and focus', () => {
  test('MOCK: the top status line never shows Applying or Declining', async ({ page, demo }) => {
    let phase: 'pending' | 'approved' = 'pending';
    let release!: () => void;
    const held = new Promise<void>((resolve) => { release = resolve; });
    await mockList(page, () => [phase === 'pending' ? request() : activeGrant()]);
    await decisions(page, async (route) => { await held; phase = 'approved'; await route.fulfill({ json: { request: activeGrant() } }); });
    await enroll(page, demo, 'bryn');
    await page.getByRole('button', { name: 'Grant 30 minutes for Alex (fictional)' }).click();
    await expect(card(page)).toContainText('Applying');
    await expect(page.locator('#notice')).not.toContainText(/Applying|Declining/);
    release();
    await expect(card(page)).toContainText('Granted until');
    await expect(page.locator('#notice')).not.toContainText(/Applying|Declining/);
  });

  test('MOCK: after Grant settles and the request leaves the list, focus lands on the card heading', async ({ page, demo }) => {
    let phase: 'pending' | 'approved' = 'pending';
    await mockList(page, () => [phase === 'pending' ? request() : activeGrant()]);
    await decisions(page, (route) => { phase = 'approved'; return route.fulfill({ json: { request: activeGrant() } }); });
    await enroll(page, demo, 'bryn');
    await page.getByRole('button', { name: 'Grant 30 minutes for Alex (fictional)' }).click();
    await expect(card(page)).toContainText('Granted until');
    await expect(page.locator('#time-requests-title')).toBeFocused();
    await expect(page.locator('#time-requests-title')).toHaveAttribute('tabindex', '-1');
  });

  test('MOCK: when the request stays pending after a failed tap, focus returns to the same control', async ({ page, demo }) => {
    await mockList(page, () => [request()]);
    await decisions(page, (route) => route.fulfill({ status: 500, json: { error: { code: 'x', message: 'Try later.' } } }));
    await enroll(page, demo, 'bryn');
    const grant = page.getByRole('button', { name: 'Grant 30 minutes for Alex (fictional)' });
    await grant.click();
    await expect(card(page)).toContainText('Try later.');
    await expect(grant).toBeEnabled();
    await expect(grant).toBeFocused();
  });
});

test.describe('reason codes and history', () => {
  const codes: Array<[string, RegExp]> = [
    ['approval_not_applied', /router change did not take effect/],
    ['grant_not_applied', /router did not accept/],
    ['grant_not_in_force', /ran out before/],
    ['apply_failed', /did not complete/],
  ];
  for (const [code, text] of codes) {
    test(`MOCK: ${code} shows parent-friendly text and keeps the code in a data attribute`, async ({ page, demo }) => {
      await mockList(page, () => [request({ state: 'apply_failed', grantedMinutes: 30, code })]);
      await enroll(page, demo, 'bryn');
      const row = page.locator('.time-request-history li');
      await expect(row).toContainText("Couldn't apply");
      await expect(row).toContainText(text);
      await expect(row).not.toContainText(code);
      await expect(row).toHaveAttribute('data-code', code);
    });
  }

  test('MOCK: an unknown code gets generic text and is never printed raw', async ({ page, demo }) => {
    await mockList(page, () => [request({ state: 'apply_failed', grantedMinutes: 30, code: 'zz_weird_code' }), request({ id: '22222222-2222-4222-8222-222222222222', state: 'unsupported', code: 'zz_other' })]);
    await enroll(page, demo, 'bryn');
    await expect(page.locator('.time-request-history li').first()).toContainText("Couldn't apply");
    await expect(card(page)).not.toContainText('zz_');
    await expect(page.locator('.time-request-history li[data-code="zz_weird_code"]')).toHaveCount(1);
  });

  test('MOCK: no empty placeholder spans are rendered', async ({ page, demo }) => {
    await mockList(page, () => [request()]);
    await enroll(page, demo, 'bryn');
    await expect(page.locator('.time-request')).toBeVisible();
    expect(await card(page).evaluate((node) => [...node.querySelectorAll('span')].filter((span) => !span.textContent && !span.children.length).length)).toBe(0);
  });

  test('MOCK: an active grant stays visible above the 8 row cap even under 9 newer rows', async ({ page, demo }) => {
    const newer = Array.from({ length: 9 }, (_, index) => request({ id: `3333333${index}-3333-4333-8333-333333333333`, state: 'declined', decidedBy: 'bryn', decidedAt: NOW - index }));
    await mockList(page, () => [...newer, activeGrant()]);
    await enroll(page, demo, 'bryn');
    await expect(endButton(page)).toBeVisible();
    expect(await page.locator('.time-request-history li').count()).toBeLessThanOrEqual(8);
  });
});

test.describe('Grant less', () => {
  const shorter = (page: Page) => page.locator('.time-request [data-grant-less] button');
  test('MOCK: a 45 minute request offers 15 and 30; a 15 minute request offers none', async ({ page, demo }) => {
    await mockList(page, () => [request({ minutes: 45 }), request({ id: '22222222-2222-4222-8222-222222222222', minutes: 15 })]);
    await enroll(page, demo, 'bryn');
    await expect(page.getByRole('button', { name: 'Grant 45 minutes for Alex (fictional)' })).toBeVisible();
    await expect(shorter(page)).toHaveCount(2);
    await expect(page.getByRole('button', { name: 'Grant 15 minutes for Alex (fictional)' })).toHaveCount(2);
    await expect(page.getByRole('button', { name: 'Grant 30 minutes for Alex (fictional)' })).toHaveCount(1);
    await expect(page.locator(`.time-request[data-request="22222222-2222-4222-8222-222222222222"] [data-grant-less]`)).toHaveCount(0);
  });

  test('MOCK: a 30 minute request offers only 15, at 44px, and posts the chosen minutes', async ({ page, demo }) => {
    const bodies: unknown[] = [];
    await mockList(page, () => [request()]);
    await decisions(page, (route) => { bodies.push(route.request().postDataJSON()); return route.fulfill({ json: { request: request({ state: 'approving', grantedMinutes: 15 }) } }); });
    await enroll(page, demo, 'bryn');
    await expect(shorter(page)).toHaveCount(1);
    const less = page.getByRole('button', { name: 'Grant 15 minutes for Alex (fictional)' });
    expect((await less.boundingBox())!.height).toBeGreaterThanOrEqual(44);
    expect((await less.boundingBox())!.width).toBeGreaterThanOrEqual(44);
    await expect(page.locator('.time-request [data-grant-less]')).toContainText('Grant less');
    await less.click();
    await expect.poll(() => bodies.length).toBe(1);
    expect(bodies).toEqual([{ minutes: 15 }]);
  });
});

test.describe('in-flight responses after a session change', () => {
  async function switchSession(page: Page, demo: { token: (id: 'bryn' | 'jd') => string }) {
    await page.getByRole('button', { name: 'Sign out', exact: true }).click();
    await page.getByLabel('One-use enrollment token').fill(demo.token('jd'));
    await page.getByRole('button', { name: 'Create a demo passkey' }).click();
  }

  test('MOCK: a request link created before a session change never appears for the next session', async ({ page, demo }) => {
    await mockList(page, () => [request()]);
    let release!: () => void;
    const held = new Promise<void>((resolve) => { release = resolve; });
    let started = 0;
    await page.route((url) => url.pathname === '/people/alex/request-link', async (route) => {
      started += 1; await held;
      await route.fulfill({ json: { path: '/request.html#LATE-SECRET-LINK' } });
    });
    await enroll(page, demo, 'bryn');
    await page.getByRole('button', { name: 'Create request link for Alex (fictional)' }).click();
    await expect.poll(() => started).toBe(1);
    await switchSession(page, demo);
    await expect(card(page)).toContainText('asks for 30 minutes');
    const poll = page.waitForResponse((r) => new URL(r.url()).pathname === '/time-requests' && r.request().method() === 'GET', { timeout: 15000 });
    release();
    await poll; // the next poll redraws the card
    await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => resolve(null))));
    await expect(page.locator('.request-link input')).toHaveCount(0);
    const html = await page.evaluate(() => document.documentElement.outerHTML + [...document.querySelectorAll('input')].map((input) => input.value).join('|'));
    expect(html).not.toContain('LATE-SECRET-LINK');
  });

  test('MOCK: a decision notice from before a session change never appears for the next session', async ({ page, demo }) => {
    await mockList(page, () => [request()]);
    let release!: () => void;
    const held = new Promise<void>((resolve) => { release = resolve; });
    let started = 0;
    await decisions(page, async (route) => { started += 1; await held; await route.fulfill({ json: { request: request({ state: 'declined' }) } }); });
    await enroll(page, demo, 'bryn');
    await page.getByRole('button', { name: 'Decline request from Alex (fictional)' }).click();
    await expect.poll(() => started).toBe(1);
    await switchSession(page, demo);
    await expect(card(page)).toContainText('asks for 30 minutes');
    const poll = page.waitForResponse((r) => new URL(r.url()).pathname === '/time-requests' && r.request().method() === 'GET', { timeout: 15000 });
    release();
    await poll; // the next poll redraws the card
    await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => resolve(null))));
    await expect(card(page)).not.toContainText('Request declined.');
  });
});

test.describe('unknown codes get the generic text', () => {
  for (const code of ['constructor', '__proto__', 'toString']) {
    test(`MOCK: code ${code} is not looked up on Object.prototype`, async ({ page, demo }) => {
      await mockList(page, () => [
        request({ state: 'apply_failed', code, decidedBy: 'bryn' }),
        request({ id: '22222222-2222-4222-8222-222222222222', state: 'unsupported', code, decidedBy: 'bryn' }),
      ]);
      await enroll(page, demo, 'bryn');
      await expect(card(page)).toContainText('the router did not confirm it');
      await expect(card(page)).not.toContainText('function');
      await expect(card(page)).not.toContainText('[object');
      await expect(card(page)).not.toContainText('native code');
    });
  }
});
