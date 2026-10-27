import { test, expect, enroll } from './browser-fixture.ts';
import type { Page, Browser } from '@playwright/test';
import { randomUUID } from 'node:crypto';
import { INITIAL_POLICY } from '../../service/src/fixtures.ts';
import { policyJSON, normalizePolicy } from '../../shared/src/router-schema.ts';

test.use({ serviceWorkers: 'block' });
test.setTimeout(60000); // child and parent poll every 5 seconds
const bryn = { id: 'bryn', displayName: 'Bryn (fictional)', role: 'parent' as const, personIds: ['alex'], permissionVersion: '1' };

/** Removes the fixture's always-active schedule so only manual pauses can block Alex. */
function clearSchedules(demo: Parameters<Parameters<typeof test>[2]>[0]['demo']) {
  const open = policyJSON(normalizePolicy({ ...INITIAL_POLICY, schedules: [] }));
  demo.store.run('UPDATE service_state SET desired_json=? WHERE singleton=1', open);
  demo.router.store.run('UPDATE fake_state SET policy=? WHERE singleton=1', open);
  demo.router.tick();
}
async function childPage(browser: Browser) {
  // A separate context: no cookies, no passkey, no account.
  const context = await browser.newContext({ serviceWorkers: 'block' });
  return { page: await context.newPage(), context };
}
async function createLink(page: Page) {
  await page.getByRole('button', { name: 'Create request link for Alex (fictional)' }).click();
  const input = page.locator('.request-link input');
  await expect(input).toBeVisible();
  return input.inputValue();
}

test('child asks for time, parent approves, the pause ends, and the child sees the approval', async ({ page, browser, demo }) => {
  clearSchedules(demo);
  await enroll(page, demo, 'bryn');
  const pauseOp = demo.policy.mutate(bryn, 'alex', 'pause', { until: 0 }, demo.policy.people(bryn).revisionToken!, randomUUID());
  expect(pauseOp.status).toBeLessThan(400);
  await expect.poll(() => demo.router.observe().policy.pauses.length).toBe(1);

  const url = await createLink(page);
  expect(url).toMatch(/\/request\.html#[A-Za-z0-9_-]{43}$/);
  const { page: child, context } = await childPage(browser);
  try {
    await child.goto(url);
    await expect(child.getByRole('heading', { name: 'Ask for more time' })).toBeVisible();
    await child.getByLabel('30 minutes').check();
    await child.getByLabel(/Why\?/).fill('<b>homework</b>');
    await child.getByRole('button', { name: 'Send request' }).click();
    await expect(child.locator('#child-state')).toContainText('Waiting for a parent');
    expect(await context.cookies()).toEqual([]);

    const card = page.locator('.time-request');
    await expect(card).toContainText('Alex (fictional) asks for 30 minutes');
    await expect(card).toContainText('<b>homework</b>');
    expect(await card.locator('b').count()).toBe(0);
    await page.getByRole('button', { name: 'Grant 30 minutes for Alex (fictional)' }).click();
    await expect(page.locator('.time-request-history')).toContainText('Granted until');
    await expect(page.locator('.time-request')).toHaveCount(0);

    await expect(child.locator('#child-state')).toContainText('Approved: 30 minutes', { timeout: 15000 });
    await expect.poll(() => demo.router.observe().policy.pauses.length).toBe(0);
    await expect(child.locator('#child-form')).toBeHidden();
  } finally { await context.close(); }
});

test('approval during a schedule block says it is not supported yet on both sides', async ({ page, browser, demo }) => {
  await enroll(page, demo, 'bryn');
  const url = await createLink(page);
  const { page: child, context } = await childPage(browser);
  try {
    await child.goto(url);
    await child.getByRole('button', { name: 'Send request' }).click();
    await expect(page.locator('.time-request')).toContainText('asks for 15 minutes');
    await page.getByRole('button', { name: 'Grant 15 minutes for Alex (fictional)' }).click();
    await expect(page.locator('#time-requests .notice')).toContainText('Not supported yet: schedules cannot be overridden');
    await expect(child.locator('#child-state')).toContainText('Not supported yet', { timeout: 15000 });
    expect(demo.router.observe().policy.pauses).toEqual([]);
  } finally { await context.close(); }
});

test('turning a link off invalidates it for the child', async ({ page, browser, demo }) => {
  await enroll(page, demo, 'bryn');
  const url = await createLink(page);
  const { page: child, context } = await childPage(browser);
  try {
    await child.goto(url);
    await expect(child.locator('#child-form')).toBeVisible();
    await page.getByRole('button', { name: 'Turn off request link for Alex (fictional)' }).click();
    await expect(page.locator('.request-link')).toContainText('no link');
    await expect(child.locator('#child-state')).toContainText('not active', { timeout: 15000 });
    await expect(child.locator('#child-form')).toBeHidden();
  } finally { await context.close(); }
});

test('an approved request whose grant was ended by a pause says the time has ended on both sides', async ({ page, browser, demo }) => {
  clearSchedules(demo);
  await enroll(page, demo, 'bryn');
  const url = await createLink(page);
  const { page: child, context } = await childPage(browser);
  try {
    await child.goto(url);
    await child.getByRole('button', { name: 'Send request' }).click();
    await page.getByRole('button', { name: 'Grant 15 minutes for Alex (fictional)' }).click();
    await expect(page.locator('.time-request-history')).toContainText('Granted until');
    await expect(child.locator('#child-state')).toContainText('Approved: 15 minutes', { timeout: 15000 });
    // A pause during a router grant keeps the request approved but with code grant_ended.
    demo.store.run("UPDATE time_requests SET decision_code='grant_ended' WHERE state='approved'");
    await expect(child.locator('#child-state')).toHaveText(/^A parent paused access, so the extra time has ended\./, { timeout: 15000 });
    await expect(child.locator('#child-state')).not.toContainText('Approved');
    await expect(page.locator('.time-request-history')).toContainText('the extra time has ended', { timeout: 15000 });
    await expect(page.locator('.time-request-history')).not.toContainText('Granted until');
  } finally { await context.close(); }
});
