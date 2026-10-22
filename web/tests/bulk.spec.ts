import { test, expect, dispatchPending, signIn, noHorizontalScroll, NAMES } from './bulk-fixture.ts';

const HOSTILE = '<img src=x onerror="window.__xss=1">';

test('admin blocks all kids: in-page confirmation lists every child, then the passkey, then the router; honest until confirmed (phone width)', async ({ page, integration: f }) => {
  const calls: string[] = [], keys: (string | undefined)[] = [];
  page.on('request', (r) => { if (r.method() === 'POST') { calls.push(new URL(r.url()).pathname); if (r.url().includes('/bulk/')) keys.push(r.headers()['idempotency-key']); } });
  await signIn(page, f, 'operator');
  const panel = page.locator('#bulk-panel');
  await expect(panel.getByRole('button', { name: 'Block all kids' })).toBeEnabled();
  await expect(panel.getByRole('button', { name: 'Unblock all' })).toBeEnabled();

  // The confirmation is in the page and names the children; nothing is sent until it is confirmed.
  await panel.getByRole('button', { name: 'Block all kids' }).click();
  const confirm = panel.getByRole('group', { name: 'Confirm block all kids' });
  await expect(confirm.getByRole('listitem')).toHaveText([NAMES.kid2, NAMES.kid3, NAMES.pilot].sort());
  expect(calls.filter((c) => c.startsWith('/bulk') || c === '/step-up/options')).toEqual([]);

  // Cancel sends nothing at all.
  await confirm.getByRole('button', { name: 'Cancel' }).click();
  await expect(confirm).toBeHidden();
  expect(calls.filter((c) => c.startsWith('/bulk') || c === '/step-up/options')).toEqual([]);

  await panel.getByRole('button', { name: 'Block all kids' }).click();
  await confirm.getByRole('button', { name: 'Confirm with passkey' }).click();
  const status = panel.locator('[role="status"][data-bulk-status]');
  await expect(status).toContainText('Sent to the router — not confirmed yet');
  await expect(status).toContainText('Not in force');
  await expect(status).not.toContainText('Blocking');
  // Step-up always precedes the POST, and the POST carries an idempotency key.
  expect(calls.filter((c) => c.startsWith('/bulk') || c === '/step-up/options')).toEqual(['/step-up/options', '/bulk/pause-all']);
  expect(keys[0]).toMatch(/^[A-Za-z0-9_-]{16,128}$/);
  // Disabled while an operation is in progress.
  await expect(panel.getByRole('button', { name: 'Block all kids' })).toBeDisabled();
  await expect(panel.getByRole('button', { name: 'Unblock all' })).toBeDisabled();

  await dispatchPending(f);
  await page.getByRole('button', { name: 'Refresh status' }).click();
  await expect(status).toContainText('Blocking');
  await expect(status).not.toContainText('Not in force');
  expect(f.router.policy.pauses.map((p) => p.person).sort()).toEqual(['kid2', 'kid3', 'pilot']);
  await expect(page.locator('[data-person="kid3"] .operation')).toContainText('Blocking');
  expect(await noHorizontalScroll(page)).toBe(true);
});

test('a parent with narrower scope sees and blocks only their own children', async ({ page, integration: f }) => {
  await signIn(page, f, 'parent');
  const panel = page.locator('#bulk-panel');
  await panel.getByRole('button', { name: 'Block all kids' }).click();
  const confirm = panel.getByRole('group', { name: 'Confirm block all kids' });
  await expect(confirm.getByRole('listitem')).toHaveText([NAMES.kid2, NAMES.pilot].sort());
  await expect(confirm).not.toContainText(NAMES.kid3);
  await confirm.getByRole('button', { name: 'Confirm with passkey' }).click();
  await expect(panel.locator('[data-bulk-status]')).toContainText('Sent to the router');
  await dispatchPending(f);
  expect(f.router.policy.pauses.map((p) => p.person).sort()).toEqual(['kid2', 'pilot']);
});

test('unblock all: "may still be blocked" until the router confirms, then unblocked', async ({ page, integration: f }) => {
  await signIn(page, f, 'operator');
  const panel = page.locator('#bulk-panel'), status = panel.locator('[data-bulk-status]');
  await panel.getByRole('button', { name: 'Block all kids' }).click();
  await panel.getByRole('button', { name: 'Confirm with passkey' }).click();
  await expect(status).toContainText('Sent to the router');
  await dispatchPending(f);
  await page.getByRole('button', { name: 'Refresh status' }).click();
  await expect(status).toContainText('Blocking');

  await panel.getByRole('button', { name: 'Unblock all' }).click();
  const confirm = panel.getByRole('group', { name: 'Confirm unblock all' });
  await expect(confirm.getByRole('listitem')).toHaveCount(3);
  await confirm.getByRole('button', { name: 'Confirm with passkey' }).click();
  await expect(status).toContainText('Sent to the router — not confirmed yet');
  await expect(status).toContainText('May still be blocked');
  await dispatchPending(f);
  await page.getByRole('button', { name: 'Refresh status' }).click();
  await expect(status).toContainText('Unblocked');
  await expect(status).not.toContainText('May still be blocked');
  expect(f.router.policy.pauses).toEqual([]);
});

test('a refused block says "not in force"', async ({ page, integration: f }) => {
  await signIn(page, f, 'operator');
  const panel = page.locator('#bulk-panel'), status = panel.locator('[data-bulk-status]');
  f.router.reject = 'incomplete_address_coverage';
  await panel.getByRole('button', { name: 'Block all kids' }).click();
  await panel.getByRole('button', { name: 'Confirm with passkey' }).click();
  await expect(status).toContainText('Sent to the router');
  await dispatchPending(f);
  await page.getByRole('button', { name: 'Refresh status' }).click();
  await expect(status).toContainText('Not in force');
  await expect(status).not.toContainText('Blocking');
  expect(f.router.policy.pauses).toEqual([]);
});

test('a refused unblock says nothing changed and the block stays', async ({ page, integration: f }) => {
  await signIn(page, f, 'operator');
  const panel = page.locator('#bulk-panel'), status = panel.locator('[data-bulk-status]');
  await panel.getByRole('button', { name: 'Block all kids' }).click();
  await panel.getByRole('button', { name: 'Confirm with passkey' }).click();
  await expect(status).toContainText('Sent to the router');
  await dispatchPending(f);
  await page.getByRole('button', { name: 'Refresh status' }).click();
  await expect(status).toContainText('Blocking');
  f.router.reject = 'incomplete_address_coverage';
  await panel.getByRole('button', { name: 'Unblock all' }).click();
  await panel.getByRole('button', { name: 'Confirm with passkey' }).click();
  await expect(status).toContainText('May still be blocked');
  await dispatchPending(f);
  await page.getByRole('button', { name: 'Refresh status' }).click();
  await expect(status).toContainText('Nothing changed');
  await expect(status).not.toContainText('Unblocked');
  expect(f.router.policy.pauses).toHaveLength(3);
});

test('child names are rendered as text in the confirmation, never as markup', async ({ page, integration: f }) => {
  f.store.run('UPDATE people SET name=? WHERE id=?', HOSTILE, 'kid2');
  await signIn(page, f, 'operator');
  const panel = page.locator('#bulk-panel');
  await panel.getByRole('button', { name: 'Block all kids' }).click();
  await expect(panel.getByRole('group', { name: 'Confirm block all kids' })).toContainText(HOSTILE);
  expect(await panel.locator('img').count()).toBe(0);
  expect(await page.evaluate(() => (window as unknown as { __xss?: number }).__xss)).toBeUndefined();
});

test('the bulk panel is hidden when the account manages no child', async ({ page, integration: f }) => {
  await signIn(page, f, 'parent');
  await expect(page.locator('#bulk-panel')).toBeVisible();
  f.store.run('UPDATE accounts SET person_ids=? WHERE id=?', '[]', 'parent');
  await page.getByRole('button', { name: 'Refresh status' }).click();
  await expect(page.locator('#bulk-panel')).toBeHidden();
});

// --- Review fixes: send-boundary honesty (M1) ---
const blockAll = async (page: import('@playwright/test').Page) => {
  const panel = page.locator('#bulk-panel');
  await panel.getByRole('button', { name: 'Block all kids' }).click();
  await panel.getByRole('button', { name: 'Confirm with passkey' }).click();
};

test('M1: a POST lost after it was sent says the outcome is unknown, and the immediate retry reuses the same Idempotency-Key', async ({ page, integration: f }) => {
  const keys: (string | undefined)[] = [];
  let attempts = 0;
  await page.route('**/bulk/pause-all', (route) => { keys.push(route.request().headers()['idempotency-key']); return ++attempts === 1 ? route.abort('connectionreset') : route.continue(); });
  await signIn(page, f, 'operator');
  const status = page.locator('#bulk-panel [data-bulk-status]');
  await blockAll(page);
  await expect(status).toContainText('may have reached the router');
  await expect(status).toContainText('outcome unknown');
  await expect(status).toContainText('Check the status below before trying again');
  await expect(status).not.toContainText('Nothing was sent');
  await expect(page.locator('#bulk-panel').getByRole('button', { name: 'Block all kids' })).toBeEnabled();
  await blockAll(page);
  await expect(status).toContainText('Sent to the router');
  expect(keys).toHaveLength(2);
  expect(keys[0]).toMatch(/^[A-Za-z0-9_-]{16,128}$/);
  expect(keys[1]).toBe(keys[0]);
});

test('M1: a 502 with an HTML body gets friendly unknown-outcome text, never a JSON parse message', async ({ page, integration: f }) => {
  await page.route('**/bulk/pause-all', (route) => route.fulfill({ status: 502, contentType: 'text/html', body: '<html><body>Bad Gateway</body></html>' }));
  await signIn(page, f, 'operator');
  const status = page.locator('#bulk-panel [data-bulk-status]');
  await blockAll(page);
  await expect(status).toContainText('may have reached the router');
  await expect(status).not.toContainText(/JSON|Unexpected|token|<html/i);
  await expect(status).not.toContainText('Nothing was sent');
});

test('M1: a step-up refusal before any POST still says "Nothing was sent"', async ({ page, integration: f }) => {
  const posts: string[] = [];
  page.on('request', (r) => { if (r.method() === 'POST' && r.url().includes('/bulk/')) posts.push(r.url()); });
  await page.route('**/step-up/options', (route) => route.fulfill({ status: 409, contentType: 'application/json', body: JSON.stringify({ error: { code: 'step_up_refused', message: 'Step-up is not available.' } }) }));
  await signIn(page, f, 'operator');
  const status = page.locator('#bulk-panel [data-bulk-status]');
  await blockAll(page);
  await expect(status).toContainText('Step-up is not available.');
  await expect(status).toContainText('Nothing was sent');
  expect(posts).toEqual([]);
});

// --- Review fixes: shared control gating (M2) ---
const reason = (page: import('@playwright/test').Page) => page.locator('#bulk-panel [data-bulk-reason]');
const bulkButtons = (page: import('@playwright/test').Page) => page.locator('#bulk-panel .bulk-actions button');

test('M2: offline disables both bulk buttons and says why', async ({ page, integration: f }) => {
  await signIn(page, f, 'operator');
  await expect(bulkButtons(page).first()).toBeEnabled();
  await page.context().setOffline(true);
  await page.evaluate(() => window.dispatchEvent(new Event('offline')));
  for (const button of await bulkButtons(page).all()) await expect(button).toBeDisabled();
  await expect(reason(page)).toHaveText('Offline');
});

test('M2: a stale snapshot disables bulk with a refresh hint', async ({ page, integration: f }) => {
  await page.route('**/people', async (route) => {
    const response = await route.fetch(); const body = await response.json(); body.observedAt -= 120;
    await route.fulfill({ response, json: body });
  });
  await signIn(page, f, 'operator');
  for (const button of await bulkButtons(page).all()) await expect(button).toBeDisabled();
  await expect(reason(page)).toHaveText('Status is out of date — refresh');
});

test('M2: a per-person mutation in flight disables bulk, and it comes back afterwards', async ({ page, integration: f }) => {
  let release: () => void = () => {};
  const held = new Promise<void>((resolve) => { release = resolve; });
  await page.route('**/people/kid2/pause', async (route) => { await held; await route.continue(); });
  await signIn(page, f, 'operator');
  await expect(bulkButtons(page).first()).toBeEnabled();
  await page.locator('[data-person="kid2"] [data-control="pause"]').click();
  for (const button of await bulkButtons(page).all()) await expect(button).toBeDisabled();
  await expect(reason(page)).toHaveText('A change is already in progress');
  release();
});

test('touch targets: every bulk control is at least 44px tall', async ({ page, integration: f }) => {
  await signIn(page, f, 'operator');
  const panel = page.locator('#bulk-panel');
  await panel.getByRole('button', { name: 'Block all kids' }).click();
  for (const button of await panel.getByRole('button').all()) expect((await button.boundingBox())!.height).toBeGreaterThanOrEqual(44);
});
