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
