import { test, expect, dispatchPending, signIn, noHorizontalScroll, NAMES, OUTSIDE, K2 } from './bulk-fixture.ts';

const MAC_LIKE = /[0-9a-f]{2}(?::[0-9a-f]{2}){5}/i;

test('admin moves a device to another child with a passkey; "Moving…" until the router confirms (phone width)', async ({ page, integration: f }) => {
  const calls: string[] = [];
  page.on('request', (r) => { if (r.method() === 'POST') calls.push(new URL(r.url()).pathname); });
  await signIn(page, f, 'operator');
  const panel = page.locator('#children-panel'), source = panel.locator('[data-entry="kid2"]'), target = panel.locator('[data-entry="pilot"]');
  const row = source.locator('[data-device="d_kid2"]');
  // The current child is never offered as a destination.
  const choose = row.getByLabel('Move Device kid2 to');
  await expect(choose.locator('option')).toHaveText(['Move to…', NAMES.pilot, NAMES.kid3]);
  await expect(row.getByRole('button', { name: 'Move device Device kid2', exact: true })).toBeDisabled();
  await choose.selectOption('pilot');
  await row.getByRole('button', { name: 'Move device Device kid2', exact: true }).click();
  await expect(panel.locator('.notice[role="status"]')).toContainText('Sent to the router');
  expect(calls.filter((c) => c === '/step-up/options' || c.includes('/move'))).toEqual(['/step-up/options', '/admin/devices/d_kid2/move']);
  await expect(source.locator('[data-device="d_kid2"]')).toContainText('Moving…');
  await expect(page.locator('[data-person="kid2"]')).toContainText('being moved');
  await expect(page.locator('[data-person="kid2"]')).not.toContainText('being removed');
  await expect(source.locator('[data-device="d_kid2"]').getByRole('button', { name: 'Move device Device kid2', exact: true })).toBeDisabled();

  await dispatchPending(f);
  await page.getByRole('button', { name: 'Refresh status' }).click();
  await expect(target.locator('[data-device="d_kid2"]')).toContainText('on the router');
  await expect(source.locator('[data-device="d_kid2"]')).toHaveCount(0);
  expect(f.router.policy.people.find((p) => p.id === 'pilot')!.macs).toContain(K2);
  expect(await noHorizontalScroll(page)).toBe(true);
});

test('moving a device to its own child is refused in the page before any passkey prompt', async ({ page, integration: f }) => {
  const calls: string[] = [];
  page.on('request', (r) => { if (r.method() === 'POST') calls.push(new URL(r.url()).pathname); });
  await signIn(page, f, 'operator');
  const panel = page.locator('#children-panel'), row = panel.locator('[data-entry="kid2"] [data-device="d_kid2"]');
  await row.getByLabel('Move Device kid2 to').evaluate((select: HTMLSelectElement) => { select.append(new Option('Own child', 'kid2')); select.value = 'kid2'; select.dispatchEvent(new Event('change', { bubbles: true })); });
  await row.getByRole('button', { name: 'Move device Device kid2', exact: true }).evaluate((b: HTMLButtonElement) => { b.disabled = false; b.click(); });
  await expect(panel.locator('.notice[role="status"]')).toContainText('already belongs');
  expect(calls.filter((c) => c === '/step-up/options' || c.includes('/move'))).toEqual([]);
});

test('a refused move (target full, no authority) is shown as a plain message and nothing is claimed', async ({ page, integration: f }) => {
  await signIn(page, f, 'operator');
  await page.route('**/admin/devices/*/move', (route) => route.fulfill({ status: 409, contentType: 'application/json', body: JSON.stringify({ error: { code: 'child_device_limit_reached', message: 'The router holds at most 8 devices per entry.' } }) }));
  const panel = page.locator('#children-panel'), row = panel.locator('[data-entry="kid2"] [data-device="d_kid2"]');
  await row.getByLabel('Move Device kid2 to').selectOption('kid3');
  await row.getByRole('button', { name: 'Move device Device kid2', exact: true }).click();
  await expect(panel.locator('.notice[role="status"]')).toContainText('The router holds at most 8 devices per entry.');
  await expect(row).not.toContainText('Moving…');
});

test('a device whose address the router has not approved shows a waiting state with the placeholder only, never a command with the address', async ({ page, integration: f }) => {
  await signIn(page, f, 'operator');
  const panel = page.locator('#children-panel'), child = panel.locator('[data-entry="pilot"]');
  await child.getByLabel('New device name for Explicit test person').fill('Phone');
  await child.getByLabel('Wi-Fi address (MAC) for Explicit test person').fill(OUTSIDE.toUpperCase());
  await child.getByRole('button', { name: 'Add device' }).click();
  const pending = panel.locator('[data-pending-approval]');
  await expect(pending).toContainText('Waiting for router approval');
  await expect(pending).toContainText('Phone');
  await expect(pending).toContainText('cfctl scope-add <ADDRESS FROM DEVICE SETTINGS> --base <router-read>');
  await expect(pending).toContainText('Wi-Fi settings');
  expect(await pending.innerText()).not.toMatch(MAC_LIKE);
  // No line of the page holds scope-add together with an address; nothing offers to copy.
  const lines = await page.evaluate(() => document.body.innerText.split('\n').filter((line) => /scope-add/.test(line)));
  expect(lines.length).toBeGreaterThan(0);
  for (const line of lines) expect(line).not.toMatch(MAC_LIKE);
  await expect(page.getByRole('button', { name: /copy/i })).toHaveCount(0);
  expect(await panel.locator('input, textarea').evaluateAll((els) => els.some((e) => /scope-add/.test((e as HTMLInputElement).value ?? '')))).toBe(false);
  await expect(child).not.toContainText('Phone'); // nothing was added to the child
  expect(await noHorizontalScroll(page)).toBe(true);
});

test('hostile child and device names are rendered as text in the move controls', async ({ page, integration: f }) => {
  const hostile = '<b id="pwn">x</b>';
  f.store.run('UPDATE people SET name=? WHERE id=?', hostile, 'kid3');
  f.store.run('UPDATE devices SET label=? WHERE id=?', '<i id="pwn2">y</i>', 'd_kid2');
  await signIn(page, f, 'operator');
  const panel = page.locator('#children-panel');
  await expect(panel.locator('[data-device="d_kid2"]')).toContainText('<i id="pwn2">y</i>');
  await expect(panel.locator('[data-device="d_kid2"] option', { hasText: hostile })).toHaveCount(1);
  expect(await page.locator('#pwn, #pwn2').count()).toBe(0);
});

test('touch targets: the move select and buttons are at least 44px tall', async ({ page, integration: f }) => {
  await signIn(page, f, 'operator');
  const row = page.locator('#children-panel [data-entry="kid2"] [data-device="d_kid2"]');
  for (const control of [row.getByLabel('Move Device kid2 to'), row.getByRole('button', { name: 'Move device Device kid2', exact: true }), row.getByRole('button', { name: /^Remove device/ })]) {
    await control.scrollIntoViewIfNeeded();
    expect((await control.boundingBox())!.height).toBeGreaterThanOrEqual(44);
  }
});
