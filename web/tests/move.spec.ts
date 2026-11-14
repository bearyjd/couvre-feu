import { test, expect, dispatchPending, signIn, noHorizontalScroll, NAMES, OUTSIDE, K2 } from './bulk-fixture.ts';
import { openTab } from './browser-fixture.ts';
import type { Locator } from '@playwright/test';

const MAC_LIKE = /[0-9a-f]{2}(?::[0-9a-f]{2}){5}/i;

const menuOf = (row: Locator) => row.getByRole('button', { name: /^Actions for / });
/** Opens the row's ⋯ menu and its Move panel. */
async function openMove(row: Locator, label: string) {
  await menuOf(row).click();
  await row.getByRole('menuitem', { name: `Move ${label}`, exact: true }).click();
  return row.locator('[data-confirm="move"]');
}

test('admin moves a device to another child with a passkey; "Moving…" until the router confirms (phone width)', async ({ page, integration: f }) => {
  const calls: string[] = [];
  page.on('request', (r) => { if (r.method() === 'POST') calls.push(new URL(r.url()).pathname); });
  await signIn(page, f, 'operator');
  await openTab(page, 'kids');
  const panel = page.locator('#children-panel'), source = panel.locator('[data-entry="kid2"]'), target = panel.locator('[data-entry="pilot"]');
  const row = source.locator('[data-device="d_kid2"]');
  const confirm = await openMove(row, 'Device kid2');
  // The current child is never offered as a destination, and nothing is sent until the sentence is confirmed.
  const choose = confirm.getByLabel('Move Device kid2 to');
  await expect(choose.locator('option')).toHaveText(['Choose…', NAMES.pilot, NAMES.kid3]);
  await expect(confirm.getByRole('button', { name: 'Yes, move it' })).toBeDisabled();
  expect(calls.filter((c) => c === '/step-up/options' || c.includes('/move'))).toEqual([]);
  await choose.selectOption('pilot');
  await confirm.getByRole('button', { name: 'Yes, move it' }).click();
  await expect(panel.locator('.notice[role="status"]')).toContainText('Sent to the router');
  expect(calls.filter((c) => c === '/step-up/options' || c.includes('/move'))).toEqual(['/step-up/options', '/admin/devices/d_kid2/move']);
  await expect(source.locator('[data-device="d_kid2"] [data-status="sent"]')).toHaveText('Sent, not confirmed yet');
  await expect(source.locator('[data-device="d_kid2"]')).toContainText('Moving…');
  await openTab(page, 'home');
  await expect(page.locator('[data-person="kid2"]')).toContainText('being moved');
  await expect(page.locator('[data-person="kid2"]')).not.toContainText('being removed');
  await openTab(page, 'kids');
  await expect(menuOf(source.locator('[data-device="d_kid2"]'))).toBeDisabled(); // a change is in flight: no second one

  await dispatchPending(f);
  await page.getByRole('button', { name: 'Refresh status' }).click();
  await expect(target.locator('[data-device="d_kid2"] [data-status="on_router"]')).toHaveText('On the router');
  await expect(source.locator('[data-device="d_kid2"]')).toHaveCount(0);
  expect(f.router.policy.people.find((p) => p.id === 'pilot')!.macs).toContain(K2);
  expect(await noHorizontalScroll(page)).toBe(true);
});

test('Cancel on the move sentence sends nothing and returns focus to the menu button', async ({ page, integration: f }) => {
  const calls: string[] = [];
  page.on('request', (r) => { if (r.method() === 'POST') calls.push(new URL(r.url()).pathname); });
  await signIn(page, f, 'operator');
  await openTab(page, 'kids');
  const row = page.locator('#children-panel [data-entry="kid2"] [data-device="d_kid2"]');
  const confirm = await openMove(row, 'Device kid2');
  await confirm.getByRole('button', { name: 'Cancel' }).click();
  await expect(confirm).toHaveCount(0);
  await expect(menuOf(row)).toBeFocused();
  expect(calls.filter((c) => c === '/step-up/options' || c.includes('/move'))).toEqual([]);
});

test('moving a device to its own child is refused in the page before any passkey prompt', async ({ page, integration: f }) => {
  const calls: string[] = [];
  page.on('request', (r) => { if (r.method() === 'POST') calls.push(new URL(r.url()).pathname); });
  await signIn(page, f, 'operator');
  await openTab(page, 'kids');
  const panel = page.locator('#children-panel'), row = panel.locator('[data-entry="kid2"] [data-device="d_kid2"]');
  const confirm = await openMove(row, 'Device kid2');
  // One atomic DOM step: a periodic redraw between separate steps would drop the injected option.
  await confirm.evaluate((c: HTMLElement) => {
    const select = c.querySelector('select') as HTMLSelectElement, button = Array.from(c.querySelectorAll('button')).find((b) => b.textContent === 'Yes, move it') as HTMLButtonElement;
    select.append(new Option('Own child', 'kid2')); select.value = 'kid2'; select.dispatchEvent(new Event('change', { bubbles: true }));
    button.disabled = false; button.click();
  });
  await expect(panel.locator('.notice[role="status"]')).toContainText('already belongs');
  expect(calls.filter((c) => c === '/step-up/options' || c.includes('/move'))).toEqual([]);
});

test('a refused move (target full, no authority) is shown as a plain message and nothing is claimed', async ({ page, integration: f }) => {
  await signIn(page, f, 'operator');
  await openTab(page, 'kids');
  await page.route('**/admin/devices/*/move', (route) => route.fulfill({ status: 409, contentType: 'application/json', body: JSON.stringify({ error: { code: 'child_device_limit_reached', message: 'The router holds at most 8 devices per entry.' } }) }));
  const panel = page.locator('#children-panel'), row = panel.locator('[data-entry="kid2"] [data-device="d_kid2"]');
  const confirm = await openMove(row, 'Device kid2');
  await confirm.getByLabel('Move Device kid2 to').selectOption('kid3');
  await confirm.getByRole('button', { name: 'Yes, move it' }).click();
  await expect(panel.locator('.notice[role="status"]')).toContainText('The router holds at most 8 devices per entry.');
  await expect(row).not.toContainText('Moving…');
  await expect(row.locator('[data-status="sent"]')).toHaveCount(0);
});

test('a device whose address the router has not approved shows a waiting row with the placeholder only, never a command with the address', async ({ page, integration: f }) => {
  await signIn(page, f, 'operator');
  await openTab(page, 'kids');
  const panel = page.locator('#children-panel'), child = panel.locator('[data-entry="pilot"]');
  await child.getByRole('button', { name: 'Add device to Explicit test person' }).click();
  await child.getByLabel('New device name for Explicit test person').fill('Phone');
  await child.getByLabel('Wi-Fi address (MAC) for Explicit test person').fill(OUTSIDE.toUpperCase());
  await child.getByRole('button', { name: 'Add device', exact: true }).click();
  const pending = panel.locator('[data-pending-approval]');
  await expect(pending).toContainText('Waiting for router approval');
  await expect(pending).toContainText('cfctl scope-add <ADDRESS FROM DEVICE SETTINGS> --base <router-read>');
  await expect(pending).toContainText('Wi-Fi settings');
  expect(await pending.innerText()).not.toMatch(MAC_LIKE);
  const waiting = child.locator('[data-pending-scope]');
  await expect(waiting).toContainText('Phone'); // the name typed in this session
  await expect(waiting.locator('[data-status="waiting"]')).toHaveText('Waiting for router approval');
  // No line of the page holds scope-add together with an address; nothing offers to copy.
  const lines = await page.evaluate(() => document.body.innerText.split('\n').filter((line) => /scope-add/.test(line)));
  expect(lines.length).toBeGreaterThan(0);
  for (const line of lines) expect(line).not.toMatch(MAC_LIKE);
  await expect(page.getByRole('button', { name: /copy/i })).toHaveCount(0);
  expect(await panel.locator('input, textarea').evaluateAll((els) => els.some((e) => /scope-add/.test((e as HTMLInputElement).value ?? '')))).toBe(false);
  await expect(child.locator('[data-device]')).toHaveCount(1); // nothing was added to the child
  expect(await noHorizontalScroll(page)).toBe(true);
});

test('hostile child and device names are rendered as text in the move controls', async ({ page, integration: f }) => {
  const hostile = '<b id="pwn">x</b>';
  f.store.run('UPDATE people SET name=? WHERE id=?', hostile, 'kid3');
  f.store.run('UPDATE devices SET label=? WHERE id=?', '<i id="pwn2">y</i>', 'd_kid2');
  await signIn(page, f, 'operator');
  await openTab(page, 'kids');
  const panel = page.locator('#children-panel'), row = panel.locator('[data-device="d_kid2"]');
  await expect(row).toContainText('<i id="pwn2">y</i>');
  const confirm = await openMove(row, '<i id="pwn2">y</i>');
  await expect(confirm.locator('option', { hasText: hostile })).toHaveCount(1);
  expect(await page.locator('#pwn, #pwn2').count()).toBe(0);
});

test('touch targets: the menu button, its items and the move sentence controls are at least 44px tall', async ({ page, integration: f }) => {
  await signIn(page, f, 'operator');
  await openTab(page, 'kids');
  const row = page.locator('#children-panel [data-entry="kid2"] [data-device="d_kid2"]');
  await menuOf(row).click();
  for (const control of [menuOf(row), row.getByRole('menuitem').first(), row.getByRole('menuitem').nth(1)]) {
    await expect.poll(() => control.evaluate((el: HTMLElement) => el.getBoundingClientRect().height)).toBeGreaterThanOrEqual(44);
  }
  await row.getByRole('menuitem').first().click();
  const confirm = row.locator('[data-confirm="move"]');
  for (const control of [confirm.getByLabel('Move Device kid2 to'), confirm.getByRole('button', { name: 'Yes, move it' }), confirm.getByRole('button', { name: 'Cancel' })]) {
    await expect.poll(() => control.evaluate((el: HTMLElement) => el.getBoundingClientRect().height)).toBeGreaterThanOrEqual(44);
  }
});
