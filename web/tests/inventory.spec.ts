import { test, expect, signIn, noHorizontalScroll, dispatchPending, SEED, K2, OUTSIDE } from './bulk-fixture.ts';
import type { World } from './bulk-fixture.ts';
import type { Page } from '@playwright/test';
import { actor } from '../../service/tests/fixtures/integration.ts';

// Placeholder MACs only. NEW_PHONE is inside the installed router scope (the add succeeds); OUTSIDE is not (the add waits for router approval).
const mac = (n: number) => `00:00:5e:00:00:${n.toString(16).padStart(2, '0')}`;
const NEW_PHONE = '02:10:20:30:40:52', NEW_TV = mac(3), LAPTOP = mac(2);
const MAC_PATTERN = /[0-9a-f]{2}(:[0-9a-f]{2}){5}/i;
const HOSTILE = '<img src=x onerror="window.__xss=1">';

function poll(f: World, devices: { mac: string; ipv4: string[]; hostname: string | null; source: 'both' }[], at: number) {
  f.worker.inventory.ingest({ inventory_version: 1, generation: f.config.router.generation, routerTime: at, devices, truncated: false, errors: [] }, at);
}
const d = (m: string, hostname: string | null, last: number) => ({ mac: m, ipv4: [`192.0.2.${last}`], hostname, source: 'both' as const });
/** One complete baseline poll, then three devices that joined afterwards (the newest last). Explicit poll times: the shared test clock (and so the router observation) is left alone. */
function seed(f: World) {
  const kid = d(K2, 'kid2-phone', 20), laptop = d(LAPTOP, 'old-laptop', 21), tv = d(NEW_TV, 'new-tv', 30), box = d(OUTSIDE, 'outside-box', 32), phone = d(NEW_PHONE, 'new-phone', 31), t = f.now();
  poll(f, [kid, laptop], t - 180);
  poll(f, [kid, laptop, tv], t - 120);
  poll(f, [kid, laptop, tv, box], t - 60);
  poll(f, [kid, laptop, tv, box, phone], t);
}
const panel = (page: Page) => page.locator('#inventory-panel');
const row = (page: Page, name: string) => panel(page).locator('li.inventory-row').filter({ hasText: name });
const flags = (page: Page, name: string) => row(page, name).locator('[data-flag]');
const status = (page: Page) => panel(page).locator('[data-inventory-status]');
const markAllAcknowledged = (f: World) => f.store.run("UPDATE inventory_devices SET acknowledged_at=1,acknowledged_by='operator'");

test('admin sees the devices newest first with the right flags, names labelled as device-reported, at phone width', async ({ page, integration: f }) => {
  seed(f);
  await signIn(page, f, 'operator');
  await expect(panel(page).getByRole('heading', { name: 'Devices on the network' })).toBeVisible();
  const names = await panel(page).locator('li.inventory-row [data-name]').allTextContents();
  expect(names.slice(0, 3)).toEqual(['new-phone', 'outside-box', 'new-tv']);
  expect(names).toHaveLength(5);
  await expect(flags(page, 'new-phone')).toHaveText(['New', 'Private address', 'Unassigned']);
  await expect(flags(page, 'new-tv')).toHaveText(['New', 'Unassigned']);
  await expect(flags(page, 'old-laptop')).toHaveText(['Unassigned']);
  await expect(flags(page, 'kid2-phone')).toHaveText(['Private address']);
  await expect(row(page, 'kid2-phone')).toContainText('Kid kid2');
  await expect(row(page, 'kid2-phone')).not.toContainText('Unassigned');
  await expect(row(page, 'new-phone')).toContainText('may rotate — set a fixed Wi-Fi address on this device');
  await expect(row(page, 'new-tv')).not.toContainText('may rotate');
  await expect(row(page, 'new-tv')).toContainText('192.0.2.30');
  await expect(row(page, 'new-tv')).toContainText('name reported by device');
  await expect(row(page, 'new-tv')).toContainText('Last seen');
  expect(await panel(page).innerText()).not.toMatch(MAC_PATTERN); // the address is only ever inside the add form
  expect(await noHorizontalScroll(page)).toBe(true);
});

test('hostile device names (markup, scripts, very long, right-to-left) render as inert text', async ({ page, integration: f }) => {
  seed(f);
  // The database refuses such names, so the response is rewritten: the page must stay safe even if the service were wrong.
  const hostile = [HOSTILE, '<script>window.__xss=2</script>', 'x'.repeat(300), '\u202Eevil\u05D0\u05D1\u05D2'];
  await page.route('**/admin/inventory', async (route) => {
    const response = await route.fetch(); const body = await response.json();
    body.inventory.devices.forEach((device: { hostname: string | null }, i: number) => { device.hostname = hostile[i % hostile.length]; });
    await route.fulfill({ response, json: body });
  });
  const errors: string[] = []; page.on('pageerror', (e) => errors.push(e.message));
  await signIn(page, f, 'operator');
  await expect(panel(page).locator('li.inventory-row')).toHaveCount(5);
  const text = await panel(page).innerText();
  expect(text).toContain(HOSTILE);
  expect(text).toContain('<script>window.__xss=2</script>');
  expect(text).toContain('x'.repeat(300));
  expect(text).toContain('\u202Eevil');
  expect(await panel(page).locator('img, script, [onerror]').count()).toBe(0);
  expect(await page.evaluate(() => (window as unknown as { __xss?: number }).__xss)).toBeUndefined();
  expect(await panel(page).locator('[data-name][dir="auto"]').count()).toBe(5);
  expect(await noHorizontalScroll(page)).toBe(true);
  expect(errors).toEqual([]);
});

test('a parent sees no inventory panel and the endpoint answers 403', async ({ page, integration: f }) => {
  seed(f);
  const requests: string[] = []; page.on('request', (r) => requests.push(new URL(r.url()).pathname));
  await signIn(page, f, 'parent');
  await expect(panel(page)).toBeHidden();
  await expect(panel(page)).toBeEmpty();
  expect(requests).not.toContain('/admin/inventory');
  const forced = await page.evaluate(async () => (await fetch('/admin/inventory')).status);
  expect(forced).toBe(403);
  const html = await page.content();
  for (const secret of ['new-tv', 'outside-box', 'old-laptop', '192.0.2.30']) expect(html).not.toContain(secret);
});

test('acknowledge removes the New badge once, and the server accepts it again', async ({ page, integration: f }) => {
  seed(f);
  const posts: string[] = []; page.on('request', (r) => { if (r.method() === 'POST') posts.push(new URL(r.url()).pathname); });
  await signIn(page, f, 'operator');
  await expect(flags(page, 'new-tv').first()).toHaveText('New');
  await row(page, 'new-tv').getByRole('button', { name: /^Acknowledge/ }).click();
  await expect(flags(page, 'new-tv')).toHaveText(['Unassigned']);
  await expect(row(page, 'new-tv').getByRole('button', { name: /^Acknowledge/ })).toHaveCount(0);
  await expect(flags(page, 'new-phone').first()).toHaveText('New'); // the others are untouched
  expect(posts.filter((p) => p.startsWith('/admin/inventory'))).toEqual(['/admin/inventory/acknowledge']);
  expect(() => f.worker.inventory.acknowledge(actor, NEW_TV)).not.toThrow(); // idempotent
  await expect(row(page, 'old-laptop').getByRole('button', { name: /^Acknowledge/ })).toHaveCount(0); // only New rows offer it
});

test('refresh: 409 while dispatch is off, 202 when accepted, 429 when repeated at once', async ({ page, integration: f }) => {
  seed(f);
  await signIn(page, f, 'operator');
  const message = panel(page).locator('[data-refresh-status]');
  await panel(page).getByRole('button', { name: 'Refresh now' }).click();
  await expect(message).toHaveText('Inventory polling is off until router dispatch is enabled');
  f.config.dispatch = { enabled: true, pollSeconds: 2, maxBackoffSeconds: 8 };
  f.store.run('INSERT INTO automatic_dispatch(singleton,epoch,owner_token,enabled) VALUES(1,?,?,1)', f.store.integrationState().dispatch_epoch, 'test-owner');
  await panel(page).getByRole('button', { name: 'Refresh now' }).click();
  await expect(message).toContainText('Refresh requested');
  await expect(message).not.toContainText('Inventory polling is off');
  await panel(page).getByRole('button', { name: 'Refresh now' }).click();
  await expect(message).toHaveText('Try again in a few seconds');
});

const BAD: [string, string | null, number | null, string][] = [
  ['old router', 'inventory_unavailable:old_router', 0, 'Router too old for inventory'],
  ['transport error', 'inventory_transport_error:ssh_exit_255', 0, 'Router connection problem'],
  ['stalled', null, -7200, 'Inventory is stalled — check the router'],
  ['never completed', 'inventory_unavailable:ssh_timeout', null, 'Inventory is stalled — check the router'],
];
for (const [name, lastError, age, wording] of BAD) {
  test(`status "${name}" is stated plainly and never claims all clear`, async ({ page, integration: f }) => {
    seed(f); markAllAcknowledged(f); // nothing is New, so only the status can say anything about the future
    f.store.run('UPDATE inventory_state SET last_error=?, last_ok_at=?', lastError, age === null ? null : age === 0 ? f.now() : f.now() + age);
    await signIn(page, f, 'operator');
    await expect(status(page)).toContainText(wording);
    if (age !== null) await expect(status(page)).toContainText('Showing the last complete scan from');
    await expect(panel(page)).not.toContainText(/no new devices/i);
    await expect(panel(page).locator('[data-all-clear]')).toHaveCount(0);
  });
}

test('a healthy complete scan with nothing New says so, with the scan time', async ({ page, integration: f }) => {
  seed(f); markAllAcknowledged(f);
  await signIn(page, f, 'operator');
  await expect(status(page)).toContainText('No new devices');
  await expect(status(page)).toContainText('Last complete scan');
  await expect(panel(page).locator('[data-all-clear]')).toHaveCount(1);
});

test('before the first complete scan nothing is claimed either', async ({ page, integration: f }) => {
  await signIn(page, f, 'operator');
  await expect(status(page)).toContainText('No complete scan yet');
  await expect(panel(page)).not.toContainText(/no new devices/i);
  await expect(panel(page).locator('li.inventory-row')).toHaveCount(0);
});

test('Add to a child opens the existing add form prefilled; the waiting notice never shows the address', async ({ page, integration: f }) => {
  seed(f);
  await signIn(page, f, 'operator');
  await expect(row(page, 'old-laptop').getByRole('button', { name: /^Add to a child/ })).toBeVisible();
  await expect(row(page, 'kid2-phone').getByRole('button', { name: /^Add to a child/ })).toHaveCount(0); // already assigned

  // Out-of-scope address: the router does not know it yet. The form carries it; nothing else on the page does.
  await row(page, 'outside-box').getByRole('button', { name: /^Add to a child/ }).click();
  await row(page, 'outside-box').getByLabel(/^Child for/).selectOption({ label: 'Explicit test person' });
  await row(page, 'outside-box').getByRole('button', { name: 'Continue' }).click();
  const children = page.locator('#children-panel');
  const form = children.locator('[data-add-device="pilot"]');
  await expect(form.getByLabel('New device name for Explicit test person')).toHaveValue('outside-box');
  await expect(form.getByLabel('Wi-Fi address (MAC) for Explicit test person')).toHaveValue(OUTSIDE);
  await expect(form).toContainText("Confirm the address in the device's own Wi-Fi settings before approving");
  expect(await children.locator('[data-add-device="kid2"]').getByLabel(/Wi-Fi address/).inputValue()).toBe('');
  await form.getByRole('button', { name: 'Add device' }).click();
  const waiting = children.locator('[data-pending-approval]');
  await expect(waiting).toContainText('Waiting for router approval');
  await expect(waiting).toContainText('outside-box');
  expect(await waiting.innerText()).not.toMatch(MAC_PATTERN);
  expect((await page.locator('body').innerText()).toLowerCase()).not.toContain(OUTSIDE); // only the form field holds it

  // In-scope address: the same flow queues the change like a typed-in device.
  await row(page, 'new-phone').getByRole('button', { name: /^Add to a child/ }).click();
  await row(page, 'new-phone').getByLabel(/^Child for/).selectOption({ label: 'Explicit test person' });
  await row(page, 'new-phone').getByRole('button', { name: 'Continue' }).click();
  await expect(form.getByLabel('Wi-Fi address (MAC) for Explicit test person')).toHaveValue(NEW_PHONE);
  await form.getByRole('button', { name: 'Add device' }).click();
  await expect(children.locator('.notice[role="status"]').first()).toContainText('Sent to the router');
  await dispatchPending(f);
  await page.getByRole('button', { name: 'Refresh status' }).click();
  await expect(children.locator('[data-entry="pilot"]')).toContainText(`${NEW_PHONE} · on the router`);
});

test('offline or stale: the last list stays readable with its time, and every button is disabled with the reason', async ({ page, integration: f }) => {
  seed(f);
  await signIn(page, f, 'operator');
  await expect(row(page, 'new-tv')).toBeVisible();
  await page.context().setOffline(true);
  await page.evaluate(() => window.dispatchEvent(new Event('offline')));
  await expect(row(page, 'new-tv')).toBeVisible();
  await expect(panel(page).locator('[data-inventory-reason]')).toHaveText('Offline');
  await expect(panel(page).locator('[data-inventory-snapshot]')).toContainText('Showing a saved list from');
  for (const button of await panel(page).getByRole('button').all()) await expect(button).toBeDisabled();
});

test('a stale status snapshot disables the buttons with a refresh hint', async ({ page, integration: f }) => {
  seed(f);
  await page.route('**/people', async (route) => {
    const response = await route.fetch(); const body = await response.json(); body.observedAt -= 120;
    await route.fulfill({ response, json: body });
  });
  await signIn(page, f, 'operator');
  await expect(panel(page).locator('[data-inventory-reason]')).toHaveText('Status is out of date — refresh');
  for (const button of await panel(page).getByRole('button').all()) await expect(button).toBeDisabled();
  await expect(row(page, 'new-tv')).toBeVisible();
});

test('touch targets are at least 44px and nothing scrolls sideways at 390px', async ({ page, integration: f }) => {
  seed(f);
  await signIn(page, f, 'operator');
  await row(page, 'new-tv').getByRole('button', { name: /^Add to a child/ }).click();
  const buttons = await panel(page).getByRole('button').all();
  expect(buttons.length).toBeGreaterThan(4);
  for (const button of buttons) expect((await button.boundingBox())!.height).toBeGreaterThanOrEqual(44);
  for (const select of await panel(page).locator('select').all()) expect((await select.boundingBox())!.height).toBeGreaterThanOrEqual(44);
  expect(await noHorizontalScroll(page)).toBe(true);
  expect(SEED).toBeTruthy();
});
