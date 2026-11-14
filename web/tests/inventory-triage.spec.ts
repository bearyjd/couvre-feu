import { test, expect, signIn, noHorizontalScroll, K2 } from './bulk-fixture.ts';
import type { World } from './bulk-fixture.ts';
import type { Page } from '@playwright/test';

// Placeholder MACs only. 45 devices: one belongs to a child already, 44 are new since the baseline scan.
const mac = (n: number) => `00:00:5e:00:01:${n.toString(16).padStart(2, '0')}`;
const MAC_PATTERN = /[0-9a-f]{2}(:[0-9a-f]{2}){5}/i;
const name = (n: number) => `device-${n}`;
const dev = (m: string, hostname: string | null, last: number) => ({ mac: m, ipv4: [`192.0.2.${last}`], hostname, source: 'both' as const });

function poll(f: World, devices: ReturnType<typeof dev>[], at: number) {
  f.worker.inventory.ingest({ inventory_version: 1, generation: f.config.router.generation, routerTime: at, devices, truncated: false, errors: [] }, at);
}
function seed45(f: World) {
  const t = f.now(), kid = dev(K2, 'kid2-phone', 20), many = Array.from({ length: 44 }, (_, i) => dev(mac(i + 1), name(i + 1), 100 + i));
  poll(f, [kid], t - 120);
  poll(f, [kid, ...many], t);
}
const triageOn = (f: World) => { f.config.inventoryUi = { triage: true, wizard: false, installReadiness: false }; };
const panel = (page: Page) => page.locator('#inventory-panel');
const chip = (page: Page, label: string) => panel(page).locator('[data-filter]').filter({ hasText: label });
const rows = (page: Page) => panel(page).locator('li.inventory-row');
async function openDevices(page: Page, f: World) {
  await signIn(page, f, 'operator');
  await page.locator('#tab-devices').click();
}
test.afterEach(async ({ page }) => { await page.unrouteAll({ behavior: 'wait' }); });

test('flag off: the current panel is unchanged (no filter chips, no role chips)', async ({ page, integration: f }) => {
  seed45(f);
  await openDevices(page, f);
  await expect(panel(page).getByRole('heading', { name: 'Devices on the network' })).toBeVisible();
  await expect(panel(page).locator('[data-filter]')).toHaveCount(0);
  await expect(panel(page).locator('[data-role]')).toHaveCount(0);
});

test('45-device seed: To sort is the default and shrinks on tap; Undo brings it back; Hidden shows hidden devices', async ({ page, integration: f }) => {
  triageOn(f); seed45(f);
  await openDevices(page, f);
  await expect(chip(page, 'To sort')).toContainText('44');
  await expect(chip(page, 'To sort')).toHaveAttribute('aria-pressed', 'true');
  await expect(chip(page, 'Kids')).toContainText('1');
  await expect(rows(page)).toHaveCount(44);
  expect(await panel(page).innerText()).not.toMatch(MAC_PATTERN);
  expect(await noHorizontalScroll(page)).toBe(true);
  // Adult: classifies at once, the row leaves To sort, Undo is offered
  const first = rows(page).first(), firstName = (await first.locator('[data-name]').innerText());
  await first.locator('[data-role="adult"]').click();
  await expect(chip(page, 'To sort')).toContainText('43');
  await expect(chip(page, 'Adults')).toContainText('1');
  await expect(rows(page)).toHaveCount(43);
  await expect(panel(page).locator('[data-undo]')).toContainText(firstName);
  await panel(page).locator('[data-undo] button').click();
  await expect(chip(page, 'To sort')).toContainText('44');
  await expect(chip(page, 'Adults')).toContainText('0');
  // Hide: shows under Hidden
  const hiddenName = await rows(page).first().locator('[data-name]').innerText();
  await rows(page).first().locator('[data-role="ignored"]').click();
  await expect(chip(page, 'Hidden')).toContainText('1');
  await expect(chip(page, 'To sort')).toContainText('43');
  await chip(page, 'Hidden').click();
  await expect(rows(page)).toHaveCount(1);
  await expect(rows(page).first().locator('[data-name]')).toHaveText(hiddenName);
  await chip(page, 'Home').click();
  await expect(rows(page)).toHaveCount(0);
  await expect(panel(page)).toContainText('Nothing here');
  expect(await panel(page).innerText()).not.toMatch(MAC_PATTERN);
});

test('rows are compact: 44 px tap targets, three lines at most, vendor and kind hints, no sideways scroll at 390 px', async ({ page, integration: f }) => {
  triageOn(f); seed45(f);
  await openDevices(page, f);
  const first = rows(page).first();
  for (const b of await first.locator('button').all()) expect((await b.boundingBox())!.height).toBeGreaterThanOrEqual(44);
  for (const b of await panel(page).locator('[data-filter]').all()) expect((await b.boundingBox())!.height).toBeGreaterThanOrEqual(44);
  await expect(first.locator('[data-presence]')).toHaveCount(1);
  expect(await first.locator('.triage-line').count()).toBeLessThanOrEqual(3);
  expect(await noHorizontalScroll(page)).toBe(true);
  expect(await panel(page).innerHTML()).not.toMatch(MAC_PATTERN);
});

test('a child chip opens the existing prefilled add form; the address is only in the form', async ({ page, integration: f }) => {
  triageOn(f); seed45(f);
  await openDevices(page, f);
  await rows(page).first().locator('[data-child]').first().click();
  await expect(page.locator('#children-panel').getByRole('textbox').first()).toBeVisible();
  expect(await panel(page).innerText()).not.toMatch(MAC_PATTERN);
});

test('502 on reload shows plain copy with Retry, and Retry recovers', async ({ page, integration: f }) => {
  triageOn(f); seed45(f);
  let fail = false;
  await page.route('**/admin/inventory', async (route) => {
    if (fail) await route.fulfill({ status: 502, contentType: 'text/html', body: '<html>Bad gateway</html>' });
    else await route.continue();
  });
  await openDevices(page, f);
  await expect(rows(page)).toHaveCount(44);
  fail = true;
  await panel(page).getByRole('button', { name: 'Refresh' }).click();
  const failed = panel(page).locator('[data-load-failed]');
  await expect(failed).toContainText("Couldn't load the device list");
  await expect(panel(page)).not.toContainText(/connection returns|saved list/i);
  fail = false;
  await failed.getByRole('button', { name: 'Retry' }).click();
  await expect(failed).toHaveCount(0);
  await expect(rows(page)).toHaveCount(44);
});

test('stalled scan says how long and who to tell; never an all-clear', async ({ page, integration: f }) => {
  triageOn(f); seed45(f);
  f.store.run('UPDATE inventory_state SET last_error=NULL, last_ok_at=?', f.now() - 48 * 60);
  await openDevices(page, f);
  await expect(panel(page).locator('[data-inventory-status]')).toContainText('Scan stalled 48 min. Tell JD.');
  await expect(panel(page)).not.toContainText(/check the router|no new devices/i);
});

test('link suggestion: "Same device" links the new row to the one that went quiet', async ({ page, integration: f }) => {
  triageOn(f);
  const t = f.now(), kid = dev(K2, 'kid2-phone', 20);
  const oldMac = '02:aa:bb:cc:dd:01', newMac = '02:aa:bb:cc:dd:02'; // randomized (locally administered) addresses, same hostname
  poll(f, [kid, dev(oldMac, 'Penns-iPhone', 40)], t - 7200);
  poll(f, [kid], t - 3600);
  poll(f, [kid, dev(newMac, 'Penns-iPhone', 41)], t);
  await openDevices(page, f);
  const suggestion = panel(page).locator('[data-suggestion]');
  await expect(suggestion).toContainText('Penns-iPhone');
  await suggestion.getByRole('button', { name: 'Same device' }).click();
  await expect(panel(page).locator('[data-suggestion]')).toHaveCount(0);
  await expect(chip(page, 'To sort')).toContainText('1');
});
