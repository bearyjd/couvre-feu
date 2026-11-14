import { test, expect, signIn, noHorizontalScroll, OUTSIDE, K2, K3 } from './bulk-fixture.ts';
import type { World } from './bulk-fixture.ts';
import { bumpVersion } from './bulk-fixture.ts';
import { openTab } from './browser-fixture.ts';
import type { Locator, Page } from '@playwright/test';

// Review fixes for the Kids tab (UI plan H): iOS taps on the ⋯ menu, double submits, stale rows, states, hints and wording.
const MAC_LIKE = /[0-9a-f]{2}(?::[0-9a-f]{2}){5}/i;
const menuOf = (row: Locator) => row.getByRole('button', { name: /^Actions for / });
const kid2 = (page: Page) => page.locator('#children-panel [data-entry="kid2"] [data-device="d_kid2"]');
async function toKids(page: Page, f: World) { await signIn(page, f, 'operator'); await openTab(page, 'kids'); }
const posts = (page: Page) => { const calls: string[] = []; page.on('request', (r) => { if (r.method() === 'POST') calls.push(new URL(r.url()).pathname); }); return calls; };
const changes = (calls: string[]) => calls.filter((c) => c === '/step-up/options' || c.includes('/move') || c.includes('/remove'));

test('H1: Safari does not focus a tapped button, so a blur must not close the menu or lose the tap; only an outside press or Escape closes it', async ({ page, integration: f }) => {
  await toKids(page, f);
  const row = kid2(page), trigger = menuOf(row);
  await trigger.click();
  await expect(row.getByRole('menu')).toBeVisible();
  // iOS: the press lands on the item without focusing it, and the trigger has lost focus.
  await page.evaluate(() => (document.activeElement as HTMLElement).blur());
  await expect(row.getByRole('menu')).toBeVisible();
  const item = row.getByRole('menuitem', { name: /^Remove / });
  await item.dispatchEvent('pointerdown');
  await item.dispatchEvent('mousedown');
  await item.dispatchEvent('click');
  await expect(row.locator('[data-confirm="remove"]')).toBeVisible();
  await expect(row.getByRole('menu')).toHaveCount(0);
  // An outside press closes an open menu.
  await row.locator('[data-confirm="remove"]').getByRole('button', { name: 'Cancel' }).click();
  await trigger.click();
  await expect(row.getByRole('menu')).toBeVisible();
  await page.locator('#children-title').click();
  await expect(row.getByRole('menu')).toHaveCount(0);
  await expect(trigger).toHaveAttribute('aria-expanded', 'false');
  // Escape closes it too, with focus back on the trigger.
  await trigger.click();
  await page.keyboard.press('Escape');
  await expect(row.getByRole('menu')).toHaveCount(0);
  await expect(trigger).toBeFocused();
});

test('M3a: a double click on Yes sends one request, for Remove and for Move', async ({ page, integration: f }) => {
  const calls = posts(page);
  await toKids(page, f);
  const row = kid2(page);
  await menuOf(row).click();
  await row.getByRole('menuitem', { name: /^Remove / }).click();
  // Two presses in one task: the second reaches the handler of the already replaced button, so only the code guard can stop it.
  await row.getByRole('button', { name: 'Yes, remove it' }).evaluate((b: HTMLElement) => { b.click(); b.click(); });
  await expect(row.locator('[data-status="sent"]')).toBeVisible();
  expect(changes(calls).filter((c) => c === '/step-up/options')).toHaveLength(1);
  expect(changes(calls).filter((c) => c.includes('/remove'))).toHaveLength(1);
});

test('M3a: a double click on Yes, move it sends one request', async ({ page, integration: f }) => {
  const calls = posts(page);
  await toKids(page, f);
  const row = kid2(page);
  await menuOf(row).click();
  await row.getByRole('menuitem', { name: 'Move Device kid2', exact: true }).click();
  await row.getByLabel('Move Device kid2 to').selectOption('pilot');
  await row.getByRole('button', { name: 'Yes, move it' }).evaluate((b: HTMLElement) => { b.click(); b.click(); });
  await expect(row.locator('[data-status="sent"]')).toBeVisible();
  expect(changes(calls).filter((c) => c === '/step-up/options')).toHaveLength(1);
  expect(changes(calls).filter((c) => c.includes('/move'))).toHaveLength(1);
});

test('M3b: the sentence is redrawn from fresh data; a renamed row shows its new name and the request still names that row', async ({ page, integration: f }) => {
  const calls = posts(page);
  await toKids(page, f);
  const row = kid2(page);
  await menuOf(row).click();
  await row.getByRole('menuitem', { name: /^Remove / }).click();
  await expect(row.locator('[data-confirm="remove"]')).toContainText('Remove Device kid2 from Kid kid2?');
  f.store.run("UPDATE devices SET label='Renamed tablet' WHERE id='d_kid2'");
  await bumpVersion(page);
  const confirm = kid2(page).locator('[data-confirm="remove"]');
  await expect(confirm).toContainText('Remove Renamed tablet from Kid kid2?');
  await confirm.getByRole('button', { name: 'Yes, remove it' }).click();
  await expect(kid2(page).locator('[data-status="sent"]')).toBeVisible();
  expect(calls.filter((c) => c.includes('/remove'))).toEqual(['/admin/devices/d_kid2/remove']);
});

test('M3b: a row that vanished while the sentence was open leaves no sentence and sends nothing', async ({ page, integration: f }) => {
  const calls = posts(page);
  await toKids(page, f);
  const row = kid2(page);
  await menuOf(row).click();
  await row.getByRole('menuitem', { name: /^Remove / }).click();
  await expect(row.locator('[data-confirm="remove"]')).toBeVisible();
  f.store.run("DELETE FROM devices WHERE id='d_kid2'");
  await bumpVersion(page);
  await expect(page.locator('#children-panel [data-device="d_kid2"]')).toHaveCount(0);
  await expect(page.locator('#children-panel [data-confirm]')).toHaveCount(0);
  expect(changes(calls)).toEqual([]);
  // The same id coming back later must not bring the old sentence back.
  f.store.run("INSERT INTO devices(id,person_id,label,identifier_kind,identifier,state,created_at) VALUES('d_kid2','kid2','Device kid2','mac',?,'active',?)", K2, f.now());
  await bumpVersion(page);
  await expect(page.locator('#children-panel [data-device="d_kid2"]')).toBeVisible();
  await expect(page.locator('#children-panel [data-confirm]')).toHaveCount(0);
});

test('M3c: the move list is redrawn on each poll even while it has focus, with the current child names', async ({ page, integration: f }) => {
  await toKids(page, f);
  const row = kid2(page);
  await menuOf(row).click();
  await row.getByRole('menuitem', { name: 'Move Device kid2', exact: true }).click();
  const select = row.getByLabel('Move Device kid2 to');
  await select.focus();
  f.store.run("UPDATE people SET name='Renamed kid' WHERE id='kid3'");
  await bumpVersion(page);
  await expect(kid2(page).getByLabel('Move Device kid2 to').locator('option')).toHaveText(['Choose…', 'Explicit test person', 'Renamed kid']);
});

test('M4: Remove is not offered as a confirmed action while the device is mid-change', async ({ page, integration: f }) => {
  const calls = posts(page);
  await toKids(page, f);
  const row = kid2(page);
  await menuOf(row).click();
  await row.getByRole('menuitem', { name: /^Remove / }).click();
  await expect(row.getByRole('button', { name: 'Yes, remove it' })).toBeEnabled();
  f.store.run("UPDATE devices SET state='removing' WHERE id='d_kid2'");
  await bumpVersion(page);
  await expect(kid2(page).getByRole('button', { name: 'Yes, remove it' })).toBeDisabled();
  expect(changes(calls)).toEqual([]);
});

const ingest = (f: World, devices: { mac: string; hostname: string }[], at: number) => f.worker.inventory.ingest({ inventory_version: 1, generation: f.config.router.generation,
  routerTime: at, devices: devices.map((d, i) => ({ ...d, ipv4: [`192.0.2.${40 + i}`], source: 'both' as const })), truncated: false, errors: [] }, at);

test('M5: "Replaced?" says what to do; the same model name on two siblings\' phones is not a replacement', async ({ page, integration: f }) => {
  const t = f.now();
  ingest(f, [{ mac: K2, hostname: 'jack-pixel' }], t - 3000);
  ingest(f, [{ mac: '02:aa:bb:cc:dd:10', hostname: 'jack-pixel' }], t);
  await toKids(page, f);
  await expect(kid2(page).locator('[data-status="replaced"]')).toHaveText('Replaced?');
  await expect(kid2(page).locator('[data-replaced-note]')).toHaveText('Check the old device before removing it.');
});

test('M5: two siblings with the same model name never get a Replaced? chip', async ({ page, integration: f }) => {
  const t = f.now();
  ingest(f, [{ mac: K2, hostname: 'galaxy-s23-ultra' }, { mac: K3, hostname: 'galaxy-s23-ultra' }], t - 3000);
  ingest(f, [{ mac: '02:aa:bb:cc:dd:11', hostname: 'galaxy-s23-ultra' }], t);
  await toKids(page, f);
  await expect(page.locator('#children-panel [data-device="d_kid2"] [data-status="on_router"]')).toBeVisible();
  await expect(page.locator('#children-panel [data-status="replaced"]')).toHaveCount(0);
});

test('wording: an unnamed waiting row says Unnamed device, and a device-reported name is labelled as such', async ({ page, integration: f }) => {
  const t = f.now();
  ingest(f, [{ mac: OUTSIDE, hostname: 'outside-box' }], t);
  await signIn(page, f, 'operator');
  await openTab(page, 'kids');
  f.store.run("INSERT INTO scope_requests(id,person_id,mac,requested_by,state,generation,created_at,expires_at) VALUES('scope_named','pilot',?,'operator','pending',?,?,?)", OUTSIDE, f.config.router.generation, t, t + 3600);
  f.store.run("INSERT INTO scope_requests(id,person_id,mac,requested_by,state,generation,created_at,expires_at) VALUES('scope_blank','pilot','02:10:20:30:40:77','operator','pending',?,?,?)", f.config.router.generation, t, t + 3600);
  await bumpVersion(page);
  const named = page.locator('[data-pending-scope="scope_named"]'), blank = page.locator('[data-pending-scope="scope_blank"]');
  await expect(named).toContainText('outside-box');
  await expect(named).toContainText('Name reported by the device');
  await expect(blank).toContainText('Unnamed device');
  await expect(blank).not.toContainText('Name reported by the device');
  await expect(blank).not.toContainText('New device');
  expect(await page.locator('#children-panel').innerText()).not.toMatch(MAC_LIKE);
  expect(await noHorizontalScroll(page)).toBe(true);
});

test('a request the router approved shows "Approved: add it now" on the card until dismissed', async ({ page, integration: f }) => {
  const t = f.now();
  await signIn(page, f, 'operator');
  f.store.run("INSERT INTO scope_requests(id,person_id,mac,requested_by,state,generation,created_at,expires_at) VALUES('scope_ok','kid3',?,'operator','pending',?,?,?)", OUTSIDE, f.config.router.generation, t, t + 3600);
  await openTab(page, 'kids');
  await bumpVersion(page);
  const card = page.locator('#children-panel [data-entry="kid3"]');
  await expect(card.locator('[data-pending-scope="scope_ok"]')).toBeVisible();
  f.store.run("UPDATE scope_requests SET state='observed',resolved_at=? WHERE id='scope_ok'", t);
  await bumpVersion(page);
  await expect(card.locator('[data-pending-scope]')).toHaveCount(0);
  await expect(card.locator('[data-approved]')).toContainText('Approved: add it now');
  await expect(page.locator('#children-panel [data-entry="kid2"] [data-approved]')).toHaveCount(0);
  await card.locator('[data-approved]').getByRole('button', { name: 'Dismiss' }).click();
  await expect(card.locator('[data-approved]')).toHaveCount(0);
});

test('a 502 or 429 on the list keeps the old rows and says "Couldn\'t refresh" with Retry, never the raw server message', async ({ page, integration: f }) => {
  await toKids(page, f);
  await expect(kid2(page)).toBeVisible();
  let status = 502;
  await page.route('**/admin/children', (route) => route.request().method() === 'GET'
    ? route.fulfill({ status, contentType: 'application/json', body: JSON.stringify({ error: { code: 'upstream', message: 'RAW upstream failure 0xDEAD' } }) }) : route.continue());
  for (const code of [502, 429]) {
    status = code;
    await bumpVersion(page).catch(() => undefined);
    const notice = page.locator('#children-panel .notice[role="status"]');
    await expect(notice).toContainText("Couldn't refresh");
    await expect(notice).not.toContainText('RAW upstream');
    await expect(kid2(page)).toBeVisible();
  }
  await page.unroute('**/admin/children');
  await page.locator('#children-panel').getByRole('button', { name: 'Retry' }).click();
  await expect(page.locator('#children-panel .notice[role="status"]')).toBeHidden();
});
