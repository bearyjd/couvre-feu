import { test, expect, signIn, noHorizontalScroll, K2 } from './bulk-fixture.ts';
import type { World } from './bulk-fixture.ts';
import type { Page } from '@playwright/test';

// "Find a kid's device" wizard (UI plan G). Placeholder MACs only. P is a randomized (locally administered) address, so it carries the private flag.
const MAC_PATTERN = /[0-9a-f]{2}(:[0-9a-f]{2}){5}/i;
const P = '02:aa:bb:cc:dd:10', A = '00:00:5e:00:02:01', B = '00:00:5e:00:02:02', OLD = '00:00:5e:00:02:03';
const dev = (m: string, hostname: string | null, last: number) => ({ mac: m, ipv4: [`192.0.2.${last}`], hostname, source: 'both' as const });
const kid = dev(K2, 'kid2-phone', 20), old = dev(OLD, 'old-laptop', 30), a = dev(A, 'phone-a', 31), b = dev(B, 'tablet-b', 32), p = dev(P, 'Pixel-7-Pro', 33);

function poll(f: World, devices: ReturnType<typeof dev>[], at: number) {
  f.worker.inventory.ingest({ inventory_version: 1, generation: f.config.router.generation, routerTime: at, devices, truncated: false, errors: [] }, at);
}
/** Baseline holds the child's device only; old-laptop was first seen 25 min ago, phone-a 400 s, tablet-b 100 s and the Pixel 60 s ago. */
function seed(f: World) {
  const t = f.now();
  poll(f, [kid], t - 3000);
  poll(f, [kid, old], t - 1500);
  poll(f, [kid, a], t - 400);
  poll(f, [kid, b, a], t - 100);
  poll(f, [kid, p, b, a], t - 60);
  poll(f, [kid, p, b, a], t);
}
const wizardOn = (f: World, wizard = true) => { f.config.inventoryUi = { triage: true, wizard, installReadiness: false }; };
const sheet = (page: Page) => page.getByRole('dialog', { name: "Find a kid's device" });
const opener = (page: Page) => page.locator('#inventory-panel [data-wizard-open]');
async function openDevices(page: Page, f: World) {
  await page.clock.install();
  await signIn(page, f, 'operator');
  await page.locator('#tab-devices').click();
}
async function openSheet(page: Page, f: World) {
  await openDevices(page, f);
  await opener(page).click();
  await expect(sheet(page)).toBeVisible();
}
async function toStep2(page: Page, f: World) {
  await openSheet(page, f);
  await sheet(page).getByRole('button', { name: 'Kid kid2' }).click();
  await expect(sheet(page)).toHaveAttribute('data-step', '2');
}
async function toggleStart(page: Page, f: World) {
  await toStep2(page, f);
  await sheet(page).getByRole('button', { name: 'Turn its Wi-Fi off and on' }).click();
  await sheet(page).getByRole('button', { name: 'Start' }).click();
  await expect(sheet(page).locator('[data-wizard-waiting]')).toBeVisible();
}
const names = (page: Page) => sheet(page).locator('[data-wizard-device] [data-name]').allInnerTexts();
test.afterEach(async ({ page }) => { await page.unrouteAll({ behavior: 'wait' }); });

test('flag off: no "Find a kid\'s device" button', async ({ page, integration: f }) => {
  wizardOn(f, false); seed(f);
  await openDevices(page, f);
  await expect(page.locator('#inventory-panel [data-filter]').first()).toBeVisible();
  await expect(opener(page)).toHaveCount(0);
});

test('flag on: a sticky 44 px button opens the sheet; Esc closes it and focus returns', async ({ page, integration: f }) => {
  wizardOn(f); seed(f);
  await openDevices(page, f);
  const box = (await opener(page).boundingBox())!;
  expect(box.height).toBeGreaterThanOrEqual(44);
  await opener(page).click();
  await expect(sheet(page)).toBeVisible();
  await expect(sheet(page)).toHaveAttribute('data-step', '1');
  await page.keyboard.press('Escape');
  await expect(sheet(page)).toHaveCount(0);
  await expect(opener(page)).toBeFocused();
});

test('focus trap: Tab from the last control wraps to the first, Shift+Tab from the first wraps to the last', async ({ page, integration: f }) => {
  wizardOn(f); seed(f);
  await openSheet(page, f);
  const last = sheet(page).locator('button').last(), first = sheet(page).getByRole('button', { name: "Close Find a kid's device" });
  await last.focus();
  await page.keyboard.press('Tab');
  await expect(first).toBeFocused();
  await page.keyboard.press('Shift+Tab');
  await expect(last).toBeFocused();
  for (let i = 0; i < 12; i++) {
    await page.keyboard.press('Tab');
    expect(await page.evaluate(() => Boolean(document.activeElement?.closest('[role="dialog"]')))).toBe(true);
  }
});

test('just connected: only devices first seen in the last 10 minutes, newest first, no address on screen', async ({ page, integration: f }) => {
  wizardOn(f); seed(f);
  await toStep2(page, f);
  await sheet(page).getByRole('button', { name: 'It just connected' }).click();
  await expect(sheet(page).locator('[data-wizard-device]')).toHaveCount(3);
  expect(await names(page)).toEqual(['Pixel-7-Pro', 'tablet-b', 'phone-a']);
  expect(await sheet(page).innerText()).not.toMatch(MAC_PATTERN);
  expect(await sheet(page).innerHTML()).not.toMatch(MAC_PATTERN);
  expect(await noHorizontalScroll(page)).toBe(true);
  for (const button of await sheet(page).locator('button').all()) expect((await button.boundingBox())!.height).toBeGreaterThanOrEqual(44);
});

test('toggle test: a device that goes quiet and comes back is highlighted, in that order', async ({ page, integration: f }) => {
  wizardOn(f); seed(f);
  await toggleStart(page, f);
  await expect(sheet(page).locator('[data-wizard-device]')).toHaveCount(0);
  // Wi-Fi off: one scan (60 s later) lists the others but not the Pixel. Its age still reads "online"; the unmoved last-seen time says it went quiet.
  f.advance(60);
  poll(f, [kid, b, a], f.now());
  await page.clock.runFor(15000);
  const row = sheet(page).locator('[data-wizard-device]');
  await expect(row).toHaveCount(1);
  await expect(row).toHaveAttribute('data-wiz-state', 'quiet');
  await expect(row).toContainText('Pixel-7-Pro');
  await expect(row).toContainText('Went quiet');
  // Wi-Fi on again.
  f.advance(5);
  poll(f, [kid, p, b, a], f.now());
  await page.clock.runFor(15000);
  await expect(row).toHaveAttribute('data-wiz-state', 'back');
  await expect(row).toContainText('Came back');
  expect(await sheet(page).innerText()).not.toMatch(MAC_PATTERN);
  expect(await noHorizontalScroll(page)).toBe(true);
});

test('timers: the 3 minute timer ends the wait, and nothing is requested after Esc or a tab change', async ({ page, integration: f }) => {
  wizardOn(f); seed(f);
  let gets = 0;
  await page.route('**/admin/inventory', async (route) => { if (route.request().method() === 'GET') gets += 1; await route.continue(); });
  await toggleStart(page, f);
  await page.clock.runFor(15000);
  await expect.poll(() => gets).toBeGreaterThan(1);
  await page.keyboard.press('Escape');
  await expect(sheet(page)).toHaveCount(0);
  await page.waitForTimeout(300);
  const afterEsc = gets;
  await page.clock.runFor(60000);
  await page.waitForTimeout(300);
  expect(gets).toBe(afterEsc);
  // Again, but leave through the tab bar while waiting.
  await opener(page).click();
  await sheet(page).getByRole('button', { name: 'Kid kid2' }).click();
  await sheet(page).getByRole('button', { name: 'Turn its Wi-Fi off and on' }).click();
  await sheet(page).getByRole('button', { name: 'Start' }).click();
  await expect(sheet(page).locator('[data-wizard-waiting]')).toBeVisible();
  await page.evaluate(() => { location.hash = '#home'; });
  await expect(sheet(page)).toHaveCount(0);
  await page.waitForTimeout(300);
  const afterTab = gets;
  await page.clock.runFor(60000);
  await page.waitForTimeout(300);
  expect(gets).toBe(afterTab);
});

test('the wait ends after 3 minutes with plain words and no more polling', async ({ page, integration: f }) => {
  wizardOn(f); seed(f);
  let gets = 0;
  await page.route('**/admin/inventory', async (route) => { if (route.request().method() === 'GET') gets += 1; await route.continue(); });
  await toggleStart(page, f);
  for (let i = 0; i < 12; i++) { await page.clock.runFor(15000); await page.waitForTimeout(60); }
  await expect(sheet(page).locator('[data-wizard-timeup]')).toContainText('Nothing went quiet');
  await expect(sheet(page).locator('[data-wizard-waiting]')).toHaveCount(0);
  await page.waitForTimeout(300);
  const done = gets;
  await page.clock.runFor(60000);
  await page.waitForTimeout(300);
  expect(gets).toBe(done);
});

test('confirm: OS wording, the private warning once, the stable check is recorded, then the add form opens with the child chosen', async ({ page, integration: f }) => {
  wizardOn(f); seed(f);
  await toStep2(page, f);
  await sheet(page).getByRole('button', { name: 'It just connected' }).click();
  expect(await sheet(page).locator('[data-private-warning]').count()).toBe(0);
  await sheet(page).locator('[data-wizard-device]').filter({ hasText: 'Pixel-7-Pro' }).getByRole('button').click();
  await expect(sheet(page)).toHaveAttribute('data-step', '3');
  await expect(sheet(page)).toContainText('Pixel-7-Pro');
  await expect(sheet(page)).toContainText('Private Wi-Fi Address: OFF');
  await expect(sheet(page)).toContainText('Use device MAC');
  await expect(sheet(page).locator('[data-private-warning]')).toHaveCount(1);
  await expect(sheet(page).locator('[data-private-warning]')).toContainText('the router stops recognising the phone');
  expect(await sheet(page).innerText()).not.toMatch(/monitor|catch|hid(e|ing)/i);
  expect(f.store.all('SELECT * FROM inventory_decisions WHERE stable_confirmed=1')).toHaveLength(0);
  await sheet(page).getByRole('button', { name: 'I turned it off' }).click();
  await expect(sheet(page)).toHaveAttribute('data-step', '4');
  expect(f.store.all('SELECT * FROM inventory_decisions WHERE stable_confirmed=1')).toHaveLength(1);
  await expect(sheet(page).locator('[data-private-warning]')).toHaveCount(0);
  await expect(sheet(page).locator('[data-wizard-find-again]')).toContainText('may show up again with a new address');
  await expect(sheet(page)).toContainText('Sent to the router, not confirmed yet');
  expect(await sheet(page).innerText()).not.toMatch(MAC_PATTERN);
  // Back to Confirm: the check is already recorded, so the warning is not repeated.
  await sheet(page).getByRole('button', { name: 'Back' }).click();
  await expect(sheet(page)).toHaveAttribute('data-step', '3');
  await expect(sheet(page).locator('[data-private-warning]')).toHaveCount(0);
  await sheet(page).getByRole('button', { name: 'Next' }).click();
  await expect(sheet(page).locator('[data-private-warning]')).toHaveCount(0);
  await sheet(page).getByRole('button', { name: 'Open the add form' }).click();
  await expect(sheet(page)).toHaveCount(0);
  const form = page.locator('#children-panel form[data-add-device]').filter({ hasText: 'Kid kid2' });
  await expect(form.locator('input[name="mac"]')).toHaveValue(P);
  await expect(form.locator('input[name="label"]')).toHaveValue("Kid kid2's Pixel");
  await expect(form.locator('input[name="label"]')).toBeFocused(); // the sheet is gone first, so nothing pulls focus back
});

test('"It has no such setting" on a fixed (not private) address records the check', async ({ page, integration: f }) => {
  wizardOn(f); seed(f);
  await toStep2(page, f);
  await sheet(page).getByRole('button', { name: 'It just connected' }).click();
  await sheet(page).locator('[data-wizard-device]').filter({ hasText: 'tablet-b' }).getByRole('button').click();
  await expect(sheet(page).locator('[data-private-warning]')).toHaveCount(0);
  await sheet(page).getByRole('button', { name: 'It has no such setting' }).click();
  await expect(sheet(page)).toHaveAttribute('data-step', '4');
  expect(f.store.all('SELECT * FROM inventory_decisions WHERE stable_confirmed=1')).toHaveLength(1);
});

test('pick from the list and the Add a child path; 390 px without sideways scroll at every step', async ({ page, integration: f }) => {
  wizardOn(f); seed(f);
  await toStep2(page, f);
  expect(await noHorizontalScroll(page)).toBe(true);
  await sheet(page).getByRole('button', { name: 'Pick from the list' }).click();
  await expect(sheet(page).locator('[data-wizard-device]').first()).toBeVisible();
  expect(await noHorizontalScroll(page)).toBe(true);
  await sheet(page).getByRole('button', { name: 'Back' }).click();
  await expect(sheet(page)).toHaveAttribute('data-step', '1');
  await sheet(page).getByRole('button', { name: 'Add a child' }).click();
  await expect(sheet(page)).toHaveCount(0);
  await expect(page.locator('#new-entry-name')).toBeVisible();
});

test('private address OFF: Find it again goes back to step 2 and the stale address is not the default', async ({ page, integration: f }) => {
  wizardOn(f); seed(f);
  await toStep2(page, f);
  await sheet(page).getByRole('button', { name: 'It just connected' }).click();
  await sheet(page).locator('[data-wizard-device]').filter({ hasText: 'Pixel-7-Pro' }).getByRole('button').click();
  await sheet(page).getByRole('button', { name: 'It has no such setting' }).click(); // private + no setting: nothing recorded
  await expect(sheet(page)).toHaveAttribute('data-step', '4');
  expect(f.store.all('SELECT * FROM inventory_decisions WHERE stable_confirmed=1')).toHaveLength(0);
  await sheet(page).getByRole('button', { name: 'Back' }).click();
  await expect(sheet(page).locator('[data-private-warning]')).toHaveCount(0); // seen once already on this path
  await sheet(page).getByRole('button', { name: 'I turned it off' }).click();
  await expect(sheet(page).getByRole('button', { name: 'Find it again' })).toHaveClass(/primary/);
  await expect(sheet(page).getByRole('button', { name: 'Open the add form' })).not.toHaveClass(/primary/);
  await sheet(page).getByRole('button', { name: 'Find it again' }).click();
  await expect(sheet(page)).toHaveAttribute('data-step', '2');
});

test('Stop ends the wait: no more requests and no time-up message later', async ({ page, integration: f }) => {
  wizardOn(f); seed(f);
  let gets = 0;
  await page.route('**/admin/inventory', async (route) => { if (route.request().method() === 'GET') gets += 1; await route.continue(); });
  await toggleStart(page, f);
  await sheet(page).getByRole('button', { name: 'Stop' }).click();
  await expect(sheet(page).locator('[data-wizard-waiting]')).toHaveCount(0);
  await page.waitForTimeout(300);
  const stopped = gets;
  await page.clock.runFor(200000);
  await page.waitForTimeout(300);
  expect(gets).toBe(stopped);
  await expect(sheet(page).locator('[data-wizard-timeup]')).toHaveCount(0);
});

test('a 502 mid-poll says so, keeps polling, and never blames the phone', async ({ page, integration: f }) => {
  wizardOn(f); seed(f);
  let fail = false;
  await page.route('**/admin/inventory', async (route) => {
    if (route.request().method() === 'GET' && fail) await route.fulfill({ status: 502, contentType: 'text/html', body: '<html>Bad gateway</html>' });
    else await route.continue();
  });
  await toggleStart(page, f);
  fail = true;
  await page.clock.runFor(15000);
  await expect(sheet(page).locator('[data-wizard-poll-error]')).toContainText("Couldn't refresh the list. Check your connection.");
  fail = false;
  f.advance(60);
  poll(f, [kid, b, a], f.now());
  await page.clock.runFor(15000);
  await expect(sheet(page).locator('[data-wizard-poll-error]')).toHaveCount(0);
  await expect(sheet(page).locator('[data-wizard-device]')).toHaveAttribute('data-wiz-state', 'quiet');
  fail = true; // run out the clock while failing: the time-up words must not blame the phone
  for (let i = 0; i < 12; i++) { await page.clock.runFor(15000); await page.waitForTimeout(60); }
  await expect(sheet(page).locator('[data-wizard-timeup]')).not.toContainText('Check the phone');
});

test('a device that appears mid-run is "New device", not "Came back"', async ({ page, integration: f }) => {
  wizardOn(f); seed(f);
  await toggleStart(page, f);
  f.advance(20);
  poll(f, [kid, p, b, a, dev('00:00:5e:00:02:09', 'late-comer', 40)], f.now());
  await page.clock.runFor(15000);
  const row = sheet(page).locator('[data-wizard-device]');
  await expect(row).toHaveCount(1);
  await expect(row).toContainText('New device');
  await expect(row).not.toContainText('Came back');
});

test('a hostile hostname is inert text', async ({ page, integration: f }) => {
  wizardOn(f); seed(f);
  const hostile = '<img src=x onerror="window.__pwned=1">';
  await page.route('**/admin/inventory', async (route) => {
    if (route.request().method() !== 'GET') { await route.continue(); return; }
    const response = await route.fetch(), body = await response.json();
    body.inventory.devices = body.inventory.devices.map((d: { hostname: string | null }) => (d.hostname === 'tablet-b' ? { ...d, hostname: hostile } : d));
    await route.fulfill({ response, json: body });
  });
  await toStep2(page, f);
  await sheet(page).getByRole('button', { name: 'It just connected' }).click();
  await expect(sheet(page)).toContainText(hostile);
  await expect(sheet(page).locator('img')).toHaveCount(0);
  expect(await page.evaluate(() => (window as unknown as { __pwned?: number }).__pwned)).toBeUndefined();
});

test('a TV gets the generic wording, not the phone settings', async ({ page, integration: f }) => {
  wizardOn(f); seed(f);
  poll(f, [kid, p, b, a, dev('00:00:5e:00:02:0b', 'Living-room-TV', 42)], f.now());
  await toStep2(page, f);
  await sheet(page).getByRole('button', { name: 'It just connected' }).click();
  await sheet(page).locator('[data-wizard-device]').filter({ hasText: 'Living-room-TV' }).getByRole('button').click();
  await expect(sheet(page)).toContainText('Turn off any private or random address option');
  await expect(sheet(page)).not.toContainText('Use device MAC');
});

test('signing out while waiting closes the sheet and stops every request', async ({ page, integration: f }) => {
  wizardOn(f); seed(f);
  let gets = 0;
  await page.route('**/admin/inventory', async (route) => { if (route.request().method() === 'GET') gets += 1; await route.continue(); });
  await toggleStart(page, f);
  await page.evaluate(() => (document.querySelector('#logout') as HTMLButtonElement).click());
  await expect(sheet(page)).toHaveCount(0);
  await page.waitForTimeout(300);
  const done = gets;
  await page.clock.runFor(60000);
  await page.waitForTimeout(300);
  expect(gets).toBe(done);
});

// UI plan H: the Kids tab's single Add device button per child opens this sheet at step 2 when the wizard flag is on.
async function toKids(page: Page, f: World) {
  await page.clock.install();
  await signIn(page, f, 'operator');
  await expect(page.locator('#inventory-panel [data-wizard-open]')).toBeAttached(); // the list (and its flag) has loaded
  await page.locator('#tab-kids').click();
}
const addDevice = (page: Page, name = 'Kid kid2') => page.locator('#children-panel').getByRole('button', { name: `Add device to ${name}` });

test('Kids tab, flag on: Add device opens the sheet at step 2 with that child chosen, and Close puts focus back on the button', async ({ page, integration: f }) => {
  wizardOn(f); seed(f);
  await toKids(page, f);
  await addDevice(page).click();
  await expect(sheet(page)).toBeVisible();
  await expect(sheet(page)).toHaveAttribute('data-step', '2');
  await expect(page.locator('#children-panel form[data-add-device]')).toHaveCount(0);
  await sheet(page).getByRole('button', { name: 'Pick from the list' }).click();
  await sheet(page).getByRole('button', { name: 'Back' }).click();
  await sheet(page).getByRole('button', { name: 'Back' }).click(); // step 1 is still reachable, but the child stays chosen
  await expect(sheet(page).getByRole('button', { name: 'Kid kid2' })).toHaveAttribute('aria-pressed', 'true');
  await page.keyboard.press('Escape');
  await expect(sheet(page)).toHaveCount(0);
  await expect(addDevice(page)).toBeFocused();
  expect(await noHorizontalScroll(page)).toBe(true);
});

test('Kids tab, flag on: finishing the sheet opens the add form inside that child card (passkey step-up unchanged)', async ({ page, integration: f }) => {
  wizardOn(f); seed(f);
  await toKids(page, f);
  await addDevice(page).click();
  await sheet(page).getByRole('button', { name: 'It just connected' }).click();
  await sheet(page).locator('[data-wizard-device]').filter({ hasText: 'tablet-b' }).getByRole('button').click();
  await sheet(page).getByRole('button', { name: 'It has no such setting' }).click();
  await sheet(page).getByRole('button', { name: 'Open the add form' }).click();
  await expect(sheet(page)).toHaveCount(0);
  const form = page.locator('#children-panel [data-entry="kid2"] form[data-add-device="kid2"]');
  await expect(form.locator('input[name="mac"]')).toHaveValue(B);
  await expect(form.locator('input[name="label"]')).toBeFocused();
});

test('Kids tab, flag off: Add device opens the add form and never the sheet', async ({ page, integration: f }) => {
  wizardOn(f, false); seed(f);
  await page.clock.install();
  await signIn(page, f, 'operator');
  await page.locator('#tab-kids').click();
  await addDevice(page).click();
  await expect(page.locator('#children-panel form[data-add-device="kid2"]')).toBeVisible();
  await expect(sheet(page)).toHaveCount(0);
});
