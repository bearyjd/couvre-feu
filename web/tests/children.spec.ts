import { test as base, expect } from '@playwright/test';
import type { Locator, Page } from '@playwright/test';
import { once } from 'node:events';
import { issueOperatorBootstrap, Auth } from '../../service/src/auth.ts';
import { appServer } from '../../service/src/http.ts';
import { integrationFixture } from '../../service/tests/fixtures/integration.ts';
import { virtualAuthenticator, openTab } from './browser-fixture.ts';

// Placeholder, locally administered MACs only. The router is the in-process test transport; the test drives dispatch.
const TABLET = '02:10:20:30:40:52', TV = '02:10:20:30:40:53';

const test = base.extend<{ integration: ReturnType<typeof integrationFixture> & { origin: string } }>({
  integration: async ({}, use) => {
    const f = integrationFixture(), port = Number(process.env.CF_WEB_TEST_PORT ?? '4273'), origin = `http://localhost:${port}`;
    f.config.routerScope = ['02:10:20:30:40:50', TABLET, TV];
    f.advance(Math.floor(Date.now() / 1000) - f.now()); // the browser checks session expiry against its own clock
    const auth = new Auth(f.store, origin, f.now, { provenance: f.config.provenance, rpName: 'Private integration test' });
    const server = appServer(auth, f.policy, { ...f.config, port, origin, host: `localhost:${port}` });
    server.listen(port, '127.0.0.1'); await once(server, 'listening');
    await f.observe();
    try { await use({ ...f, origin }); } finally {
      await new Promise<void>((resolve) => { server.close(() => resolve()); server.closeAllConnections(); });
      f.cleanup();
    }
  },
});
test.use({ serviceWorkers: 'block' });
test.setTimeout(60000);

async function dispatchPending(f: ReturnType<typeof integrationFixture>) {
  const id = f.store.integrationState().active_operation_id;
  if (!id) throw new Error('no queued operation');
  const plan = f.worker.prepare('apply', id); await f.worker.execute(plan, plan.scriptSha256);
  f.advance(1); await f.observe();
}

const MAC_LIKE = /[0-9a-f]{2}(?::[0-9a-f]{2}){5}/i;
const menuOf = (row: Locator) => row.getByRole('button', { name: /^Actions for / });

async function signInOperator(page: Page, f: { origin: string; store: Parameters<typeof issueOperatorBootstrap>[0]; now: () => number }) {
  await page.goto(f.origin);
  await virtualAuthenticator(page);
  await page.getByLabel('One-use enrollment token').fill(issueOperatorBootstrap(f.store, 'operator', f.now()));
  await page.getByRole('button', { name: 'Create a passkey' }).click();
  await expect(page.locator('#status-view')).toBeVisible();
  await openTab(page, 'kids');
}

test('admin adds devices through one Add device button, sees status chips and removes through the row menu, at phone width', async ({ page, integration: f }) => {
  const dialogs: string[] = [];
  page.on('dialog', (dialog) => { dialogs.push(dialog.type()); void dialog.dismiss(); });
  await signInOperator(page, f);
  const panel = page.locator('#children-panel');
  await expect(panel.getByRole('heading', { name: 'Children and device groups' })).toBeVisible();
  const child = panel.locator('[data-entry="pilot"]');
  await expect(child).toContainText('Child · 1 device');
  // The per-child inline forms are gone: nothing to type into until Add device is pressed.
  await expect(panel.locator('form[data-add-device]')).toHaveCount(0);
  await expect(child.locator('[data-device]').first().locator('[data-status="on_router"]')).toHaveText('On the router');

  // Wizard flag off: Add device opens the existing add form for this child; step-up, queued, then confirmed by the router.
  await child.getByRole('button', { name: 'Add device to Explicit test person' }).click();
  const form = child.locator('form[data-add-device="pilot"]');
  await expect(form.getByLabel('New device name for Explicit test person')).toBeFocused();
  await form.getByLabel('New device name for Explicit test person').fill('Tablet');
  await form.getByLabel('Wi-Fi address (MAC) for Explicit test person').fill(TABLET.toUpperCase());
  await form.getByRole('button', { name: 'Add device' }).click();
  await expect(panel.locator('.notice[role="status"]')).toContainText('Sent to the router');
  const tablet = child.locator('[data-device]').filter({ hasText: 'Tablet' });
  await expect(tablet.locator('[data-status="sent"]')).toHaveText('Sent, not confirmed yet');
  await expect(tablet).toContainText('Adding…');
  await expect(tablet.locator('[data-status="on_router"]')).toHaveCount(0);
  await dispatchPending(f);
  await page.getByRole('button', { name: 'Refresh status' }).click();
  await expect(tablet.locator('[data-status="on_router"]')).toHaveText('On the router');
  await expect(tablet.locator('[data-status="sent"]')).toHaveCount(0);
  expect(await child.innerText()).not.toMatch(MAC_LIKE); // the address lives only inside forms
  await openTab(page, 'home');
  await expect(page.locator('[data-person="pilot"]')).toContainText('2 assigned devices');
  await openTab(page, 'kids');

  // A non-child entry (e.g. a TV) is labelled as a device group, never as a child.
  await panel.getByLabel('New name').fill('Living-room TV');
  await panel.getByLabel('Type').selectOption('device_group');
  await panel.getByRole('button', { name: 'Add', exact: true }).click();
  const group = panel.locator('[data-entry^="group_"]');
  await expect(group).toContainText('Device group · 0 devices');
  await group.getByRole('button', { name: 'Add device to Living-room TV' }).click();
  await group.getByLabel('New device name for Living-room TV').fill('TV');
  await group.getByLabel('Wi-Fi address (MAC) for Living-room TV').fill(TV);
  await group.getByRole('button', { name: 'Add device', exact: true }).click();
  await expect(group.locator('[data-status="sent"]')).toBeVisible();
  await dispatchPending(f);
  await page.getByRole('button', { name: 'Refresh status' }).click();
  await expect(group.locator('[data-status="on_router"]')).toHaveText('On the router');
  await openTab(page, 'home');
  const card = page.locator('article.person').filter({ hasText: 'Living-room TV' });
  await expect(card.locator('.person-id')).toHaveText(/^Device group · 1 assigned device$/);
  await openTab(page, 'kids');

  // Removal: ⋯ menu, in-page confirm sentence, passkey, then through the router.
  await menuOf(tablet).click();
  await tablet.getByRole('menuitem', { name: 'Remove Tablet' }).click();
  const confirm = tablet.locator('[data-confirm="remove"]');
  await expect(confirm).toContainText('Remove Tablet from Explicit test person?');
  await confirm.getByRole('button', { name: 'Yes, remove it' }).click();
  await expect(tablet.locator('[data-status="sent"]')).toBeVisible();
  await expect(tablet).toContainText('Removing…');
  await dispatchPending(f);
  await page.getByRole('button', { name: 'Refresh status' }).click();
  await expect(child).not.toContainText('Tablet');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  expect(dialogs).toEqual([]); // no window.confirm anywhere
});

test('a device the router has not approved waits as a row from the service: it survives a reload and the address never shows', async ({ page, integration: f }) => {
  f.worker.inventory.ingest({ inventory_version: 1, generation: f.config.router.generation, routerTime: f.now(), devices: [{ mac: '02:10:20:30:40:5e', ipv4: ['192.0.2.44'], hostname: 'unknown-box', source: 'both' }], truncated: false, errors: [] }, f.now());
  await signInOperator(page, f);
  const panel = page.locator('#children-panel'), child = panel.locator('[data-entry="pilot"]');
  await child.getByRole('button', { name: 'Add device to Explicit test person' }).click();
  await child.getByLabel('New device name for Explicit test person').fill('Unknown');
  await child.getByLabel('Wi-Fi address (MAC) for Explicit test person').fill('02:10:20:30:40:5e');
  await child.getByRole('button', { name: 'Add device', exact: true }).click();
  const waiting = child.locator('[data-pending-scope]');
  await expect(waiting).toHaveCount(1);
  await expect(waiting.locator('[data-status="waiting"]')).toHaveText('Waiting for router approval');
  await expect(panel.locator('[data-pending-approval]')).toContainText('cfctl scope-add <ADDRESS FROM DEVICE SETTINGS> --base <router-read>');
  await expect(child.locator('[data-device]')).toHaveCount(1); // nothing was added to the child
  await page.reload();
  await expect(page.locator('#status-view')).toBeVisible();
  await openTab(page, 'kids');
  const again = page.locator('#children-panel [data-entry="pilot"] [data-pending-scope]');
  await expect(again).toHaveCount(1);
  await expect(again).toContainText('unknown-box');
  await expect(again.locator('[data-status="waiting"]')).toHaveText('Waiting for router approval');
  await expect(again.getByRole('button')).toHaveCount(0); // nothing to move or remove yet
  expect(await page.locator('#children-panel').innerText()).not.toMatch(MAC_LIKE);
  expect(await page.locator('#children-panel').innerHTML()).not.toMatch(MAC_LIKE);
});

test('hostile child and device names are inert text in the card, the menu and the confirm sentence', async ({ page, integration: f }) => {
  f.store.run('UPDATE people SET name=? WHERE id=?', '<b id="pwn">x</b>', 'pilot');
  f.store.run('UPDATE devices SET label=? WHERE person_id=?', '<i id="pwn2">y</i>', 'pilot');
  await signInOperator(page, f);
  const panel = page.locator('#children-panel'), row = panel.locator('[data-entry="pilot"] [data-device]');
  await expect(row).toContainText('<i id="pwn2">y</i>');
  await menuOf(row).click();
  await row.getByRole('menuitem', { name: /^Remove / }).click();
  await expect(row.locator('[data-confirm="remove"]')).toContainText('Remove <i id="pwn2">y</i> from <b id="pwn">x</b>?');
  expect(await page.locator('#pwn, #pwn2').count()).toBe(0);
});

test('the row menu works from the keyboard and the confirm sentence can be cancelled without anything being sent', async ({ page, integration: f }) => {
  const posts: string[] = [];
  page.on('request', (r) => { if (r.method() === 'POST') posts.push(new URL(r.url()).pathname); });
  const dialogs: string[] = [];
  page.on('dialog', (dialog) => { dialogs.push(dialog.type()); void dialog.dismiss(); });
  await signInOperator(page, f);
  const row = page.locator('#children-panel [data-entry="pilot"] [data-device]'), trigger = menuOf(row);
  await expect(trigger).toHaveAttribute('aria-haspopup', 'menu');
  await expect(trigger).toHaveAttribute('aria-expanded', 'false');
  await trigger.focus();
  await page.keyboard.press('Enter');
  const menu = row.getByRole('menu');
  await expect(menu).toBeVisible();
  await expect(trigger).toHaveAttribute('aria-expanded', 'true');
  await expect(row.getByRole('menuitem').first()).toBeFocused();
  await page.keyboard.press('ArrowDown');
  await expect(row.getByRole('menuitem').nth(1)).toBeFocused();
  await page.keyboard.press('ArrowDown'); // wraps
  await expect(row.getByRole('menuitem').first()).toBeFocused();
  await page.keyboard.press('Escape');
  await expect(menu).toHaveCount(0);
  await expect(trigger).toBeFocused();
  await expect(trigger).toHaveAttribute('aria-expanded', 'false');
  // Open again, choose Remove with Enter: the confirm sentence takes focus, Cancel puts it back on the trigger.
  await page.keyboard.press('ArrowDown');
  await expect(row.getByRole('menuitem').first()).toBeFocused();
  await page.keyboard.press('ArrowDown');
  await page.keyboard.press('Enter');
  const confirm = row.locator('[data-confirm="remove"]');
  await expect(confirm).toBeVisible();
  await expect(menu).toHaveCount(0);
  expect(await confirm.evaluate((el) => el.contains(document.activeElement))).toBe(true);
  await confirm.getByRole('button', { name: 'Cancel' }).click();
  await expect(confirm).toHaveCount(0);
  await expect(trigger).toBeFocused();
  await expect(row).toBeVisible();
  // Escape also cancels the sentence.
  await trigger.click();
  await row.getByRole('menuitem', { name: /^Remove / }).click();
  await expect(confirm).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(confirm).toHaveCount(0);
  await expect(trigger).toBeFocused();
  expect(posts.filter((path) => path === '/step-up/options' || path.includes('/remove'))).toEqual([]);
  expect(dialogs).toEqual([]);
});

test('390 px: cards, rows, the menu and the open add form do not scroll sideways and every control is at least 44 px', async ({ page, integration: f }) => {
  await signInOperator(page, f);
  const child = page.locator('#children-panel [data-entry="pilot"]'), row = child.locator('[data-device]');
  await child.getByRole('button', { name: 'Add device to Explicit test person' }).click();
  for (const control of [child.getByLabel('New device name for Explicit test person'), child.getByRole('button', { name: 'Add device', exact: true }), child.getByRole('button', { name: 'Cancel' })]) {
    await expect.poll(() => control.evaluate((el: HTMLElement) => el.getBoundingClientRect().height)).toBeGreaterThanOrEqual(44);
  }
  await child.getByRole('button', { name: 'Cancel' }).click();
  await menuOf(row).click();
  for (const control of [menuOf(row), row.getByRole('menuitem').first(), row.getByRole('menuitem').nth(1)]) {
    await expect.poll(() => control.evaluate((el: HTMLElement) => { const box = el.getBoundingClientRect(); return Math.min(box.height, box.width); })).toBeGreaterThanOrEqual(44);
  }
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});

test('parents never see the child admin panel or device addresses', async ({ page, integration: f }) => {
  await page.goto(f.origin);
  await virtualAuthenticator(page);
  await page.getByLabel('One-use enrollment token').fill(issueOperatorBootstrap(f.store, 'parent', f.now()));
  await page.getByRole('button', { name: 'Create a passkey' }).click();
  await expect(page.locator('#status-view')).toBeVisible();
  await expect(page.locator('#children-panel')).toBeHidden();
  await expect(page.locator('#children-panel')).toHaveJSProperty('hidden', true); // the panel itself is off, not just its tab
  await expect(page.locator('#tab-kids')).toBeHidden();
  expect(await page.content()).not.toContain('02:10:20:30:40:50');
  const status = await page.evaluate(async () => (await fetch('/admin/children')).status);
  expect(status).toBe(403);
});
