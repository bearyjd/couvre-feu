import { test, expect, signIn, K2, NAMES } from './bulk-fixture.ts';
import type { World } from './bulk-fixture.ts';
import { readFile } from 'node:fs/promises';

test.use({ readiness: true });
const MAC_PATTERN = /[0-9a-f]{2}(:[0-9a-f]{2}){5}/i;
const HOSTILE = '<img src=x onerror="window.__xss=1">';
const panel = (page: import('@playwright/test').Page) => page.locator('#install-readiness-panel');
function seed(f: World) {
  f.worker.inventory.ingest({ inventory_version: 1, generation: f.config.router.generation, routerTime: f.now(), devices: [{ mac: K2, ipv4: ['192.0.2.20'], hostname: 'kid2-phone', source: 'both' }], truncated: false, errors: [] }, f.now());
}

test('admin reviews the list at phone width: children, warnings, digest, no horizontal scroll, hostile names as text', async ({ page, integration: f }) => {
  seed(f);
  f.store.run("UPDATE people SET name=? WHERE id='kid3'", HOSTILE);
  f.store.run("DELETE FROM devices WHERE person_id='kid3'");
  await page.setViewportSize({ width: 390, height: 800 });
  await signIn(page, f, 'operator');
  await expect(panel(page).getByRole('heading', { name: 'Review for the router install' })).toBeVisible();
  await expect(panel(page).locator('h3').filter({ hasText: NAMES.kid2 })).toBeVisible();
  await expect(panel(page).locator('[data-device]').filter({ hasText: 'Device kid2' })).toContainText(K2);
  await expect(panel(page).locator('[data-warnings]')).toContainText('has no device on the list');
  await expect(panel(page).locator('[data-warnings]')).toContainText('private (changing) address');
  await expect(panel(page).locator('[data-digest]')).toHaveText(/^[0-9a-f]{64}$/);
  await expect(panel(page).locator('[data-reviewed]')).toHaveText('Not approved yet.');
  expect(await page.evaluate(() => (window as unknown as { __xss?: number }).__xss)).toBeUndefined();
  expect(await page.locator('#install-readiness-panel img').count()).toBe(0);
  // the hostile child name also widens the existing status card (not this panel); here only the review panel must stay inside the viewport
  const wide = await page.evaluate(() => [...document.querySelectorAll('#install-readiness-panel, #install-readiness-panel *')].filter((n) => n.getBoundingClientRect().right > window.innerWidth + 1).length);
  expect(wide).toBe(0);
  // addresses stay inside the review and download: nowhere else on this panel's page chrome
  expect((await panel(page).locator('h2, h3, [data-warnings], [data-digest]').allInnerTexts()).join(' ')).not.toMatch(MAC_PATTERN);
});

test('approve with a passkey records the review; download gives the JSON for the current digest', async ({ page, integration: f }) => {
  seed(f);
  await approveAndDownload(page, f);
});

async function approveAndDownload(page: import('@playwright/test').Page, f: World) {
  await signIn(page, f, 'operator');
  const digest = await panel(page).locator('[data-digest]').innerText();
  await panel(page).getByRole('button', { name: 'Approve this list (passkey)' }).click();
  await expect(panel(page).locator('[data-reviewed]')).toContainText('Approved');
  expect(f.store.all<{ action: string; outcome: string }>("SELECT action,outcome FROM audit WHERE action LIKE 'install_list_%'")).toEqual([{ action: 'install_list_reviewed', outcome: `digest:${digest}` }]);
  const download = page.waitForEvent('download');
  await panel(page).getByRole('button', { name: 'Download' }).click();
  const file = await download;
  expect(file.suggestedFilename()).toBe(`install-list-${digest.slice(0, 12)}.json`);
  const body = JSON.parse(await readFile((await file.path())!, 'utf8'));
  expect(body.digest).toBe(digest); expect(body.reviewed).toBe(true);
  expect(body.adults[0].mac).toBe(f.config.protectedMacs[0]); // adult addresses appear only in the export
  expect(JSON.stringify(body.children)).toContain(K2);
  expect(f.store.all<{ action: string }>("SELECT action FROM audit WHERE action LIKE 'install_list_%' ORDER BY id").map((r) => r.action)).toEqual(['install_list_reviewed', 'install_list_exported']);
  expect(JSON.stringify(f.store.all("SELECT * FROM audit WHERE action LIKE 'install_list_%'"))).not.toMatch(MAC_PATTERN);
}

test('adults are a count from the protected set, never raw MACs in the page', async ({ page, integration: f }) => {
  seed(f);
  await signIn(page, f, 'operator');
  await expect(panel(page).locator('[data-adults] h3')).toHaveText('Protected devices (existing protected set)');
  await expect(panel(page).locator('[data-adult-count]')).toHaveText('1 protected device');
  await expect(panel(page).locator('[data-adults-notice]')).toHaveCount(0);
  expect(await page.locator('body').innerText()).not.toContain(f.config.protectedMacs[0]);
  expect(await page.content()).not.toContain(f.config.protectedMacs[0]);
});

test('with no protected set the review says so and Approve is disabled', async ({ page, integration: f }) => {
  seed(f);
  f.config.protectedMacs = [];
  await signIn(page, f, 'operator');
  await expect(panel(page).locator('[data-adults-notice]')).toHaveText('Adult devices are not included in this review yet.');
  await expect(panel(page).getByRole('button', { name: 'Approve this list (passkey)' })).toBeDisabled();
  await expect(panel(page).getByRole('button', { name: 'Download' })).toBeEnabled();
  await panel(page).getByRole('button', { name: 'Approve this list (passkey)' }).click({ force: true });
  expect(f.store.all("SELECT * FROM audit WHERE action LIKE 'install_list_%'")).toEqual([]);
});

test('a hostile device label stays inert text', async ({ page, integration: f }) => {
  seed(f);
  f.store.run("UPDATE devices SET label=? WHERE id='d_kid2'", HOSTILE);
  await signIn(page, f, 'operator');
  await expect(panel(page).locator('[data-name]').filter({ hasText: HOSTILE })).toBeVisible();
  expect(await panel(page).locator('img').count()).toBe(0);
  expect(await page.evaluate(() => (window as unknown as { __xss?: number }).__xss)).toBeUndefined();
});

test('a parent never sees the review', async ({ page, integration: f }) => {
  await signIn(page, f, 'parent');
  await expect(page.locator('#status-view')).toBeVisible();
  await expect(panel(page)).toBeHidden();
});

test('without a hostile name the whole page has no horizontal scroll at 390px', async ({ page, integration: f }) => {
  seed(f);
  await page.setViewportSize({ width: 390, height: 800 });
  await signIn(page, f, 'operator');
  await expect(panel(page).locator('[data-digest]')).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});
