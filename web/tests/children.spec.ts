import { test as base, expect } from '@playwright/test';
import { once } from 'node:events';
import { issueOperatorBootstrap, Auth } from '../../service/src/auth.ts';
import { appServer } from '../../service/src/http.ts';
import { integrationFixture } from '../../service/tests/fixtures/integration.ts';
import { virtualAuthenticator } from './browser-fixture.ts';

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

test('admin adds a device group and devices with passkey step-up through the router path, at phone width', async ({ page, integration: f }) => {
  await page.goto(f.origin);
  await virtualAuthenticator(page);
  await page.getByLabel('One-use enrollment token').fill(issueOperatorBootstrap(f.store, 'operator', f.now()));
  await page.getByRole('button', { name: 'Create a passkey' }).click();
  await expect(page.locator('#status-view')).toBeVisible();
  const panel = page.locator('#children-panel');
  await expect(panel.getByRole('heading', { name: 'Children and device groups' })).toBeVisible();
  await expect(panel.locator('[data-entry="pilot"]')).toContainText('Child · 1 device');

  // A second device for the seeded child: step-up, queued, then confirmed by the router.
  const child = panel.locator('[data-entry="pilot"]');
  await child.getByLabel('New device name for Explicit test person').fill('Tablet');
  await child.getByLabel('Wi-Fi address (MAC) for Explicit test person').fill(TABLET.toUpperCase());
  await child.getByRole('button', { name: 'Add device' }).click();
  await expect(panel.locator('.notice[role="status"]')).toContainText('Sent to the router');
  await expect(child).toContainText('Adding…');
  await dispatchPending(f);
  await page.getByRole('button', { name: 'Refresh status' }).click();
  await expect(child).toContainText(`${TABLET} · on the router`);
  await expect(page.locator('[data-person="pilot"]')).toContainText('2 assigned devices');

  // A non-child entry (e.g. a TV) is labelled as a device group, never as a child.
  await panel.getByLabel('New name').fill('Living-room TV');
  await panel.getByLabel('Type').selectOption('device_group');
  await panel.getByRole('button', { name: 'Add', exact: true }).click();
  const group = panel.locator('[data-entry^="group_"]');
  await expect(group).toContainText('Device group · 0 devices');
  await group.getByLabel('New device name for Living-room TV').fill('TV');
  await group.getByLabel('Wi-Fi address (MAC) for Living-room TV').fill(TV);
  await group.getByRole('button', { name: 'Add device' }).click();
  await expect(group).toContainText('Adding…');
  await dispatchPending(f);
  await page.getByRole('button', { name: 'Refresh status' }).click();
  await expect(group).toContainText(`${TV} · on the router`);
  const card = page.locator('article.person').filter({ hasText: 'Living-room TV' });
  await expect(card.locator('.person-id')).toHaveText(/^Device group · 1 assigned device$/);

  // A refused MAC shows the server's explanation and changes nothing.
  await child.getByLabel('New device name for Explicit test person').fill('Unknown');
  await child.getByLabel('Wi-Fi address (MAC) for Explicit test person').fill('02:10:20:30:40:5e');
  await child.getByRole('button', { name: 'Add device' }).click();
  await expect(panel.locator('[data-pending-approval]')).toContainText('Waiting for router approval');
  await expect(panel.locator('[data-pending-approval]')).toContainText('cfctl scope-add <ADDRESS FROM DEVICE SETTINGS> --base <router-read>');
  await expect(panel.locator('[data-pending-approval]')).not.toContainText('02:10:20:30:40:5e');

  // Removal goes through the router as well.
  await child.getByRole('button', { name: 'Remove device Tablet from Explicit test person' }).click();
  await expect(child).toContainText('Removing…');
  await dispatchPending(f);
  await page.getByRole('button', { name: 'Refresh status' }).click();
  await expect(child).not.toContainText('Tablet');

  // Phone width: no horizontal page scroll.
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});

test('parents never see the child admin panel or device addresses', async ({ page, integration: f }) => {
  await page.goto(f.origin);
  await virtualAuthenticator(page);
  await page.getByLabel('One-use enrollment token').fill(issueOperatorBootstrap(f.store, 'parent', f.now()));
  await page.getByRole('button', { name: 'Create a passkey' }).click();
  await expect(page.locator('#status-view')).toBeVisible();
  await expect(page.locator('#children-panel')).toBeHidden();
  expect(await page.content()).not.toContain('02:10:20:30:40:50');
  const status = await page.evaluate(async () => (await fetch('/admin/children')).status);
  expect(status).toBe(403);
});
