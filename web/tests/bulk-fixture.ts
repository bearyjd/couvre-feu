import { test as base, expect } from '@playwright/test';
import type { Page } from '@playwright/test';
import { once } from 'node:events';
import { issueOperatorBootstrap, Auth } from '../../service/src/auth.ts';
import { appServer } from '../../service/src/http.ts';
import { integrationFixture } from '../../service/tests/fixtures/integration.ts';
import { normalizePolicy } from '../../shared/src/router-schema.ts';
import { virtualAuthenticator } from './browser-fixture.ts';

// Placeholder, locally administered MACs only. Three children on the router; the operator manages all, the parent two.
export const SEED = '02:10:20:30:40:50', K2 = '02:10:20:30:40:62', K3 = '02:10:20:30:40:63', OUTSIDE = '02:10:20:30:40:5e';
export const NAMES = { pilot: 'Explicit test person', kid2: 'Kid kid2', kid3: 'Kid kid3' };
export type World = ReturnType<typeof integrationFixture> & { origin: string };

export const test = base.extend<{ integration: World }>({
  integration: async ({}, use) => {
    const f = integrationFixture(), port = Number(process.env.CF_WEB_TEST_PORT ?? '4273'), origin = `http://localhost:${port}`;
    f.config.routerScope = [SEED, K2, K3, '02:10:20:30:40:52'];
    f.advance(Math.floor(Date.now() / 1000) - f.now()); // the browser checks session expiry against its own clock
    const created = f.now();
    for (const [id, mac] of [['kid2', K2], ['kid3', K3]]) {
      f.store.run("INSERT INTO people(id,name,kind,active,created_at) VALUES(?,?,'child',1,?)", id, NAMES[id as 'kid2' | 'kid3'], created);
      f.store.run("INSERT INTO devices(id,person_id,label,identifier_kind,identifier,state,created_at) VALUES(?,?,?,'mac',?,'active',?)", `d_${id}`, id, `Device ${id}`, mac, created);
    }
    f.store.run('UPDATE accounts SET person_ids=? WHERE id=?', JSON.stringify(['pilot', 'kid2', 'kid3']), 'operator');
    f.store.run('UPDATE accounts SET person_ids=? WHERE id=?', JSON.stringify(['pilot', 'kid2']), 'parent');
    f.router.policy = normalizePolicy({ version: 1, revision: 1, people: [{ id: 'pilot', macs: [SEED] }, { id: 'kid2', macs: [K2] }, { id: 'kid3', macs: [K3] }], pauses: [], schedules: [] }, f.config.protectedMacs);
    const auth = new Auth(f.store, origin, f.now, { provenance: f.config.provenance, rpName: 'Private integration test' });
    const server = appServer(auth, f.policy, { ...f.config, port, origin, host: `localhost:${port}` }, undefined, undefined, undefined, f.worker.inventory);
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
export { expect };

/** The router applies the one queued operation and the service observes the result (the test is the dispatcher). */
export async function dispatchPending(f: World) {
  const id = f.store.integrationState().active_operation_id;
  if (!id) throw new Error('no queued operation');
  const plan = f.worker.prepare('apply', id); await f.worker.execute(plan, plan.scriptSha256);
  f.advance(1); await f.observe();
}

export async function signIn(page: Page, f: World, account: 'operator' | 'parent') {
  await page.goto(f.origin);
  await virtualAuthenticator(page);
  await page.getByLabel('One-use enrollment token').fill(issueOperatorBootstrap(f.store, account, f.now()));
  await page.getByRole('button', { name: 'Create a passkey' }).click();
  await expect(page.locator('#status-view')).toBeVisible();
}

export const noHorizontalScroll = (page: Page) => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth);
