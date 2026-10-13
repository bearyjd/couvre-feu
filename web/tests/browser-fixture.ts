import { test as base, expect } from '@playwright/test';
import type { Page } from '@playwright/test';
import { mkdtempSync, unlinkSync, rmdirSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import { Store } from '../../service/src/db.ts';
import { seedAccounts, INITIAL_POLICY } from '../../service/src/fixtures.ts';
import { Auth, issueBootstrap } from '../../service/src/auth.ts';
import { PolicyService } from '../../service/src/policy.ts';
import { appServer } from '../../service/src/http.ts';
import { ParentAlerts, systemActor } from '../../service/src/parent-alerts.ts';
import { TimeRequestService } from '../../service/src/time-requests.ts';
import { ActivityStore } from '../../service/src/activity-store.ts';
import { FakeRouter } from '../../demo-router/src/router.ts';
import { policyJSON, normalizePolicy } from '../../shared/src/router-schema.ts';

type Demo = {
  origin: string; store: Store; router: FakeRouter; policy: PolicyService; alerts: ParentAlerts;
  token: (id: 'jd' | 'bryn') => string;
  activity: ActivityStore; setActivityClock: (seconds: number | null) => void;
  advanceRouterClock: (seconds: number) => void;
  stopService: () => Promise<void>; startService: () => Promise<void>;
};

export const test = base.extend<{ demo: Demo }>({
  demo: async ({}, use) => {
    const dataDir = mkdtempSync(join(tmpdir(), 'couvre-feu-browser-'));
    const port = Number(process.env.CF_WEB_TEST_PORT ?? '4273');
    const origin = `http://localhost:${port}`;
    const store = new Store(join(dataDir, 'service.sqlite')); seedAccounts(store);
    let clockOffset = 0;
    const routerNow = () => Date.now() / 1000 + clockOffset;
    const router = new FakeRouter(join(dataDir, 'fake-router.sqlite'), { now: routerNow, delay: 1.4 });
    // A deterministic active UTC schedule spanning this short scenario run.
    const minute = new Date().getUTCHours() * 60 + new Date().getUTCMinutes();
    const hhmm = (value: number) => { const normalized = (value + 1440) % 1440; return `${String(Math.floor(normalized / 60)).padStart(2, '0')}:${String(normalized % 60).padStart(2, '0')}`; };
    const fixturePolicy = normalizePolicy({ ...INITIAL_POLICY, schedules: [{ person: 'alex', id: 'browser_fixture', weekdays: ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'], start: hhmm(minute - 2), stop: hhmm(minute + 10) }] });
    store.run('UPDATE service_state SET desired_json=? WHERE singleton=1', policyJSON(fixturePolicy));
    router.store.run('UPDATE fake_state SET policy=? WHERE singleton=1', policyJSON(fixturePolicy));
    const auth = new Auth(store, origin);
    const policy = new PolicyService(store, router, () => Math.floor(routerNow()));
    const timeRequests = new TimeRequestService(store, policy, () => Math.floor(routerNow()));
    const alerts = new ParentAlerts(store, { people: () => policy.people(systemActor), timeRequests: () => timeRequests.pendingForAlerts() }, () => Math.floor(routerNow()));
    let activityClock: number | null = null; // Tests that seed history pin the evaluation time; otherwise it follows the router clock.
    const activity = new ActivityStore(store, { now: () => activityClock ?? Math.floor(routerNow()) });
    const config = { port, origin, host: `localhost:${port}`, dataDir };
    let server = appServer(auth, policy, config, alerts, activity, timeRequests);
    const startService = async () => { server = appServer(auth, policy, config, alerts, activity, timeRequests); server.listen(port, '127.0.0.1'); await once(server, 'listening'); };
    const stopService = async () => { const closed = new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve())); server.closeAllConnections(); await closed; }; // preconnected browser sockets would otherwise keep close() pending
    router.tick();
    const tick = setInterval(() => router.tick(), 50); // Independent fake engine, never calls policy/service.
    await startService();
    try {
      await use({ origin, store, router, policy, alerts, activity, setActivityClock: (seconds) => { activityClock = seconds; }, token: (id) => issueBootstrap(store, id), advanceRouterClock: (seconds) => { clockOffset += seconds; router.tick(); }, stopService, startService });
    } finally {
      clearInterval(tick);
      if (server.listening) await stopService();
      router.close(); store.close();
      // Remove only known files we created; no recursive deletion or retained credentials.
      for (const name of ['service.sqlite', 'service.sqlite-wal', 'service.sqlite-shm', 'fake-router.sqlite', 'fake-router.sqlite-wal', 'fake-router.sqlite-shm']) {
        const path = join(dataDir, name);
        if (existsSync(path)) unlinkSync(path);
      }
      rmdirSync(dataDir);
    }
  },
});
export { expect };

export async function virtualAuthenticator(page: Page, userVerified = true) {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: userVerified ? 'internal' : 'usb', hasResidentKey: true, hasUserVerification: userVerified, isUserVerified: userVerified, automaticPresenceSimulation: true } });
  return { cdp, authenticatorId };
}

export async function enroll(page: Page, demo: Demo, id: 'jd' | 'bryn' = 'bryn') {
  await page.bringToFront();
  await page.goto(demo.origin);
  await expect(page.getByRole('button', { name: 'Create a demo passkey' })).toBeEnabled();
  const authenticator = await virtualAuthenticator(page);
  await page.getByLabel('One-use enrollment token').fill(demo.token(id));
  await page.getByRole('button', { name: 'Create a demo passkey' }).click();
  await expect(page.locator('#status-view')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Pause Alex (fictional)', exact: true })).toBeEnabled();
  return authenticator;
}

export async function browserAPI(page: Page, path: string, body?: unknown, extraHeaders: Record<string, string> = {}) {
  return page.evaluate(async ({ path, body, extraHeaders }) => {
    const sessionResponse = await fetch('/auth/session', { cache: 'no-store' });
    const session = await sessionResponse.json();
    const response = await fetch(path, { method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin', cache: 'no-store', headers: { ...(body === undefined ? {} : { 'Content-Type': 'application/json', 'X-CSRF-Token': session.csrfToken }), ...extraHeaders }, body: body === undefined ? undefined : JSON.stringify(body) });
    return { status: response.status, body: await response.json() };
  }, { path, body, extraHeaders });
}
