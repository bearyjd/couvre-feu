import { test, expect, enroll, browserAPI, virtualAuthenticator } from './browser-fixture.ts';
import { decodeCBOR, encodeCBOR } from '@levischuck/tiny-cbor';

test('genuine parent passkey, pending confirmation, resume schedule and phone keyboard layout', async ({ page, demo }) => {
  const errors: string[] = []; page.on('pageerror', (error) => errors.push(error.message));
  await enroll(page, demo);
  await expect(page.locator('[data-person="alex"]')).toBeVisible();
  await expect(page.locator('[data-person="blair"]')).toHaveCount(0);
  await expect(page.locator('.demo-banner')).toContainText('Synthetic demo');
  await expect(page.locator('.reasons dd').filter({ hasText: 'Schedule currently blocks access' })).toBeVisible();
  await page.getByRole('button', { name: 'Pause Alex (fictional)', exact: true }).click();
  await expect(page.locator('.operation')).toContainText('Pause pending');
  await expect(page.getByRole('button', { name: 'Pause Alex (fictional)', exact: true })).toBeDisabled();
  await expect(page.locator('.operation')).toContainText('Pause confirmed');
  await expect(page.locator('.reasons dd').filter({ hasText: 'Paused until you resume' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Resume Alex (fictional) manual pause' })).toBeEnabled();
  await page.getByRole('button', { name: 'Resume Alex (fictional) manual pause' }).click();
  await expect(page.locator('.operation')).toContainText('Resume confirmed');
  await expect(page.locator('.reasons dd').filter({ hasText: 'No manual pause' })).toBeVisible();
  await expect(page.locator('.reasons dd').filter({ hasText: 'Schedule currently blocks access' })).toBeVisible();
  await expect(page.locator('.operation')).toContainText('An active schedule can still block access');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.goto(demo.origin);
  await expect(page.getByRole('button', { name: 'Pause Alex (fictional)', exact: true })).toBeEnabled();
  await page.keyboard.press('Tab');
  await expect(page.locator('.skip-link')).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.locator('#main')).toBeFocused();
  await expect(page.getByLabel('Pause duration for Alex (fictional)')).toBeVisible();
  await expect(page.locator('.unavailable')).toContainText('Usage');
  await expect(page.locator('.unavailable dd')).toHaveText(['Unavailable', 'Unavailable', 'Unavailable']);
  expect(errors).toEqual([]);
  await page.locator('#main').evaluate((element) => (element as HTMLElement).blur());
  await page.screenshot({ path: '/tmp/couvre-feu-parent-phone.png', fullPage: true });
  await page.setViewportSize({ width: 1280, height: 900 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: '/tmp/couvre-feu-parent-desktop.png', fullPage: true });
});

test('timed pause expires in independent fake engine while the service is stopped', async ({ page, demo }) => {
  await enroll(page, demo);
  await page.getByLabel('Pause duration for Alex (fictional)').selectOption('60');
  await page.getByRole('button', { name: 'Pause Alex (fictional)', exact: true }).click();
  await expect(page.locator('.operation')).toContainText('Pause confirmed');
  expect(demo.router.observe().status.effectivePauses).toHaveLength(1);
  await demo.stopService();
  demo.advanceRouterClock(61); // Deterministic router clock; no service reconciliation or policy write.
  expect(demo.router.observe().status.effectivePauses).toHaveLength(0);
  expect(demo.router.observe().policy.pauses).toHaveLength(1); // Retained replay metadata is not an active pause.
  await demo.startService();
  await page.getByRole('button', { name: 'Refresh status' }).click();
  await expect(page.locator('.reasons dd').filter({ hasText: 'Expired in the latest observation' })).toBeVisible();
  await expect(page.locator('.reasons dd').filter({ hasText: 'Schedule currently blocks access' })).toBeVisible();
});

test('explicit failure stays visible and unknown response can reconcile without a mutation retry', async ({ page, demo }) => {
  await enroll(page, demo);
  demo.router.scenario('failed');
  await page.getByRole('button', { name: 'Pause Alex (fictional)', exact: true }).click();
  await expect(page.locator('#notice')).toContainText('request failed');
  await page.getByRole('button', { name: 'Refresh status' }).click();
  await expect(page.locator('.operation')).toContainText('Pause failed');
  await expect(page.getByRole('button', { name: 'Pause Alex (fictional)', exact: true })).toBeEnabled();
  demo.router.scenario('timeout');
  let writes = 0; page.on('request', (request) => { if (request.method() === 'POST' && /\/people\//.test(request.url())) writes++; });
  await page.getByRole('button', { name: 'Pause Alex (fictional)', exact: true }).click();
  await expect(page.locator('.operation')).toContainText('outcome unknown');
  await expect(page.getByRole('button', { name: 'Pause Alex (fictional)', exact: true })).toBeDisabled();
  await expect.poll(() => demo.router.observe().status.confirmedRevision === demo.router.observe().status.desiredRevision).toBe(true);
  await page.getByRole('button', { name: 'Refresh status' }).click();
  await expect(page.locator('.operation')).toContainText('Pause confirmed');
  expect(writes).toBe(1);
});

test('revision advance cancels stale intent and requires a new deliberate action', async ({ page, demo }) => {
  await enroll(page, demo);
  let writes = 0; page.on('request', (request) => { if (request.method() === 'POST' && /\/people\//.test(request.url())) writes++; });
  demo.router.localAdvance();
  await page.getByRole('button', { name: 'Pause Alex (fictional)', exact: true }).click();
  await expect(page.locator('#notice')).toContainText('revision or your permissions changed');
  expect(writes).toBe(0);
  await page.getByRole('button', { name: 'Pause Alex (fictional)', exact: true }).click();
  await expect(page.locator('.operation')).toContainText('Pause confirmed');
  expect(writes).toBe(1);
});

test('a router change after preflight returns HTTP conflict and requires explicit refresh', async ({ page, demo }) => {
  await enroll(page, demo);
  let intercepted = false;
  await page.route('**/people/alex/pause', async (route) => {
    if (!intercepted) { intercepted = true; demo.router.localAdvance(); }
    await route.continue();
  });
  await page.getByRole('button', { name: 'Pause Alex (fictional)', exact: true }).click();
  await expect(page.locator('#notice')).toContainText('Revision conflict. No retry was sent.');
  await expect(page.getByRole('button', { name: 'Pause Alex (fictional)', exact: true })).toBeDisabled();
  await page.getByRole('button', { name: 'Refresh status' }).click();
  await expect(page.getByRole('button', { name: 'Pause Alex (fictional)', exact: true })).toBeEnabled();
  await page.getByRole('button', { name: 'Pause Alex (fictional)', exact: true }).click();
  await expect(page.locator('.operation')).toContainText('Pause confirmed');
});

test('offline shell is timestamped read-only, has no auth cache and reconnect refreshes before controls', async ({ page, context, demo }) => {
  await enroll(page, demo);
  const session = await browserAPI(page, '/auth/session');
  const storage = await page.evaluate(() => JSON.stringify({ ...localStorage }));
  expect(storage).not.toContain(session.body.csrfToken);
  expect(storage).not.toContain('clientDataJSON');
  expect(storage).not.toContain('attestationObject');
  await page.evaluate(async () => { await navigator.serviceWorker.ready; });
  await page.waitForFunction(() => Boolean(navigator.serviceWorker.controller));
  const cachedURLs = await page.evaluate(async () => (await Promise.all((await caches.keys()).map(async (name) => (await (await caches.open(name)).keys()).map((request) => new URL(request.url).pathname)))).flat());
  expect(cachedURLs).toContain('/');
  expect(cachedURLs.some((path) => /^\/(auth|people|operations)(\/|$)/.test(path))).toBe(false);
  let writes = 0; page.on('request', (request) => { if (request.method() === 'POST' && /\/people\//.test(request.url())) writes++; });
  await context.setOffline(true);
  await page.reload();
  await expect(page.locator('#connection')).toContainText('Offline · read-only snapshot');
  await expect(page.locator('#connection')).toContainText('cached');
  await expect(page.getByRole('button', { name: 'Pause Alex (fictional)', exact: true })).toBeDisabled();
  await page.getByRole('button', { name: 'Pause Alex (fictional)', exact: true }).click({ force: true });
  expect(writes).toBe(0);
  demo.router.localAdvance();
  await context.setOffline(false);
  await expect(page.locator('#connection')).toContainText('Connected');
  await expect(page.getByRole('button', { name: 'Pause Alex (fictional)', exact: true })).toBeEnabled();
  expect(writes).toBe(0);
});

test('offline clock-ahead countdown never fabricates router-confirmed expiry', async ({ page, context, demo }) => {
  const errors: string[] = []; page.on('pageerror', (error) => errors.push(error.message));
  await enroll(page, demo);
  await page.getByLabel('Pause duration for Alex (fictional)').selectOption('60');
  await page.getByRole('button', { name: 'Pause Alex (fictional)', exact: true }).click();
  await expect(page.locator('.operation')).toContainText('Pause confirmed');
  await context.setOffline(true);
  await page.clock.install();
  await page.clock.fastForward('02:00');
  await expect(page.locator('[data-until]')).toContainText('Waiting for a fresh router observation');
  await expect(page.locator('.reasons dd').filter({ hasText: 'Expired in the latest observation' })).toHaveCount(0);
  await expect(page.getByText(/Paused until /).first()).toBeVisible();
  expect(demo.router.observe().status.effectivePauses).toHaveLength(1);
  expect(errors).toEqual([]); // parent-alerts load/render must stay isolated while offline
  await expect(page.locator('#parent-alerts')).toBeHidden();
});

test('offline logout clears status immediately and completes real server logout on reconnect', async ({ page, context, demo }) => {
  await enroll(page, demo);
  await context.setOffline(true);
  await page.getByRole('button', { name: 'Sign out', exact: true }).click();
  await expect(page.locator('#status-view')).toBeHidden();
  await expect(page.locator('#notice')).toContainText('server sign-out is still required');
  expect(await page.evaluate(() => Object.keys(localStorage).filter((key) => key.startsWith('cf-status:')))).toEqual([]);
  expect((await context.cookies()).some((cookie) => cookie.name === 'cf_session')).toBe(true);
  await context.setOffline(false);
  await expect(page.locator('#notice')).toContainText('Server sign-out completed');
  expect((await context.cookies()).some((cookie) => cookie.name === 'cf_session')).toBe(false);
  await expect(page.locator('#status-view')).toBeHidden();
});

test('parent authorization, replay rejection, account selection rejection and revoked-permission cache isolation', async ({ page, demo }) => {
  let registrationBody: unknown;
  page.on('request', (request) => { if (request.url().endsWith('/auth/register/verify')) registrationBody = request.postDataJSON(); });
  await enroll(page, demo);
  expect((await browserAPI(page, '/devices')).status).toBe(403);
  const status = await browserAPI(page, '/people');
  expect((await browserAPI(page, '/people/blair/pause', { until: 0 }, { 'If-Match': status.body.revisionToken, 'Idempotency-Key': crypto.randomUUID() })).status).toBe(404);
  expect((await browserAPI(page, '/auth/register/verify', registrationBody)).status).toBe(401);
  expect((await browserAPI(page, '/auth/register/options', { token: 'a'.repeat(43), role: 'admin', account: 'jd', personIds: ['blair'] })).status).toBe(400);
  demo.store.run('UPDATE accounts SET permission_version=permission_version+1,person_ids=? WHERE id=?', '[]', 'bryn');
  await page.getByRole('button', { name: 'Refresh status' }).click();
  await expect(page.locator('#status-view')).toBeHidden();
  expect(await page.evaluate(() => Object.keys(localStorage).filter((key) => key.startsWith('cf-status:')))).toEqual([]);
  await page.getByRole('button', { name: 'Sign in with a passkey' }).click();
  await expect(page.locator('#status-view')).toBeVisible();
  await expect(page.locator('[data-person="alex"]')).toHaveCount(0);
  const activeKey = await page.evaluate(() => localStorage.getItem('cf-status-active:v1'));
  expect(activeKey).toContain('"2"');
});

test('shared-browser account switch and cross-tab logout remove previous scoped status', async ({ page, context, demo }) => {
  const admin = await enroll(page, demo, 'jd');
  await expect(page.locator('[data-person="blair"]')).toBeVisible();
  const second = await context.newPage();
  await second.goto(demo.origin);
  await expect(second.locator('[data-person="blair"]')).toBeVisible();
  await page.getByRole('button', { name: 'Sign out', exact: true }).click();
  await expect(second.locator('#status-view')).toBeHidden();
  await admin.cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: admin.authenticatorId });
  await enroll(page, demo, 'bryn');
  await expect(page.locator('[data-person="blair"]')).toHaveCount(0);
  const serialized = await page.evaluate(() => JSON.stringify({ ...localStorage }));
  expect(serialized).not.toContain('Blair (fictional)');
  expect(serialized).not.toContain('Fictional laptop');
  await second.close();
});

test('server rejects browser attestation when the required user-verification flag is removed', async ({ page, demo }) => {
  await page.goto(demo.origin);
  await virtualAuthenticator(page);
  await page.route('**/auth/register/verify', async (route) => {
    const input = route.request().postDataJSON();
    const attestation = decodeCBOR(Uint8Array.from(Buffer.from(input.response.response.attestationObject, 'base64url'))) as Map<string, unknown>;
    const authData = Uint8Array.from(attestation.get('authData') as Uint8Array);
    authData[32] &= ~0x04; // Remove UV from the actual browser-generated authenticator data.
    attestation.set('authData', authData);
    input.response.response.attestationObject = Buffer.from(encodeCBOR(attestation as Parameters<typeof encodeCBOR>[0])).toString('base64url');
    await route.continue({ postData: JSON.stringify(input) });
  });
  await expect(page.getByRole('button', { name: 'Create a demo passkey' })).toBeEnabled();
  await page.getByLabel('One-use enrollment token').fill(demo.token('bryn'));
  const verification = page.waitForResponse('**/auth/register/verify');
  await page.getByRole('button', { name: 'Create a demo passkey' }).click();
  expect((await verification).status()).toBe(401);
  await expect(page.locator('#notice')).toContainText('passkey_verification_failed');
  expect(demo.store.all('SELECT id FROM credentials')).toHaveLength(0);
  await expect(page.locator('#status-view')).toBeHidden();
});

test('server rejects a wrong-origin attestation from the genuine browser enrollment flow', async ({ page, demo }) => {
  await page.goto(demo.origin);
  await virtualAuthenticator(page);
  await page.route('**/auth/register/verify', async (route) => {
    const input = route.request().postDataJSON();
    const clientData = JSON.parse(Buffer.from(input.response.response.clientDataJSON, 'base64url').toString());
    clientData.origin = 'https://wrong-origin.invalid';
    input.response.response.clientDataJSON = Buffer.from(JSON.stringify(clientData)).toString('base64url');
    await route.continue({ postData: JSON.stringify(input) });
  });
  await expect(page.getByRole('button', { name: 'Create a demo passkey' })).toBeEnabled();
  await page.getByLabel('One-use enrollment token').fill(demo.token('bryn'));
  const verification = page.waitForResponse('**/auth/register/verify');
  await page.getByRole('button', { name: 'Create a demo passkey' }).click();
  expect((await verification).status()).toBe(401);
  expect(demo.store.all('SELECT id FROM credentials')).toHaveLength(0);
  await expect(page.locator('#status-view')).toBeHidden();
});

for (const stage of ['options', 'verify'] as const) {
  test(`cross-tab logout cancels an outstanding passkey ${stage} response without restoring a session`, async ({ page, context, demo }) => {
    await page.goto(demo.origin);
    await expect(page.getByRole('button', { name: 'Sign in with a passkey' })).toBeEnabled();
    const signedPage = await context.newPage();
    const registered = await enroll(signedPage, demo);
    const { credentials } = await registered.cdp.send('WebAuthn.getCredentials', { authenticatorId: registered.authenticatorId });
    const loginAuthenticator = await virtualAuthenticator(page);
    await loginAuthenticator.cdp.send('WebAuthn.addCredential', { authenticatorId: loginAuthenticator.authenticatorId, credential: credentials[0] });
    await page.bringToFront();
    let releaseHeld!: () => void;
    let reportArrival!: () => void;
    const held = new Promise<void>((resolve) => { releaseHeld = resolve; });
    const arrived = new Promise<void>((resolve) => { reportArrival = resolve; });
    let verifies = 0;
    page.on('request', (request) => { if (request.url().endsWith('/auth/login/verify')) verifies++; });
    await page.route(`**/auth/login/${stage}`, async (route) => {
      // Node fetch deliberately avoids installing Set-Cookie in the browser before delivery.
      const upstream = await fetch(route.request().url(), { method: route.request().method(), headers: route.request().headers(), body: route.request().postData() });
      const body = await upstream.text();
      reportArrival();
      await held;
      try { await route.fulfill({ status: upstream.status, headers: Object.fromEntries(upstream.headers), body }); }
      catch { /* The aborted browser request is already closed. */ }
    });
    await page.getByRole('button', { name: 'Sign in with a passkey' }).click();
    await arrived;
    await signedPage.getByRole('button', { name: 'Sign out', exact: true }).click();
    await expect(page.locator('#notice')).toContainText('Signed out in another tab');
    releaseHeld();
    await expect(signedPage.locator('#notice')).toContainText('Signed out. Local status has been cleared.');
    await page.unrouteAll({ behavior: 'wait' });
    expect(verifies).toBe(stage === 'options' ? 0 : 1);
    expect((await context.cookies()).some((cookie) => cookie.name === 'cf_session')).toBe(false);
    expect((await browserAPI(page, '/auth/session')).status).toBe(401);
    await expect(page.getByRole('button', { name: 'Sign in with a passkey' })).toBeEnabled();
    await expect(page.locator('#status-view')).toBeHidden();
    await signedPage.close();
  });
}

test('quick pause presets show remaining time, End now removes the pause, and extra time is explained as unavailable', async ({ page, demo }) => {
  await enroll(page, demo);
  await expect(page.getByRole('button', { name: /^Pause Alex \(fictional\) for \d+ minutes$/ })).toHaveText(['Pause 15 min', 'Pause 30 min', 'Pause 60 min']);
  await expect(page.getByRole('button', { name: 'Extra time 15 / 30 / 60 min' })).toBeDisabled();
  await expect(page.locator('[data-extra-time="alex"]')).toContainText('not turned on');
  await page.getByRole('button', { name: 'Pause Alex (fictional) for 30 minutes', exact: true }).click();
  await expect(page.locator('.operation')).toContainText('Pause confirmed');
  await expect(page.locator('[data-remaining]')).toHaveText(/^(29|30)m \d+s$/);
  const pauses = demo.router.observe().status.effectivePauses;
  expect(pauses).toHaveLength(1);
  expect(pauses[0].until - Math.floor(Date.now() / 1000)).toBeGreaterThan(29 * 60 - 30);
  await page.screenshot({ path: '/tmp/couvre-feu-quick-pause.png', fullPage: true });
  await page.getByRole('button', { name: 'End Alex (fictional) timed pause now', exact: true }).click();
  await expect(page.locator('.operation')).toContainText('Resume confirmed');
  expect(demo.router.observe().status.effectivePauses).toHaveLength(0);
  await expect(page.locator('[data-remaining]')).toHaveCount(0);
});
