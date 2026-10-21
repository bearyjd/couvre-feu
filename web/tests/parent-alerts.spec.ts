import { test, expect, enroll } from './browser-fixture.ts';

const nowSeconds = () => Math.floor(Date.now() / 1000);
const delta = (person: string, over: object = {}) => ({ person, mac: '02:00:00:00:02:01', windowStart: nowSeconds() - 60, windowEnd: nowSeconds(),
  txBytes: 3 * 1024 * 1024, rxBytes: 0, blockedPackets: 0, enforcementActive: true, ...over });

test('parent sees a badge and persisted alerts for assigned children only, acknowledges one, and local alerts still work', async ({ page, demo }) => {
  const errors: string[] = []; page.on('pageerror', (error) => errors.push(error.message));
  demo.alerts.reconcile({ now: nowSeconds(), activity: [delta('alex'), delta('blair')], timeRequests: [{ person: 'alex', requestId: 'r1', createdAt: nowSeconds() - 30 }] });
  await enroll(page, demo, 'bryn');
  await expect(page.locator('#parent-alerts')).toBeVisible();
  await expect(page.locator('#alert-badge')).toHaveText('2');
  const rows = page.locator('#parent-alert-feed .parent-alert');
  await expect(rows).toHaveCount(2);
  await expect(page.locator('#parent-alert-feed')).toContainText('Possible bypass');
  await expect(page.locator('#parent-alert-feed')).toContainText('Time request waiting');
  await expect(page.locator('#parent-alert-feed')).not.toContainText('Blair');
  expect(await page.locator('#parent-alert-feed').innerText()).not.toMatch(/02:00:00/);
  // Server-side scope: the browser cannot widen it by asking.
  const response = await page.evaluate(async () => (await fetch('/alerts', { credentials: 'same-origin' })).json());
  expect(response.alerts.map((a: { personId: string }) => a.personId)).toEqual(['alex', 'alex']);
  await page.getByRole('button', { name: 'Acknowledge' }).first().click();
  await expect(page.locator('#alert-badge')).toHaveText('1');
  await expect(page.locator('#parent-alert-feed [data-alert-state="acknowledged"]')).toHaveCount(1);
  // Existing browser-local alert panel is untouched and still renders.
  await expect(page.getByRole('heading', { name: 'Recent alerts in this browser' })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: '/tmp/couvre-feu-parent-alerts.png', fullPage: true });
  expect(errors).toEqual([]);
});

test('an admin also sees alerts for every child, and a resolved alert leaves the badge', async ({ page, demo }) => {
  demo.alerts.reconcile({ now: nowSeconds(), activity: [delta('blair')] });
  await enroll(page, demo, 'jd');
  await expect(page.locator('#alert-badge')).toHaveText('1');
  await expect(page.locator('#parent-alert-feed')).toContainText('Blair (fictional)');
  demo.alerts.reconcile({ now: nowSeconds() + 120, activity: [delta('blair', { txBytes: 0, windowStart: nowSeconds() + 60, windowEnd: nowSeconds() + 120 })] });
  await page.getByRole('button', { name: 'Refresh status' }).click();
  await expect(page.locator('#alert-badge')).toBeHidden();
  await expect(page.locator('#parent-alert-feed [data-alert-state="resolved"]')).toHaveCount(1);
});

test('an admin sees a router_scope_change alert with counts only and its matched/unmatched wording', async ({ page, demo }) => {
  const errors: string[] = []; page.on('pageerror', (error) => errors.push(error.message));
  const alert = (id: number, matched: boolean, severity: string) => ({ id, personId: null, kind: 'router_scope_change', severity, createdAt: nowSeconds(), firstSeen: nowSeconds(), lastSeen: nowSeconds(), count: 1,
    state: 'open', acknowledgedAt: null, resolvedAt: null, details: { added: 2, removed: 1, matched, changeId: id } });
  // The demo database has no router_scope_change kind, so the server response is fixed here; the real server path is covered in service tests.
  await page.route('**/alerts', (route) => route.fulfill({ json: { alerts: [alert(2, false, 'critical'), alert(1, true, 'info')], nextBefore: null, openCount: 2 } }));
  await enroll(page, demo, 'jd');
  const feed = page.locator('#parent-alert-feed');
  await expect(feed.locator('.parent-alert')).toHaveCount(2);
  await expect(feed).toContainText('Router device list changed');
  await expect(feed).toContainText('2 devices added and 1 removed from the router\'s allowed list. No matching request');
  await expect(feed).toContainText('A request exists.');
  expect(await feed.innerText()).not.toMatch(/[0-9a-f]{2}(:[0-9a-f]{2}){5}/);
  expect(errors).toEqual([]);
});
