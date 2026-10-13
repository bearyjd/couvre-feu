import { test, expect, enroll, browserAPI } from './browser-fixture.ts';

const ACTIVITY_LABEL = 'Estimated network activity — not app use, websites or screen time';
const ALEX = '02:00:00:00:02:01', BLAIR = '02:00:00:00:02:02';
// A fixed mid-day UTC reference keeps day boundaries and minute counts deterministic.
const T = Date.UTC(2026, 9, 14, 12, 0, 0) / 1000, DAY = 86400;
type Demo = Parameters<Parameters<typeof test>[2]>[0]['demo'];
const poll = (person: string, mac: string, tx: number, blocked: number, offload: string) => ({ version: 1, router_epoch: 1, counter_epoch: 1, offload, errors: [], devices: [{ person, mac, ip: null, neighbor: 'REACHABLE', tx_bytes: tx, rx_bytes: 0, tx_packets: 0, rx_packets: 0, blocked_packets: blocked }] });

/** Synthetic counters: `polls` 30 second polls from `start`, each adding `perPoll` bytes and `blockedPerPoll` blocked packets. */
function seed(demo: Demo) {
  let tx = 1000, blocked = 0;
  const run = (start: number, polls: number, perPoll: number, blockedPerPoll: number, offload = 'off') => {
    demo.activity.ingest(poll('alex', ALEX, tx, blocked, offload), start);
    for (let k = 1; k <= polls; k++) { tx += perPoll; blocked += blockedPerPoll; demo.activity.ingest(poll('alex', ALEX, tx, blocked, offload), start + 30 * k); }
  };
  run(T - 4 * DAY - 7200, 40, 300000, 0, 'on'); // 20 minutes, offload on
  run(T - DAY - 10800, 20, 1000, 0); // yesterday morning, quiet
  run(T - DAY - 3600, 20, 300000, 0); // yesterday, busy; the stretch between is unknown
  run(T - 600, 10, 300000, 0); // today: five busy minutes
  run(T - 300, 10, 1000, 3); // today: five quiet minutes with blocked attempts
  demo.activity.ingest(poll('blair', BLAIR, 9, 0, 'off'), T - 600); demo.activity.ingest(poll('blair', BLAIR, 9999999, 0, 'off'), T - 570);
  demo.setActivityClock(T);
}

test('assigned parent sees labelled, honest per-child estimates with gaps and the offload caveat', async ({ page, demo }) => {
  const errors: string[] = []; page.on('pageerror', (error) => errors.push(error.message));
  seed(demo);
  await enroll(page, demo);
  const card = page.locator('[data-activity-person="alex"]');
  await expect(card).toBeVisible();
  await expect(page.locator('[data-activity-person="blair"]')).toHaveCount(0);
  await expect(card).toContainText(ACTIVITY_LABEL);
  await expect(card).toContainText('Estimated network activity — not app use, websites or screen time');
  const days = card.locator('.activity-day');
  await expect(days).toHaveCount(8);
  const today = days.last();
  await expect(today.locator('.activity-day-name')).toHaveText('Today');
  await expect(today).toHaveAttribute('data-date', '2026-10-14');
  await expect(today.locator('.activity-figures')).toHaveText('At least 5 min online · 3.0 MB · 30 blocked attempts');
  await expect(today.locator('.activity-coverage-note')).toContainText('Observed 10 of 720 min (1%); 710 min unknown.');
  await expect(today.locator('.activity-gaps')).toContainText('00:00–11:50');
  const yesterday = days.nth(6);
  await expect(yesterday).toHaveAttribute('data-coverage', 'partial');
  await expect(yesterday.locator('.activity-gaps')).toContainText('11:10–24:00');
  await expect(days.first().locator('.activity-gaps')).toHaveCount(0);
  await expect(days.nth(3)).toHaveAttribute('data-date', '2026-10-10');
  const offloaded = days.nth(3);
  await expect(offloaded.locator('.activity-offload')).toContainText('Hardware offload was on: traffic may be undercounted.');
  await expect(offloaded.locator('.activity-figures')).toContainText('At least');
  const unknown = days.first();
  await expect(unknown).toHaveAttribute('data-coverage', 'none');
  await expect(unknown.locator('.activity-figures')).toHaveText('No data: activity unknown');
  await expect(card).not.toContainText(/\b0 min online/);
  await expect(card.locator('.activity-method')).toContainText('Unobserved time is unknown, not zero');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  expect(errors).toEqual([]);
  await card.screenshot({ path: '/tmp/couvre-feu-activity-phone.png' });
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.locator('#activity-panel')).toBeHidden();
  await expect(page.locator('[data-activity-person]')).toHaveCount(0);
});

test('activity is server-enforced for assigned people only and unavailable without a session', async ({ page, demo }) => {
  seed(demo);
  expect((await fetch(`${demo.origin}/people/alex/activity`)).status).toBeGreaterThanOrEqual(401);
  await enroll(page, demo);
  const own = await browserAPI(page, '/people/alex/activity');
  expect(own.status).toBe(200);
  expect(own.body.disclaimer).toBe(ACTIVITY_LABEL);
  expect(own.body.days).toHaveLength(8);
  expect(JSON.stringify(own.body)).not.toContain(BLAIR);
  for (const person of ['blair', 'nobody', 'jd']) expect((await browserAPI(page, `/people/${person}/activity`)).status).toBe(404);
  expect((await browserAPI(page, '/people/alex/activity', {})).status).toBe(404); // activity is read-only; there is no write route
});

test('without any samples the panel says unknown and never reports zero', async ({ page, demo }) => {
  demo.setActivityClock(T);
  await enroll(page, demo);
  const card = page.locator('[data-activity-person="alex"]');
  await expect(card.locator('.activity-day[data-coverage="none"]')).toHaveCount(8);
  await expect(card.locator('.activity-figures')).toHaveText(Array(8).fill('No data: activity unknown'));
});
