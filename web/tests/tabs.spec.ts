import { test as demoTest, expect, enroll } from './browser-fixture.ts';
import { test as integrationTest, signIn, noHorizontalScroll } from './bulk-fixture.ts';
import type { World } from './bulk-fixture.ts';
import { mergeTests } from '@playwright/test';
import type { Page } from '@playwright/test';
import { K2, OUTSIDE } from './bulk-fixture.ts';

const test = mergeTests(demoTest, integrationTest);
test.use({ viewport: { width: 390, height: 844 }, serviceWorkers: 'block' });
test.afterEach(async ({ page }) => { await page.unrouteAll({ behavior: 'wait' }); });

const ADMIN_TABS = ['home', 'kids', 'devices', 'alerts', 'more'];
const tab = (page: Page, name: string) => page.locator(`#tab-${name}`);
const panel = (page: Page, name: string) => page.locator(`#panel-${name}`);
const hash = (page: Page) => page.evaluate(() => location.hash);
const selected = (page: Page) => page.locator('[role="tab"][aria-selected="true"]');
const visiblePanels = (page: Page) => page.evaluate(() => [...document.querySelectorAll('[role="tabpanel"]')].filter((p) => !(p as HTMLElement).hidden).map((p) => p.id));
const mac = (n: number) => `00:00:5e:00:00:${n.toString(16).padStart(2, '0')}`;

/** A baseline poll, then three devices that joined afterwards: three "new" devices for the badge. */
function seedNewDevices(f: World) {
  const d = (m: string, hostname: string, last: number) => ({ mac: m, ipv4: [`192.0.2.${last}`], hostname, source: 'both' as const });
  const t = f.now(), kid = d(K2, 'kid2-phone', 20), laptop = d(mac(2), 'old-laptop', 21);
  const poll = (devices: ReturnType<typeof d>[], at: number) => f.worker.inventory.ingest({ inventory_version: 1, generation: f.config.router.generation, routerTime: at, devices, truncated: false, errors: [] }, at);
  poll([kid, laptop], t - 180);
  poll([kid, laptop, d(mac(3), 'new-tv', 30)], t - 120);
  poll([kid, laptop, d(mac(3), 'new-tv', 30), d(OUTSIDE, 'outside-box', 32)], t - 60);
  poll([kid, laptop, d(mac(3), 'new-tv', 30), d(OUTSIDE, 'outside-box', 32), d('02:10:20:30:40:52', 'new-phone', 31)], t);
}

test('signed out: no tab bar at all', async ({ page, integration: f }) => {
  await page.goto(f.origin);
  await expect(page.locator('#auth-view')).toBeVisible();
  await expect(page.getByRole('tablist')).toHaveCount(0);
  await expect(page.locator('#tabbar')).toBeHidden();
  await page.goto(`${f.origin}/#devices`);
  await expect(page.locator('#tabbar')).toBeHidden();
  expect(await noHorizontalScroll(page)).toBe(true);
});

test('admin gets five tabs in order, Home first, one panel at a time, 44 px targets pinned to the bottom edge on a phone', async ({ page, integration: f }) => {
  await signIn(page, f, 'operator');
  const tabs = page.getByRole('tab');
  await expect(tabs).toHaveCount(5);
  expect(await tabs.evaluateAll((els) => els.map((e) => e.id))).toEqual(ADMIN_TABS.map((n) => `tab-${n}`));
  await expect(selected(page)).toHaveCount(1);
  await expect(tab(page, 'home')).toHaveAttribute('aria-selected', 'true');
  expect(await visiblePanels(page)).toEqual(['panel-home']);
  await expect(page.locator('#people')).toBeVisible();
  await expect(page.locator('#inventory-panel')).toBeHidden();
  for (const name of ADMIN_TABS) {
    const box = (await tab(page, name).boundingBox())!;
    expect(box.height).toBeGreaterThanOrEqual(44);
    expect(box.width).toBeGreaterThanOrEqual(44);
  }
  const bar = (await page.locator('#tabbar').boundingBox())!;
  expect(Math.round(bar.y + bar.height)).toBe(844); // the bar sits on the bottom edge and does not scroll away
  await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
  expect(Math.round(((await page.locator('#tabbar').boundingBox())!).y + bar.height)).toBe(844);
  expect(await noHorizontalScroll(page)).toBe(true);
  // ARIA wiring: each tab controls its panel, each panel is named by its tab.
  for (const name of ADMIN_TABS) {
    await expect(tab(page, name)).toHaveAttribute('aria-controls', `panel-${name}`);
    await expect(panel(page, name)).toHaveAttribute('aria-labelledby', `tab-${name}`);
  }
});

test('every panel keeps its id and lands in exactly one tab', async ({ page, integration: f }) => {
  await signIn(page, f, 'operator');
  const home = ['#people', '#time-requests', '#bulk-panel', '#connection'], kids = ['#children-panel'], devices = ['#inventory-panel'];
  const alerts = ['#parent-alerts', '#operational-alerts'], more = ['#activity-panel', '#audit-panel', '#accounts-panel', '#schedule-editor'];
  const where = { home, kids, devices, alerts, more };
  for (const [name, selectors] of Object.entries(where)) {
    for (const selector of selectors) {
      expect(await page.evaluate(([s]) => document.querySelector(s)?.closest('[role="tabpanel"]')?.id, [selector]), selector).toBe(`panel-${name}`);
    }
  }
  expect(await page.locator('[role="tabpanel"]').count()).toBe(5);
});

test('a deep link to #devices lands on the devices panel, also after a reload', async ({ page, integration: f }) => {
  seedNewDevices(f);
  await signIn(page, f, 'operator');
  await page.goto(`${f.origin}/#devices`);
  await expect(page.locator('#inventory-panel')).toBeVisible();
  await expect(tab(page, 'devices')).toHaveAttribute('aria-selected', 'true');
  expect(await visiblePanels(page)).toEqual(['panel-devices']);
  await expect(page.locator('#people')).toBeHidden();
  await page.reload();
  await expect(page.locator('#inventory-panel')).toBeVisible();
  await expect(tab(page, 'devices')).toHaveAttribute('aria-selected', 'true');
  expect(await hash(page)).toBe('#devices');
  expect(await noHorizontalScroll(page)).toBe(true);
});

test('sub-hash #more/accounts opens More and scrolls that panel to the top; an unknown sub-hash still opens More', async ({ page, integration: f }) => {
  await page.setViewportSize({ width: 390, height: 500 });
  await signIn(page, f, 'operator');
  await page.goto(`${f.origin}/#more/accounts`);
  await expect(tab(page, 'more')).toHaveAttribute('aria-selected', 'true');
  await expect(page.locator('#accounts-panel')).toBeVisible();
  await expect.poll(() => page.evaluate(() => Math.round(document.querySelector('#accounts-panel')!.getBoundingClientRect().top))).toBeLessThanOrEqual(2);
  await page.goto('about:blank'); // a fresh load (no restored scroll): the late-loading target is scrolled to as well
  await page.goto(`${f.origin}/#more/accounts`);
  await expect.poll(() => page.evaluate(() => Math.round(document.querySelector('#accounts-panel')?.getBoundingClientRect().top ?? 999))).toBeLessThanOrEqual(2);
  await page.goto(`${f.origin}/#more/nonsense`);
  await expect(tab(page, 'more')).toHaveAttribute('aria-selected', 'true');
  await expect(panel(page, 'more')).toBeVisible();
});

test('unknown hash opens Home; a tab the viewer cannot have opens Home; the skip link does not change tab', async ({ page, integration: f }) => {
  const errors: string[] = []; page.on('pageerror', (error) => errors.push(error.message));
  await signIn(page, f, 'operator');
  await page.goto(`${f.origin}/#nonsense`);
  await expect(tab(page, 'home')).toHaveAttribute('aria-selected', 'true');
  await tab(page, 'more').click();
  await expect(tab(page, 'more')).toHaveAttribute('aria-selected', 'true');
  await page.locator('.skip-link').focus();
  await page.keyboard.press('Enter');
  expect(await hash(page)).toBe('#main');
  await expect(tab(page, 'more')).toHaveAttribute('aria-selected', 'true');
  expect(await visiblePanels(page)).toEqual(['panel-more']);
  expect(errors).toEqual([]);
});

test('a parent sees three tabs; a deep link to #devices falls back to Home', async ({ page, integration: f }) => {
  await signIn(page, f, 'parent');
  await expect(page.getByRole('tab')).toHaveCount(3);
  expect(await page.getByRole('tab').evaluateAll((els) => els.map((e) => e.id))).toEqual(['tab-home', 'tab-alerts', 'tab-more']);
  await expect(tab(page, 'kids')).toBeHidden();
  await expect(tab(page, 'devices')).toBeHidden();
  await page.goto(`${f.origin}/#devices`);
  await expect(tab(page, 'home')).toHaveAttribute('aria-selected', 'true');
  expect(await visiblePanels(page)).toEqual(['panel-home']);
  await page.goto(`${f.origin}/#kids`);
  await expect(tab(page, 'home')).toHaveAttribute('aria-selected', 'true');
});

test('tab taps replace the history entry; a deep link pushes one, and Back returns to the previous page state', async ({ page, integration: f }) => {
  await signIn(page, f, 'operator');
  const before = await page.evaluate(() => history.length);
  await tab(page, 'kids').click();
  await tab(page, 'devices').click();
  await tab(page, 'more').click();
  expect(await hash(page)).toBe('#more');
  expect(await page.evaluate(() => history.length)).toBe(before); // taps never add entries
  await page.goto(`${f.origin}/#alerts`); // linked navigation pushes
  await expect(tab(page, 'alerts')).toHaveAttribute('aria-selected', 'true');
  expect(await page.evaluate(() => history.length)).toBe(before + 1);
  await page.goBack();
  await expect(tab(page, 'more')).toHaveAttribute('aria-selected', 'true'); // the entry the taps replaced
  expect(await visiblePanels(page)).toEqual(['panel-more']);
  await expect(page.locator('#more-heading')).toBeFocused();
  await page.goForward();
  await expect(tab(page, 'alerts')).toHaveAttribute('aria-selected', 'true');
});

test('choosing a tab moves focus to that panel heading; the same tab again does too', async ({ page, integration: f }) => {
  await signIn(page, f, 'operator');
  await expect(page.locator('#children-title')).toBeAttached();
  await expect(page.locator('#inventory-title')).toBeAttached();
  for (const name of ['kids', 'devices', 'alerts', 'more', 'home']) {
    await tab(page, name).click();
    await expect(tab(page, name)).toHaveAttribute('aria-selected', 'true');
    await expect.poll(() => page.evaluate(() => { const e = document.activeElement as HTMLElement; return `${e.tagName.replace(/^H1$/, 'H2')}|${e.getAttribute('tabindex')}|${e.closest('[role="tabpanel"]')?.id ?? ''}`; })).toBe(`H2|-1|panel-${name}`);
  }
  await page.locator('#people-title').evaluate((e) => (e as HTMLElement).blur());
  await tab(page, 'home').click(); // already selected: still hands focus to the heading
  await expect(page.locator('#people-title')).toBeFocused();
  // Linked navigation and Back move focus the same way.
  await page.goto(`${f.origin}/#devices`);
  await expect(page.locator('#inventory-title')).toBeFocused();
  await page.goBack();
  await expect(page.locator('#people-title')).toBeFocused();
});

test('a deep link does not steal focus on load', async ({ page, integration: f }) => {
  await signIn(page, f, 'operator');
  await page.goto(`${f.origin}/#alerts`);
  await page.reload();
  await expect(tab(page, 'alerts')).toHaveAttribute('aria-selected', 'true');
  expect(await page.evaluate(() => document.activeElement?.tagName)).toBe('BODY');
});

test('keyboard: one tab stop, arrows move between tabs and wrap, Home/End jump, Enter or Space opens', async ({ page, integration: f }) => {
  await signIn(page, f, 'operator');
  expect(await page.locator('[role="tab"][tabindex="0"]').evaluateAll((els) => els.map((e) => e.id))).toEqual(['tab-home']);
  await tab(page, 'home').focus();
  await page.keyboard.press('ArrowRight');
  await expect(tab(page, 'kids')).toBeFocused();
  await expect(tab(page, 'home')).toHaveAttribute('aria-selected', 'true'); // moving focus does not navigate
  await page.keyboard.press('ArrowRight');
  await expect(tab(page, 'devices')).toBeFocused();
  await page.keyboard.press('End');
  await expect(tab(page, 'more')).toBeFocused();
  await page.keyboard.press('ArrowRight');
  await expect(tab(page, 'home')).toBeFocused(); // wraps
  await page.keyboard.press('ArrowLeft');
  await expect(tab(page, 'more')).toBeFocused();
  await page.keyboard.press('Home');
  await expect(tab(page, 'home')).toBeFocused();
  await page.keyboard.press('ArrowRight');
  await page.keyboard.press('ArrowRight');
  await page.keyboard.press('Enter');
  await expect(tab(page, 'devices')).toHaveAttribute('aria-selected', 'true');
  expect(await hash(page)).toBe('#devices');
  await expect(page.locator('#inventory-title')).toBeFocused(); // choosing a tab hands focus to its panel; the arrows work from the tab again
  await tab(page, 'devices').focus();
  await page.keyboard.press('ArrowRight');
  await page.keyboard.press('ArrowRight');
  await expect(tab(page, 'more')).toBeFocused();
  await page.keyboard.press('Space');
  await expect(tab(page, 'more')).toHaveAttribute('aria-selected', 'true');
  // Roving tabindex follows the selection, and Tab leaves the list instead of walking every tab.
  expect(await page.locator('[role="tab"][tabindex="0"]').evaluateAll((els) => els.map((e) => e.id))).toEqual(['tab-more']);
  await page.keyboard.press('Tab');
  expect(await page.evaluate(() => !!document.activeElement?.closest('[role="tablist"]'))).toBe(false);
});

test('the Devices badge counts new devices and names them; no badge when there are none', async ({ page, integration: f }) => {
  seedNewDevices(f);
  await signIn(page, f, 'operator');
  const badge = tab(page, 'devices').locator('.tab-badge');
  await expect(badge).toHaveText('3');
  await expect(tab(page, 'devices')).toHaveAttribute('aria-label', /3 new devices/);
  await expect(tab(page, 'kids').locator('.tab-badge')).toBeHidden();
  await tab(page, 'devices').click();
  await page.locator('#inventory-panel [data-ack]').first().click();
  await expect(badge).toHaveText('2');
  f.store.run("UPDATE inventory_devices SET acknowledged_at=1,acknowledged_by='operator'");
  await page.reload();
  await expect(tab(page, 'home')).toBeVisible();
  await expect(tab(page, 'devices').locator('.tab-badge')).toBeHidden();
  await expect(tab(page, 'devices')).toHaveAttribute('aria-label', 'Devices');
});

test('the Alerts badge shows the open alert count and names it', async ({ page, demo }) => {
  const at = Math.floor(Date.now() / 1000);
  demo.alerts.reconcile({ now: at, activity: [], timeRequests: [{ person: 'alex', requestId: 'r1', createdAt: at - 30 }, { person: 'alex', requestId: 'r2', createdAt: at - 20 }] });
  await enroll(page, demo, 'bryn');
  const badge = tab(page, 'alerts').locator('.tab-badge');
  await expect(badge).toBeVisible();
  const count = await badge.innerText();
  expect(Number(count)).toBeGreaterThan(0);
  await expect(tab(page, 'alerts')).toHaveAttribute('aria-label', new RegExp(`${count} alerts? need`));
  await tab(page, 'alerts').click();
  await expect(page.locator('#alert-badge')).toHaveText(count);
});

test('demo mode has no Kids or Devices tab (their panels do not exist there)', async ({ page, demo }) => {
  await enroll(page, demo, 'bryn');
  expect(await page.getByRole('tab').evaluateAll((els) => els.map((e) => e.id))).toEqual(['tab-home', 'tab-alerts', 'tab-more']);
});

for (const size of [{ width: 390, height: 844 }, { width: 1280, height: 900 }]) {
  test(`${size.width} px: every tab fits without horizontal scroll`, async ({ page, integration: f }) => {
    seedNewDevices(f);
    await page.setViewportSize(size);
    await signIn(page, f, 'operator');
    for (const name of ADMIN_TABS) {
      await tab(page, name).click();
      await expect(panel(page, name)).toBeVisible();
      expect(await noHorizontalScroll(page), name).toBe(true);
    }
    const bar = (await page.locator('#tabbar').boundingBox())!, heading = (await page.locator('.masthead').boundingBox())!;
    if (size.width >= 900) {
      expect(bar.y).toBeLessThan(300); // navigation at the top on a desktop, not pinned under the content
      expect(bar.y).toBeGreaterThan(heading.y);
    } else expect(Math.round(bar.y + bar.height)).toBe(size.height);
  });
}

test('the unreachable banner stays above the tabs and visible on every tab, and Retry works from another tab', async ({ page, demo }) => {
  await enroll(page, demo);
  const probe = () => page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')));
  await demo.stopService();
  await probe();
  const banner = page.locator('#service-down');
  await expect(banner).toBeVisible();
  expect((await banner.boundingBox())!.height).toBeLessThan(130); // compact: text and Retry share a row
  for (const name of ['alerts', 'more', 'home']) {
    await tab(page, name).click();
    await expect(banner).toBeVisible();
    await expect(page.locator('#tabbar')).toBeVisible();
    await expect(page.locator('#connection')).toContainText('Not responding');
  }
  await page.setViewportSize({ width: 1280, height: 900 });
  const above = (await banner.boundingBox())!, bar = (await page.locator('#tabbar').boundingBox())!;
  expect(above.y + above.height).toBeLessThanOrEqual(bar.y + 1);
  await page.setViewportSize({ width: 390, height: 844 });
  await tab(page, 'more').click();
  await demo.startService();
  await banner.getByRole('button', { name: 'Retry' }).click();
  await expect(banner).toBeHidden();
  await expect(tab(page, 'more')).toHaveAttribute('aria-selected', 'true'); // recovery does not move the viewer
});

test('offline snapshot keeps the tabs and the chosen tab', async ({ page, context, demo }) => {
  await enroll(page, demo);
  await tab(page, 'alerts').click();
  await context.setOffline(true);
  await expect(page.locator('#connection')).toContainText('Offline');
  await expect(page.getByRole('tab')).toHaveCount(3);
  await expect(tab(page, 'alerts')).toHaveAttribute('aria-selected', 'true');
  await tab(page, 'home').click();
  await expect(page.locator('[data-person="alex"]')).toBeVisible();
  await context.setOffline(false);
});

test('signing out removes the tab bar', async ({ page, integration: f }) => {
  await signIn(page, f, 'operator');
  await expect(page.getByRole('tablist')).toBeVisible();
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.locator('#auth-view')).toBeVisible();
  await expect(page.getByRole('tablist')).toHaveCount(0);
});

test('an empty tab says so instead of showing a blank page', async ({ page, integration: f }) => {
  await signIn(page, f, 'operator');
  await page.route('**/admin/children', (route) => route.fulfill({ status: 500, json: { error: { code: 'x', message: 'x' } } }));
  await page.reload();
  await tab(page, 'kids').click();
  await expect(panel(page, 'kids').locator('.tab-empty')).toBeVisible();
  expect(await panel(page, 'kids').locator('.tab-empty').innerText()).not.toMatch(/refresh/i); // never points at a control that is on screen
});

test('"Add to a child" on a device opens the Kids tab with the form focused, and Back returns to Devices', async ({ page, integration: f }) => {
  seedNewDevices(f);
  await signIn(page, f, 'operator');
  await tab(page, 'devices').click();
  const row = page.locator('#inventory-panel li.inventory-row').filter({ hasText: 'new-tv' });
  await row.getByRole('button', { name: /^Add to a child/ }).click();
  await row.getByLabel(/^Child for/).selectOption({ label: 'Explicit test person' });
  await row.getByRole('button', { name: 'Continue' }).click();
  await expect(tab(page, 'kids')).toHaveAttribute('aria-selected', 'true');
  await expect(page.locator('#children-panel [data-add-device="pilot"] input[name="label"]')).toBeFocused();
  expect(await hash(page)).toBe('#kids');
  await page.goBack();
  await expect(tab(page, 'devices')).toHaveAttribute('aria-selected', 'true');
});

test('each tab has one heading that takes focus, with no stacked duplicate title', async ({ page, integration: f }) => {
  await signIn(page, f, 'operator');
  await expect(page.locator('#children-title')).toBeAttached();
  await expect(page.locator('#inventory-title')).toBeAttached();
  for (const name of ADMIN_TABS) {
    await tab(page, name).click();
    await expect.poll(() => page.evaluate((id) => document.activeElement === document.querySelector(`#panel-${id}`)!.querySelector('h1, h2, h3'), name)).toBe(true);
    expect(await page.locator(`#panel-${name}`).locator('h1:visible, .tab-title:visible').count()).toBeLessThanOrEqual(1);
    if (name === 'devices') expect(await page.locator('#panel-devices').getByRole('heading', { name: /^Devices/ }).count()).toBe(1); // not "Devices" plus "Devices on the network"
    if (name === 'kids') expect(await page.locator('#panel-kids').getByRole('heading', { name: /^(Kids|Children)/ }).count()).toBe(1);
  }
});

test('one refresh control per tab: text button on Home, a single icon button elsewhere, wired to the same handler', async ({ page, integration: f }) => {
  await signIn(page, f, 'operator');
  for (const name of ADMIN_TABS) {
    await tab(page, name).click();
    const buttons = page.getByRole('button', { name: 'Refresh status' });
    await expect(buttons).toHaveCount(1);
    if (name !== 'home') expect((await buttons.innerText()).trim()).toBe('');
    expect((await buttons.boundingBox())!.width).toBeGreaterThanOrEqual(44);
  }
  await tab(page, 'devices').click();
  const requested = page.waitForRequest((r) => new URL(r.url()).pathname === '/people');
  await page.getByRole('button', { name: 'Refresh status' }).click();
  await requested;
});

test('the "Signed in as" notice collapses by itself', async ({ page, integration: f }) => {
  await signIn(page, f, 'operator');
  await expect(page.locator('#notice')).toBeHidden({ timeout: 15000 });
});

test('More is ordered Schedules, Activity, Audit log, Accounts, About, with a jump list to the visible ones', async ({ page, integration: f }) => {
  await signIn(page, f, 'operator');
  await tab(page, 'more').click();
  expect(await page.evaluate(() => [...document.querySelectorAll('#panel-more > [id]')].map((e) => e.id).filter((id) => id !== 'more-heading'))).toEqual(
    ['more-jump', 'schedule-editor', 'activity-panel', 'activity-boundary', 'audit-panel', 'accounts-panel', 'about-panel']);
  await expect(page.locator('#about-panel')).toBeVisible();
  const links = page.locator('#more-jump a:visible');
  expect(await links.allInnerTexts()).toContain('Accounts');
  expect(await links.allInnerTexts()).toContain('About');
  await page.setViewportSize({ width: 390, height: 500 });
  await page.locator('#more-jump').getByRole('link', { name: 'Accounts' }).click();
  expect(await hash(page)).toBe('#more/accounts');
  await expect.poll(() => page.evaluate(() => Math.round(document.querySelector('#accounts-panel')!.getBoundingClientRect().top))).toBeLessThanOrEqual(2);
});

const luminance = ([r, g, b]: number[]) => { const c = [r, g, b].map((v) => { const x = v / 255; return x <= 0.03928 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4; }); return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]; };
const ratio = (a: number[], b: number[]) => { const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x); return (hi + 0.05) / (lo + 0.05); };
const rgb = (css: string) => (css.match(/[\d.]+/g) ?? []).slice(0, 3).map(Number);

test('tab contrast: labels at least 4.5:1, the active tab is a filled pill, badges are ringed and legible', async ({ page, integration: f }) => {
  seedNewDevices(f);
  await signIn(page, f, 'operator');
  const style = (sel: string, prop: string) => page.locator(sel).evaluate((e, p) => getComputedStyle(e).getPropertyValue(p), prop);
  const bar = rgb(await style('#tabbar', 'background-color'));
  expect(ratio(rgb(await style('#tab-kids', 'color')), bar)).toBeGreaterThanOrEqual(4.5);
  const fill = rgb(await style('#tab-home', 'background-color'));
  expect(ratio(rgb(await style('#tab-home', 'color')), fill)).toBeGreaterThanOrEqual(4.5);
  expect(ratio(fill, bar)).toBeGreaterThanOrEqual(3); // the selected tab is a visible shape, not only a thin line
  expect(Number(await style('#tab-home', 'font-weight'))).toBeGreaterThan(Number(await style('#tab-kids', 'font-weight')));
  const badge = page.locator('#tab-devices .tab-badge');
  await expect(badge).toBeVisible();
  expect((await badge.boundingBox())!.height).toBeGreaterThanOrEqual(16);
  expect(await style('#tab-devices .tab-badge', 'box-shadow')).toMatch(/2px/);
  expect(ratio(rgb(await style('#tab-devices .tab-badge', 'color')), rgb(await style('#tab-devices .tab-badge', 'background-color')))).toBeGreaterThanOrEqual(4.5);
});

test('on a phone the bar steps aside while a text field is focused, and returns after; a desktop keeps it', async ({ page, integration: f }) => {
  await signIn(page, f, 'operator');
  await tab(page, 'more').click();
  await expect(page.locator('#new-account-name')).toBeVisible();
  await page.locator('#new-account-name').focus();
  await expect(page.locator('#tabbar')).toBeHidden();
  await page.locator('#new-account-name').blur();
  await expect(page.locator('#tabbar')).toBeVisible();
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.locator('#new-account-name').focus();
  await expect(page.locator('#tabbar')).toBeVisible();
});

test('the pinned bar never covers the end of the page on a tall panel at 390x844', async ({ page, integration: f }) => {
  seedNewDevices(f);
  await signIn(page, f, 'operator');
  for (const name of ['devices', 'more']) {
    await tab(page, name).click();
    await page.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight));
    const bar = (await page.locator('#tabbar').boundingBox())!;
    const last = await page.evaluate(() => Math.max(...[...document.querySelectorAll('footer > *, .source-footnote')].map((e) => e.getBoundingClientRect().bottom)));
    expect(last, name).toBeLessThanOrEqual(bar.y + 1);
    const lastCard = await page.evaluate((id) => { const kids = [...document.querySelectorAll(`#panel-${id} > *`)].filter((e) => !(e as HTMLElement).hidden); return kids[kids.length - 1].getBoundingClientRect().bottom; }, name);
    expect(lastCard, name).toBeLessThanOrEqual(bar.y + 1);
  }
});

test('signing out resets the tab state: a later sign-in with an unknown hash lands on Home, not the old tab', async ({ page, integration: f }) => {
  await signIn(page, f, 'operator');
  await tab(page, 'devices').click();
  await expect(tab(page, 'devices')).toHaveAttribute('aria-selected', 'true');
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.locator('#auth-view')).toBeVisible();
  await page.evaluate(() => history.replaceState(null, '', '#bogus'));
  await page.getByRole('button', { name: 'Sign in with a passkey' }).click();
  await expect(page.locator('#status-view')).toBeVisible();
  await expect(tab(page, 'home')).toHaveAttribute('aria-selected', 'true');
  expect(await visiblePanels(page)).toEqual(['panel-home']);
  expect(await page.locator('[role="tab"][aria-selected="true"]').count()).toBe(1);
});
