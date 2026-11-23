import { test, expect, enroll, openTab } from './browser-fixture.ts';
import type { Page } from '@playwright/test';

// iOS restyle layout guards: the sticky masthead, safe-area insets, forced colours, secondary-button contrast and
// disclosure markers. Chromium cannot emulate env(safe-area-inset-*), so the tests set the --safe-* tokens that every
// inset in the stylesheets goes through.
test.use({ serviceWorkers: 'block' });
test.afterEach(async ({ page }) => { await page.unrouteAll({ behavior: 'wait' }); });

const NAME_64 = 'Bryn ' + 'Long-Fictional-Name-'.repeat(3).slice(0, 59);
const NAME_128 = 'Bryn ' + 'Long-Fictional-Name-'.repeat(7).slice(0, 123);
const insets = (page: Page, top: number, bottom: number) => page.evaluate(([t, b]) => {
  document.documentElement.style.setProperty('--safe-t', `${t}px`);
  document.documentElement.style.setProperty('--safe-b', `${b}px`);
}, [top, bottom]);

async function signInAs(page: Page, demo: Parameters<typeof enroll>[1], name?: string) {
  await enroll(page, demo);
  if (name) {
    demo.store.run("UPDATE accounts SET display_name=? WHERE id='bryn'", name);
    await page.reload();
    await expect(page.locator('#account-actions .account-name')).toContainText(name.slice(0, 20));
  }
}

/** The masthead's bottom edge and the pinned tab bar's top edge (innerHeight when the bar is not pinned). */
const bounds = (page: Page) => page.evaluate(() => {
  const bar = document.querySelector('#tabbar') as HTMLElement | null;
  const pinned = bar && !bar.hidden && getComputedStyle(bar).position === 'fixed';
  return { top: document.querySelector('.masthead')!.getBoundingClientRect().bottom, bottom: pinned ? bar!.getBoundingClientRect().top : innerHeight };
});

async function expectClearOfMasthead(page: Page, selector: string) {
  await expect.poll(() => page.evaluate((sel) => {
    const el = document.querySelector(sel); const bar = document.querySelector('.masthead');
    if (!el || !bar) return 'missing';
    const h = el.querySelector('h2, h3') ?? el; const r = h.getBoundingClientRect();
    if (r.top < bar.getBoundingClientRect().bottom - 1) return `heading top ${Math.round(r.top)} under masthead bottom ${Math.round(bar.getBoundingClientRect().bottom)}`;
    const hit = document.elementFromPoint(r.left + 4, r.top + r.height / 2);
    return hit && (h === hit || h.contains(hit)) ? 'ok' : `covered by ${hit?.tagName}.${hit?.className}`;
  }, selector)).toBe('ok');
}

for (const [label, name] of [['64', NAME_64], ['128', NAME_128]] as const) {
  test(`601 px, ${label}-character account name: a deep link clears the taller masthead`, async ({ page, demo }) => {
    await page.setViewportSize({ width: 601, height: 700 });
    await signInAs(page, demo, name);
    const { height, padding } = await page.evaluate(() => ({ height: document.querySelector('.masthead')!.getBoundingClientRect().height, padding: parseFloat(getComputedStyle(document.documentElement).scrollPaddingTop) }));
    expect(height, 'the long name wraps the masthead taller than the old fixed 72 px offset assumed').toBeGreaterThan(72);
    expect(padding).toBeGreaterThanOrEqual(height);
    await page.goto(`${demo.origin}/#more/accounts`);
    await expectClearOfMasthead(page, '#accounts-panel');
  });

  test(`601 px, ${label}-character account name: every Tab stop lands clear of the masthead and the tab bar`, async ({ page, demo }) => {
    await page.setViewportSize({ width: 601, height: 700 });
    await signInAs(page, demo, name);
    await openTab(page, 'more');
    // Walk backwards from the end of the page: each earlier control scrolls in from above, under the masthead.
    await page.evaluate(() => {
      window.scrollTo(0, document.documentElement.scrollHeight);
      const controls = [...document.querySelectorAll<HTMLElement>('main a[href], main button, main input, main select, main summary')].filter((el) => el.offsetParent !== null);
      controls[controls.length - 1].focus();
    });
    const problems: string[] = [];
    for (let i = 0; i < 40; i += 1) {
      await page.keyboard.press('Shift+Tab');
      const result = await page.evaluate(() => {
        const el = document.activeElement as HTMLElement | null;
        if (!el || el === document.body || el.closest('.masthead, #tabbar, .skip-link')) return null;
        const r = el.getBoundingClientRect();
        return { id: el.id || el.tagName, top: r.top, bottom: r.bottom };
      });
      if (!result) continue;
      const b = await bounds(page);
      if (result.top < b.top - 1 || result.bottom > b.bottom + 1) problems.push(`${result.id} ${Math.round(result.top)}-${Math.round(result.bottom)} vs ${Math.round(b.top)}-${Math.round(b.bottom)}`);
    }
    expect(problems).toEqual([]);
  });
}

test('safe-area insets: the stuck masthead sits below the top inset and the scroll offsets include both insets', async ({ page, demo }) => {
  await page.setViewportSize({ width: 390, height: 700 });
  await signInAs(page, demo);
  await insets(page, 59, 34);
  await openTab(page, 'more');
  await page.evaluate(() => window.scrollTo(0, 600));
  const r = await page.evaluate(() => {
    const out = document.querySelector('#logout')!.getBoundingClientRect();
    const bar = document.querySelector('#tabbar')!.getBoundingClientRect();
    const html = getComputedStyle(document.documentElement);
    return { signOutTop: out.top, mastheadBottom: document.querySelector('.masthead')!.getBoundingClientRect().bottom, padTop: parseFloat(html.scrollPaddingTop), padBottom: parseFloat(html.scrollPaddingBottom), barHeight: bar.height };
  });
  expect(r.signOutTop).toBeGreaterThanOrEqual(59);
  expect(r.padTop).toBeGreaterThanOrEqual(r.mastheadBottom);
  expect(r.padBottom).toBeGreaterThanOrEqual(r.barHeight);
  await page.goto(`${demo.origin}/#more/accounts`);
  await insets(page, 59, 34);
  await page.evaluate(() => document.querySelector('#accounts-panel')!.scrollIntoView({ block: 'start' }));
  await expectClearOfMasthead(page, '#accounts-panel');
});

test('safe-area insets: request.html starts its content below the top inset', async ({ page, demo }) => {
  await page.setViewportSize({ width: 390, height: 700 });
  await page.goto(`${demo.origin}/request.html`);
  await insets(page, 59, 34);
  const top = await page.evaluate(() => document.querySelector('.child-request .eyebrow')!.getBoundingClientRect().top);
  expect(top).toBeGreaterThanOrEqual(59 + 8);
});

test('forced colours: selects keep a native arrow and the recovery switch shows its checked state', async ({ page, demo }) => {
  await signInAs(page, demo);
  await page.emulateMedia({ forcedColors: 'active' });
  const styles = await page.evaluate(() => {
    const select = document.createElement('select'); document.querySelector('main')!.append(select);
    const sw = document.querySelector('#hide-recovery') as HTMLInputElement;
    const out = { select: getComputedStyle(select).appearance, switch: getComputedStyle(sw).appearance, before: getComputedStyle(sw, '::before').content };
    select.remove();
    return out;
  });
  expect(styles.select).not.toBe('none');
  expect(styles.switch).not.toBe('none');
  expect(['none', 'normal']).toContain(styles.before);
});

const luminance = ([r, g, b]: number[]) => { const c = [r, g, b].map((v) => { const x = v / 255; return x <= 0.03928 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4; }); return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]; };
const ratio = (a: number[], b: number[]) => { const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x); return (hi + 0.05) / (lo + 0.05); };
const rgba = (value: string) => { const m = value.match(/[\d.]+/g)!.map(Number); return { rgb: m.slice(0, 3), a: m[3] ?? 1 }; };
const over = (top: string, base: number[]) => { const t = rgba(top); return t.rgb.map((v, i) => v * t.a + base[i] * (1 - t.a)); };

for (const scheme of ['light', 'dark'] as const) {
  test(`secondary buttons reach 4.5:1 composited on every grouped background (${scheme}, rest and hover)`, async ({ page, demo }) => {
    await page.emulateMedia({ colorScheme: scheme });
    await signInAs(page, demo);
    const tokens = await page.evaluate(() => {
      const probe = document.createElement('button'); probe.className = 'button secondary'; probe.textContent = 'Grant less';
      document.querySelector('main')!.append(probe);
      const css = getComputedStyle(document.documentElement);
      const resolve = (v: string) => { probe.style.backgroundColor = v; return getComputedStyle(probe).backgroundColor; };
      const out = { color: getComputedStyle(probe).color, fill: resolve(css.getPropertyValue('--fill')), hover: resolve(css.getPropertyValue('--fill-hover')),
        bases: ['--paper', '--surface', '--surface-2'].map((name) => resolve(css.getPropertyValue(name))) };
      probe.remove();
      return out;
    });
    const text = rgba(tokens.color).rgb;
    for (const base of tokens.bases) {
      for (const fill of [tokens.fill, tokens.hover]) {
        expect(ratio(text, over(fill, rgba(base).rgb)), `${tokens.color} on ${fill} over ${base}`).toBeGreaterThanOrEqual(4.5);
      }
    }
  });
}

test('disclosure summaries keep a visible marker that follows the open state', async ({ page, demo }) => {
  await signInAs(page, demo);
  await openTab(page, 'more');
  await page.goto(`${demo.origin}/#more/schedules`);
  const summary = page.locator('.schedule-summary summary').first();
  await expect(summary).toBeVisible();
  const displays = await page.evaluate(() => [...document.querySelectorAll('summary')].map((s) => getComputedStyle(s).display));
  expect(displays.length).toBeGreaterThan(0);
  for (const display of displays) expect(display).toBe('list-item');
  expect(await summary.evaluate((s) => getComputedStyle(s).listStyleType)).not.toBe('none');
  const closed = await summary.screenshot();
  await summary.evaluate((s) => { (s.parentElement as HTMLDetailsElement).open = true; });
  const open = await summary.screenshot();
  expect(open.equals(closed), 'the marker is drawn and turns when the disclosure opens').toBe(false);
});
