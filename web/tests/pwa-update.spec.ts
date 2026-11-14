import { test, expect, enroll } from './browser-fixture.ts';
import type { Page } from '@playwright/test';

// Rewrites GET /auth/session answers after the page has signed in; sign-in itself is untouched.
async function rewriteSession(page: Page, change: (body: Record<string, unknown>) => Record<string, unknown>) {
  await page.route('**/auth/session', async (route) => {
    const response = await route.fetch();
    await route.fulfill({ response, json: change(await response.json()) });
  });
}

test('a newer service version shows an update banner and Reload brings the new build', async ({ page, demo }) => {
  await enroll(page, demo);
  await expect(page.locator('#update-banner')).toBeHidden();
  await page.locator('#refresh').click();
  await expect(page.locator('#update-banner')).toBeHidden(); // Same version as the loaded build.
  await rewriteSession(page, (body) => ({ ...body, version: 'next-build' }));
  await page.locator('#refresh').click();
  await expect(page.locator('#update-banner')).toBeVisible();
  await expect(page.locator('#update-banner')).toContainText('Update available');
  const reload = page.locator('#update-banner').getByRole('button', { name: 'Reload' });
  await Promise.all([page.waitForEvent('load'), reload.click()]);
  await expect(page.locator('#update-banner')).toBeHidden(); // The reloaded page treats the answered version as its own.
});

test('Reload with a waiting worker posts skipWaiting and reloads on controllerchange, not on the fallback timer', async ({ page, demo }) => {
  await page.addInitScript(() => {
    if (sessionStorage.getItem('stubbed-done')) return;
    // A waiting registration stub: postMessage is recorded, and the worker "takes over" 1 s later.
    const worker = { postMessage: (message: unknown) => {
      sessionStorage.setItem('posted', String(message));
      setTimeout(() => navigator.serviceWorker.dispatchEvent(new Event('controllerchange')), 1000);
    } };
    navigator.serviceWorker.getRegistration = (async () => ({ waiting: worker })) as unknown as typeof navigator.serviceWorker.getRegistration;
  });
  await enroll(page, demo);
  await page.locator('#refresh').click();
  await rewriteSession(page, (body) => ({ ...body, version: 'next-build' }));
  await page.locator('#refresh').click();
  await expect(page.locator('#update-banner')).toBeVisible();
  await page.evaluate(() => sessionStorage.setItem('stubbed-done', '1')); // The reloaded page uses the real registration.
  const started = Date.now();
  await Promise.all([page.waitForEvent('load'), page.locator('#update-banner').getByRole('button', { name: 'Reload' }).click()]);
  const elapsed = Date.now() - started;
  expect(await page.evaluate(() => sessionStorage.getItem('posted'))).toBe('skipWaiting');
  expect(elapsed).toBeGreaterThanOrEqual(900); // Waited for controllerchange rather than reloading at once.
  expect(elapsed).toBeLessThan(2800); // And did not need the 3 s fallback.
});

test('the service worker accepts a skipWaiting message and the shell cache is renamed', async ({ page, demo }) => {
  const sw = await (await page.request.get(demo.origin + '/sw.js')).text();
  expect(sw).toContain("'skipWaiting'");
  expect(sw).toContain("'cf-shell-v10'");
  expect(sw).not.toContain('cf-shell-v9');
  expect(sw).toContain('/pwa-update.js');
});

test('sign-in and requests work when AbortSignal.any does not exist (older iOS Safari)', async ({ page, demo }) => {
  const errors: string[] = []; page.on('pageerror', (error) => errors.push(error.message));
  await page.addInitScript(() => { delete (AbortSignal as unknown as { any?: unknown }).any; });
  await page.goto(demo.origin);
  expect(await page.evaluate(() => typeof (AbortSignal as unknown as { any?: unknown }).any)).toBe('undefined');
  await enroll(page, demo);
  await expect(page.locator('[data-person="alex"]')).toBeVisible();
  await expect(page.locator('#service-down')).toBeHidden();
  expect(errors).toEqual([]);
});

test('apple home-screen tags and a PNG touch icon are present', async ({ page, demo }) => {
  await page.goto(demo.origin);
  await expect(page.locator('link[rel="apple-touch-icon"]')).toHaveAttribute('href', '/apple-touch-icon.png');
  await expect(page.locator('meta[name="apple-mobile-web-app-capable"]')).toHaveAttribute('content', 'yes');
  await expect(page.locator('meta[name="apple-mobile-web-app-title"]')).toHaveAttribute('content', 'Couvre-feu');
  const icon = await page.request.get(demo.origin + '/apple-touch-icon.png');
  expect(icon.headers()['content-type']).toBe('image/png');
  expect((await icon.body()).subarray(1, 4).toString()).toBe('PNG');
});

test('a signing-out-soon notice appears 60 seconds before expiry and stays dismissed', async ({ page, demo }) => {
  await enroll(page, demo);
  await expect(page.locator('#session-grace')).toBeHidden();
  await rewriteSession(page, (body) => ({ ...body, expiresAt: Math.floor(Date.now() / 1000) + 40 }));
  await page.locator('#refresh').click();
  await expect(page.locator('#session-grace')).toBeVisible();
  await expect(page.locator('#session-grace')).toContainText('Signing out soon');
  await expect(page.locator('#session-grace')).toContainText(/\d+s/);
  await page.locator('#session-grace').getByRole('button', { name: 'Dismiss' }).click();
  await expect(page.locator('#session-grace')).toBeHidden();
  await page.waitForTimeout(2200);
  await expect(page.locator('#session-grace')).toBeHidden(); // The 1 s tick must not bring it back.
});

test('the notice gives way to the existing expiry message when the session ends', async ({ page, demo }) => {
  await enroll(page, demo);
  await rewriteSession(page, (body) => ({ ...body, expiresAt: Math.floor(Date.now() / 1000) + 3 }));
  await page.locator('#refresh').click();
  await expect(page.locator('#session-grace')).toBeVisible();
  await expect(page.locator('#notice')).toContainText('Your session expired', { timeout: 8000 });
  await expect(page.locator('#session-grace')).toBeHidden();
});
