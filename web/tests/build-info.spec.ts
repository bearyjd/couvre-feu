import { test, expect, enroll } from './browser-fixture.ts';

test('signed-in parents see a plain version line; signed-out visitors do not', async ({ page, demo }) => {
  await page.goto(demo.origin);
  await expect(page.locator('#build-info')).toHaveText('');
  await enroll(page, demo);
  const schema = (demo.store.get('PRAGMA user_version') as { user_version: number }).user_version;
  await expect(page.locator('footer')).toContainText(new RegExp(`Couvre-feu \\S+ · schema ${schema}`));
  await expect(page.locator('#build-info')).toHaveText(new RegExp(`^\\S+ · schema ${schema}$`));
  // After a reload the line is restored from /auth/session, not only from the sign-in response.
  await page.goto(demo.origin);
  await expect(page.locator('#build-info')).toContainText(`schema ${schema}`);
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.locator('#build-info')).toHaveText('');
});
