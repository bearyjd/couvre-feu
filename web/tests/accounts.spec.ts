import { test, expect, enroll, virtualAuthenticator } from './browser-fixture.ts';

test.use({ serviceWorkers: 'block' });
test.setTimeout(60000);

test('admin adds a parent and a device: token shown once, pending device shows its pairing code, approval lets it sign in, removal ends it', async ({ page, browser, demo }) => {
  await enroll(page, demo, 'jd');
  const panel = page.locator('#accounts-panel');
  await expect(panel.getByRole('heading', { name: 'Devices and accounts' })).toBeVisible();
  await expect(panel.getByRole('list', { name: 'Your passkeys' })).toContainText('this device');
  await panel.getByLabel('New parent name').fill('Casey (fictional)');
  await panel.getByRole('button', { name: 'Create account' }).click();
  const card = panel.locator('[data-account]').filter({ hasText: 'Casey (fictional)' });
  await expect(card).toContainText('0 passkeys');
  await card.getByRole('button', { name: 'Create add-device token for Casey (fictional)' }).click();
  const token = await card.getByLabel('Add-device token for Casey (fictional)', { exact: true }).inputValue();
  expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);

  const context = await browser.newContext({ serviceWorkers: 'block' });
  const device = await context.newPage();
  try {
    await device.goto(demo.origin);
    await expect(device.getByRole('button', { name: 'Create a demo passkey' })).toBeEnabled();
    await virtualAuthenticator(device);
    await device.getByLabel('One-use enrollment token').fill(token);
    await device.getByRole('button', { name: 'Create a demo passkey' }).click();
    await expect(device.locator('#pairing-code')).toHaveText(/^[A-Z2-7]{6}$/);
    const pairing = (await device.locator('#pairing-code').textContent())!;
    // The token is spent: a second device using it is told so and warned not to let unknown devices be approved.
    const reuse = await context.newPage();
    await reuse.goto(demo.origin);
    await expect(reuse.getByRole('button', { name: 'Create a demo passkey' })).toBeEnabled();
    await reuse.getByLabel('One-use enrollment token').fill(token);
    await reuse.getByRole('button', { name: 'Create a demo passkey' }).click();
    await expect(reuse.locator('#notice')).toContainText('has already been used');
    await expect(reuse.locator('#notice')).toContainText('not approve any they do not recognise');
    await reuse.close();
    await expect(device.locator('#status-view')).toBeHidden();
    // Pending: the passkey cannot sign in yet.
    await device.getByRole('button', { name: 'Sign in with a passkey' }).click();
    await expect(device.locator('#notice')).toContainText('credential_not_bound');

    await page.bringToFront();
    await panel.getByRole('button', { name: 'Refresh devices' }).click();
    await expect(card).toContainText(/pending · added .+ · pairing code/);
    await card.getByRole('button', { name: `Approve passkey with pairing code ${pairing} for Casey (fictional)` }).click();
    await expect(card.getByRole('button', { name: /Remove passkey Passkey of Casey/ })).toBeVisible();
    await expect(card).not.toContainText('pending');

    await device.bringToFront();
    await device.getByRole('button', { name: 'Sign in with a passkey' }).click();
    await expect(device.locator('#status-view')).toBeVisible();
    await expect(device.locator('#account-context')).toContainText('Casey (fictional) · parent');
    await expect(device.locator('#accounts-panel').getByRole('heading', { name: 'Parent accounts' })).toHaveCount(0);
    for (const view of [page, device]) expect(await view.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);

    await page.bringToFront();
    await card.getByRole('button', { name: /Remove passkey Passkey of Casey/ }).click();
    await expect(card).toContainText('0 passkeys');
    await device.bringToFront();
    await device.reload();
    await expect(device.locator('#auth-view')).toBeVisible();
  } finally { await context.close(); }
});

test('the only admin cannot remove their last passkey, and the refusal is explained', async ({ page, demo }) => {
  await enroll(page, demo, 'jd');
  const panel = page.locator('#accounts-panel');
  await panel.getByRole('button', { name: 'Remove my passkey Passkey (this device)' }).click();
  await expect(panel.getByRole('status')).toContainText('At least one active admin must keep a working passkey.');
  await expect(page.locator('#status-view')).toBeVisible();
});
