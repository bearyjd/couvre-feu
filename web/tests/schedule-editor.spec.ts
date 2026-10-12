import { test, expect, enroll, browserAPI } from './browser-fixture.ts';
import type { Page } from '@playwright/test';

const editor = (page: Page) => page.locator('#schedule-editor');

async function fillWindow(page: Page, name: string, days: string[], start: string, stop: string) {
  await editor(page).getByLabel('Name', { exact: true }).fill(name);
  for (const day of days) await editor(page).getByLabel(day, { exact: true }).check();
  await editor(page).getByLabel('Start').fill(start);
  await editor(page).getByLabel('Stop').fill(stop);
}

test('create, edit and delete a cross-midnight window with plain-language preview', async ({ page, demo }) => {
  const errors: string[] = []; page.on('pageerror', (error) => errors.push(error.message));
  await enroll(page, demo);
  await expect(editor(page).getByRole('heading', { name: 'Schedules for Alex (fictional)' })).toBeVisible();
  await expect(editor(page).locator('[data-schedule-id="browser_fixture"]')).toBeVisible();
  await expect(editor(page).getByText('Blair')).toHaveCount(0);

  await editor(page).getByRole('button', { name: 'Add a schedule for Alex (fictional)' }).click();
  await fillWindow(page, 'bedtime', ['Mon', 'Tue'], '22:00', '06:30');
  await expect(editor(page).locator('[data-preview]')).toContainText('Mon 22:00 → Tue 06:30');
  await expect(editor(page).locator('[data-preview]')).toContainText('Tue 22:00 → Wed 06:30');
  await editor(page).getByRole('button', { name: 'Save schedule' }).click();
  await expect(page.locator('.operation')).toContainText('Schedule addition pending');
  await expect(page.locator('.operation')).toContainText('Schedule addition confirmed');
  const row = editor(page).locator('[data-schedule-id="bedtime"]');
  await expect(row).toContainText('Mon, Tue · 22:00 → 06:30 (next day)');
  expect(demo.router.observe().policy.schedules.map((s) => s.id)).toContain('bedtime');

  await row.getByRole('button', { name: 'Edit schedule bedtime for Alex (fictional)' }).click();
  await expect(editor(page).getByLabel('Name', { exact: true })).toHaveAttribute('readonly', '');
  await editor(page).getByLabel('Wed', { exact: true }).check();
  await editor(page).getByLabel('Stop').fill('07:00');
  await expect(editor(page).locator('[data-preview]')).toContainText('Wed 22:00 → Thu 07:00');
  await editor(page).getByRole('button', { name: 'Save schedule' }).click();
  await expect(page.locator('.operation')).toContainText('Schedule change confirmed');
  await expect(row).toContainText('Mon, Tue, Wed · 22:00 → 07:00 (next day)');

  await row.getByRole('button', { name: 'Delete schedule bedtime for Alex (fictional)' }).click();
  await editor(page).getByRole('button', { name: 'Keep it' }).click();
  await expect(row).toBeVisible();
  await row.getByRole('button', { name: 'Delete schedule bedtime for Alex (fictional)' }).click();
  await editor(page).getByRole('button', { name: 'Confirm delete bedtime' }).click();
  await expect(page.locator('.operation')).toContainText('Schedule removal confirmed');
  await expect(row).toHaveCount(0);
  expect(demo.router.observe().policy.schedules.map((s) => s.id)).toEqual(['browser_fixture']);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  expect(errors).toEqual([]);
});

test('client validation explains errors and sends nothing; overlaps are allowed with an explanation', async ({ page, demo }) => {
  await enroll(page, demo);
  let writes = 0; page.on('request', (request) => { if (request.method() === 'POST' && /\/schedules/.test(request.url())) writes++; });
  await editor(page).getByRole('button', { name: 'Add a schedule for Alex (fictional)' }).click();
  await editor(page).getByLabel('Name', { exact: true }).fill('Bad Name');
  await editor(page).getByLabel('Start').fill('08:00');
  await editor(page).getByLabel('Stop').fill('08:00');
  await editor(page).getByRole('button', { name: 'Save schedule' }).click();
  await expect(editor(page).locator('[data-error="id"]')).toContainText('lowercase letter first');
  await expect(editor(page).locator('[data-error="weekdays"]')).toContainText('Choose at least one day');
  await expect(editor(page).locator('[data-error="form"]')).toContainText('Start and stop must differ');
  await editor(page).getByLabel('Name', { exact: true }).fill('browser_fixture');
  await expect(editor(page).locator('[data-error="id"]')).toContainText('already exists');
  expect(writes).toBe(0);

  await editor(page).getByLabel('Name', { exact: true }).fill('overlap');
  await editor(page).getByLabel('Mon', { exact: true }).check();
  await editor(page).getByLabel('Stop').fill('09:00');
  await expect(editor(page).locator('[data-error]:not(:empty)')).toHaveCount(0);
  const hour = await page.evaluate(() => new Date().getUTCHours());
  const start = `${String(hour).padStart(2, '0')}:00`, stop = `${String((hour + 1) % 24).padStart(2, '0')}:00`;
  for (const day of ['Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']) await editor(page).getByLabel(day, { exact: true }).check();
  await editor(page).getByLabel('Start').fill(start);
  await editor(page).getByLabel('Stop').fill(stop);
  await expect(editor(page).locator('[data-preview]')).toContainText('Overlaps browser_fixture. Overlaps are allowed');
  await editor(page).getByRole('button', { name: 'Cancel' }).click();
  await expect(editor(page).getByRole('button', { name: 'Add a schedule for Alex (fictional)' })).toBeEnabled();
});

test('server-side validation and permissions stay authoritative', async ({ page, demo }) => {
  await enroll(page, demo);
  const state = await browserAPI(page, '/people');
  const headers = (key: string) => ({ 'If-Match': state.body.revisionToken, 'Idempotency-Key': key });
  const blair = await browserAPI(page, '/people/blair/schedules', { id: 'sneaky', weekdays: ['Mon'], start: '22:00', stop: '06:30' }, headers('blair-attempt-000000001'));
  expect(blair.status).toBe(404);
  const invalid = await browserAPI(page, '/people/alex/schedules', { id: 'x', weekdays: ['Mon'], start: '25:00', stop: '06:30' }, headers('invalid-clock-00000001'));
  expect(invalid.status).toBe(400);
  expect(invalid.body.error.code).toBe('invalid_clock');
  expect(demo.router.observe().policy.schedules).toHaveLength(1);
});

test('a revision advanced elsewhere cancels the edit, reloads, and keeps the draft for a deliberate retry', async ({ page, demo }) => {
  await enroll(page, demo);
  let writes = 0; page.on('request', (request) => { if (request.method() === 'POST' && /\/schedules/.test(request.url())) writes++; });
  await editor(page).getByRole('button', { name: 'Add a schedule for Alex (fictional)' }).click();
  await fillWindow(page, 'weekend', ['Sat', 'Sun'], '23:00', '08:00');
  demo.router.localAdvance();
  await editor(page).getByRole('button', { name: 'Save schedule' }).click();
  await expect(page.locator('#notice')).toContainText('changed elsewhere');
  await expect(editor(page).locator('[data-error="form"]')).toContainText('Schedules changed elsewhere');
  expect(writes).toBe(0);
  await expect(editor(page).getByLabel('Name', { exact: true })).toHaveValue('weekend');
  await editor(page).getByRole('button', { name: 'Save schedule' }).click();
  await expect(page.locator('.operation')).toContainText('Schedule addition confirmed');
  expect(writes).toBe(1);
});
