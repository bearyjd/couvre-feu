import { test, expect, enroll, browserAPI, openTab } from './browser-fixture.ts';
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
  await openTab(page, 'more');
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
  await expect(editor(page).locator('[data-preview]')).not.toContainText('(next day)');
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
  await openTab(page, 'more');
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
  await openTab(page, 'more');
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
  await openTab(page, 'more');
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

test('an age-band starting point fills the form without a request and saves the same fields as a typed window', async ({ page, demo }) => {
  await enroll(page, demo);
  await openTab(page, 'more');
  const storageBefore = await page.evaluate(() => JSON.stringify({ ...localStorage }));
  const bodies: unknown[] = []; let writes = 0;
  page.on('request', (request) => { if (request.method() === 'POST' && /\/schedules/.test(request.url())) { writes++; bodies.push(request.postDataJSON()); } });
  await expect(editor(page).getByLabel('Age band (optional)')).toHaveCount(0);
  await editor(page).getByRole('button', { name: 'Add a schedule for Alex (fictional)' }).click();
  const chooser = editor(page).getByLabel('Age band (optional)');
  await expect(editor(page)).toContainText('Starting point: edit before saving. Unverified on this router.');
  await chooser.selectOption('10to12:weekend');
  expect(writes).toBe(0);
  await expect(editor(page).getByLabel('Start')).toHaveValue('21:30');
  await expect(editor(page).getByLabel('Stop')).toHaveValue('08:00');
  await expect(editor(page).getByLabel('Name', { exact: true })).toHaveValue('window_1');
  for (const day of ['Fri', 'Sat']) await expect(editor(page).getByLabel(day, { exact: true })).toBeChecked();
  await expect(editor(page).getByLabel('Mon', { exact: true })).not.toBeChecked();
  await expect(editor(page).locator('[data-preview]')).toContainText('Fri 21:30 → Sat 08:00');
  await expect(editor(page).locator('[data-preview]')).not.toContainText('(next day)');
  await expect(chooser).toHaveValue('10to12:weekend');
  expect(await page.evaluate(() => JSON.stringify({ ...localStorage }))).toBe(storageBefore);
  await editor(page).getByRole('button', { name: 'Save schedule' }).click();
  await expect(page.locator('.operation')).toContainText('Schedule addition confirmed');
  expect(writes).toBe(1);
  expect(bodies[0]).toEqual({ id: 'window_1', weekdays: ['Fri', 'Sat'], start: '21:30', stop: '08:00' });
  expect(await page.evaluate(() => JSON.stringify({ ...localStorage, ...sessionStorage }))).not.toMatch(/10to12|weekend|template/i);
});

test('a starting point keeps a typed name, stays selected with a note, and posts days in week order', async ({ page, demo }) => {
  await enroll(page, demo);
  await openTab(page, 'more');
  const bodies: unknown[] = [];
  page.on('request', (request) => { if (request.method() === 'POST' && /\/schedules/.test(request.url())) bodies.push(request.postDataJSON()); });
  await editor(page).getByRole('button', { name: 'Add a schedule for Alex (fictional)' }).click();
  const chooser = editor(page).getByLabel('Age band (optional)'), name = editor(page).getByLabel('Name', { exact: true });
  const note = editor(page).locator('[data-template-note]');
  await expect(note).toHaveAttribute('aria-live', 'polite');
  await expect(note).toHaveText('');
  const liveRegion = await note.elementHandle();
  await name.fill('school_nights');
  await chooser.selectOption('16to17:schoolNight');
  await expect(name).toHaveValue('school_nights');
  await expect(chooser).toHaveValue('16to17:schoolNight');
  await expect(note).toHaveText('Filled from 16 to 17, school nights. Nothing is saved until you press Save.');
  // The announcement needs the same live region to change; a re-created one is often silent.
  expect(await liveRegion!.evaluate((node) => node.isConnected)).toBe(true);
  await chooser.selectOption('');
  await expect(note).toHaveText('');
  await expect(editor(page).getByLabel('Start')).toHaveValue('22:30');
  await name.fill('');
  await chooser.selectOption('under10:schoolNight');
  await expect(name).toHaveValue('window_1');
  await expect(note).toHaveText('Filled from Under 10, school nights. Nothing is saved until you press Save.');
  await name.fill('school_nights');
  expect(bodies).toHaveLength(0);
  await editor(page).getByRole('button', { name: 'Save schedule' }).click();
  await expect(page.locator('.operation')).toContainText('Schedule addition confirmed');
  expect(bodies).toEqual([{ id: 'school_nights', weekdays: ['Mon', 'Tue', 'Wed', 'Thu', 'Sun'], start: '19:30', stop: '07:00' }]);
});

test('edit mode shows no starting-point chooser', async ({ page, demo }) => {
  await enroll(page, demo);
  await openTab(page, 'more');
  await editor(page).locator('[data-schedule-id="browser_fixture"]').getByRole('button', { name: /Edit schedule/ }).click();
  await expect(editor(page).getByLabel('Start', { exact: true })).toBeVisible();
  await expect(editor(page).getByLabel('Age band (optional)')).toHaveCount(0);
  await expect(editor(page).locator('[data-template-note]')).toHaveCount(0);
  await expect(editor(page)).not.toContainText('Starting point');
});

test('the starting-point note shows only while the form still matches the chosen band', async ({ page, demo }) => {
  await enroll(page, demo);
  await openTab(page, 'more');
  await editor(page).getByRole('button', { name: 'Add a schedule for Alex (fictional)' }).click();
  const note = editor(page).locator('[data-template-note]'), start = editor(page).getByLabel('Start'), stop = editor(page).getByLabel('Stop');
  const filled = 'Filled from 10 to 12, weekends. Nothing is saved until you press Save.';
  await editor(page).getByLabel('Age band (optional)').selectOption('10to12:weekend');
  await expect(note).toHaveText(filled);
  // The name is not filled from a band, so changing it leaves the note true.
  await editor(page).getByLabel('Name', { exact: true }).fill('late_nights');
  await expect(note).toHaveText(filled);
  await start.fill('21:45');
  await expect(note).toHaveText('');
  await start.fill('21:30');
  await expect(note).toHaveText(filled);
  await stop.fill('08:15');
  await expect(note).toHaveText('');
  await stop.fill('08:00');
  await expect(note).toHaveText(filled);
  await editor(page).getByLabel('Fri', { exact: true }).uncheck();
  await expect(note).toHaveText('');
  await editor(page).getByLabel('Fri', { exact: true }).check();
  await expect(note).toHaveText(filled);
  await editor(page).getByLabel('Mon', { exact: true }).check();
  await expect(note).toHaveText('');
});

/** Refuses the first `count` schedule creations with a start-field error, then lets the rest through; returns every posted body. */
async function refuseSaves(page: Page, count: number) {
  const bodies: unknown[] = [];
  await page.route('**/people/alex/schedules', async (route) => {
    if (route.request().method() !== 'POST') { await route.continue(); return; }
    bodies.push(route.request().postDataJSON());
    if (bodies.length > count) { await route.continue(); return; }
    await route.fulfill({ status: 400, json: { error: { code: 'invalid_clock', message: 'Fictional clock refusal.' } } });
  });
  return bodies;
}

/** The app re-renders the control state every second; outlasting two ticks proves a node is not rebuilt, and no event exists for that. */
const pastControlTick = (page: Page) => page.waitForTimeout(2500);

test('choosing a starting point after a refused save clears the error, refills the form and saves the new values', async ({ page, demo }) => {
  await enroll(page, demo);
  await openTab(page, 'more');
  const bodies = await refuseSaves(page, 1);
  await editor(page).getByRole('button', { name: 'Add a schedule for Alex (fictional)' }).click();
  const chooser = editor(page).getByLabel('Age band (optional)'), note = editor(page).locator('[data-template-note]');
  const start = editor(page).getByLabel('Start'), startError = editor(page).locator('[data-error="start"]');
  const save = editor(page).getByRole('button', { name: 'Save schedule' });
  await editor(page).getByLabel('Name', { exact: true }).fill('retry');
  await chooser.selectOption('10to12:weekend');
  await save.click();
  await expect(startError).toHaveText('Fictional clock refusal.');
  await expect(start).toHaveAttribute('aria-invalid', '');
  await expect(chooser).toBeEnabled();
  await expect(chooser).toHaveValue('10to12:weekend');
  const liveRegion = await note.elementHandle();

  await chooser.selectOption('under10:schoolNight');
  await expect(startError).toHaveText('');
  await expect(start).not.toHaveAttribute('aria-invalid');
  await expect(start).toHaveValue('19:30');
  await expect(editor(page).getByLabel('Stop')).toHaveValue('07:00');
  for (const day of ['Mon', 'Tue', 'Wed', 'Thu', 'Sun']) await expect(editor(page).getByLabel(day, { exact: true })).toBeChecked();
  for (const day of ['Fri', 'Sat']) await expect(editor(page).getByLabel(day, { exact: true })).not.toBeChecked();
  await expect(editor(page).getByLabel('Name', { exact: true })).toHaveValue('retry');
  await expect(note).toHaveText('Filled from Under 10, school nights. Nothing is saved until you press Save.');
  await pastControlTick(page);
  expect(await liveRegion!.evaluate((node) => node.isConnected)).toBe(true);
  await expect(startError).toHaveText('');
  expect(bodies).toHaveLength(1);

  // A refusal asks for a status refresh first; the refreshed form must keep the new choice and not bring the old error back.
  await page.getByRole('button', { name: 'Refresh status' }).click();
  await expect(save).toBeEnabled();
  await expect(chooser).toHaveValue('under10:schoolNight');
  await expect(start).toHaveValue('19:30');
  await expect(startError).toHaveText('');
  await save.click();
  await expect(page.locator('.operation')).toContainText('Schedule addition confirmed');
  expect(bodies).toHaveLength(2);
  expect(bodies[1]).toEqual({ id: 'retry', weekdays: ['Mon', 'Tue', 'Wed', 'Thu', 'Sun'], start: '19:30', stop: '07:00' });
});

test('a hand edit after a refused save keeps the form in place, and later errors still show and clear', async ({ page, demo }) => {
  await enroll(page, demo);
  await openTab(page, 'more');
  const bodies = await refuseSaves(page, 2);
  await editor(page).getByRole('button', { name: 'Add a schedule for Alex (fictional)' }).click();
  const name = editor(page).getByLabel('Name', { exact: true }), startError = editor(page).locator('[data-error="start"]');
  const formError = editor(page).locator('[data-error="form"]'), save = editor(page).getByRole('button', { name: 'Save schedule' });
  await editor(page).getByLabel('Age band (optional)').selectOption('10to12:weekend');
  await save.click();
  await expect(startError).toHaveText('Fictional clock refusal.');
  await expect(save).toBeDisabled();
  await pastControlTick(page);
  await expect(startError).toHaveText('Fictional clock refusal.');
  const nodes = await Promise.all(['[data-template-note]', '[data-preview]', '[data-field="id"]'].map((selector) => editor(page).locator(selector).elementHandle()));

  await name.fill('by_hand');
  await expect(startError).toHaveText('');
  await pastControlTick(page);
  for (const node of nodes) expect(await node!.evaluate((element) => element.isConnected)).toBe(true);
  await expect(name).toBeFocused();
  await expect(startError).toHaveText('');

  // Save is disabled until a refresh; a submit that still arrives must explain itself, and the next edit must clear that.
  await editor(page).locator('[data-schedule-form]').evaluate((form: HTMLFormElement) => form.requestSubmit());
  await expect(formError).toContainText('Controls are unavailable until status is refreshed.');
  await name.fill('by_hand_again');
  await expect(formError).toHaveText('');
  await pastControlTick(page);
  await expect(formError).toHaveText('');
  expect(bodies).toHaveLength(1);

  // The same refusal a second time is shown again.
  await page.getByRole('button', { name: 'Refresh status' }).click();
  await expect(save).toBeEnabled();
  await save.click();
  await expect(startError).toHaveText('Fictional clock refusal.');
  await expect(name).toHaveValue('by_hand_again');
  expect(bodies).toHaveLength(2);
});
