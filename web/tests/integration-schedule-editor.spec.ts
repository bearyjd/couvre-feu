import type { Page, Request } from '@playwright/test';
import { DAYS, normalizePolicy, type Schedule } from '../../shared/src/router-schema.ts';
import type { PeopleDTO } from '../../shared/src/contracts.ts';
import { enroll, openTab, test as demoTest } from './browser-fixture.ts';
import { dispatchPending, expect, signIn, test, type World } from './bulk-fixture.ts';

const editor = (page: Page) => page.locator('#schedule-editor');
const schedulesPath = '/people/pilot/schedules';
const schedulePath = schedulesPath + '/bedtime';
const schedule: Schedule = { person: 'pilot', id: 'bedtime', weekdays: [DAYS[0]], start: '20:00', stop: '23:00' };

async function openEditor(page: Page, f: World, count = 1, clock?: World['config']['scheduleClock'], first = schedule) {
  f.config.schedules = { editable: true };
  f.config.scheduleClock = clock ?? { timezone: 'America/New_York' };
  const schedules = [first, ...Array.from({ length: count - 1 }, (_, index) => ({ ...schedule, id: `window_${index + 1}` }))];
  for (const window of schedules) {
    f.store.run('INSERT INTO schedule_windows(person_id,id,weekdays,start,stop) VALUES(?,?,?,?,?)', window.person, window.id, window.weekdays.join(','), window.start, window.stop);
  }
  f.router.policy = normalizePolicy({ ...f.router.policy, revision: f.router.policy.revision + 1, schedules });
  f.advance(1);
  await f.observe();
  await signIn(page, f, 'parent');
  await openTab(page, 'more');
  await expect(editor(page).locator('[data-schedule-id=bedtime]')).toBeVisible();
}

function requests(page: Page) {
  const attempts: Request[] = [], options: Request[] = [];
  page.on('request', (request) => {
    if (request.method() !== 'POST') return;
    const path = new URL(request.url()).pathname;
    if (path === schedulesPath || path === schedulePath || path === schedulePath + '/delete') attempts.push(request);
    if (path === '/step-up/options') options.push(request);
  });
  return { attempts, options };
}

async function editStart(page: Page, start: string) {
  await editor(page).getByRole('button', { name: /Edit schedule bedtime/ }).click();
  await editor(page).getByLabel('Start').fill(start);
  await editor(page).getByRole('button', { name: 'Save schedule' }).click();
}

test('integration widening stays single-request and shortening binds one proof to the same revision and intent', async ({ page, integration: f }) => {
  await openEditor(page, f);
  const calls = requests(page);
  await editStart(page, '19:00');
  await expect.poll(() => f.store.integrationState().active_operation_id).not.toBeNull();
  await dispatchPending(f);
  await expect(editor(page).locator('[data-schedule-id=bedtime]')).toContainText('19:00');
  expect(calls.attempts).toHaveLength(1);
  expect(calls.options).toHaveLength(0);

  await editStart(page, '21:00');
  await expect.poll(() => f.store.integrationState().active_operation_id).not.toBeNull();
  expect(calls.options).toHaveLength(1);
  expect(calls.attempts).toHaveLength(3);
  const [, first, proof] = calls.attempts;
  const intent = { weekdays: ['Mon'], start: '21:00', stop: '23:00' };
  expect(first.postDataJSON()).toEqual(intent);
  expect(calls.options[0].postDataJSON()).toEqual({
    action: 'schedule_change', person: 'pilot', scheduleAction: 'schedule_update', scheduleId: 'bedtime',
    precondition: first.headers()['if-match'], change: intent,
  });
  const { stepUp, ...sent } = proof.postDataJSON();
  expect(sent).toEqual(intent);
  expect(Boolean(stepUp?.challengeId && stepUp?.response)).toBe(true);
  expect(proof.headers()['idempotency-key']).toBe(first.headers()['idempotency-key']);
  expect(proof.headers()['if-match']).toBe(first.headers()['if-match']);
  await dispatchPending(f);
  await expect(editor(page).locator('[data-schedule-id=bedtime]')).toContainText('21:00');
});

test('cancelling a passkey keeps the integration draft and sends no proof', async ({ page, integration: f }) => {
  await openEditor(page, f);
  const calls = requests(page);
  await page.evaluate(() => Object.defineProperty(navigator.credentials, 'get', {
    value: async () => { throw new DOMException('Cancelled in this fixture', 'NotAllowedError'); },
  }));
  await editStart(page, '21:00');
  await expect(page.locator('#notice')).toContainText('Passkey confirmation was cancelled');
  await expect(editor(page).getByLabel('Start')).toHaveValue('21:00');
  await expect(editor(page).getByRole('button', { name: 'Save schedule' })).toBeEnabled();
  expect(calls.options).toHaveLength(1);
  expect(calls.attempts).toHaveLength(1);
  expect(f.store.integrationState().active_operation_id).toBeNull();
});

test('integration deletion binds its empty change and sends proof once', async ({ page, integration: f }) => {
  await openEditor(page, f);
  const calls = requests(page);
  await editor(page).getByRole('button', { name: /Delete schedule bedtime/ }).click();
  await editor(page).getByRole('button', { name: 'Confirm delete bedtime' }).click();
  await expect.poll(() => f.store.integrationState().active_operation_id).not.toBeNull();
  expect(calls.options).toHaveLength(1);
  expect(calls.attempts).toHaveLength(2);
  const [first, proof] = calls.attempts;
  expect(first.postDataJSON()).toEqual({});
  expect(calls.options[0].postDataJSON()).toEqual({
    action: 'schedule_change', person: 'pilot', scheduleAction: 'schedule_delete', scheduleId: 'bedtime',
    precondition: first.headers()['if-match'], change: {},
  });
  expect(Object.keys(proof.postDataJSON())).toEqual(['stepUp']);
  expect(proof.headers()['idempotency-key']).toBe(first.headers()['idempotency-key']);
  await dispatchPending(f);
  await expect(editor(page).locator('[data-schedule-id=bedtime]')).toHaveCount(0);
});

for (const [status, code] of [[401, 'invalid_challenge'], [403, 'step_up_mismatch']] as const) {
  test(`a rejected proof (${code}) leaves the parent signed in and keeps the draft`, async ({ page, integration: f }) => {
    await openEditor(page, f);
    const calls = requests(page);
    await page.route('**' + schedulePath, async (route) => {
      if (route.request().postDataJSON().stepUp) {
        await route.fulfill({ status, json: { error: { code } } });
      } else {
        await route.continue();
      }
    });
    await editStart(page, '21:00');
    await expect(page.locator('#notice')).toContainText('The service refused the passkey confirmation');
    await expect(editor(page).getByLabel('Start')).toHaveValue('21:00');
    await expect(editor(page).getByRole('button', { name: 'Save schedule' })).toBeEnabled();
    expect(calls.attempts).toHaveLength(2);
    expect(calls.options).toHaveLength(1);
    expect(f.store.integrationState().active_operation_id).toBeNull();
  });
}

const passkeyGate = async (page: Page) => {
  await page.evaluate(() => {
    const original = navigator.credentials.get.bind(navigator.credentials);
    Object.defineProperty(navigator.credentials, 'get', {
      value: async (options: CredentialRequestOptions) => {
        await new Promise<void>((resolve) => {
          document.addEventListener('release-passkey-fixture', () => resolve(), { once: true });
          document.documentElement.dataset.fixturePasskeyWaiting = 'true';
        });
        return original(options);
      },
    });
  });
};

for (const change of ['revision', 'session'] as const) {
  test(`a ${change} change during the prompt keeps the draft and discards the proof`, async ({ page, integration: f }) => {
    await openEditor(page, f);
    const calls = requests(page);
    await passkeyGate(page);
    await editStart(page, '21:00');
    await expect(page.locator('#notice')).toContainText('Confirm with your passkey');
    await expect(page.locator('html')).toHaveAttribute('data-fixture-passkey-waiting', 'true');
    await expect(editor(page).getByRole('button', { name: 'Save schedule' })).toBeDisabled();
    await editor(page).locator('form').dispatchEvent('submit');
    if (change === 'revision') {
      f.router.policy = normalizePolicy({ ...f.router.policy, revision: f.router.policy.revision + 1 });
      f.advance(1); await f.observe();
    } else {
      await page.route('**/auth/session', async (route) => {
        const response = await route.fetch();
        await route.fulfill({ response, json: { ...await response.json(), csrfToken: 'new-fixture-session' } });
      });
    }
    await page.evaluate(() => document.dispatchEvent(new Event('release-passkey-fixture')));
    await expect(page.locator('#notice')).toContainText('Schedules changed elsewhere');
    await expect(editor(page).getByLabel('Start')).toHaveValue('21:00');
    expect(calls.options).toHaveLength(1);
    expect(calls.attempts).toHaveLength(1);
    expect(f.store.integrationState().active_operation_id).toBeNull();
  });
}

for (const outcome of ['accepted', 'lost'] as const) {
  test(`a session key rotation while the proof POST is ${outcome} requires a fresh observation`, async ({ page, integration: f }) => {
    // App refresh is blocked during a write. Expose state in this fixture to exercise same-generation key rotation directly.
    await page.route('**/schedule-editor.js', async (route) => {
      const response = await route.fetch();
      const body = (await response.text()).replace('const { root, state } = deps;', 'const { root, state } = deps; window.fixtureScheduleState = state;');
      await route.fulfill({ response, body });
    });
    await openEditor(page, f);
    const calls = requests(page);
    let release!: () => void;
    const held = new Promise<void>((resolve) => { release = resolve; });
    await page.route('**' + schedulePath, async (route) => {
      if (!route.request().postDataJSON().stepUp) return route.continue();
      await held;
      if (outcome === 'lost') return route.abort('connectionreset');
      return route.continue();
    });
    await editStart(page, '21:00');
    try {
      await expect.poll(() => calls.attempts.length).toBe(2);
      await page.evaluate(() => {
        const { fixtureScheduleState: state } = window as unknown as { fixtureScheduleState: { session: { csrfToken: string } } };
        state.session = { ...state.session, csrfToken: 'rotated-fixture-session' };
      });
    } finally {
      release();
    }
    await expect(page.locator('#notice')).toContainText('Outcome unknown');
    await expect(editor(page).getByRole('button', { name: 'Save schedule' })).toBeDisabled();
    const status = await page.evaluate(() => {
      const { fixtureScheduleState: state } = window as unknown as { fixtureScheduleState: { operation: unknown; localUnknown: boolean; needsRefresh: boolean } };
      return [state.operation, state.localUnknown, state.needsRefresh];
    });
    expect(status).toEqual([null, true, true]);
    if (outcome === 'accepted') expect(f.store.integrationState().active_operation_id).not.toBeNull();
    expect(calls.attempts).toHaveLength(2);
  });
}

test('a challenge without a finite positive timeout never opens a passkey prompt', async ({ page, integration: f }) => {
  await openEditor(page, f);
  const calls = requests(page);
  await passkeyGate(page);
  await page.route('**/step-up/options', async (route) => {
    const response = await route.fetch();
    const body = await response.json();
    delete body.options.timeout;
    await route.fulfill({ response, json: body });
  });
  await editStart(page, '21:00');
  await expect(page.locator('#notice')).toContainText('The service did not provide a valid passkey timeout');
  await expect(page.locator('html')).not.toHaveAttribute('data-fixture-passkey-waiting', 'true');
  await expect(editor(page).getByLabel('Start')).toHaveValue('21:00');
  expect(calls.attempts).toHaveLength(1);
  expect(calls.options).toHaveLength(1);
});

test('post-passkey refresh explains when current controls are unavailable and sends no proof', async ({ page, integration: f }) => {
  await openEditor(page, f);
  const calls = requests(page);
  await page.route('**/people', async (route) => {
    const response = await route.fetch();
    if (!calls.options.length) return route.fulfill({ response });
    await route.fulfill({ response, json: { ...await response.json(), routerDesiredRevision: null } });
  });
  await editStart(page, '21:00');
  await expect(page.locator('#notice')).toContainText('Schedule controls are unavailable');
  await expect(editor(page).getByLabel('Start')).toHaveValue('21:00');
  await expect(editor(page).getByRole('button', { name: 'Save schedule' })).toBeDisabled();
  expect(calls.attempts).toHaveLength(1);
  expect(calls.options).toHaveLength(1);
});

demoTest('a demo schedule 409 keeps its original revision-conflict feedback and draft', async ({ page, demo }) => {
  await enroll(page, demo);
  await openTab(page, 'more');
  await expect(editor(page).getByRole('button', { name: 'Skip tonight', exact: true })).toHaveCount(0);
  let attempts = 0;
  await page.route('**/people/alex/schedules', async (route) => {
    attempts += 1;
    expect(route.request().postDataJSON()).not.toHaveProperty('kind');
    await route.fulfill({ status: 409, json: { error: { code: 'operation_in_progress' } } });
  });
  await editor(page).getByRole('button', { name: 'Add a schedule for Alex (fictional)' }).click();
  await expect(editor(page).getByLabel('Schedule type')).toHaveCount(0);
  await editor(page).getByLabel('Tue', { exact: true }).check();
  await editor(page).getByLabel('Start').fill('19:00');
  await editor(page).getByLabel('Stop').fill('21:00');
  await editor(page).getByRole('button', { name: 'Save schedule' }).click();
  await expect(page.locator('#notice')).toContainText('Revision conflict');
  await expect(editor(page).getByLabel('Start')).toHaveValue('19:00');
  await expect(editor(page).getByRole('button', { name: 'Save schedule' })).toBeEnabled();
  expect(attempts).toBe(1);
});

demoTest('a demo schedule refusal keeps the service error message', async ({ page, demo }) => {
  await enroll(page, demo);
  await openTab(page, 'more');
  await page.route('**/people/alex/schedules', route => route.fulfill({
    status: 400, json: { error: { code: 'schedule_payload_inadmissible', message: 'The demo rejected this schedule payload.' } },
  }));
  await editor(page).getByRole('button', { name: 'Add a schedule for Alex (fictional)' }).click();
  await editor(page).getByLabel('Tue', { exact: true }).check();
  await editor(page).getByLabel('Start').fill('19:00');
  await editor(page).getByLabel('Stop').fill('21:00');
  await editor(page).getByRole('button', { name: 'Save schedule' }).click();
  await expect(page.locator('#notice')).toContainText('The demo rejected this schedule payload.');
  await expect(editor(page).locator('[data-error="form"]')).toHaveText('The demo rejected this schedule payload.');
});

test('a lost proof submission stays unknown until refresh and is never resent', async ({ page, integration: f }) => {
  await openEditor(page, f);
  const calls = requests(page);
  await page.route('**' + schedulePath, async (route) => {
    if (route.request().postDataJSON().stepUp) await route.abort('connectionreset');
    else await route.continue();
  });
  await editStart(page, '21:00');
  await expect(page.locator('#notice')).toContainText('Outcome unknown');
  await expect(editor(page).getByRole('button', { name: 'Save schedule' })).toBeDisabled();
  await editor(page).locator('form').dispatchEvent('submit');
  expect(calls.attempts).toHaveLength(2);
  expect(calls.options).toHaveLength(1);
});

for (const action of ['edit', 'delete'] as const) {
  test(`an opened ${action} cannot act on a window already changed elsewhere`, async ({ page, integration: f }) => {
    await openEditor(page, f);
    const calls = requests(page);
    await editor(page).getByRole('button', { name: new RegExp(`${action} schedule bedtime`, 'i') }).click();
    if (action === 'edit') await editor(page).getByLabel('Start').fill('21:00');
    const changed = { ...schedule, start: '19:00' };
    f.store.run('UPDATE schedule_windows SET start=? WHERE person_id=? AND id=?', changed.start, changed.person, changed.id);
    f.router.policy = normalizePolicy({ ...f.router.policy, revision: f.router.policy.revision + 1, schedules: [changed] });
    f.advance(1);
    await f.observe();
    await page.getByRole('button', { name: 'Refresh status' }).click();
    await expect(editor(page).locator('[data-schedule-id=bedtime]')).toContainText('19:00');
    await editor(page).getByRole('button', { name: action === 'edit' ? 'Save schedule' : 'Confirm delete bedtime' }).click();
    await expect(page.locator('#notice')).toContainText('The window changed since you opened it');
    if (action === 'edit') await expect(editor(page).getByLabel('Start')).toHaveValue('21:00');
    expect(calls.attempts).toHaveLength(0);
    expect(calls.options).toHaveLength(0);
  });
}

test('Cancel closes an edit during the passkey prompt without sending proof', async ({ page, integration: f }) => {
  await openEditor(page, f);
  const calls = requests(page);
  await passkeyGate(page);
  await editStart(page, '21:00');
  await expect(page.locator('html')).toHaveAttribute('data-fixture-passkey-waiting', 'true');
  await editor(page).getByRole('button', { name: 'Cancel', exact: true }).click();
  await expect(editor(page).locator('form')).toBeHidden();
  await page.evaluate(() => document.dispatchEvent(new Event('release-passkey-fixture')));
  await expect(editor(page).getByRole('button', { name: /Edit schedule bedtime/ })).toBeEnabled();
  expect(calls.attempts).toHaveLength(1);
  expect(f.store.integrationState().active_operation_id).toBeNull();
});

test('Cancel is disabled while a schedule POST is pending and an unclassified 4xx keeps its outcome unknown', async ({ page, integration: f }) => {
  await openEditor(page, f);
  const calls = requests(page);
  let release!: () => void;
  const pending = new Promise<void>((resolve) => { release = resolve; });
  await page.route('**' + schedulePath, async (route) => {
    await pending;
    await route.fulfill({ status: 409, json: {} });
  });
  await editStart(page, '19:00');
  try {
    await expect.poll(() => calls.attempts.length).toBe(1);
    await expect(editor(page).getByRole('button', { name: 'Cancel', exact: true })).toBeDisabled();
  } finally {
    release();
  }
  await expect(page.locator('#notice')).toContainText('Outcome unknown');
  await expect(editor(page).getByRole('button', { name: 'Save schedule' })).toBeDisabled();
  await expect(editor(page).getByLabel('Start')).toHaveValue('19:00');
  expect(calls.attempts).toHaveLength(1);
  expect(calls.options).toHaveLength(0);
});

test('a confirmed busy refusal keeps the draft without reporting a revision conflict', async ({ page, integration: f }) => {
  await openEditor(page, f);
  const calls = requests(page);
  await page.route('**' + schedulePath, (route) => route.fulfill({ status: 409, json: { error: { code: 'operation_in_progress' } } }));
  await editStart(page, '19:00');
  await expect(page.locator('#notice')).toContainText('Another router change is already in progress');
  await expect(editor(page).getByLabel('Start')).toHaveValue('19:00');
  await expect(editor(page).getByRole('button', { name: 'Save schedule' })).toBeDisabled();
  expect(calls.attempts).toHaveLength(1);
  expect(calls.options).toHaveLength(0);
});

test('integration create is direct and the editor shows the configured timezone and unverified clock', async ({ page, integration: f }) => {
  await openEditor(page, f);
  await expect(editor(page)).toContainText('Configured router timezone: America/New_York. Router clock unverified.');
  await expect(editor(page)).not.toContainText('UTC in this demo');
  const calls = requests(page);
  await editor(page).getByRole('button', { name: 'Add a schedule for Explicit test person', exact: true }).click();
  await editor(page).getByLabel('Tue').check();
  await editor(page).getByLabel('Start').fill('19:00');
  await editor(page).getByLabel('Stop').fill('21:00');
  await editor(page).getByRole('button', { name: 'Save schedule' }).click();
  await expect.poll(() => f.store.integrationState().active_operation_id).not.toBeNull();
  await dispatchPending(f);
  await expect(editor(page).locator('[data-schedule-id=window_1]')).toContainText('19:00');
  expect(calls.attempts).toHaveLength(1);
  expect(calls.options).toHaveLength(0);
});

test('an owner-reviewed clock shows its timezone for scheduled children and no clock claim for an empty card', async ({ page, integration: f }) => {
  await openEditor(page, f, 1, { timezone: 'UTC', conformance: {
    utcOffsetMinutes: 0, verifiedAt: f.now() - 1, validUntil: f.now() + 60, evidenceSha256: 'e'.repeat(64),
  } });
  const card = editor(page).locator('[data-schedule-person="pilot"]');
  await expect(card).toContainText('Configured router timezone: UTC.');
  await expect(card).not.toContainText('Router clock unverified.');
  const emptyCard = editor(page).locator('[data-schedule-person="kid2"]');
  await expect(emptyCard).toContainText('No weekly schedule windows.');
  await expect(emptyCard).not.toContainText(/Configured router timezone|Router clock unverified/);
  await expect(emptyCard.getByRole('button', { name: /Add a schedule/ })).toBeEnabled();
});

test('a child with eight mixed-kind integration windows can edit but cannot add another', async ({ page, integration: f }) => {
  f.config.focus = { enabled: true };
  await openEditor(page, f, 8);
  f.store.run("UPDATE schedule_windows SET kind='focus' WHERE person_id=? AND id=?", 'pilot', 'bedtime');
  await page.getByRole('button', { name: 'Refresh status' }).click();
  await expect(editor(page).locator('[data-schedule-id="bedtime"] [data-schedule-kind="focus"]')).toBeVisible();
  await expect(editor(page).getByRole('button', { name: 'Add a schedule for Explicit test person', exact: true })).toBeDisabled();
  await expect(editor(page).getByRole('button', { name: /Edit schedule bedtime/ })).toBeEnabled();
  await expect(editor(page)).toContainText('maximum of 8 schedule windows');
});

test('integration with editable schedules off still hides the editor when focus is enabled', async ({ page, integration: f }) => {
  f.config.focus = { enabled: true };
  const calls = requests(page);
  await signIn(page, f, 'parent');
  await openTab(page, 'more');
  await expect(editor(page)).toBeHidden();
  const status: PeopleDTO = await (await page.request.get(f.origin + '/people')).json();
  expect(status.people.every(person => !('recurringFocusEditable' in person))).toBe(true);
  expect(calls.options).toHaveLength(0);
  expect(calls.attempts).toHaveLength(0);
});

const extraPath = '/people/pilot/schedule-extra-time';
const skipPath = '/people/pilot/schedule-skip-tonight';
const pilotSchedules = (page: Page) => editor(page).locator('[data-schedule-person="pilot"]');
const extraButton = (page: Page, minutes: number) => pilotSchedules(page).getByRole('button', { name: `Add ${minutes} minutes of extra time`, exact: true });

async function openAllowanceEditor(page: Page, f: World, { reviewed = true, active = true, claimSeconds = 0, calibrationSeconds = 7200 } = {}) {
  // Keep the fake service's claim timestamp bound to the browser's wall clock as status is fetched.
  await page.route('**/people', async (route) => {
    f.advance(Math.round(Date.now() / 1000) - f.now());
    if (!claimSeconds) return route.continue();
    const response = await route.fetch();
    const body = await response.json();
    const pilot = body.people[0];
    if (pilot.scheduleAllowanceValidUntil !== null) {
      pilot.scheduleAllowanceValidUntil = Math.min(pilot.scheduleAllowanceValidUntil, f.now() + claimSeconds);
    }
    await route.fulfill({ response, json: body });
  });
  const time = (offset: number) => new Date((f.now() + offset * 60) * 1000).toISOString().slice(11, 16);
  await openEditor(page, f, 1, { timezone: 'UTC', ...(reviewed ? { conformance: {
    utcOffsetMinutes: 0, verifiedAt: f.now() - 5, validUntil: f.now() + calibrationSeconds, evidenceSha256: 'e'.repeat(64),
  } } : {}) }, { ...schedule, weekdays: [...DAYS], start: time(active ? -2 : 60), stop: time(120) });
}

test('schedule extra time waits for router confirmation, permits extension, and reports a cap refusal', async ({ page, integration: f }) => {
  await openAllowanceEditor(page, f);
  const sent: Request[] = [];
  page.on('request', request => {
    if (request.method() === 'POST' && [extraPath, '/step-up/options'].includes(new URL(request.url()).pathname)) sent.push(request);
  });
  const started = f.store.observation().value!.routerTime;
  await extraButton(page, 15).click();
  await expect.poll(() => f.store.integrationState().active_operation_id).not.toBeNull();
  await expect(page.locator('#notice')).toContainText('Extra time pending');
  await expect(pilotSchedules(page)).not.toContainText('Router reported extra time until');
  await expect(extraButton(page, 15)).toBeDisabled();
  await extraButton(page, 15).dispatchEvent('click');
  expect(sent).toHaveLength(1);
  expect(sent[0].postDataJSON()).toEqual({ minutes: 15 });
  expect(sent[0].headers()['if-match']).toBeTruthy();
  expect(sent[0].headers()['idempotency-key']).toBeTruthy();
  expect(sent[0].headers()['x-csrf-token']).toBeTruthy();
  await dispatchPending(f);
  await expect(pilotSchedules(page)).toContainText('Router reported extra time until');
  expect(f.router.policy.allowances).toEqual([{ person: 'pilot', until: started + 900 }]);
  await expect(pilotSchedules(page).locator('time')).toHaveAttribute('datetime', new Date((started + 900) * 1000).toISOString());
  await extraButton(page, 30).click();
  await expect.poll(() => f.store.integrationState().active_operation_id).not.toBeNull();
  await dispatchPending(f);
  await expect(extraButton(page, 60)).toBeEnabled();
  expect(f.router.policy.allowances).toEqual([{ person: 'pilot', until: started + 2700 }]);
  await extraButton(page, 60).click();
  await expect(page.locator('#notice')).toContainText('Extra time cannot exceed 60 minutes');
  expect(f.store.integrationState().active_operation_id).toBeNull();
  expect(sent.map(request => request.postDataJSON())).toEqual([{ minutes: 15 }, { minutes: 30 }, { minutes: 60 }]);
});

test('Skip tonight explains the cap and sends one empty allowance request', async ({ page, integration: f }) => {
  await openAllowanceEditor(page, f);
  await expect(pilotSchedules(page)).toContainText('up to 60 minutes');
  const started = f.store.observation().value!.routerTime;
  const posted = page.waitForRequest(request => request.method() === 'POST' && new URL(request.url()).pathname === skipPath);
  await pilotSchedules(page).getByRole('button', { name: 'Skip tonight', exact: true }).click();
  expect((await posted).postDataJSON()).toEqual({});
  await expect.poll(() => f.store.integrationState().active_operation_id).not.toBeNull();
  await dispatchPending(f);
  await expect(pilotSchedules(page)).toContainText('Router reported extra time until');
  expect(f.router.policy.allowances).toEqual([{ person: 'pilot', until: started + 3600 }]);
  await expect(pilotSchedules(page).locator('time')).toHaveAttribute('datetime', new Date((started + 3600) * 1000).toISOString());
});

test('Skip tonight is unavailable when its end equals clock review expiry', async ({ page, integration: f }) => {
  // openEditor advances the router's observation by one second before the initial read.
  await openAllowanceEditor(page, f, { calibrationSeconds: 3601 });
  expect(f.config.scheduleClock!.conformance!.validUntil).toBe(f.store.observation().value!.routerTime + 3600);
  await expect(extraButton(page, 15)).toBeEnabled();
  await expect(pilotSchedules(page).getByRole('button', { name: 'Skip tonight', exact: true })).toBeDisabled();
});

test('a schedule with an unverified clock has no enabled allowance controls', async ({ page, integration: f }) => {
  await openAllowanceEditor(page, f, { reviewed: false });
  await expect(pilotSchedules(page)).toContainText('Router clock unverified');
  await expect(extraButton(page, 15)).toBeDisabled();
  await expect(pilotSchedules(page).getByRole('button', { name: 'Skip tonight', exact: true })).toBeDisabled();
});

test('an unrelated allowance does not make an inactive schedule eligible', async ({ page, integration: f }) => {
  f.router.policy = normalizePolicy({ ...f.router.policy, allowances: [{ person: 'pilot', until: f.now() + 1800 }] });
  await openAllowanceEditor(page, f, { active: false });
  await expect(pilotSchedules(page)).toContainText('Router reported extra time until');
  await expect(extraButton(page, 15)).toBeDisabled();
  await expect(pilotSchedules(page).getByRole('button', { name: 'Skip tonight', exact: true })).toBeDisabled();
});

test('a manual pause keeps schedule allowances unavailable during an active window', async ({ page, integration: f }) => {
  f.router.policy = normalizePolicy({ ...f.router.policy, pauses: [{ person: 'pilot', until: 0 }],
    allowances: [{ person: 'pilot', until: f.now() + 1800 }] });
  await openAllowanceEditor(page, f);
  await expect(pilotSchedules(page)).toContainText('Router reported extra time until');
  await expect(extraButton(page, 15)).toBeDisabled();
  await expect(pilotSchedules(page).getByRole('button', { name: 'Skip tonight', exact: true })).toBeDisabled();
});

test('allowance eligibility from the service ends when the clock review expires', async ({ page, integration: f }) => {
  await openAllowanceEditor(page, f, { calibrationSeconds: 20 });
  const response = await page.request.get(f.origin + '/people');
  expect(response.ok()).toBe(true);
  const status: PeopleDTO = await response.json();
  const pilot = status.people.find(entry => entry.id === 'pilot');
  expect(pilot?.scheduleAllowanceValidUntil).toBe(f.config.scheduleClock!.conformance!.validUntil);
});

test('schedule allowance controls expire before the overall clock witness', async ({ page, integration: f }) => {
  await openAllowanceEditor(page, f, { claimSeconds: 8 });
  await expect(extraButton(page, 15)).toBeEnabled();
  await page.evaluate(() => {
    const wall = Date.now.bind(Date);
    const monotonic = performance.now.bind(performance);
    Date.now = () => wall() + 10000;
    Object.defineProperty(performance, 'now', { value: () => monotonic() + 10000 });
  });
  await expect(extraButton(page, 15)).toBeDisabled();
  await expect(pilotSchedules(page).getByRole('button', { name: 'Skip tonight', exact: true })).toBeDisabled();
  await expect(pilotSchedules(page).getByRole('button', { name: /Edit schedule bedtime/ })).toBeEnabled();
});

test('a refreshed revision change prevents an allowance POST', async ({ page, integration: f }) => {
  await openAllowanceEditor(page, f);
  let sent = 0;
  await page.route('**' + extraPath, async (route) => { sent++; await route.continue(); });
  // Tag only the status read initiated by this click, so periodic refresh cannot consume the change first.
  await page.evaluate(() => {
    const fetch = window.fetch.bind(window);
    let preflight = false;
    document.addEventListener('click', event => {
      if ((event.target as HTMLElement).closest('[data-sched-action="extra"][data-minutes="15"]')) preflight = true;
    }, true);
    window.fetch = (input, init) => {
      if (!preflight || input !== '/people') return fetch(input, init);
      preflight = false;
      const headers = new Headers(init?.headers);
      headers.set('X-Fixture-Schedule-Preflight', '1');
      return fetch(input, { ...init, headers });
    };
  });
  await page.route('**/people', async (route) => {
    if (route.request().headers()['x-fixture-schedule-preflight']) {
      f.router.policy = normalizePolicy({ ...f.router.policy, revision: f.router.policy.revision + 1 });
      const nextObservation = f.store.observation().value!.routerTime + 1;
      f.advance(Math.max(1, nextObservation - f.now()));
      await f.observe();
    }
    await route.fallback();
  });
  await extraButton(page, 15).click();
  await expect(page.locator('#notice')).toContainText('Schedules changed elsewhere');
  expect(sent).toBe(0);
  expect(f.store.integrationState().active_operation_id).toBeNull();
});

test('an accepted allowance with a lost response stays unknown and cannot be retried automatically', async ({ page, integration: f }) => {
  await openAllowanceEditor(page, f);
  let sent = 0, status: number | undefined;
  await page.route('**' + extraPath, async (route) => {
    sent++;
    status = (await route.fetch()).status();
    await route.abort('connectionreset');
  });
  await extraButton(page, 15).click();
  await expect(page.locator('#notice')).toContainText('Outcome unknown');
  await expect(extraButton(page, 15)).toBeDisabled();
  await expect(pilotSchedules(page)).not.toContainText('Router reported extra time until');
  await extraButton(page, 15).dispatchEvent('click');
  expect(status).toBe(202);
  expect(f.store.integrationState().active_operation_id).not.toBeNull();
  expect(sent).toBe(1);
});

test('recurring focus capability reaches assigned empty cards and focus creation settles before showing the label', async ({ page, integration: f }) => {
  f.config.focus = { enabled: true };
  await openEditor(page, f);
  const response = await page.request.get(f.origin + '/people');
  expect(response.ok()).toBe(true);
  const status: PeopleDTO = await response.json();
  expect(status.people.map(person => [person.id, person.recurringFocusEditable])).toEqual([['pilot', true], ['kid2', true]]);
  const empty = editor(page).locator('[data-schedule-person="kid2"]');
  await empty.getByRole('button', { name: /Add a schedule/ }).click();
  await expect(empty.getByLabel('Schedule type')).toHaveValue('bedtime');
  await empty.getByRole('button', { name: 'Cancel', exact: true }).click();
  const pilot = pilotSchedules(page);
  await expect(pilot.locator('[data-schedule-id="bedtime"] [data-schedule-kind="bedtime"]')).toHaveText('Bedtime');
  const calls = requests(page);
  await pilot.getByRole('button', { name: /Add a schedule/ }).click();
  await expect(pilot.getByLabel('Schedule type')).toHaveValue('bedtime');
  await pilot.getByLabel('Schedule type').selectOption('focus');
  await pilot.getByLabel('Mon', { exact: true }).check();
  await pilot.getByLabel('Start').fill('19:00');
  await pilot.getByLabel('Stop').fill('21:00');
  await expect(pilot.locator('[data-preview]')).toContainText('Overlaps bedtime');
  await pilot.getByRole('button', { name: 'Save schedule' }).click();
  await expect.poll(() => f.store.integrationState().active_operation_id).not.toBeNull();
  await expect.poll(() => calls.attempts.length).toBe(1);
  expect(calls.options).toHaveLength(0);
  expect(calls.attempts.map(request => request.postDataJSON())).toEqual([
    { id: 'window_1', weekdays: ['Mon'], start: '19:00', stop: '21:00', kind: 'focus' },
  ]);
  await expect(pilot.locator('[data-schedule-id="window_1"]')).toHaveCount(0);
  await dispatchPending(f);
  await expect(pilot.locator('[data-schedule-id="window_1"] [data-schedule-kind="focus"]')).toHaveText('Focus');
});

test('recurring focus label-only edit is direct and a shortening binds the selected type to one proof', async ({ page, integration: f }) => {
  f.config.focus = { enabled: true };
  await openEditor(page, f);
  const pilot = pilotSchedules(page), calls = requests(page);
  const row = pilot.locator('[data-schedule-id="bedtime"]');
  const edit = () => row.getByRole('button', { name: /Edit schedule bedtime/ }).click();
  const save = () => pilot.getByRole('button', { name: 'Save schedule' }).click();

  await edit();
  await expect(pilot.getByLabel('Schedule type')).toHaveValue('bedtime');
  await pilot.getByLabel('Schedule type').selectOption('focus');
  await save();
  await expect.poll(() => f.store.integrationState().active_operation_id).not.toBeNull();
  await expect.poll(() => calls.attempts.length).toBe(1);
  expect(calls.options).toHaveLength(0);
  expect(calls.attempts[0].postDataJSON()).toEqual({ weekdays: ['Mon'], start: '20:00', stop: '23:00', kind: 'focus' });
  await expect(row.locator('[data-schedule-kind="bedtime"]')).toBeVisible();
  await dispatchPending(f);
  await expect(row.locator('[data-schedule-kind="focus"]')).toBeVisible();

  await edit();
  await expect(pilot.getByLabel('Schedule type')).toHaveValue('focus');
  await pilot.getByLabel('Schedule type').selectOption('bedtime');
  await pilot.getByLabel('Start').fill('21:00');
  await save();
  await expect.poll(() => f.store.integrationState().active_operation_id).not.toBeNull();
  await expect.poll(() => calls.attempts.length).toBe(3);
  const [, first, proof] = calls.attempts;
  const intent = { weekdays: ['Mon'], start: '21:00', stop: '23:00', kind: 'bedtime' };
  expect(first.postDataJSON()).toEqual(intent);
  expect(calls.options).toHaveLength(1);
  expect(calls.options[0].postDataJSON()).toEqual({
    action: 'schedule_change', person: 'pilot', scheduleAction: 'schedule_update', scheduleId: 'bedtime',
    precondition: first.headers()['if-match'], change: intent,
  });
  const { stepUp, ...change } = proof.postDataJSON();
  expect(change).toEqual(intent);
  expect(stepUp?.challengeId).toBeTruthy();
  expect(proof.headers()['if-match']).toBe(first.headers()['if-match']);
  expect(proof.headers()['idempotency-key']).toBe(first.headers()['idempotency-key']);
  await expect(row.locator('[data-schedule-kind="focus"]')).toBeVisible();
  await dispatchPending(f);
  await expect(row.locator('[data-schedule-kind="bedtime"]')).toBeVisible();
});

for (const change of ['disabled', 'kind'] as const) {
  test(change === 'disabled' ? 'disabling recurring focus during the passkey prompt discards the proof'
    : 'changing the recurring schedule kind during the passkey prompt discards the proof', async ({ page, integration: f }) => {
    f.config.focus = { enabled: true };
    await openEditor(page, f);
    const calls = requests(page), pilot = pilotSchedules(page);
    await passkeyGate(page);
    await editStart(page, '21:00');
    await expect(page.locator('html')).toHaveAttribute('data-fixture-passkey-waiting', 'true');
    if (change === 'disabled') {
      f.config.focus = { enabled: false };
    } else {
      const before: PeopleDTO = await (await page.request.get(f.origin + '/people')).json();
      expect(before.revisionToken).toEqual(expect.any(String));
      f.store.run("UPDATE schedule_windows SET kind='focus' WHERE person_id=? AND id=?", 'pilot', 'bedtime');
      const after: PeopleDTO = await (await page.request.get(f.origin + '/people')).json();
      expect(after.revisionToken).toBe(before.revisionToken);
    }
    await page.evaluate(() => document.dispatchEvent(new Event('release-passkey-fixture')));
    await expect(page.locator('#notice')).toContainText(change === 'disabled' ? 'Schedule type settings changed' : 'The window changed since you opened it');
    await expect(pilot.getByLabel('Start')).toHaveValue('21:00');
    if (change === 'disabled') {
      await expect(pilot.getByLabel('Schedule type')).toHaveCount(0);
    } else {
      await expect(pilot.getByLabel('Schedule type')).toHaveValue('bedtime');
      await expect(pilot.locator('[data-schedule-id="bedtime"] [data-schedule-kind="focus"]')).toBeVisible();
    }
    expect(calls.options).toHaveLength(1);
    expect(calls.attempts).toHaveLength(1);
    expect(f.store.integrationState().active_operation_id).toBeNull();
  });
}

test('focus off preserves a retained label while legacy update omits kind and delete still needs proof', async ({ page, integration: f }) => {
  await openEditor(page, f);
  f.store.run("UPDATE schedule_windows SET kind='focus' WHERE person_id=? AND id=?", 'pilot', 'bedtime');
  const status: PeopleDTO = await (await page.request.get(f.origin + '/people')).json();
  expect(status.people.every(person => !('recurringFocusEditable' in person))).toBe(true);
  expect(status.people[0].schedules?.[0]).not.toHaveProperty('kind');

  const calls = requests(page), pilot = pilotSchedules(page);
  await editStart(page, '19:00');
  await expect(page.locator('#notice')).toContainText('Recurring focus is unavailable. You can delete this window');
  await expect(pilot.getByLabel('Start')).toHaveValue('19:00');
  await expect(pilot.getByLabel('Schedule type')).toHaveCount(0);
  expect(calls.attempts[0].postDataJSON()).toEqual({ weekdays: ['Mon'], start: '19:00', stop: '23:00' });
  expect(calls.options).toHaveLength(0);
  expect(f.store.get<{kind: string}>('SELECT kind FROM schedule_windows WHERE person_id=? AND id=?', 'pilot', 'bedtime')?.kind).toBe('focus');
  expect(f.store.integrationState().active_operation_id).toBeNull();

  await pilot.getByRole('button', { name: 'Cancel', exact: true }).click();
  await pilot.getByRole('button', { name: /Delete schedule bedtime/ }).click();
  await pilot.getByRole('button', { name: 'Confirm delete bedtime' }).click();
  await expect.poll(() => f.store.integrationState().active_operation_id).not.toBeNull();
  await expect.poll(() => calls.attempts.length).toBe(3);
  expect(calls.options[0].postDataJSON().change).toEqual({});
  expect(calls.attempts[1].postDataJSON()).toEqual({});
  expect(Object.keys(calls.attempts[2].postDataJSON())).toEqual(['stepUp']);
  await dispatchPending(f);
  await expect(pilot.locator('[data-schedule-id="bedtime"]')).toHaveCount(0);
});

test('re-enabling recurring focus lets a parent relabel a retained window after a legacy refusal', async ({ page, integration: f }) => {
  await openEditor(page, f);
  f.store.run("UPDATE schedule_windows SET kind='focus' WHERE person_id=? AND id=?", 'pilot', 'bedtime');
  const calls = requests(page), pilot = pilotSchedules(page);
  await editStart(page, '19:00');
  await expect(page.locator('#notice')).toContainText('Recurring focus is unavailable. You can delete this window');

  await pilot.getByRole('button', { name: 'Cancel', exact: true }).click();
  f.config.focus = { enabled: true };
  await page.getByRole('button', { name: 'Refresh status' }).click();
  const row = pilot.locator('[data-schedule-id="bedtime"]');
  await expect(row.locator('[data-schedule-kind="focus"]')).toBeVisible();
  await row.getByRole('button', { name: /Edit schedule bedtime/ }).click();
  await expect(pilot.getByLabel('Schedule type')).toHaveValue('focus');
  await pilot.getByLabel('Schedule type').selectOption('bedtime');
  await pilot.getByRole('button', { name: 'Save schedule' }).click();
  await expect.poll(() => f.store.integrationState().active_operation_id).not.toBeNull();
  await expect.poll(() => calls.attempts.length).toBe(2);
  expect(calls.attempts[1].postDataJSON()).toEqual({ weekdays: ['Mon'], start: '20:00', stop: '23:00', kind: 'bedtime' });
  expect(calls.options).toHaveLength(0);
  await dispatchPending(f);
  await expect(row.locator('[data-schedule-kind="bedtime"]')).toBeVisible();
});

test('a terminal router refusal preserves the committed recurring schedule label', async ({ page, integration: f }) => {
  f.config.focus = { enabled: true };
  await openEditor(page, f);
  const row = pilotSchedules(page).locator('[data-schedule-id="bedtime"]');
  await row.getByRole('button', { name: /Edit schedule bedtime/ }).click();
  await pilotSchedules(page).getByLabel('Schedule type').selectOption('focus');
  await pilotSchedules(page).getByRole('button', { name: 'Save schedule' }).click();
  await expect.poll(() => f.store.integrationState().active_operation_id).not.toBeNull();
  f.router.reject = 'missing_dependencies';
  await dispatchPending(f);
  await expect(page.locator('#notice')).toContainText('was not delivered');
  const status: PeopleDTO = await (await page.request.get(f.origin + '/people')).json();
  const window = status.people.find(person => person.id === 'pilot')?.schedules?.find(schedule => schedule.id === 'bedtime');
  expect(window?.kind).toBe('bedtime');
  await expect(row.locator('[data-schedule-kind="bedtime"]')).toBeVisible();
  await expect(row.locator('[data-schedule-kind="focus"]')).toHaveCount(0);
});

test('a committed recurring focus label may be displayed while enforcement is unknown', async ({ page, integration: f }) => {
  f.config.focus = { enabled: true };
  await openEditor(page, f);
  const pilot = pilotSchedules(page);
  await pilot.getByRole('button', { name: /Edit schedule bedtime/ }).click();
  await pilot.getByLabel('Schedule type').selectOption('focus');
  await pilot.getByRole('button', { name: 'Save schedule' }).click();
  await expect.poll(() => f.store.integrationState().active_operation_id).not.toBeNull();
  const id = f.store.integrationState().active_operation_id!;
  f.router.transform = observation => ({ ...observation, status: { ...observation.status, ok: false, errors: ['previous_apply_failed'] } });
  const plan = f.worker.prepare('apply', id);
  await f.worker.execute(plan, plan.scriptSha256);
  await expect(page.locator('#notice')).toContainText('outcome unknown');
  await page.getByRole('button', { name: 'Refresh status' }).click();
  await expect(pilot.locator('[data-schedule-id="bedtime"] [data-schedule-kind="focus"]')).toBeVisible();
  await expect(pilot.getByRole('button', { name: /Edit schedule bedtime/ })).toBeDisabled();
});

test('a malformed recurring focus kind cannot open an edit', async ({ page, integration: f }) => {
  f.config.focus = { enabled: true };
  await page.route('**/people', async (route) => {
    const response = await route.fetch();
    const body = await response.json();
    body.people.find((person: { id: string }) => person.id === 'pilot').schedules[0].kind = ['focus'];
    await route.fulfill({ response, json: body });
  });
  await openEditor(page, f);
  await expect(pilotSchedules(page).locator('[data-schedule-kind]')).toHaveCount(0);
  await pilotSchedules(page).getByRole('button', { name: /Edit schedule bedtime/ }).click();
  await expect(page.locator('#notice')).toContainText('The schedule type is unavailable');
  await expect(editor(page).getByLabel('Schedule type')).toHaveCount(0);
});

test('an opened recurring focus edit cannot overwrite a label changed elsewhere', async ({ page, integration: f }) => {
  f.config.focus = { enabled: true };
  await openEditor(page, f);
  const pilot = pilotSchedules(page), calls = requests(page);
  await pilot.getByRole('button', { name: /Edit schedule bedtime/ }).click();
  await expect(pilot.getByLabel('Schedule type')).toHaveValue('bedtime');
  f.store.run("UPDATE schedule_windows SET kind='focus' WHERE person_id=? AND id=?", 'pilot', 'bedtime');
  f.router.policy = normalizePolicy({ ...f.router.policy, revision: f.router.policy.revision + 1 });
  f.advance(1);
  await f.observe();
  await page.getByRole('button', { name: 'Refresh status' }).click();
  await expect(pilot.locator('[data-schedule-id="bedtime"] [data-schedule-kind="focus"]')).toBeVisible();
  await pilot.getByRole('button', { name: 'Save schedule' }).click();
  await expect(page.locator('#notice')).toContainText('The window changed since you opened it');
  await expect(pilot.getByLabel('Schedule type')).toHaveValue('bedtime');
  expect(calls.attempts).toHaveLength(0);
  expect(calls.options).toHaveLength(0);
});
