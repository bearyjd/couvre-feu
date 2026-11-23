import type { Page, Request } from '@playwright/test';
import { normalizePolicy } from '../../shared/src/router-schema.ts';
import { enroll, openTab, test as demoTest } from './browser-fixture.ts';
import { dispatchPending, expect, signIn, test, type World } from './bulk-fixture.ts';

const editor = (page: Page) => page.locator('#schedule-editor');
const schedulesPath = '/people/pilot/schedules';
const schedulePath = schedulesPath + '/bedtime';
const schedule = { person: 'pilot', id: 'bedtime', weekdays: ['Mon' as const], start: '20:00', stop: '23:00' };

async function openEditor(page: Page, f: World, count = 1, clock?: World['config']['scheduleClock']) {
  f.config.schedules = { editable: true };
  f.config.scheduleClock = clock ?? { timezone: 'America/New_York' };
  const schedules = [schedule, ...Array.from({ length: count - 1 }, (_, index) => ({ ...schedule, id: `window_${index + 1}` }))];
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
  let attempts = 0;
  await page.route('**/people/alex/schedules', async (route) => {
    attempts += 1;
    await route.fulfill({ status: 409, json: { error: { code: 'operation_in_progress' } } });
  });
  await editor(page).getByRole('button', { name: 'Add a schedule for Alex (fictional)' }).click();
  await editor(page).getByLabel('Tue', { exact: true }).check();
  await editor(page).getByLabel('Start').fill('19:00');
  await editor(page).getByLabel('Stop').fill('21:00');
  await editor(page).getByRole('button', { name: 'Save schedule' }).click();
  await expect(page.locator('#notice')).toContainText('Revision conflict');
  await expect(editor(page).getByLabel('Start')).toHaveValue('19:00');
  await expect(editor(page).getByRole('button', { name: 'Save schedule' })).toBeEnabled();
  expect(attempts).toBe(1);
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

test('a child with eight integration windows can edit but cannot add another', async ({ page, integration: f }) => {
  await openEditor(page, f, 8);
  await expect(editor(page).getByRole('button', { name: 'Add a schedule for Explicit test person', exact: true })).toBeDisabled();
  await expect(editor(page).getByRole('button', { name: /Edit schedule bedtime/ })).toBeEnabled();
  await expect(editor(page)).toContainText('maximum of 8 schedule windows');
});

test('integration with editable schedules off still hides the editor', async ({ page, integration: f }) => {
  const calls = requests(page);
  await signIn(page, f, 'parent');
  await openTab(page, 'more');
  await expect(editor(page)).toBeHidden();
  expect(calls.options).toHaveLength(0);
  expect(calls.attempts).toHaveLength(0);
});
