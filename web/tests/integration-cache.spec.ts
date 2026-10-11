import { test, expect } from './browser-fixture.ts';

test('real-source cached status is scoped to source, installation and authenticated account', async ({page, demo}) => {
    await page.goto(demo.origin);
    const result = await page.evaluate(async () => {
        const modulePath = '/status-cache.js';
        const cache = await import(modulePath) as {saveStatus(session: unknown, status: unknown): void; readStatus(): {status: {source: string; people: {id: string}[]}} | null};
        const scope = 'a'.repeat(64);
        document.documentElement.dataset.source = 'real-router-integration';
        document.documentElement.dataset.integrationScope = scope;
        const actor = {id: 'private_test_parent', displayName: 'Private cache test', role: 'parent', personIds: ['pilot'], permissionVersion: '1'};
        const provenance = {source: 'real-router-integration', routerCompatibilityVerified: false, integrationScope: scope};
        const session = {...provenance, actor, csrfToken: 'DO_NOT_CACHE', expiresAt: Math.floor(Date.now() / 1000) + 600};
        const status = {...provenance, people: [{id: 'pilot', name: 'Private cache fixture', devices: [], manualPause: null, effectiveManualPause: null, scheduleBlocked: false, scheduleExplanation: 'Explicit cache fixture', observationHealth: 'unconfirmed', status: 'unknown', latestOperation: null}], serviceDesiredRevision: 0, routerDesiredRevision: null, routerConfirmedRevision: null, observedAt: null, statusAgeSeconds: null, lastSuccessfulConfirmationAt: null, revisionToken: null, errors: [], packetAcceptance: 'unmeasured'};
        cache.saveStatus(session, status);
        const first = cache.readStatus();
        const secretLeaked = JSON.stringify(localStorage).includes('DO_NOT_CACHE');
        document.documentElement.dataset.integrationScope = 'b'.repeat(64);
        const otherInstallation = cache.readStatus();
        document.documentElement.dataset.integrationScope = scope;
        cache.saveStatus(session, {...status, source: 'synthetic-fake-router'});
        const wrongSource = cache.readStatus();
        cache.saveStatus(session, {...status, people: [...status.people, {...status.people[0], id: 'forbidden'}]});
        const filtered = cache.readStatus();
        const active = localStorage.getItem('cf-status-active:v1');
        const tampered = JSON.parse(localStorage.getItem(active!)!); tampered.actor.personIds = ['forbidden']; localStorage.setItem(active!, JSON.stringify(tampered));
        const wrongAccountScope = cache.readStatus();
        return {first: first?.status.source, secretLeaked, otherInstallation, wrongSource, allowed: filtered?.status.people.map(p => p.id), wrongAccountScope};
    });
    expect(result).toEqual({first: 'real-router-integration', secretLeaked: false, otherInstallation: null, wrongSource: null, allowed: ['pilot'], wrongAccountScope: null});
});

test('enabled integration distinguishes automatic queue, sent request and unknown outcome without offering retry', async ({page, demo}) => {
    const scope = 'e'.repeat(64), now = Math.floor(Date.now() / 1000);
    const provenance = {source: 'real-router-integration', integrationScope: scope, routerCompatibilityVerified: false};
    const actor = {id: 'fixture_parent', displayName: 'Explicit UI fixture', role: 'parent', personIds: ['pilot'], permissionVersion: '1'};
    const operation = {...provenance, id: '00000000-0000-4000-8000-000000000000', personId: 'pilot', action: 'pause', revision: 1, state: 'pending', createdAt: now, updatedAt: now, error: null, confirmedAt: null, dispatch: 'awaiting_automatic_dispatch'};
    await page.route(demo.origin + '/', async route => {
        const response = await route.fetch();
        const html = (await response.text()).replace('<html lang="en">', `<html lang="en" data-source="real-router-integration" data-integration-scope="${scope}" data-automatic-dispatch="true">`);
        await route.fulfill({response, body: html});
    });
    await page.route('**/auth/session', route => route.fulfill({json: {...provenance, actor, csrfToken: 'explicit-browser-fixture', expiresAt: now + 600}}));
    await page.route('**/people', route => route.fulfill({json: {...provenance, packetAcceptance: 'unmeasured', people: [{id: 'pilot', name: 'Explicit test person', devices: [{id: 'phone', label: 'Explicit test device'}], manualPause: null, effectiveManualPause: null, scheduleBlocked: false, scheduleExplanation: 'Schedules unavailable in this fixture.', observationHealth: 'healthy', status: operation.state, latestOperation: operation}], serviceDesiredRevision: 1, routerDesiredRevision: 0, routerConfirmedRevision: 0, revisionToken: null, observedAt: now, statusAgeSeconds: 0, lastSuccessfulConfirmationAt: now, errors: []}}));
    await page.goto(demo.origin);
    await expect(page.getByText('Pause pending. Waiting for automatic router confirmation.', {exact: true})).toBeVisible();
    await expect(page.locator('[data-control="pause"]')).toBeDisabled();
    await expect(page.locator('[data-control="resume"]')).toBeDisabled();
    operation.dispatch = 'consumed';
    await page.getByRole('button', {name: 'Refresh status'}).click();
    await expect(page.getByText('Pause pending. Waiting for the router receipt.', {exact: true})).toBeVisible();
    operation.state = 'unknown'; operation.dispatch = 'uncertain';
    await page.getByRole('button', {name: 'Refresh status'}).click();
    await expect(page.getByText(/Pause outcome unknown.*No retry is authorized/)).toBeVisible();
    await expect(page.locator('[data-control="pause"]')).toBeDisabled();
    await expect(page.locator('[data-control="resume"]')).toBeDisabled();
    await expect(page.getByRole('button', {name: /retry/i})).toHaveCount(0);
});

test('integration distinguishes active, inactive and unknown owner schedules while resume remains a manual control', async ({page, demo}) => {
    const scope = 'f'.repeat(64), now = Math.floor(Date.now() / 1000);
    const provenance = {source: 'real-router-integration', integrationScope: scope, routerCompatibilityVerified: false};
    const actor = {id: 'fixture_parent', displayName: 'Explicit schedule fixture', role: 'parent', personIds: ['pilot'], permissionVersion: '1'};
    const person = {id: 'pilot', name: 'Schedule test person', devices: [{id: 'phone', label: 'Explicit test device'}], manualPause: null, effectiveManualPause: null, scheduleBlocked: true as boolean | null,
        scheduleExplanation: 'Owner schedules in America/New_York: bedtime: Mon, Tue 21:00–07:00. Resume clears only manual pause. Active at the router observation: bedtime.', scheduleWitness: 'owner-reviewed-clock', scheduleValidUntil: now + 31, scheduleCheckedAt: now, observationHealth: 'healthy', status: 'confirmed', latestOperation: null};
    await page.clock.install({time: new Date((now - 1) * 1000)});
    await page.clock.pauseAt(new Date(now * 1000));
    await page.route(demo.origin + '/', async route => {
        const response = await route.fetch();
        const html = (await response.text()).replace('<html lang="en">', `<html lang="en" data-source="real-router-integration" data-integration-scope="${scope}" data-automatic-dispatch="true">`);
        await route.fulfill({response, body: html});
    });
    await page.route('**/auth/session', route => route.fulfill({json: {...provenance, actor, csrfToken: 'explicit-browser-fixture', expiresAt: now + 600}}));
    await page.route('**/people', route => route.fulfill({json: {...provenance, packetAcceptance: 'unmeasured', people: [person], serviceDesiredRevision: 0, routerDesiredRevision: 0, routerConfirmedRevision: 0,
        revisionToken: '"s0-r0-' + 'a'.repeat(64) + '"', observedAt: now, statusAgeSeconds: 0, lastSuccessfulConfirmationAt: now, errors: []}}));
    await page.goto(demo.origin);
    const schedule = page.locator('#people .reasons dd').nth(1);
    await expect(schedule).toContainText('Schedule currently blocks access');
    await expect(page.getByText(/Owner schedules in America\/New_York/)).toBeVisible();
    await expect(page.locator('[data-control="resume"]')).toBeEnabled();
    person.scheduleBlocked = null; person.scheduleExplanation = 'Owner schedules in America/New_York: bedtime: Mon, Tue 21:00–07:00. Current schedule state unknown: router clock calibration expired. Resume clears only manual pause.';
    await page.getByRole('button', {name: 'Refresh status'}).click();
    await expect(schedule).toContainText('Schedule state unknown');
    await expect(schedule).not.toContainText('No active schedule block');
    await expect(page.locator('[data-control="resume"]')).toBeEnabled();
    person.scheduleBlocked = false; person.scheduleExplanation = 'No owner window active at the router observation.';
    await page.getByRole('button', {name: 'Refresh status'}).click();
    await expect(schedule).toContainText('No active schedule block');
    await page.context().setOffline(true);
    await page.evaluate(() => window.dispatchEvent(new Event('offline')));
    await expect(schedule).toContainText('Schedule state unknown');
    await expect(page.locator('[data-control="resume"]')).toBeDisabled();
    await page.context().setOffline(false);
    await page.evaluate(() => window.dispatchEvent(new Event('online')));
    await page.getByRole('button', {name: 'Refresh status'}).click();
    await expect(schedule).toContainText('No active schedule block');
    await page.clock.fastForward(31000);
    await expect(schedule).toContainText('Schedule state unknown');
    await expect(page.locator('[data-control="resume"]')).toBeDisabled();
});

test.describe('schedule deadline clock validity', () => {
test.use({serviceWorkers: 'block'});
test('a frozen real schedule response expires at its calibration deadline while manual controls remain fresh', async ({page, demo}) => {
    const scope = '1'.repeat(64), now = Math.floor(Date.now() / 1000);
    const provenance = {source: 'real-router-integration', integrationScope: scope, routerCompatibilityVerified: false};
    const actor = {id: 'deadline_parent', displayName: 'Explicit deadline fixture', role: 'parent', personIds: ['pilot'], permissionVersion: '1'};
    await page.clock.install({time: new Date((now - 1) * 1000)});
    await page.clock.pauseAt(new Date(now * 1000));
    await page.route(demo.origin + '/', async route => {
        const response = await route.fetch();
        await route.fulfill({response, body: (await response.text()).replace('<html lang="en">', `<html lang="en" data-source="real-router-integration" data-integration-scope="${scope}" data-automatic-dispatch="true">`)});
    });
    await page.route('**/auth/session', route => route.fulfill({json: {...provenance, actor, csrfToken: 'explicit-deadline-fixture', expiresAt: now + 600}}));
    await page.route('**/people', route => route.fulfill({json: {...provenance, packetAcceptance: 'unmeasured', people: [{id: 'pilot', name: 'Deadline test person', devices: [], manualPause: null, effectiveManualPause: null,
        scheduleBlocked: false, scheduleExplanation: 'No owner window active at the last router observation.', scheduleTimezone: 'America/New_York', scheduleWitness: 'owner-reviewed-clock', scheduleValidUntil: now + 3, scheduleCheckedAt: now,
        observationHealth: 'healthy', status: 'confirmed', latestOperation: null}], serviceDesiredRevision: 0, routerDesiredRevision: 0, routerConfirmedRevision: 0,
        revisionToken: '"s0-r0-' + 'a'.repeat(64) + '"', observedAt: now, statusAgeSeconds: 0, lastSuccessfulConfirmationAt: now, errors: []}}));
    await page.goto(demo.origin);
    const heading = page.locator('[data-schedule-state="pilot"]');
    await expect(heading).toHaveText('No active schedule block');
    const cached = await page.evaluate(() => JSON.parse(localStorage.getItem(localStorage.getItem('cf-status-active:v1')!)!).status.people[0]);
    expect(cached.scheduleValidUntil).toBe(now + 3); expect(cached.scheduleWitness).toBe('owner-reviewed-clock'); expect(cached.scheduleCheckedAt).toBe(now);
    await page.clock.fastForward(2000); await expect(heading).toHaveText('No active schedule block');
    await page.clock.fastForward(1000); await expect(heading).toHaveText('Schedule state unknown');
    await expect(page.locator('[data-control="resume"]')).toBeEnabled();
    await page.clock.setSystemTime(new Date((now - 60) * 1000));
    await page.clock.fastForward(1000); await expect(heading).toHaveText('Schedule state unknown');
    await page.reload(); // A new receipt basis cannot bless a clock-skewed frozen response.
    await expect(heading).toHaveText('Schedule state unknown');
});
});
