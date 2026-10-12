import { test, expect } from './browser-fixture.ts';
import type { Page } from '@playwright/test';

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


test.describe('assigned device enrollment evidence', () => {
    test.use({serviceWorkers: 'block'});
    test('frozen evidence expires after exactly 30 seconds and cached offline history keeps aging', async ({page, demo}) => {
        const scope = '5'.repeat(64), now = Math.floor(Date.now() / 1000);
        const provenance = {source: 'real-router-integration', integrationScope: scope, routerCompatibilityVerified: false};
        const actor = {id: 'device_parent', displayName: 'Device fixture parent', role: 'parent', personIds: ['pilot'], permissionVersion: '1'};
        const evidence = {source: 'router-policy', sourceObservedAt: now, serviceReceivedAt: now, freshUntil: now + 31, freshness: 'fresh', enrollment: 'included', mac: 'DO_NOT_CACHE', rawMembership: ['DO_NOT_CACHE']};
        const person = {id: 'pilot', name: 'Device fixture person', devices: [{id: 'phone', label: 'Fixture phone', evidence}], manualPause: null, effectiveManualPause: null, scheduleBlocked: false,
            scheduleExplanation: 'No fixture schedule.', observationHealth: 'healthy', status: 'confirmed', latestOperation: null};
        const status = {...provenance, packetAcceptance: 'unmeasured', people: [person], serviceDesiredRevision: 0, routerDesiredRevision: 0, routerConfirmedRevision: 0,
            revisionToken: '"s0-r0-' + 'a'.repeat(64) + '"', observedAt: now, statusAgeSeconds: 0, lastSuccessfulConfirmationAt: now, errors: []};
        await page.clock.install({time: new Date((now - 1) * 1000)}); await page.clock.pauseAt(new Date(now * 1000));
        await page.route(demo.origin + '/', async route => {
            const response = await route.fetch();
            await route.fulfill({response, body: (await response.text()).replace('<html lang="en">', `<html lang="en" data-source="real-router-integration" data-integration-scope="${scope}">`)});
        });
        await page.route('**/auth/session', route => route.fulfill({json: {...provenance, actor, csrfToken: 'fixture_only', expiresAt: now + 600}}));
        await page.route('**/people', route => route.fulfill({json: status}));
        await page.goto(demo.origin);
        const label = page.locator('[data-device-evidence="phone"]');
        await expect(label).toContainText('Router · Observed enrollment: included');
        await expect(label).toContainText('Activity unavailable');
        const cached = await page.evaluate(() => localStorage.getItem(localStorage.getItem('cf-status-active:v1')!)!);
        expect(cached).not.toContain('DO_NOT_CACHE'); expect(JSON.parse(cached).status.people[0].devices[0].evidence.freshUntil).toBe(now + 31);
        await page.screenshot({path: '/tmp/couvre-feu-device-freshness-005-privacy-ui.png', fullPage: true});
        await page.clock.fastForward(30000); await expect(label).toContainText('Observed enrollment: included'); await expect(label).not.toContainText('historical');
        await page.clock.fastForward(1000); await expect(label).toContainText('Last observed enrollment: included · historical');
        await page.addInitScript(() => Object.defineProperty(navigator, 'onLine', {get: () => false}));
        await page.reload(); await expect(page.locator('#connection')).toContainText('Offline');
        await expect(label).toContainText('historical'); await expect(page.locator('[data-control="resume"]')).toBeDisabled();
        await page.clock.fastForward(20000); await expect(label).toContainText('51s ago');
        await page.evaluate(() => window.dispatchEvent(new StorageEvent('storage', {key: 'cf-scope-event:v1', newValue: 'changed'})));
        await expectStatusDOMCleared(page, ['Device fixture person', 'Fixture phone', '51s ago']);
        expect(await page.evaluate(() => localStorage.getItem('cf-status-active:v1'))).toBeNull();
    });
    test('legacy, wrong source, future time and a changed browser clock render enrollment unknown', async ({page, demo}) => {
        const now = Math.floor(Date.now() / 1000);
        const provenance = {source: 'synthetic-fake-router', routerCompatibilityVerified: false};
        const actor = {id: 'legacy_parent', displayName: 'Legacy fixture', role: 'parent', personIds: ['alex'], permissionVersion: '1'};
        const device: {id: string; label: string; evidence?: Record<string, unknown>} = {id: 'phone', label: 'Legacy phone'};
        await page.clock.install({time: new Date((now - 1) * 1000)}); await page.clock.pauseAt(new Date(now * 1000));
        await page.route('**/auth/session', route => route.fulfill({json: {...provenance, actor, csrfToken: 'fixture_only', expiresAt: now + 600}}));
        await page.route('**/people', route => route.fulfill({json: {...provenance, people: [{id: 'alex', name: 'Legacy fixture person', devices: [device], manualPause: null, effectiveManualPause: null,
            scheduleBlocked: false, scheduleExplanation: 'Fixture.', observationHealth: 'healthy', status: 'confirmed', latestOperation: null}], serviceDesiredRevision: 0, routerDesiredRevision: 0,
            routerConfirmedRevision: 0, revisionToken: 'fixture', observedAt: now, statusAgeSeconds: 0, lastSuccessfulConfirmationAt: now, errors: []}}));
        await page.goto(demo.origin); const label = page.locator('[data-device-evidence="phone"]');
        await expect(label).toContainText('Demo · Enrollment unknown');
        device.evidence = {source: 'router-policy', sourceObservedAt: now, serviceReceivedAt: now, freshUntil: now + 31, freshness: 'fresh', enrollment: 'included'};
        await page.getByRole('button', {name: 'Refresh status'}).click(); await expect(label).toContainText('Enrollment unknown');
        const cached = await page.evaluate(() => JSON.parse(localStorage.getItem(localStorage.getItem('cf-status-active:v1')!)!).status.people[0].devices[0]);
        expect(cached.evidence).toBeUndefined();
        device.evidence = {...device.evidence, source: 'synthetic-policy', serviceReceivedAt: null, sourceObservedAt: now + 1, freshUntil: now + 32};
        await page.getByRole('button', {name: 'Refresh status'}).click(); await expect(label).toContainText('Enrollment unknown');
        device.evidence = {...device.evidence, sourceObservedAt: now, freshUntil: now + 31};
        await page.getByRole('button', {name: 'Refresh status'}).click(); await expect(label).toContainText('Observed enrollment: included');
        await page.clock.setSystemTime(new Date((now - 60) * 1000)); await page.clock.fastForward(1000); await expect(label).toContainText('Enrollment unknown');
    });
});


async function expectStatusDOMCleared(page: Page, previousText: string[]) {
    await expect(page.locator('#status-view')).toBeHidden();
    await expect(page.locator('#people > *, #connection > *, [data-device-evidence], [data-control]')).toHaveCount(0);
    await expect(page.locator('#account-context')).toHaveText('');
    const text = await page.locator('#status-view').textContent();
    for (const value of previousText) expect(text).not.toContain(value);
}

async function privacyFixture(page: Page, origin: string) {
    const now = Math.floor(Date.now() / 1000), provenance = {source: 'synthetic-fake-router', routerCompatibilityVerified: false};
    const session = {...provenance, actor: {id: 'old_parent', displayName: 'Prior account fixture', role: 'parent', personIds: ['alex'], permissionVersion: '1'}, csrfToken: 'fixture_only', expiresAt: now + 600};
    const person = {id: 'alex', name: 'Prior child fixture', devices: [{id: 'old_phone', label: 'Prior device fixture', evidence: {source: 'synthetic-policy', sourceObservedAt: now,
        serviceReceivedAt: null, freshUntil: now + 31, freshness: 'fresh', enrollment: 'included'}}], manualPause: null, effectiveManualPause: null, scheduleBlocked: false,
        scheduleExplanation: 'Prior schedule fixture', observationHealth: 'healthy', status: 'confirmed', latestOperation: null};
    const status = {...provenance, people: [person], serviceDesiredRevision: 0, routerDesiredRevision: 0, routerConfirmedRevision: 0, revisionToken: 'fixture', observedAt: now,
        statusAgeSeconds: 0, lastSuccessfulConfirmationAt: now, errors: []};
    await page.clock.install({time: new Date((now - 1) * 1000)}); await page.clock.pauseAt(new Date(now * 1000));
    await page.route('**/auth/session', route => route.fulfill({json: session}));
    await page.route('**/auth/logout', route => route.fulfill({json: {}}));
    await page.route('**/people', route => route.fulfill({json: status}));
    await page.goto(origin);
    await expect(page.locator('[data-device-evidence="old_phone"]')).toContainText('Observed enrollment: included');
    return {session, status, oldText: ['Prior account fixture', 'Prior child fixture', 'Prior device fixture', 'Prior schedule fixture', new Date(now * 1000).toLocaleString()]};
}

test.describe('cleared status DOM', () => {
    test.use({serviceWorkers: 'block'});
    for (const action of ['logout', 'offline logout', 'cross-tab logout', 'permission revocation'] as const) {
        test(`${action} removes retained labels and evidence from hidden DOM`, async ({page, demo}) => {
            const fixture = await privacyFixture(page, demo.origin);
            if (action === 'logout' || action === 'offline logout') {
                if (action === 'offline logout') await page.evaluate(() => window.dispatchEvent(new Event('offline')));
                await page.getByRole('button', {name: 'Sign out', exact: true}).click();
            } else if (action === 'cross-tab logout') {
                await page.evaluate(() => window.dispatchEvent(new StorageEvent('storage', {key: 'cf-logout-event:v1', newValue: 'other-tab'})));
            } else {
                await page.route('**/auth/session', route => route.fulfill({status: 401, json: {error: {code: 'permissions_changed', message: 'Fixture permissions revoked'}}}));
                await page.getByRole('button', {name: 'Refresh status'}).click();
            }
            await expectStatusDOMCleared(page, fixture.oldText);
            expect(await page.evaluate(() => localStorage.getItem('cf-status-active:v1'))).toBeNull();
        });
    }
    test('account changes clear old DOM before delayed status, recover controls, and stay clear after a failed new scope read', async ({page, demo}) => {
        const fixture = await privacyFixture(page, demo.origin);
        fixture.session.actor = {id: 'new_parent', displayName: 'New account fixture', role: 'parent', personIds: ['blair'], permissionVersion: '1'};
        const newer = structuredClone(fixture.status);
        newer.people[0] = {...newer.people[0], id: 'blair', name: 'New child fixture', devices: [{...newer.people[0].devices[0], id: 'new_phone', label: 'New device fixture'}]};
        let release!: () => void; const gate = new Promise<void>(resolve => {release = resolve;});
        await page.route('**/people', async route => {await gate; await route.fulfill({json: newer});});
        await page.getByRole('button', {name: 'Refresh status'}).click();
        await expectStatusDOMCleared(page, fixture.oldText);
        release();
        await expect(page.locator('[data-person="blair"]')).toBeVisible();
        await expect(page.locator('[data-control="resume"]')).toBeEnabled();
        let sent = 0;
        await page.route('**/people/blair/resume', route => {
            sent++;
            return route.fulfill({json: {...fixture.status, operation: {...fixture.status, id: 'fixture_op', personId: 'blair', action: 'resume', revision: 1, state: 'confirmed', createdAt: fixture.status.observedAt,
                updatedAt: fixture.status.observedAt, confirmedAt: fixture.status.observedAt, error: null}}});
        });
        await page.locator('[data-control="resume"]').click();
        await expect.poll(() => sent).toBe(1); await expect(page.locator('[data-control="resume"]')).toBeEnabled();
        fixture.session.actor.permissionVersion = '2';
        await page.route('**/people', route => route.fulfill({status: 500, json: {error: {code: 'fixture_failure', message: 'Fixture status unavailable'}}}));
        await page.getByRole('button', {name: 'Refresh status'}).click();
        await expectStatusDOMCleared(page, [...fixture.oldText, 'New child fixture', 'New device fixture']);
        expect(await page.evaluate(() => localStorage.getItem('cf-status-active:v1'))).toBeNull();
    });
    test('late pre-revocation status response cannot restore cleared DOM or cache', async ({page, demo}) => {
        const fixture = await privacyFixture(page, demo.origin);
        let release!: () => void, entered!: () => void;
        const gate = new Promise<void>(resolve => {release = resolve;}), received = new Promise<void>(resolve => {entered = resolve;});
        await page.route('**/people', async route => {entered(); await gate; await route.fulfill({json: fixture.status});});
        await page.getByRole('button', {name: 'Refresh status'}).click(); await received;
        await page.evaluate(() => window.dispatchEvent(new StorageEvent('storage', {key: 'cf-scope-event:v1', newValue: 'revoked'})));
        await expectStatusDOMCleared(page, fixture.oldText);
        const response = page.waitForResponse('**/people'); release(); await response;
        await page.clock.fastForward(1000);
        await expectStatusDOMCleared(page, fixture.oldText);
        expect(await page.evaluate(() => localStorage.getItem('cf-status-active:v1'))).toBeNull();
    });
});
