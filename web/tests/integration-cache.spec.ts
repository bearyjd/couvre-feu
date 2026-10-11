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
