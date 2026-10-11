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
