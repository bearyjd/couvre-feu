import { test, expect } from './browser-fixture.ts';
import type { BrowserContext } from '@playwright/test';

test.use({serviceWorkers: 'block'});

async function alertFixture(context: BrowserContext, origin: string) {
    const at = Math.floor(Date.now() / 1000), provenance = {source: 'synthetic-fake-router', routerCompatibilityVerified: false};
    const actor = {id: 'alert_parent', displayName: 'Explicit alert fixture', role: 'parent', personIds: ['alex'], permissionVersion: '1'};
    const evidence = {source: 'synthetic-policy', evaluatedAt: at, sourceObservedAt: null as number | null, serviceReceivedAt: null,
        freshUntil: null as number | null, freshness: 'unknown', healthy: false, confirmedOperationId: null,
        expiryVerifiedThrough: null as number | null, conditions: [{code: 'observation-unavailable'}] as {code: string}[], rawStderr: 'DO_NOT_RETAIN', mac: 'DO_NOT_RETAIN'};
    const person = {id: 'alex', name: 'Alert test person', devices: [], manualPause: null, effectiveManualPause: null, scheduleBlocked: false,
        scheduleExplanation: 'Explicit fictional alert fixture.', observationHealth: 'unconfirmed', status: 'unknown', latestOperation: null, operationalAlerts: evidence};
    let revoked = false;
    await context.route(origin + '/auth/session', route => revoked ? route.fulfill({status: 401, json: {...provenance, error: {code: 'session_expired', message: 'Fixture session expired'}}}) :
        route.fulfill({json: {...provenance, actor, csrfToken: 'DO_NOT_RETAIN', expiresAt: at + 600}}));
    await context.route(origin + '/people', route => route.fulfill({json: {...provenance, people: actor.personIds.length ? [person] : [],
        serviceDesiredRevision: 0, routerDesiredRevision: 0, routerConfirmedRevision: null, revisionToken: null,
        observedAt: evidence.sourceObservedAt, statusAgeSeconds: 0, lastSuccessfulConfirmationAt: null, errors: []}}));
    return {at, actor, person, evidence, revoke: () => { revoked = true; }, healthy: (time: number) => {
        Object.assign(evidence, {evaluatedAt: time, sourceObservedAt: time, freshUntil: time + 31, freshness: 'fresh', healthy: true, expiryVerifiedThrough: time, conditions: []});
        person.observationHealth = 'healthy'; person.status = 'confirmed';
    }, fail: (time: number) => {
        Object.assign(evidence, {evaluatedAt: time, freshness: 'unknown', healthy: false, expiryVerifiedThrough: null, conditions: [{code: 'observation-unavailable'}]});
        person.observationHealth = 'unconfirmed'; person.status = 'unknown';
    }};
}

test('local alert feed survives reload, witnesses one recovery and keeps recurrent warnings visible when history is muted', async ({page, demo}) => {
    const fixture = await alertFixture(page.context(), demo.origin);
    const errors: string[] = []; page.on('pageerror', error => errors.push(error.message));
    await page.clock.install({time: new Date((fixture.at - 1) * 1000)}); await page.clock.pauseAt(new Date(fixture.at * 1000));
    await page.goto(demo.origin);
    await expect(page.getByRole('heading', {name: 'Recent alerts in this browser'})).toBeVisible();
    await expect(page.locator('#alert-feed .alert-row')).toHaveCount(1);
    await expect(page.locator('#alert-feed')).toContainText('Current verification warning');
    await page.getByRole('button', {name: 'Refresh status'}).click();
    await expect(page.locator('#alert-feed .alert-row')).toHaveCount(1);
    await page.reload(); await expect(page.locator('#alert-feed .alert-row')).toHaveCount(1);
    await page.clock.fastForward(2000); fixture.healthy(fixture.at + 2);
    await page.getByRole('button', {name: 'Refresh status'}).click();
    await expect(page.locator('#alert-feed .recovered')).toHaveCount(1);
    await page.getByRole('button', {name: 'Refresh status'}).click(); await expect(page.locator('#alert-feed .recovered')).toHaveCount(1);
    await page.getByLabel('Hide recovery history').check(); await expect(page.locator('#alert-feed .alert-row')).toHaveCount(0);
    await page.clock.fastForward(1000); fixture.fail(fixture.at + 3);
    await page.getByRole('button', {name: 'Refresh status'}).click();
    await expect(page.locator('#alert-feed .alert-row')).toHaveCount(1);
    await expect(page.locator('#alert-feed')).toContainText('Current verification warning');
    await expect(page.locator('[data-control="pause"]')).toBeDisabled();
    await expect(page.locator('[data-control="resume"]')).toBeDisabled();
    const stored = await page.evaluate(() => JSON.stringify(localStorage)); expect(stored).not.toContain('DO_NOT_RETAIN');
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.screenshot({path: '/tmp/couvre-feu-operational-alerts-005-synthetic-ui.png', fullPage: true});
    await page.evaluate(() => window.dispatchEvent(new Event('offline'))); fixture.healthy(fixture.at + 4);
    await page.clock.fastForward(1000);
    await expect(page.locator('#alert-feed')).toContainText('Historical warning · unresolved');
    await expect(page.locator('#alert-feed .recovered')).toHaveCount(0); expect(errors).toEqual([]);
});

test('tabs share scoped episodes and preference; revocation clears alert DOM, memory and storage', async ({page, demo}) => {
    const fixture = await alertFixture(page.context(), demo.origin);
    await page.goto(demo.origin); await expect(page.locator('#alert-feed .alert-row')).toHaveCount(1);
    const other = await page.context().newPage(); await other.goto(demo.origin); await expect(other.locator('#alert-feed .alert-row')).toHaveCount(1);
    await page.getByLabel('Hide recovery history').check(); await expect(other.getByLabel('Hide recovery history')).toBeChecked();
    fixture.actor.permissionVersion = '2'; fixture.actor.personIds = [];
    await page.getByRole('button', {name: 'Refresh status'}).click();
    await expect(page.locator('#alert-feed .alert-row')).toHaveCount(0);
    await expect(other.locator('#status-view')).toBeHidden();
    await expect(other.locator('#alert-feed')).toBeEmpty();
    expect(await page.evaluate(() => JSON.stringify(localStorage))).not.toContain('observation-unavailable');
    fixture.actor.personIds = ['alex']; fixture.actor.permissionVersion = '3';
    await page.getByRole('button', {name: 'Refresh status'}).click(); await expect(page.locator('#alert-feed .alert-row')).toHaveCount(1);
    fixture.revoke(); await page.getByRole('button', {name: 'Refresh status'}).click();
    await expect(page.locator('#operational-alerts')).toBeHidden(); await expect(page.locator('#alert-feed')).toBeEmpty();
    const keys = await page.evaluate(() => Object.keys(localStorage).filter(key => key.startsWith('cf-alerts'))); expect(keys).toEqual([]);
    await page.evaluate(() => window.dispatchEvent(new StorageEvent('storage', {key: 'cf-alerts-active:v1', newValue: 'wrong-scope'})));
    await expect(page.locator('#alert-feed')).toBeEmpty(); await other.close();
});
