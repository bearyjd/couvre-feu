import { AppError } from '../../shared/src/errors.ts';
import { object } from '../../shared/src/json.ts';
import type { AuthSession } from './auth.ts';
import type { InventoryStore } from './inventory-store.ts';
import type { Routed } from './time-requests-http.ts';

/**
 * Admin-only inventory routes (session and, for POST, Origin and CSRF are checked by the caller; the store refuses non-admins with 403).
 * `now` is the service clock: the page measures scan age against it, never against the viewer's own clock.
 * Hostnames leave here as plain strings that the device chose (`reportedByDevice: true`); the client must render them as text only.
 */
export function inventoryGet(inventory: InventoryStore | null, session: AuthSession, path: string): Routed | null {
    if (!inventory) return null;
    if (path === '/admin/inventory') return {status: 200, body: {inventory: inventory.list(session.dto.actor), now: inventory.now()}};
    // The "show hidden" filter: the same list with guests that went quiet for 14 days kept in. Exists only while inventoryUi.triage is on.
    if (path === '/admin/inventory/hidden' && inventory.triage) return {status: 200, body: {inventory: inventory.list(session.dto.actor, {includeHidden: true}), now: inventory.now()}};
    return null;
}
const ROW_ID = '[1-9][0-9]{0,9}';
const DECISION_PATH = new RegExp(`^/admin/inventory/(${ROW_ID})/(classify|undo|link|stable)$`);
/** DELETE /admin/inventory/:id/link; the caller (http.ts) checks Origin, session and CSRF first. */
export const INVENTORY_LINK_PATH = new RegExp(`^/admin/inventory/(${ROW_ID})/link$`);
export function inventoryDelete(inventory: InventoryStore | null, session: AuthSession, path: string): Routed | null {
    const row = INVENTORY_LINK_PATH.exec(path)?.[1];
    return inventory?.triage && row !== undefined ? {status: 200, body: {device: inventory.unlink(session.dto.actor, Number(row))}} : null;
}
export function inventoryPost(inventory: InventoryStore | null, session: AuthSession, path: string, payload: unknown): Routed | null {
    if (!inventory) return null;
    if (path === '/admin/inventory/acknowledge') return {status: 200, body: {device: inventory.acknowledge(session.dto.actor, object(payload, ['mac']).mac)}};
    const decision = DECISION_PATH.exec(path);
    if (decision && inventory.triage) {
        const actor = session.dto.actor, row = Number(decision[1]);
        // Strict bodies: unknown keys are refused, so a MAC or hostname sent along is a 400 and never read.
        if (decision[2] === 'classify') { const body = object(payload, ['role'], ['label']); return {status: 200, body: {device: inventory.classify(actor, row, body.role, body.label)}}; }
        if (decision[2] === 'undo') { object(payload, []); return {status: 200, body: {device: inventory.undo(actor, row)}}; }
        if (decision[2] === 'stable') return {status: 200, body: {device: inventory.confirmStable(actor, row, object(payload, ['value']).value)}};
        const replaces = object(payload, ['replaces']).replaces;
        if (!Number.isSafeInteger(replaces)) throw new AppError(400, 'invalid_replaces');
        return {status: 200, body: {device: inventory.link(actor, row, replaces)}};
    }
    if (path === '/admin/inventory/refresh') {
        object(payload, []);
        inventory.requestRefresh(session.dto.actor);
        return {status: 202, body: {requested: true}};
    }
    return null;
}
