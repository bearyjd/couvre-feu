import { object } from '../../shared/src/json.ts';
import type { AuthSession } from './auth.ts';
import type { InventoryStore } from './inventory-store.ts';
import type { Routed } from './time-requests-http.ts';

/**
 * Admin-only inventory routes (session and, for POST, Origin and CSRF are checked by the caller; the store refuses non-admins with 403).
 * Hostnames leave here as plain strings that the device chose (`reportedByDevice: true`); the client must render them as text only.
 */
export function inventoryGet(inventory: InventoryStore | null, session: AuthSession, path: string): Routed | null {
    return inventory && path === '/admin/inventory' ? {status: 200, body: {inventory: inventory.list(session.dto.actor)}} : null;
}
export function inventoryPost(inventory: InventoryStore | null, session: AuthSession, path: string, payload: unknown): Routed | null {
    if (!inventory) return null;
    if (path === '/admin/inventory/acknowledge') return {status: 200, body: {device: inventory.acknowledge(session.dto.actor, object(payload, ['mac']).mac)}};
    if (path === '/admin/inventory/refresh') {
        object(payload, []);
        inventory.requestRefresh(session.dto.actor);
        return {status: 202, body: {requested: true}};
    }
    return null;
}
