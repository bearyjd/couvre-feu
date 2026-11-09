import type { InventorySource } from './router-inventory.ts';
import type { InventoryKind, InventoryPresence } from './inventory-hints.ts';

/**
 * Admin HTTP inventory DTOs; these are separate from the strict router inventory wire protocol.
 * Additive hint fields (UI plan C), admin-only like the rest of this DTO and never stored, alerted, audited or logged:
 * `id` is the inventory row id (what audit rows already use; never a MAC), `vendor` the OUI maker (absent for randomized or unlisted
 * addresses), `kind` a guess from hostname and vendor, `presence` derived from `source` and `lastSeen`, and `suggestedReplaces` the row id
 * this randomized row may replace. All of them are hints, never identity.
 */
export interface InventoryDeviceDTO {
    id: number; vendor?: string; kind: InventoryKind; presence: InventoryPresence; suggestedReplaces?: number;
    mac: string; inScope: boolean; ipv4: string[]; hostname: string | null; reportedByDevice: true; source: InventorySource;
    firstSeen: number; lastSeen: number; acknowledgedAt: number | null; personId: string | null; personName: string | null; flags: {new: boolean; private: boolean; unassigned: boolean};
}
export interface InventoryDTO {
    status: {baselineAt: number | null; lastOkAt: number | null; lastAttemptAt: number | null; lastError: string | null; refreshRequestedAt: number | null; pollSeconds: number; retentionDays: number};
    devices: InventoryDeviceDTO[];
}
