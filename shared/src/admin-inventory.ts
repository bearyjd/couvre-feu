import type { InventorySource } from './router-inventory.ts';

/** Admin HTTP inventory DTOs; these are separate from the strict router inventory wire protocol. */
export interface InventoryDeviceDTO {
    mac: string; inScope: boolean; ipv4: string[]; hostname: string | null; reportedByDevice: true; source: InventorySource;
    firstSeen: number; lastSeen: number; acknowledgedAt: number | null; personId: string | null; personName: string | null; flags: {new: boolean; private: boolean; unassigned: boolean};
}
export interface InventoryDTO {
    status: {baselineAt: number | null; lastOkAt: number | null; lastAttemptAt: number | null; lastError: string | null; refreshRequestedAt: number | null; pollSeconds: number; retentionDays: number};
    devices: InventoryDeviceDTO[];
}
