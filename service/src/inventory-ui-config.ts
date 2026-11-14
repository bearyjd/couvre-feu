import { object } from '../../shared/src/json.ts';

/** Admin inventory UI switches (UI plan). Strict: only these three booleans; each defaults to false and an absent key is all off. */
export interface InventoryUiConfig { triage: boolean; wizard: boolean; installReadiness: boolean }
const KEYS = ['triage', 'wizard', 'installReadiness'] as const;

export function parseInventoryUi(value: unknown): InventoryUiConfig | undefined {
    if (value === undefined) return undefined;
    let settings: Record<string, unknown>;
    try { settings = object(value, [], [...KEYS]); } catch { throw new Error('invalid_inventory_ui'); }
    for (const key of KEYS) if (settings[key] !== undefined && typeof settings[key] !== 'boolean') throw new Error('invalid_inventory_ui');
    return {triage: settings.triage === true, wizard: settings.wizard === true, installReadiness: settings.installReadiness === true};
}
