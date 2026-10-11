import { randomBytes } from 'node:crypto';
import { normalizePolicy } from '../../shared/src/router-schema.ts';
import type { Store } from './db.ts';
export const FICTIONAL_PEOPLE = [
    {
        id: 'alex', name: 'Alex (fictional)', devices: [{
                id: 'alex_phone', label: 'Fictional phone', mac: '02:00:00:00:02:01'
            }]
    },
    {
        id: 'blair', name: 'Blair (fictional)', devices: [{
                id: 'blair_laptop', label: 'Fictional laptop', mac: '02:00:00:00:02:02'
            }]
    },
];
export const PROTECTED_MACS = ['02:00:00:00:02:ff'];
export const INITIAL_POLICY = normalizePolicy({
    version: 1, revision: 0,
    people: FICTIONAL_PEOPLE.map(p => ({
        id: p.id, macs: p.devices.map(d => d.mac)
    })), pauses: [],
    schedules: [{
            person: 'alex', id: 'school_nights', weekdays: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'], start: '22:00', stop: '06:30'
        }],
});
export function seedAccounts(store: Store) {
    store.transaction(() => {
        for (const [account, name, role, people] of [['jd', 'JD (fictional)', 'admin', ['alex', 'blair']], ['bryn', 'Bryn (fictional)', 'parent', ['alex']]] as const) {
            store.run('INSERT OR IGNORE INTO accounts(id,display_name,role,person_ids,webauthn_user_id) VALUES(?,?,?,?,?)', account, name, role, JSON.stringify(people), randomBytes(32).toString('base64url'));
        }
        store.run('INSERT OR IGNORE INTO service_state(singleton,desired_json,highwater) VALUES(1,?,0)', JSON.stringify(INITIAL_POLICY));
    });
}
