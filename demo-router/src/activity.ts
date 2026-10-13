/** Fictional, deterministic counters in the `cfctl rpc-activity --json` shape. No real traffic is observed or modelled. */
import type { ActivityDevice, OffloadState, RouterActivity } from '../../shared/src/router-activity.ts';
import type { RouterPolicy } from '../../shared/src/router-schema.ts';

/** The fictional router "reboots" its counters weekly, which exercises the service reset path. */
export const DEMO_EPOCH_SECONDS = 7 * 86400;
const mix = (a: number, b: number): number => {
    let h = (Math.imul(a ^ 0x9e3779b9, 0x85ebca6b) ^ Math.imul(b + 0x7f4a7c15, 0xc2b2ae35)) >>> 0;
    h = Math.imul(h ^ (h >>> 15), 0x2c1b3c6d) >>> 0;
    return ((h ^ (h >>> 12)) >>> 0) / 4294967296;
};
const seed = (id: string) => [...id].reduce((sum, c) => (sum * 31 + c.charCodeAt(0)) | 0, 7);
/** One fictional minute: busy in the afternoon and evening, light chatter otherwise, blocked attempts during the night schedule. */
export function syntheticMinute(person: string, device: number, minute: number): {tx: number; rx: number; txPackets: number; rxPackets: number; blocked: number} {
    const hour = Math.floor(minute / 60) % 24, roll = mix(seed(person) + device, minute);
    const busy = (hour >= 15 && hour < 21) ? 0.6 : (hour >= 6 && hour < 8) ? 0.25 : (hour >= 8 && hour < 15) ? 0.1 : 0.02;
    const bytes = roll < busy ? Math.floor(150000 + mix(minute, device + 1) * 4000000) : Math.floor(1500 + roll * 6000);
    const night = person === 'alex' && (hour >= 22 || hour < 6);
    return {tx: Math.floor(bytes * 0.1), rx: bytes - Math.floor(bytes * 0.1), txPackets: Math.ceil(bytes / 9000), rxPackets: Math.ceil(bytes / 1400),
        blocked: night && mix(minute, 99) < 0.3 ? 1 + Math.floor(mix(minute, 7) * 12) : 0};
}
export function syntheticActivity(policy: RouterPolicy, nowSeconds: number, offload: OffloadState = 'off'): RouterActivity {
    const epoch = Math.floor(nowSeconds / DEMO_EPOCH_SECONDS), first = epoch * DEMO_EPOCH_SECONDS / 60, last = Math.floor(nowSeconds / 60);
    const devices: ActivityDevice[] = [];
    let index = 0;
    for (const person of policy.people) person.macs.forEach((mac, slot) => {
        const total = {tx: 0, rx: 0, txPackets: 0, rxPackets: 0, blocked: 0};
        let recent = false;
        for (let minute = first; minute < last; minute++) {
            const m = syntheticMinute(person.id, slot, minute);
            total.tx += m.tx; total.rx += m.rx; total.txPackets += m.txPackets; total.rxPackets += m.rxPackets; total.blocked += m.blocked;
            if (minute >= last - 5 && m.tx + m.rx > 100000) recent = true;
        }
        devices.push({person: person.id, mac, ip: `192.168.8.${20 + index}`, neighbor: recent ? 'REACHABLE' : 'STALE', tx_bytes: total.tx, rx_bytes: total.rx,
            tx_packets: total.txPackets, rx_packets: total.rxPackets, blocked_packets: total.blocked});
        index++;
    });
    return {version: 1, router_epoch: 1, counter_epoch: epoch, offload, devices, errors: []};
}
