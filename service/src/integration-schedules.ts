import { DAYS } from '../../shared/src/router-schema.ts';
import type { RouterPolicy } from '../../shared/src/router-schema.ts';
import type { IntegrationManifest } from './integration-config.ts';
import { scheduleClockReader } from './schedule-clock.ts';

/** Clock evidence is an explicit owner assertion, not a new router/DST capability. */
function readScheduleState(policy: RouterPolicy, config: IntegrationManifest, routerTime: number | null, healthy: boolean, currentTime = routerTime, observationValidUntil = routerTime === null ? null : routerTime + 31, personId = config.person.id) {
    const schedules = policy.schedules.filter(s => s.person === personId);
    if (!schedules.length) return {scheduleBlocked: false, scheduleExplanation: 'No owner-configured schedule.', scheduleWitness: 'none' as const, scheduleValidUntil: null, scheduleCheckedAt: null, activeUntil: null};
    const clock = config.scheduleClock;
    const windows = schedules.map(s => `${s.id}: ${s.weekdays.join(', ')} ${s.start}–${s.stop}`).join('; ');
    const description = `Owner schedules in ${clock?.timezone ?? 'an unverified timezone'}: ${windows}. Resume clears only manual pause.`;
    const unknown = (reason: string) => ({scheduleBlocked: null, scheduleExplanation: `${description} Current schedule state unknown: ${reason}.`, scheduleTimezone: clock?.timezone, scheduleWitness: 'unverified' as const, scheduleValidUntil: null, scheduleCheckedAt: null, activeUntil: null});
    if (!healthy || routerTime === null) return unknown('fresh healthy router observation required');
    if (!clock?.conformance) return unknown('owner-reviewed router clock calibration required');
    const record = clock.conformance;
    if (routerTime < record.verifiedAt || routerTime >= record.validUntil || currentTime === null || currentTime < record.verifiedAt || currentTime >= record.validUntil) return unknown('router clock calibration is outside its verified interval');
    const readClock = scheduleClockReader(clock.timezone), local = readClock(routerTime);
    if (local.utcOffsetMinutes !== record.utcOffsetMinutes || readClock(currentTime).utcOffsetMinutes !== record.utcOffsetMinutes) return unknown('timezone offset differs from the reviewed clock; DST support is unverified');
    const scheduleValidUntil = Math.min(record.validUntil, observationValidUntil ?? 0);
    if (currentTime >= scheduleValidUntil) return unknown('router observation validity deadline passed');
    const day = DAYS.indexOf(local.weekday as typeof DAYS[number]), previous = (day + 6) % 7;
    const minute = local.minute;
    const active = schedules.filter(s => s.start < s.stop
        ? s.weekdays.includes(DAYS[day]) && minute >= s.start && minute < s.stop
        : (s.weekdays.includes(DAYS[day]) && minute >= s.start) || (s.weekdays.includes(DAYS[previous]) && minute < s.stop));
    const minutes = (time: string) => Number(time.slice(0, 2)) * 60 + Number(time.slice(3));
    const activeUntil = active.length ? Math.max(...active.map(s => {
        const nextDay = s.start > s.stop && minute >= s.start;
        return Math.floor(routerTime / 60) * 60 + (minutes(s.stop) - minutes(minute) + (nextDay ? 1440 : 0)) * 60;
    })) : null;
    return {activeUntil, scheduleBlocked: active.length > 0, scheduleExplanation: `${description} ${active.length ? `Active at the router observation: ${active.map(s => s.id).join(', ')}.` : 'No window active at the router observation.'} Based on owner-reviewed clock calibration; automatic DST and packet behavior remain unverified.`, scheduleTimezone: clock.timezone, scheduleWitness: 'owner-reviewed-clock' as const, scheduleValidUntil, scheduleCheckedAt: currentTime};
}

export function integrationScheduleState(policy: RouterPolicy, config: IntegrationManifest, routerTime: number | null, healthy: boolean, currentTime = routerTime, observationValidUntil = routerTime === null ? null : routerTime + 31, personId = config.person.id) {
    const {activeUntil: _activeUntil, ...state} = readScheduleState(policy, config, routerTime, healthy, currentTime, observationValidUntil, personId);
    return state;
}

/** Active schedule window end by the reviewed router clock, before applying any allowance. */
export function activeScheduleEnd(policy: RouterPolicy, config: IntegrationManifest, person: string, routerTime: number, now: number): number | null | undefined {
    const state = readScheduleState(policy, config, routerTime, true, now, routerTime + 31, person);
    return state.scheduleBlocked === null ? undefined : state.activeUntil;
}
