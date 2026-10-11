/** Read the declared timezone consistently for validation and observed schedule state. */
export function scheduleClockReader(timezone: string) {
    const formatter = new Intl.DateTimeFormat('en-US', {timeZone: timezone, weekday: 'short', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23'});
    return (time: number) => {
        const parts = formatter.formatToParts(new Date(time * 1000));
        const part = (type: Intl.DateTimeFormatPartTypes) => parts.find(p => p.type === type)!.value;
        const localEpoch = Date.UTC(+part('year'), +part('month') - 1, +part('day'), +part('hour'), +part('minute')) / 1000;
        return {weekday: part('weekday'), minute: `${part('hour')}:${part('minute')}`, utcOffsetMinutes: (localEpoch - Math.floor(time / 60) * 60) / 60};
    };
}
