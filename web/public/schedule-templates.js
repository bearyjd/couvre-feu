// Age-band schedule templates (owner decision D1, roadmap Phase 3 item 2). Editable starting points only: nothing is stored, no age or band
// leaves the browser, and a template never applies itself; a parent still saves each window. UNVERIFIED as a standard.
// "School night" = start days Sun to Thu (the planner's reading of D1); weekend = start days Fri and Sat. Every part crosses midnight.
const SCHOOL_NIGHT_DAYS = Object.freeze(['Sun', 'Mon', 'Tue', 'Wed', 'Thu']);
const WEEKEND_DAYS = Object.freeze(['Fri', 'Sat']);
const TABLE = Object.freeze({
  under10: Object.freeze({ schoolNight: Object.freeze({ weekdays: SCHOOL_NIGHT_DAYS, start: '19:30', stop: '07:00' }), weekend: Object.freeze({ weekdays: WEEKEND_DAYS, start: '20:30', stop: '07:30' }) }),
  '10to12': Object.freeze({ schoolNight: Object.freeze({ weekdays: SCHOOL_NIGHT_DAYS, start: '20:30', stop: '07:00' }), weekend: Object.freeze({ weekdays: WEEKEND_DAYS, start: '21:30', stop: '08:00' }) }),
  '13to15': Object.freeze({ schoolNight: Object.freeze({ weekdays: SCHOOL_NIGHT_DAYS, start: '21:30', stop: '07:00' }), weekend: Object.freeze({ weekdays: WEEKEND_DAYS, start: '22:30', stop: '08:00' }) }),
  '16to17': Object.freeze({ schoolNight: Object.freeze({ weekdays: SCHOOL_NIGHT_DAYS, start: '22:30', stop: '07:00' }), weekend: Object.freeze({ weekdays: WEEKEND_DAYS, start: '23:30', stop: '08:00' }) }),
});
export const BANDS = Object.freeze(Object.keys(TABLE));
export const PARTS = Object.freeze(['schoolNight', 'weekend']);

/** A new frozen {weekdays, start, stop} for a band and part, or null for an unknown band or part. */
export function templatePart(band, part) {
  if (typeof band !== 'string' || typeof part !== 'string' || !Object.hasOwn(TABLE, band) || !Object.hasOwn(TABLE[band], part)) return null;
  const { weekdays, start, stop } = TABLE[band][part];
  return Object.freeze({ weekdays: Object.freeze([...weekdays]), start, stop });
}
