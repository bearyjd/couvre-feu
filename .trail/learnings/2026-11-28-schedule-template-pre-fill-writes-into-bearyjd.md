---
title: Schedule template pre-fill writes into the form and its note shows only while the form still matches
author: Bearyjd
date: 2026-11-28
branch: fix/template-note-and-quiet-hours-tests
id: l-27e7c44b
scope: repo
status: active
replaces: l-bf90e2d2
src: agent
touches:
  - web/public/schedule-editor.js
  - web/tests/schedule-editor.spec.ts
  - web/tests/integration-schedule-editor.spec.ts
  - service/src/push-runtime.ts
  - service/tests/push-digest.test.ts
---

## Decided
Picking an age band writes the values into the existing form inputs instead of re-rendering, because a re-render rebuilds the markup and a freshly inserted live region is often not announced by screen readers. The preview gets no next-day suffix because each preview line already names the end day; the card rows keep it since they do not name it. The note saying the form was filled from a band is shown only while days, times and, where editable, type still match that band; editing the name keeps it because a band does not set a name.
A test that checks the schedule form was left in place has to wait longer than two refresh ticks before looking. Validation errors from the server are written into the form in place and are not part of what decides a full redraw. Request counts after a save are polled, never read once. If the marker saying an alert was pushed cannot be saved before a restart, sending that one alert again is accepted, because the alternative is possibly losing it.

## Tried and ruled out
Leaving the note up after hand edits, as first shipped: it then claimed something the form no longer held.
A refused-save test that checked immediately: it passed only because no tick landed in between and hid a real bug where the next tick rebuilt the form and silenced the screen reader announcement. A test demanding exactly one push after a failure between the two markers: it contradicted the guarantee that no held alert is lost. Reading the request count straight after server state changed: it failed roughly one run in eight on unchanged code.

## Watch out
The chosen band stays selected after hand edits, so picking the same band again fires no change event until another option is chosen. Anything new in the open-form view state must be rendered by both the markup builder and the live update, or the next status refresh drops it. The service already normalises weekday order everywhere; sorting the draft only makes the posted body match a hand-typed one.

In the code:
- `web/public/schedule-editor.js`: `updateLive`, `formMarkup`, `view.open.template`.
A marker that can never be saved still causes a repeat push on every pass while the alert stays open; that is recorded as a known failing test and is not fixed.

- `web/public/schedule-editor.js`: render key, `updateLive`.
- `web/tests/schedule-editor.spec.ts`, `web/tests/integration-schedule-editor.spec.ts`: waits and `expect.poll`.
- `service/src/push-runtime.ts` held and urgent mark writes; `service/tests/push-digest.test.ts` remaining `todo`.
