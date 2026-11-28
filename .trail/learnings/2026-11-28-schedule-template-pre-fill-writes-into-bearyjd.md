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
---

## Decided
Picking an age band writes the values into the existing form inputs instead of re-rendering, because a re-render rebuilds the markup and a freshly inserted live region is often not announced by screen readers. The preview gets no next-day suffix because each preview line already names the end day; the card rows keep it since they do not name it. The note saying the form was filled from a band is shown only while days, times and, where editable, type still match that band; editing the name keeps it because a band does not set a name.

## Tried and ruled out
Leaving the note up after hand edits, as first shipped: it then claimed something the form no longer held.

## Watch out
The chosen band stays selected after hand edits, so picking the same band again fires no change event until another option is chosen. Anything new in the open-form view state must be rendered by both the markup builder and the live update, or the next status refresh drops it. The service already normalises weekday order everywhere; sorting the draft only makes the posted body match a hand-typed one.

In the code:
- `web/public/schedule-editor.js`: `updateLive`, `formMarkup`, `view.open.template`.
