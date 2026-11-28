---
title: Schedule template pre-fill updates the add form in place
author: Bearyjd
date: 2026-11-26
branch: pub/t2-template-chooser
id: l-bf90e2d2
scope: repo
status: active
src: agent
touches:
  - "web/public/schedule-editor.js#applyTemplate"
  - "web/public/schedule-editor.js#updateLive"
---

Decided: picking an age band writes the values into the existing form inputs instead of calling render(), because render() rebuilds innerHTML and a freshly inserted aria-live region is often not announced by screen readers. The preview gets no '(next day)' suffix because each preview line already names the end day; the card rows from describe() keep it since they do not.
Watch out: the chosen option stays selected after hand edits (updateLive only hides the note while days, times or type differ from the band), so re-applying the same band fires no change event until another option is chosen. Anything new in view.open must be rendered by formMarkup or updateLive, or the next status refresh drops it.
The service already normalises weekday order everywhere; sorting the draft only makes the POST body match a hand-typed one.
