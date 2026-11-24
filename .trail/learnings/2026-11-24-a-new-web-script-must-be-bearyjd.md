---
title: "A new web script must be added to the service's static-file allowlist or sign-in breaks"
author: Bearyjd
date: 2026-11-24
branch: feat/digest-preview-panel
id: l-784d86bf
scope: repo
status: active
src: agent
touches:
  - web/public/sw.js
  - service/src/http.ts
---

## Decided
Any new file under the parent web app has to be listed in two places: the service worker asset list and the service's static-route allowlist. The panel work added the second entry.

## Tried and ruled out
The design said "no service changes" for the digest panel. That cannot hold: without the allowlist entry the new module is refused with 401 before sign-in, app.js fails to import it and the whole app stops loading.

## Watch out
The first green-looking run failed all 11 browser tests for this reason, not because of the panel logic. Check the allowlist first when a new module 401s.

In the code: web/public/sw.js (ASSETS), service/src/http.ts (static route allowlist, around line 47).
