<!-- Generated: 2026-10-17 | Files scanned: ~200 | Token estimate: ~218 -->
# Frontend (web/public, static PWA, no bundler)
| File | Role |
|---|---|
| index.html, styles.css | parent shell |
| app.js (~530 lines) | main UI; calls /auth/session, /people, ops; imports auth-client, status-cache |
| auth-client.js | WebAuthn createPasskey/getPasskey |
| status-cache.js | actor-scoped cache of status/alert evidence |
| schedule-editor.js/.css | schedule CRUD UI (shared/src/schedule-edit.ts rules) |
| activity.js | per-child estimated activity (DOM + textContent only) |
| parent-alerts.js | server-persisted alerts + badge |
| operational-alerts.js | browser-local journal of operational alerts |
| time-requests.js | parent: request links, approve/decline |
| reward-time.js | parent: Reward +15 / +30 min buttons (flagged off) |
| request.html, request.js | child page; token in URL fragment |
| sw.js | shell-only offline cache; no API cache, no queued writes |
| manifest.webmanifest, icon.svg | PWA metadata |

Rules: dynamic text via textContent; nothing sensitive in browser storage.
Tests: web/tests/*.spec.ts (Playwright, chromium; browser-fixture.ts); `npm run test:web`.
