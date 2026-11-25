<!-- Generated: 2026-11-24 | Files scanned: ~496 (origin/main 727daf6) | Token estimate: ~620 -->
# Frontend (web/public, static PWA, no bundler)
| File | Role |
|---|---|
| index.html, styles.css | parent shell: `#auth-view`, `#status-view`, `nav#tabbar` (home, kids, devices, alerts, more) |
| app.js (~650 lines) | main UI; calls /auth/session, /people, ops; imports `createX` factories and hands each a mount `<section>` (hidden until a flag or `/people` capability shows it) |
| auth-client.js | WebAuthn createPasskey/getPasskey |
| status-cache.js | actor-scoped cache of status/alert evidence |
| tabs.js | bottom tab bar (top bar from 900 px); hash routes #home #kids #devices #alerts #more; More sub-routes #more/{schedules,activity,audit,accounts,install,digest,about}; wraps the panels, never re-creates them |
| children.js | children, devices, Block all/Unblock all, bulk and inventory panels (changes behind step-up) |
| kids-card.js, kids-model.js | Kids tab cards (PR #172); `replacedMacs` |
| inventory-wizard.js, -wizard-model.js, inventory-triage.js | find-a-device wizard and triage for "Devices on the network" |
| schedule-editor.js/.css | schedule CRUD UI (shared/src/schedule-edit.ts rules); `schedules.editable` |
| schedule-templates.js | pure age-band template model (D1; four bands x school-night/weekend); wired into the schedule editor's add form as an "Age band (optional)" select (create mode only); `schedules.editable` |
| activity.js | per-child estimated activity (DOM + textContent only) |
| parent-alerts.js | server-persisted alerts + badge |
| operational-alerts.js | browser-local journal of operational alerts |
| accounts.js | passkeys and parent accounts |
| time-requests.js | parent: request links, approve/decline |
| reward-time.js | Reward +15/+30 min (only when `/people` says `rewardTime`) |
| focus-window.js | Focus 15-120 min and the Focus chip (only when `/people` says `focusWindow`) |
| audit.js | "Activity log" (`GET /audit/limit/50`, older via `/before/:id`; only when `/people` says `auditLog`) |
| content-filter.js | "Content filter" card on Home (`GET/PUT /people/:id/filter`); 404 `route_not_found` hides it for the session; loosening retries with a passkey step-up after a 403 `step_up_required` |
| digest-preview.js | "Weekly digest preview" panel in More (`#more/digest`; admin only; `GET /digest/preview`; 404/403 hides it, 503 shows "unavailable", never zero; nothing persisted, cleared on sign-out; refetches after offline) |
| install-readiness.js | "Install readiness" panel (`/admin/install-readiness`, admin) |
| pwa-update.js | update prompt and session grace (`createUpdatePrompt`, `createSessionGrace`); pairs with the `skipWaiting` handler in sw.js |
| request.html, request.js | child page; token in URL fragment |
| sw.js | network-first shell; offline cache fallback only for GETs of listed `ASSETS` (no query string); no API cache, no queued writes |
| manifest.webmanifest, icon.svg | PWA metadata |

Service worker cache: `SHELL='cf-shell-dev'` placeholder; at startup service/src/sw-shell.ts reads every `ASSETS` file (28 paths), hashes sw.js + served bytes and rewrites it to `cf-shell-<hash>[-<variant>]`. Every shipped file must be in `ASSETS` (startup throws otherwise); never hand-bump the name; restart the server after editing assets.
Rules: dynamic text via textContent; nothing sensitive in browser storage.
Tests: web/tests/*.spec.ts (28 Playwright specs, chromium; browser-fixture.ts, bulk-fixture.ts); `npm run test:web` (`CF_WEB_TEST_PORT`, `--workers=1`).
