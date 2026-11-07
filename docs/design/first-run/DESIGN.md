# First-run flow: add children, group devices (parent PWA)

Prototype: `index.html` (throwaway, inline JS allowed there only). Look = PR #80 tokens (system fonts, inset cards, pill buttons, tinted chips, light+dark). Checked at 360px and 700px: no sideways scroll, targets >=44px, no console errors. Screenshots in `shots/`.

## Flow (words)
Trigger: real-router mode, role admin, `GET /admin/children` returns `canCreate` and no child has a device (or a "Finish setup" card on the Devices tab). Tab bar is hidden during setup; "Later" returns to Overview and keeps progress.
1 Welcome -> 2 Add children -> 3 Prepare phones (random address) -> 4 Assign devices (inventory) -> 5 Review -> 6 Sending (per-change status) -> 7 Done + next steps.
States on screen 4: scan OK / scan OK but empty / router unreachable. Manual "add by Wi-Fi address" dialog is the fallback for all three.

## Screens and API mapping
| # | Purpose | Calls |
|---|---|---|
| 1 | Set expectations: 4 steps, passkey per change, nothing blocked by setup | none |
| 2 | Names (1-64 chars, no control chars, no duplicates client-side); optional "device group" (TV) | per entry: `POST /step-up/options {action:child_create}` then `POST /admin/children {name,kind,stepUp}` (admin-children.ts:259-260, 143; normalize :48-52; limit CHILD_LIMIT 64 integration-children.ts:9) |
| 3 | Fix the cause before picking: turn off Private Wi-Fi Address so the MAC is stable. Static copy, reused in a dialog from rows and review | none |
| 4 | Newest-first router inventory; pick child per device with a radio pill group (select when >4 children) | `GET /admin/inventory` (inventory-http.ts:11), `POST /admin/inventory/refresh` (:17, 202/409/429 copy at children.js:333-410); private flag = `isPrivateAddress` (router-inventory.ts:92) |
| 5 | Summary per child, editable device label, random-address count, total passkey prompts | none |
| 6 | Run changes sequentially; show each state honestly | per device: `/step-up/options {device_add}` then `POST /admin/children/:id/devices {label,mac,precondition,stepUp}` (admin-children.ts:259, 262, 168-186); poll `GET /admin/children` (children.js:53, reloads on status version bump :197) |
| 7 | Honest summary by state; next steps | none |
Not used here: `device_move`/`device_remove` (:212, :189) stay in the Devices tab for later fixes.

## State wording (never "applied" for queued)
- Waiting for your passkey | Saved here (child, no device yet, "not on the router") | Sent to the router, not confirmed yet (device `enrolling`, response has `operation`; children.js:75) | On the router, confirmed (`state:active` and `onRouter:true`, admin-children.ts:87) | Waiting for router approval, nothing added (409 `device_pending_router_scope`, :178; children.js:84). Reuses the existing "nothing was added and nothing is blocked" meaning.
- A child with no devices is not on the router (integration-children.ts `withoutDevice`), so "Saved here" is the true state.
- Unknown outcome after a timeout reuses children.js UNKNOWN_OUTCOME ("may have reached the router, check status before trying again").

## Copy decisions
- Frame as "so one pause reaches all their devices", never "monitor" or "catch". Kids are named, not counted. No shame for random addresses: "the router stops recognising the phone", not "the child is hiding".
- Device names are labelled "Name reported by the device" and rendered with textContent (existing M1 rule). No MAC is ever printed or placed in aria/data attributes; it only goes into the add request and the manual input value (inventory.spec.ts:299).
- Unknown device (null hostname): italic "Unnamed device" plus the Wi-Fi off/on then Refresh trick (newest first makes the row move).
- "Sent" and "confirmed" are different chips with different colours (amber vs green), and the text differs, so colour is never the only cue.
- Random-address warning appears when assigned (row), once more in review, and is non-blocking.

## Open questions for the owner
1. Passkey fatigue: step-up is bound per exact change, so 3 children + 6 devices = 9 prompts. Accept for v1, or add a bound batch action (service change, security review)?
2. Router scope: any MAC outside the install-time allow list hits `device_pending_router_scope` and needs `cfctl scope-add`. Expose `inScope` on `GET /admin/inventory` so the UI can show "needs router approval" before the passkey prompt? Without it the Switch row only learns this at send time.
3. Do setup-added children get schedules? Schedules are owner/manifest configured (integration-children.ts ownerSchedules), so "nothing is limited until you add a schedule" may be wrong where the manifest already has one. Confirm the copy on screen 7.
4. Does Bryn (admin) see JD's new children? `list()` filters by `actor.personIds` (admin-children.ts:85); confirm `scope_all` covers new rows. Screen 7 only says she can sign in.
5. Seeded manifest child (`seedChildren`) means "no children" is rarely true. Trigger on "no devices" or an explicit Finish-setup card?
6. OS how-to wording (iOS, Android, Windows) is from memory; verify on current versions. Is a QR or printable card for the other parent in scope?
7. Resume: keep draft in memory only (no storage of names/MACs, matches existing no-storage tests) or accept losing it on reload?

## Implementation plan
Files: new `web/public/first-run.js` (module, DOM via the `el()` helper pattern, textContent only), `first-run.css` (PR #80 tokens), mount point in `index.html`, one line each in `app.js` (near :29-30, `children.update()` :497) and `sw.js` ASSETS + bump `SHELL`. Reuse by export: `call`/`confirmed`/`queued` from children.js (extract to shared helper), `inventoryStatus`, `PRIVATE_HINT`. Keep children.js card list as the post-setup editor. No service change required for v1 (Q2 optional, ~0.5 day).
Tests (Playwright, `web/tests/first-run.spec.ts`, same fixtures as children/inventory specs): trigger for admin only, parent never sees it; add 3 children; dup/empty name errors; assign with private flag shows warning; unknown-device row; pending-scope 409 renders waiting-for-approval and no MAC in DOM; queued shows "not confirmed yet" and never "applied"; empty scan; router unreachable (503/transport); 360px and 700px no overflow, 44px targets; focus moves to h1 per screen; reduced motion. Add axe check for contrast.
Effort: ~3 days (UI 1.5, state/step-up sequencing 0.5, tests 1). +1 day if batch step-up (Q1) is wanted.
