# Roadmap

Status as of 2026-10-27. This is the current plan; [`.omc/plans/full-app-roadmap.md`](../.omc/plans/full-app-roadmap.md) is the original, historical proposal. "Built" means code merged and tested in CI. It does **not** mean proven on a real router: nothing here has been run live yet (see [Live proof](#live-proof)).

## Tier 1: basics (built, not yet proven live)

Block or unblock one child, block or unblock all children, assign and move devices, parent sign-in with passkeys, and router-local timed pauses.

Open before the first live use:

| Item | State |
|---|---|
| First live rehearsal, then permanent install | Not run. Needs the owner at home and approval of the exact plan hash ([runbook](runbooks/live-first-rehearsal.md)). |
| Install watchdog (bound the install step) | Not merged. The bound must come from a measured install time on a quiet host or the real router; the first measurement under load exceeded the 80 s stop rule. A clean TERM at the `intent` phase leaves the router needing `recover-install-lock`, so the teardown outcome needs a redesign. |
| M4b evidence receipt | Template exists; not filled or signed. |
| Service key entry on the router, confinement probes, dispatch, live pause/resume/expiry/reboot tests | Follow the live rehearsal. |
| Fixed Wi-Fi address for children's devices | Household rule: scope and protection are MAC-based, so a device that rotates its address escapes them. |

## Tier 2: next

| Item | State |
|---|---|
| Ask for time (child requests, parent one-tap approval as timed grants) | Service built behind `timeRequests.enabled` (off by default): grants are router allowances, 60 min cap, lift pauses and schedules, a parent's Pause ends a grant. Web side and live proof remain. The design is in the maintainer's local planning notes (not in this repository). |
| Weekly schedules / bedtime per child | Designed; builds after ask-for-time. The first four steps need no router change and can merge behind an off-by-default flag; live proof of the time windows (flow offload off) needs the owner at home. The design is in the maintainer's local planning notes (not in this repository). |
| Device recognition and unknown-device alerts | Not started. A small read-only helper on the router; the design can start offline. |
| DNS enforcement | Partly shipped (kids' port 53 redirect, DoH set; see [enforcement contract](enforcement-contract.md)). Gap: port 853 and broader DoH coverage. Needs the "no DNS changes" project rule lifted explicitly, and the DNS baseline re-measured. |
| Per-child AdGuard profiles | Not recommended: on the GL firmware it likely breaks GL's own filtering, and AdGuard's per-client schedule is an inverse window that does not match this project's schedule model. Research notes are local (not in this repository). |

## Tier 3: later

VPN/Tor blocking lists from a feed; homework mode and a guest profile; a daily time quota; an activity view and weekly summary (estimated activity already exists).

## Follow-ups

- A fifth `test-core` CI partition (that suite cannot get under about 1000 s per shard with four).
- Split the tab logic out of `app.js` into its own file (needs a service static-file allowlist change).
- Close fd 9 for `timeout` children, a stderr warning when buffered output is lost, and the remaining full-pipe/signal tests (tracked in [tier1-rpc §9](contracts/tier1-rpc.md)).
- Parent iPhone check of the iOS restyle before it merges.

## Live proof

Unproven until a real run: power loss and durability, hardware behaviour, live traffic and packets, reboot, sync timing under the 13 s window with the OS-trust profile, the kernel time gate with flow offload on, and whether the installed release includes router allowances.

## Limits to state to users

A router cannot stop mobile data or hotspots, VPN to a direct IP, or a determined child. Device-level tools (Screen Time, Family Link) complement it. Per-device and client-IPv6 traffic, flow offload, inbound UDP, the 5 s cutoff and key confinement are unproven. See "Known limits" in [RUNBOOK.md](RUNBOOK.md).
