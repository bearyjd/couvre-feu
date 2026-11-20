---
title: "CT107 package installs can need an offline path, and its Host-header check means a bare local HTTP 200 is not a health gate"
author: Bearyjd
date: 2026-11-16
branch: main
cost: { minutes: 265, tokens: 1022638 }
id: l-cd10b600
scope: repo
status: active
src: agent
---

## Decided
- Node on CT107 was upgraded 26.8.1 to 26.13.1 with a sandbox-tested script and the owner's yes on its exact sha. Port ownership (ss -ltnp pid = new MainPID), the journal line, /proc/PID/exe and a 30 s soak are startup evidence only: they can pass while the service is broken (proxy returns 502, /health returns 503 on a database failure). The recorded upgrade evidence covered startup only; the configured-route check below was not verified for that upgrade.
- Health is declared only after a check through the configured route (the publicOrigin / proxy path, not a bare local request) that `GET /health` returns `ok:true` and the expected release in `version`, per docs/runbooks/deploy.md (Health and version). A 429 proves liveness only, not health.
- For the one package tested (psmisc), the .deb was pushed via <transfer-host>, with the sha pinned and cross-checked against CT107's own apt-cache SHA256. Before installing, run a dry run (`apt-get -s install ...` with the same options) to check the package transaction: with apt sources disabled, dependencies the .deb needs must already be installed or also pushed, or they stay unresolved.
## Tried and ruled out
- apt-get install psmisc on CT107: the Debian mirror timed out twice. That shows only that the tested mirror was unreachable from CT107 at that time, not that CT107 has no internet at all.
- `apt-get install --no-download /abs/pkg.deb` with the tested APT build on Debian 13 failed with "Pathname to install is not absolute" for the psmisc .deb; this was not tested for other packages or APT builds. What worked: `-o Dir::Etc::SourceList=/dev/null -o Dir::Etc::SourceParts=/dev/null /abs/pkg.deb`.
- A local HTTP 200 health gate: a request with a Host other than the configured one is answered 403 host_rejected (untrusted sources may instead be disconnected before Host validation, so the 403 is not guaranteed), and the app listens on listen.host in LAN modes. Use the configured route with the right Host instead.
- Parsing the service port with sed: manifest.router.port is the SSH port, not the service port; use the top-level `port` via node JSON.parse.
## Watch out
- Executors edit in place, so save a copy of a reviewed artifact before every change, or a delta review cannot be diffed.
- Stubs that accept the exact command string hide real command bugs: make them reject bad forms.
In the code: docs/runbooks/deploy.md (tracked deploy runbook) and the service /health source (service/src/health.ts). Private operator records, not in the repo: the upgrade script under ~/.cache/cf-overnight/node-upgrade/ (sha e80c93e1334d) and the gitignored .omc/research/live-log.txt and .omc/STATE.md.
