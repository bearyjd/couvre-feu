---
title: "CT107 has no internet and rejects non-config Host headers: install packages offline and never gate health on a bare local HTTP 200"
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
- Node on CT107 was upgraded 26.8.1 to 26.13.1 with a sandbox-tested script and the owner's yes on its exact sha. Port ownership (ss -ltnp pid = new MainPID), the journal line, /proc/PID/exe and a 30 s soak are startup evidence only: they can pass while the service is broken (proxy returns 502, /health returns 503 on a database failure). Health is declared only after a check through the configured route (the publicOrigin / proxy path, not a bare local request) that `GET /health` returns `ok:true` and the expected release in `version`, per docs/runbooks/deploy.md (Health and version).
- Packages are installed from a .deb pushed via atlas, with the sha pinned and cross-checked against CT107's own apt-cache SHA256.
## Tried and ruled out
- apt-get install psmisc on CT107: the Debian mirror times out (no outbound internet, twice).
- `apt-get install --no-download /abs/pkg.deb` fails on Debian 13 (Pathname to install is not absolute). Use `-o Dir::Etc::SourceList=/dev/null -o Dir::Etc::SourceParts=/dev/null /abs/pkg.deb`.
- A local HTTP 200 health gate: a request with a Host other than the configured one is answered 403 host_rejected (untrusted sources may instead be disconnected before Host validation, so the 403 is not guaranteed), and the app listens on listen.host in LAN modes. Use the configured route with the right Host instead.
- Parsing the service port with sed: manifest.router.port is 22; use the top-level `port` via node JSON.parse.
## Watch out
- Executors edit in place, so save a copy of a reviewed artifact before every change, or a delta review cannot be diffed.
- Stubs that accept the exact command string hide real command bugs: make them reject bad forms.
- In the deploy2 test, run suites one at a time; concurrent podman :Z relabel and the TERM-during-stop case both fail under load.
In the code: ~/.cache/cf-overnight/node-upgrade/upgrade-node-ct107.sh (sha e80c93e1334d), .omc/research/live-log.txt, .omc/STATE.md.
