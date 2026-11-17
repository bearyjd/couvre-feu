---
title: "CT107 has no internet and rejects non-config Host headers: install packages offline and never gate health on HTTP 200"
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
- Node on CT107 was upgraded 26.8.1 to 26.13.1 with a sandbox-tested script and the owner's yes on its exact sha. Health is proven by port ownership (ss -ltnp pid = new MainPID), the journal line, /proc/PID/exe and a 30 s soak, never by an HTTP 200.
- Packages are installed from a .deb pushed via atlas, with the sha pinned and cross-checked against CT107's own apt-cache SHA256.
## Tried and ruled out
- apt-get install psmisc on CT107: the Debian mirror times out (no outbound internet, twice).
- `apt-get install --no-download /abs/pkg.deb` fails on Debian 13 (Pathname to install is not absolute). Use `-o Dir::Etc::SourceList=/dev/null -o Dir::Etc::SourceParts=/dev/null /abs/pkg.deb`.
- An HTTP 200 health gate: the app returns 403 host_rejected for any Host not equal to its configured host, and listens on listen.host in LAN modes.
- Parsing the service port with sed: manifest.router.port is 22; use the top-level `port` via node JSON.parse.
## Watch out
- Executors edit in place, so save a copy of a reviewed artifact before every change, or a delta review cannot be diffed.
- Stubs that accept the exact command string hide real command bugs: make them reject bad forms.
- In the deploy2 test, run suites one at a time; concurrent podman :Z relabel and the TERM-during-stop case both fail under load.
In the code: ~/.cache/cf-overnight/node-upgrade/upgrade-node-ct107.sh (sha e80c93e1334d), .omc/research/live-log.txt, .omc/STATE.md.
