---
title: "Do not auto-merge npm major bumps: the npm version is a pinned toolchain value, and green CI proves nothing about it"
author: Bearyjd
date: 2026-11-20
branch: chore/renovate-hold-npm-major
id: l-92c06dad
scope: repo
status: active
src: agent
touches:
  - renovate.json
  - package.json
---

## Decided
Renovate's npm major bump (npm 12) was closed unmerged and Renovate is told to stop proposing npm majors. The npm version is part of the pinned toolchain (the exact npm the docs, the container build and the offline CT107 install all name), so moving it is a deliberate change made together with a Node bump and updated pins, not a dependency update.

## Tried and ruled out
- Merging the bump because CI was green: all checks passed, but CI never installed or asserted npm 12, so green said nothing about it. Under Node 26.13.1 (bundles npm 11.x) a strict install fails with an engine mismatch.
- Letting the minor/patch bump through unchanged: it needed a fix first, because CI did not provision the pinned npm either (the same blind spot); the fix installs and asserts the exact npm in CI.

## Watch out
- CT107 has no internet, so any npm change must also be installable offline.
- A Codex review caught this where CI did not; for toolchain-pin changes, check what CI actually installs.
In the code: renovate.json packageRules entry for npm major; the engine pin in package.json; the CI step that asserts the npm version (from the npm 11.21.3 bump).
