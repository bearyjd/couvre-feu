---
title: "Green checks do not prove a base image update works, so build the image before merging it"
author: Bearyjd
date: 2026-11-27
branch: docs/learning-schedule-recovery-redesign
cost: { minutes: 3, tokens: 28633 }
id: l-c002c679
scope: repo
status: active
src: agent
touches:
  - ".github/workflows/ci.yml"
---

## Decided
Review a base image digest update by confirming the digest is what the registry tag points to, then building the image from the update merged onto current main and running offline smoke checks (runtime version, service user, ssh client present, main dependency imports). CI runs no image build, so all-green says nothing about it.

## Tried and ruled out
Merging on green checks alone. The checks also ran against older versions of main than the one being merged into.

## Watch out
On this workstation the container tool is a shell alias, so scripts must call it through the host. The HEALTHCHECK warning during a local build comes from the default image format and is not a failure.

In the code:
- `deploy/docker/Dockerfile` pins the digest; `.github/workflows/ci.yml` has no docker build step.
- `distrobox-host-exec podman build -f deploy/docker/Dockerfile -t localhost/<tag> .`
