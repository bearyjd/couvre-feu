# Live pilot v2

**Blocked before live use:** M4b must complete before the first live rehearsal or permanent installation. The new-format recovery path requires a final release identity and a full independent adversarial review/test cycle; target eligibility and prerequisites remain UNVERIFIED. Production legacy automatic restoration refuses pending a separate maintenance recovery decision. Acceptance of the installer residual for M5 code merges does not authorize a live run.

This pilot follows a successful [empty-policy rehearsal](live-first-rehearsal.md). It exercises a floor device and a phone, then attempts one uninstall and proves exact restoration. The operator approves each exact live invocation separately. This document grants no router or infrastructure access.

## Before the rehearsal

Keep password login available as break-glass recovery. Retain full administrator edit rights, including access to administrator keys, an unrestricted administrator shell and a PTY. The pilot does not change `authorized_keys`, Dropbear, password login or administrator access; do not disable or confine them for this procedure. See the [operator key guide](operator-ssh-agent.md).

After M4b, obtain separate approval for a read-only prerequisite inspection **before** the empty-policy rehearsal. Confirm `setsid` exists and, in the admitted non-interactive router shell, execs without forking: the baseline's background `( exec setsid /bin/sh -c 'exit 7' )` probe must yield status **7**, not 0. Record the callable path and exit status. This creates only a short-lived probe process; do not install a package or change configuration to manufacture a pass. The pilot repeats this check before mutation (`missing_tool setsid` / `setsid_forks` refuse). Its implementation is [`cfp_baseline`](../../tools/live/penn-pilot.sh).

Approve the exact rehearsal plan and complete its restoration proof before approving this pilot. Read-only checks, the rehearsal and the pilot are distinct authorizations; do not reuse their approval files.

## Prepare and approve the pilot

1. Check out the reviewed commit. Copy [`config.pilot.example.json`](../../tools/live/config.pilot.example.json) to a private directory outside the repository. Store real identities, keys, pinned host keys, authorization and evidence only there. The public example contains fictional addresses.
2. Use `schemaVersion: 2`. `roles.penn_child` is the floor device; `roles.scope_target` is the phone added to and removed from scope. Confirm ownership from the device itself. Neither may be an adult, management or infrastructure device. `roles.ct107` is protected infrastructure; its MAC must also be in `protectedHistoricalMacs`. The pilot never logs in to that container.
3. Preserve the management/adult protection set and every historical protected MAC. The install scope initially contains only the floor device. Schema v2 refuses `penn_child_2`; do not use the pilot config with `first-rehearsal.py`, which accepts schema v1 only.
4. Create private persistent evidence storage, a fresh exact-run authorization file and an adequate `deadlineUtc`. Review the [schema and source/key checks](../../tools/live/README.md#config-schema-v2-scope_target-and-configpilotexamplejson).

Run the plan locally; this command sends nothing to the router:

```sh
python3 -I tools/live/penn-pilot.py plan "<PRIVATE_CONFIG>"
```

Review the source commit/release, roles and protected set, phase order, payload and pinned-file hashes, timeouts, policies, operation ids, and the complete leg-1 and four leg-2 SSH argument lists. Approval binds the exact `planSha256`. Any changed source, configuration, authorization or pinned file requires a new plan and approval.

With shipped timing, `minimumRemoteTimeoutSeconds` is **10,371 s** (2 h 52 min 51 s), or **10,553 s** (2 h 55 min 53 s) with optional `scopeNegativeTest`. This is roughly 2.9 hours of conservative budgeting; it is **not a bound on INSTALL**, which remains deliberately unbounded. The example uses 10,700 s. The effective maximum is `min(10800, minimumRemoteTimeoutSeconds + 900)`; both shipped shapes are capped at 10,800 s. Local timeout adds 60 s, and the approval deadline must also allow the local tool's 300 s admission margin.

The pilot reserves 480 s for teardown (467 s worst disclosed failure path). Main-shell supervision includes two seconds of polling slack per call and a full 15 s KILL grace after TERM. V2 starts teardown at 70% of the remote timeout and refuses phases whose worst case crosses that mark. A run that consumes every conservative wait can therefore stop and restore before all phases pass. Use the actual plan's values for other timing settings.

After explicit approval, execute once:

```sh
python3 -I tools/live/penn-pilot.py execute "<PRIVATE_CONFIG>" --expect-plan-sha256 "<APPROVED_PLAN_SHA256>"
```

There is no retry. Do not start additional scope commands or type an independent confirmation while the driver owns the legs.

## Phases and the leg driver

The common opening is PAYLOAD, IDENTITY, PREREQ, SNAPSHOT, BASELINE, INSTALL and ENROLL. INSTALL activates an empty policy scoped to the floor device; ENROLL adds that device to policy. Optional SCOPE is an out-of-scope rejection check before SCOPE-ADD-1. The remaining v2 sequence is:

| Phase | Required observation |
|---|---|
| SCOPE-ADD-1 | Direct preview and no-TTY refusal leave scope unchanged; leg 2a adds the phone and 2b removes it. |
| SCOPE-ADD-2 | Wrapper preview and malformed-argv refusals leave scope unchanged; leg 2c adds the phone, then policy enrolls it with the floor device. |
| PAUSE / RESUME | Both devices enter and leave the kernel pause set; protected adult probes continue. |
| MOVE | Move the floor device to a temporary person, pause/resume it without pausing the phone, then move it back and prove the firewall fingerprint restored. |
| BULK | One policy sync pauses both policy persons; one resumes them. Require the expected receipt revisions and memberships. A failed block-all is reported as `unchanged`, not proof of packet behavior. |
| EXPIRY / DNS | Observe cron expiry without another modifying call, then collect scoped DNS/counter evidence; unmeasured behavior remains unmeasured. |
| INVENTORY | Three direct samples and one wrapper sample: validate shape, both pilot devices and exclusion of protected MACs. Keep counts, sizes, timings and hashes; never publish raw replies or household identities. |
| SCOPE-REMOVE | Unenroll the phone before leg 2d removes it from scope; require the original floor scope hash. |
| UNINSTALL / RESTORE / CONNECTIVITY | Attempt the single teardown, compare the original snapshot exactly and check protected connectivity. |

[`penn_pilot_leg2.py`](../../tools/live/penn_pilot_leg2.py) starts the four digest-bound `ssh -tt` commit legs locally under a PTY, in order, one at a time. It types the phone MAC's last six hex digits once only after the complete output exactly matches the expected operation/base line and confirmation prompt. Extra remote text refuses; local SSH stderr is counted, not treated as a prompt or retained. Each leg has a 60 s deadline, no retry and remote process-group supervision. Leg 1 independently rereads scope/status instead of trusting a leg's reply.

STOP, cancellation, leg-1 termination or local timeout prevents further legs and ends the active leg. After `CFP_LEG2_CANCEL`, the driver acknowledges only after local legs are reaped and a router-side process scan finds no commit still running. Teardown waits up to 75 s for acknowledgement, absent locks and stable scope; timeout is logged and the single uninstall still proceeds. See the [driver contract](../../tools/live/README.md#v2-phases-scope_target) for failure details.

## Outcomes and recovery

Exit 0 and `PENN_PILOT_PASS` mean every required phase and restoration proof passed. Packet blocking is established only where measured counters support it. Exit 1 is a refusal before mutation; exit 2 means STOPPED, FAIL or UNKNOWN after mutation may have begun. Inspect `summary.json` and the final marker: STOPPED with restoration is not a full pilot pass. Preserve the evidence directory privately, including `legs.json`, and report unmeasured results.

A disconnect does not prove the router-side work ended. Do not retry, rerun install or repeat uninstall blindly. The approved procedure attempts one uninstall when the recovery script exists; an absent/refusing script needs separately approved recovery. Password login is the manual break-glass path, with full administrator shell/edit rights intact. Follow [stale install-lock recovery](live-first-rehearsal.md#stale-install-lock-recovery) and [absent/refusing uninstall guidance](../../tools/live/README.md#if-the-single-uninstall-is-absent-or-refuses). Never delete the journal.

The accepted install residual remains: INSTALL is unbounded and can outlive the remote timeout with an empty-policy installation; nothing is enrolled or paused then. A separately reviewed watchdog phase must prove whole-transaction drain before changing this contract. For new-format state, use a complete authenticated external source for `cfctl recover-install-lock`, then its single ordinary `uninstall.sh`; do not remove locks manually. An absent journal `ready` is recoverable only with validated new-format ownership and PREPARED. Ambiguous/legacy state refuses and retains evidence. **M4b remains the blocker for any first live rehearsal or permanent installation.**

Implementation references: [phase/policy/timing contracts](../../tools/live/penn_pilot_v2.py), [local plan and execution](../../tools/live/penn-pilot.py), [remote phases/supervision](../../tools/live/penn-pilot.sh), and [install lock/journal preflight](../../router/lib/install-common.sh).
