# Operations runbook

Operational reference for people running Couvre-feu. It links to the detailed runbooks rather than repeating them. Every live-router command, including reads, needs approval of that exact invocation.

## Live rehearsal and pilot

| Task | Where |
|---|---|
| First empty install, verify, exact uninstall, restoration proof | [live-first-rehearsal](runbooks/live-first-rehearsal.md), tool `tools/live/first-rehearsal.py` |
| One-device pilot (gate 3) | [tools/live/README.md](../tools/live/README.md), tool `tools/live/penn-pilot.py` |
| Ordered live gates and integration manifest | [integration-004](integration-004.md) |
| SSH agent for the operator | [operator-ssh-agent](runbooks/operator-ssh-agent.md) |
| Vendor platform admission | [vendor-platform-admission](runbooks/vendor-platform-admission.md) |

Both tools run only as `python3 -I`, first `plan` (local, disclosed), then `execute ... --expect-plan-sha256 <HEX>` once. Keep the configuration, evidence and authorization record in a private directory outside the repository.

## Deployment

- LAN HTTPS: [lan-https](runbooks/lan-https.md)
- Plain HTTP behind a TLS-terminating proxy: [http-behind-proxy](runbooks/http-behind-proxy.md)

## Health and status checks

<!-- AUTO-GENERATED -->
| Command (on the router) | Reads |
|---|---|
| `cfctl status --json` | Desired and confirmed revision, effective pauses, observed sets, drift, capabilities, errors |
| `cfctl rpc-status --json [operation_id]` | Accepted policy, installation generation, receipt and runtime witness |

A healthy fresh install reports ok, no drift, no errors, revision 0, no kids and no pauses. `cfctl expire` runs from minute cron; confirm crond is running. Install checks (`cron_preflight`, `cron_running`) that `/etc/init.d/cron` is a `USE_PROCD=1` script, enabled at boot, and that procd reports a running cron instance. A separate firmware crond on `/tmp/gl_crontabs` (GL firmware) is normal.

Service side: `npm run integration:start -- "<PRIVATE_MANIFEST>"` refuses an edited manifest (its digest is bound in the database); `dispatch -- stop` revokes dispatch locally only; it does not prove remote drain or authorize router rollback.
<!-- /AUTO-GENERATED -->

## Common failures

| Symptom | Meaning and action |
|---|---|
| `FAIL_AFTER_MUTATION` | Mutation began and a step failed. **Never retry.** Do not rerun install or uninstall to clean up. Preserve the evidence directory, read the `DIFF` lines, and get explicit operator approval for a specific recovery command |
| Exit 2 / UNKNOWN (ssh 255, timeout) | The router may be mid-transaction. Wait until `/tmp/couvrefeu-install.lock` and `/tmp/couvrefeu-platform.lock` are gone, then use an approved read-only command to read the retained `phase.log` |
| Install failed | The installer kept its journal and uninstall is deliberately not attempted. Recovery needs approval |
| Uninstall refused (drift) | The journal and changed files are kept. Resolve the drift explicitly; never delete the journal |
| `uninstall_recovery_in_progress` | Recovery markers exist under `/etc/couvrefeu/backup`; `cfctl expire` and `resume` refuse. Only `uninstall.sh` clears them. Do not run `cfctl remove-fw` by hand |
| `PENN_KERNEL_STATE paused` or `unknown` | The child's MAC may still be blocked and the pause has no kernel time bound. Treat `unknown` as paused. Lifting it is a mutation needing its own approval |
| Restore `DIFF` mismatch | Report the `DIFF -` and `DIFF +` lines before doing anything else. Directory mtimes are a known non-restored attribute |
| `unsafe_private_path` / `unsafe_private_ancestor` | A manifest, key or data path is group/world accessible, a symlink, or has an unsafe ancestor. Fix the permissions; the service never repairs them |
| `unsupported_database_version` / `unsupported_database_schema` | The database is newer than or foreign to this build. Restore a backup or use a matching build |

## Rollback

- Router: `router/uninstall.sh` restores originals by rename after drift checks and proves exact restoration. It refuses on drift and keeps the journal. Uninstall exactness is part of every rehearsal; do not enroll before it has been proven.
- Service: database migrations (`PRAGMA user_version`, forward only) are not reversible. Before upgrading or any migration, stop the service and copy `integration.sqlite` together with `integration.sqlite-wal` and `integration.sqlite-shm` from `dataDir` into a private backup. Restore all three files together.
- A manifest edit changes its digest and existing database bindings refuse it; use reviewed private backup and recovery or a fresh enrollment, never edit identity markers to bypass the refusal.

## Feature flags

Time requests, the audit log and Reward Time ship off. Operating notes and the turn-on and turn-off checklist (including why a manifest edit needs `integration:rebind`) are in the [service contract](service-contract.md#operating-notes-for-the-flagged-features).

## Known limits

Couvre-feu enforces at the router. These cases are outside what a router can do:

- Mobile data and hotspots: a device that leaves the home network is not enforced.
- VPN and IP-direct traffic: traffic that avoids DNS or tunnels past the router is not reliably blocked. There is no VPN/Tor list and none is planned (owner decision 2026-10-28; reasons in [ROADMAP.md](ROADMAP.md#do-not-build)). A router cannot stop Tor or a VPN; on-device controls (Screen Time, Family Link) are the real answer. The DoT/DoH/853 and port-53 enforcement is unchanged.
- Encrypted DNS: kids' port 853 and UDP 784/8853 are blocked, but DoH is blocked only for addresses in the policy `doh` arrays (at most 256 per family, supplied by hand today), so any DoH resolver not listed still works. Unverified on a live router.
- A skilled kid: a determined child with technical knowledge may find a way around router-level controls.

These are unproven; do not rely on them until live evidence exists:

- Per-device and client-IPv6 traffic
- Flow offload interaction
- Inbound UDP
- The 5 s cutoff
- Confinement of the router key

Other constraints:

- Floor MACs (install-time scope) are removable only by reinstall.
- Growing the installed scope widens what `rpc-activity` exposes to the service.
