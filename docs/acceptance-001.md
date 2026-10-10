# Acceptance 001 — evidence and recovery gates

This runbook preserves [PRP-001 §8](prp/PRP-001-enforcement-core.md) while incorporating the [spike](spike-001.md). Local implementation authorization does not authorize SSH, router staging/activation, network tests, firmware upgrade, service deployment or child enrollment. Each live run requires approval of its exact script, target, one test MAC, protected identities, expected effects and rollback. No approved test MAC is currently supplied.

## Evidence levels

| Level | Current meaning | Cannot establish |
|---|---|---|
| Local fixtures | Installer/core grammar, validation, restoration and simulated backend behavior | Real packets, target kernel/ash/awk, offload or household safety |
| Isolated supported OpenWrt integration | Pending actual fw3/iptables/ipset/conntrack environment | Live router acceptance |
| Live router | Pending separate exact-script approval | Firmware upgrade acceptance without its own run |

The complete local `sh tests/run.sh` run passed 43 installer fixtures (73.922 s), 64 core fixtures (477.869 s), ShellCheck and syntax checks using host sh. Independent source review approved head `06e924fa…`, with six focused tests (47.614 s) and a separate fresh-child/protected-STALE collision probe passing. Genuine BusyBox CI and latest-head review/checks remain merge gates; this evidence does not satisfy packet/live acceptance. For subsequent runs record command, commit, runtime versions, actual totals and concise failures. Run `sh tests/acceptance.sh --preflight` for read-only local discovery. `--fixtures` runs that same suite with explicit PRP §8 coverage mapping. `--installed` is a read-only installed-router check of dependencies, observed status and include/cron/preservation metadata; its exact live invocation still needs per-run approval and does not prove packet behavior. Its `--live` mode does not implement live actions; environment flags and a MAC never grant authorization. CI fixtures are not packet evidence.

## Before approving a live script

Resolve firmware identity, individually callable conntrack/ip6tables, shell/awk and newly required timeout behavior, timezone and clock health, GL includes/marks, DNS listener ownership and AdGuard health, current GL parental controls and acceleration. Obtain protected identities and uniquely resolve the current control client's IP-to-MAC mapping. The script must fail rather than guess on missing/ambiguous mappings or overlap. Preserve protection for noninteractive cron/include operations. Do not change WAN, dnsmasq, existing GL controls or offload merely to obtain a passing test.

Require a protected recovery connection, exact original backup/journal, safe uninstall procedure and an explicit abort condition before activation. Separately approve even read-only router commands. For isolated integration, establish real compatible tools first; missing dependencies keep the gate pending.

## Packet and operational matrix

| Test | Evidence required / pass condition |
|---|---|
| Pause during IPv4 video streaming | On the single approved child MAC, record pause confirmation and packet/playback cutoff within five seconds; protected adult access and DNS continue. Buffered playback alone is insufficient packet evidence. |
| Existing flow crosses schedule start | Real bidirectional established traffic, including inbound UDP, stops; early source-MAC and verified fresh child destination-IP time mirrors run before established acceptance. Confirm mappings cannot target protected/shared/stale addresses. Address gaps must show `addressCoverageComplete=false`/`incomplete_address_coverage` for required active coverage; expiry/resume/reconstruction clear obsolete rules despite gaps. An inactive policy can confirm with offline children. Native zone rules alone are insufficient. Test cross-midnight boundaries and declared timezone/DST behavior. |
| Resume during schedule | Manual pause clears while active schedule continues blocking; no bonus or Allow-until implied. |
| Timed pause, service offline | Absolute expiry survives service loss, cron re-evaluates current policy, access resumes within declared minute tolerance only if schedule allows. Verify reboot/stale sync cannot resurrect expiry. |
| Manual IPv4 DNS | Approved child queries to a chosen external resolver reach local DNS through kids-only redirect; correlate DNS logs/packet evidence and GL marks. Do not assume listener identity or logging is enabled. Any logging change needs separate consent/approval. Adults retain their original behavior. |
| Known DoH / Firefox | Choose an endpoint actually in the approved list; Firefox DoH fails or falls back. Record destination and result; a list cannot establish universal encrypted-DNS prevention. |
| DoT/DoQ | Approved child TCP/UDP 853 and UDP 784/8853 attempts fail while protected adults remain unaffected. |
| IPv6 | On a real approved child with usable global IPv6 and route, pause blocks external traffic. If unavailable, mark test unavailable, not passed. Verify external DNS blocking without NAT6 and local DNS usability. |
| Offload | Verify established-flow and schedule cutoff across the actual enabled acceleration path. Missing FLOWOFFLOAD text does not establish absence of hardware offload. Do not disable acceleration without separate approval. |
| WAN DNS from cellular | TCP and UDP checks to the actual WAN address from outside home Wi-Fi time out; record only sanitized result. WAN input is DROP in the spike. Listener binding and route health alone do not prove closure. |
| Firewall reload and reboot | Separately approved actions reconstruct pause/schedule rules and observed status with correct revisions; adults retain DNS/access. |
| Restricted key | Dedicated key cannot obtain an arbitrary shell, execute unlisted commands, or use port/agent forwarding or PTY; valid controls remain constrained. Compiled Dropbear strings and wrapper fixtures are insufficient runtime proof. |
| Same-line firmware upgrade | Separate approval, supported-version check, recovery access and preserved originals; post-upgrade dependencies, status and real rules/traffic pass. Preservation paths alone are insufficient. |

For each row retain timestamps, runtime/firmware, revision, sanitized command/script, expected result, actual result, logs and limitations. A failed or unavailable row remains a release blocker for that capability. Do not copy public WAN addresses, private neighbor inventory, credentials or real child identifiers into this public repository.

## Recovery and drift refusal

Default `router/install.sh` stages/validates without installing; `--activate` is explicit and belongs only in a separately approved script. Stage first with confirmed canonical protected MACs. The installer captures file bytes, permissions and original absence, retains a checksum journal, and records possible activation before applying so partial failures remain recoverable. It does not modify authorized keys.

After an approved partial install or activation failure, preserve `/etc/couvrefeu` and its journal. Uninstall records durable `kernel-cleaned`, `restoring` and `restored` phases. Before restoring managed directories it moves the journal to `/etc/.couvrefeu-recovery`; `/etc/.couvrefeu-recovery.done` records completed restoration while final journal cleanup finishes. Preserve either recovery artifact if interrupted; reinstall and ordinary core mutations refuse pending recovery even after transient locks are released. The authenticated installer handoff alone can continue internal remove-fw. Original files and directory records remain until all restorations succeed. The completion record is private, root-owned mode 600; validated temporary rename sources can resume, while foreign or wrong-metadata collisions are refused. Retries validate already-restored originals and remaining expected contents rather than invoking a core executable already restored/removed; kernel-cleaned skips completed kernel removal. Kernel cleanup retains an atomic `runtime/firewall.cleanup` inventory before deleting objects. Retries accept only exact recorded remaining objects, flushed empty owned chains, or absent objects; foreign references and changed remaining objects are refused. Preserve this intent and any validated `.cleanup.<pid>` artifact after failure. A separately approved `router/uninstall.sh` first checks owned objects and expected current contents, invokes internal kernel cleanup where applicable, restores exact originals, then reloads firewall. A reload failure retains recovery evidence. Only the trusted core’s exact validated zero-owned-mutation proof persists `no-kernel-mutations` and permits skipping original-firewall reload; partial-owned mutation still cleans up and reloads. Test refusal/rollback before first owned mutation separately from partial activation. Durable phase `.next` markers also block ordinary mutations. Do not assume uninstall is read-only.

On drift, stop: uninstall must refuse destructive restoration and preserve changed configurations. Compare the journal originals with current files and choose an explicitly reviewed resolution; do not delete changed files, force blanket restoration, or erase the journal. If dedicated-key setup was manually approved, its independently saved authorized-key originals and permissions require a separate reviewed restoration action.

No live test, SSH action, activation or firmware operation has been executed as part of this documentation.
