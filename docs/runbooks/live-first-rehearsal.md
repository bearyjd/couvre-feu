# Live FIRST rehearsal

This runbook covers the one-session rehearsal that must succeed before any one-device enrollment. It installs Couvre-feu with an empty policy, verifies it, uninstalls it and proves that managed original bytes, mode, owner, nanosecond mtime, prior absence, directory modes and firewall objects came back exactly. The permanent exclusion inode is retained; directory mtimes and other filesystem identity are outside this proof. Prepare the operator key first with the [operator SSH agent guide](operator-ssh-agent.md).

Everything runs in one SSH invocation, so the identity and prerequisite evidence is from the same session as the mutation. The tool never retries.

Before any rehearsal, complete the M4b gate and separately approved read-only `setsid` prerequisite inspection in the [v2 pilot runbook](live-penn-pilot-v2.md#before-the-rehearsal). A successful empty-policy rehearsal precedes that pilot.

## 1. Prepare the private configuration

Copy [`tools/live/config.example.json`](../../tools/live/config.example.json) to a private directory outside the repository and fill in the real values. The schema is in [`tools/live/README.md`](../../tools/live/README.md). Create the evidence directory with mode 0700 on a persistent, private filesystem (not tmpfs). Write the user's approval to the `authorizationPath` file and set `deadlineUtc` to the end of the approved window.

Check out the reviewed commit. The payload is built from the `HEAD` blobs of `router/` and `tools/live/`, never from loose disk files. The tool refuses if the index or working tree differs from `HEAD` there, including untracked, ignored, skip-worktree or assume-unchanged files. It runs git with every `GIT_*` variable removed and `core.fsmonitor=false`.

## 2. Plan and disclose

```sh
python3 -I tools/live/first-rehearsal.py plan "<PRIVATE_CONFIG>"
```

`plan` runs only locally and sends nothing to the router. It prints:

- the source commit and release ID
- the payload sha256 and size
- the remote script template sha256
- the exact ssh argv, including the resolved `ssh` path and the remote command
- the timeouts, the deadline and the roles
- the sha256 of the known_hosts file and of the admin public key file
- `planSha256`: the sha256 of the canonical JSON of the payload sha256, the full ssh argv, both timeouts, the deadline, the authorization and evidence paths, and the known_hosts and public key hashes

Show this output to the user. **The approval covers exactly `planSha256`.** Any change to the commit, configuration, template, key file or known_hosts file changes it, and the change needs new approval.

## 3. Execute once

```sh
python3 -I tools/live/first-rehearsal.py execute "<PRIVATE_CONFIG>" --expect-plan-sha256 <DISCLOSED_PLAN_SHA256>
```

Before connecting, `execute`:

1. rebuilds the whole plan and refuses if `planSha256` differs from the disclosed value
2. refuses unless now + local timeout + 300 s is no later than the deadline
3. checks that the public key's fingerprint matches the configuration and that `ssh-add -l` lists it
4. creates a new evidence directory, refusing if the name already exists or if `evidenceDir` is under `/tmp`, `/run`, `/dev/shm` or `/var/tmp`, or on tmpfs, according to `/proc/mounts`

It then runs one `ssh` with the payload on stdin. From then on, every local failure, including Ctrl-C, is reported as UNKNOWN with exit 2. On the router, the script writes the files to a fresh `mktemp -d /tmp/couvre-feu-first.XXXXXX` and runs the phases in order. Each phase prints one `PHASE <name> OK|FAIL <reason>` line:

| Phase | What it checks or does |
|---|---|
| PAYLOAD | Every file's sha256 matches the embedded manifest; the release closure modes are set |
| IDENTITY | Each role has one `br-lan` IPv4 neighbor with the configured MAC (management REACHABLE, as the installer requires; the others REACHABLE, STALE or DELAY) and one matching DHCP lease. `SSH_CONNECTION` comes from the management IP. No live MAC equals a protected historical MAC |
| PREREQ | Normal-PATH `stat` and `od` (coreutils `/bin/stat` and `/usr/bin/od` on the target) are callable; their paths are printed. `stat -c %y` on a probe file the script creates in its own staging directory, and on `/etc/config/firewall`, must show nine fractional digits, and `stat -c '%d %m'` on `/etc/config` must print a device number and an absolute mount point (the installer's same-filesystem proof). `install.sh` validates and stages without `--activate` and leaves no lock or stage residue |
| SNAPSHOT | Records sha256, mode, uid, gid, size and mtime (seconds plus nanoseconds) for every installer-managed path, their `.couvrefeu-tmp` siblings, the journal, recovery, release and lock paths, and records absent paths explicitly. Records mode, owner and existence for the managed directories (not their mtimes). Hashes `iptables-save`/`ip6tables-save` (comments and counters stripped), sorted `ipset list -n` and `ipset save` (members), `uci export firewall` and the root crontab. Every snapshot record is also printed as a `SNAPSHOT` line, so local `stdout.log` holds the baseline |
| INSTALL | `install.sh --activate` with the profile and `--protect` for management, JD and every historical MAC. No people are enrolled. The installer moves each existing original into its journal by rename, immediately before renaming the new content over the path, so the kernel keeps its bytes, owner, mode and nanosecond mtime (no copy, no `touch`, no hard link). It refuses, with no change, if an original's directory, the journal and the recovery journal are not on one filesystem (`stat -c '%d %m'` of the directories), because BusyBox `mv` would silently copy across filesystems. After the crontab rename it runs `/etc/init.d/cron reload` and then requires procd to report a running cron instance (`ubus call service list`); if either fails it reports `cron reload failed`, keeps the journal and does not report success (use the separately approved authenticated recovery/uninstall flow) |
| VERIFY | `cfctl status --json` is ok, with no drift, no errors, revision 0 and no kids or pauses |
| UNINSTALL | `/etc/.couvrefeu-release-<id>/uninstall.sh`, run exactly once (also after a VERIFY failure). Contention refuses safely. New-format uninstall restores cron while the installed executable is fenced, reloads through the audited service path, and requires the expected service state before restoring executables. Reconciliation failure preserves recovery evidence. Owned release and journal cleanup is restartable through `CFRETIREMENT 2`, whose unlink is last; the permanent mutex remains. |
| RESTORE | A second snapshot must equal the first byte for byte. Each difference prints as `DIFF` lines |
| CONNECTIVITY | The management and JD neighbors are still present with the same MACs |

The script never touches dnsmasq, the WAN zone, offload or firmware. It removes only its own staging directory.

## Exit codes

| Exit | Meaning | Action |
|---|---|---|
| 0 | PASS. `FIRST_REHEARSAL_PASS` is the final line, printed exactly once, and every phase passed | Record the evidence directory in the acceptance record |
| 1 | REFUSED. The tool stopped locally, or the remote script refused before `MUTATION_BEGIN`. No router mutation was attempted | Fix the cause. Get fresh approval before running again |
| 2 | FAIL or UNKNOWN. Mutation may have begun: a phase failed after install started, or the session ended without a complete result (timeout, dropped connection, unparseable output) | Follow the next section |

## Session drops and timeouts

The remote script refuses to begin INSTALL if more than 300 s have passed since it started. Once `MUTATION_BEGIN` is printed, it ignores SIGHUP and SIGPIPE and runs install, verify, uninstall and restore to completion even if the SSH session drops. It appends every marker line to `<stage>/phase.log` and child output to `<stage>/child.log`. It prints `INFO staging <stage>` (the path is also in local `stdout.log`). When stdout was lost, it keeps the staging directory and ends `phase.log` with `STAGE_RETAINED <stage>`.

`remoteTimeoutSeconds` (default 1800 s) is a generous last-resort router-side `timeout -s KILL`. BusyBox `timeout` kills only its direct child, the rehearsal shell, so installer or uninstaller processes could keep running after it. Size the timeout well above the expected few-minute runtime so the script bounds itself first.

INSTALL remains deliberately unbounded: a hung installer can outlive the remote timeout and leave an empty-policy installation; nothing is enrolled or paused then. The accepted M5 code-merge residual (2026-10-23) remains until a separately reviewed INSTALL supervisor proves whole-transaction drain and updates both live tools and budgets. The new recovery path does not itself bound INSTALL or authorize a watchdog. **M4b still blocks first live rehearsal and permanent installation:** final release identity, independent adversarial review, repository gates and separately approved target prerequisite inspection remain required.

### Stale install lock recovery

Each exact live-router invocation below requires separate approval. Password login, unrestricted administrator shell/edit rights and PTY access remain available. A timeout or dead recorded PID alone proves neither worker drain nor permission to remove a lock.

1. Preserve the private evidence, journal, transaction records and release directories. Obtain approval to inspect the retained state. Never unlink `/etc/.couvrefeu-mutex`, remove lock directories by hand, or infer ownership from age.
2. Select a complete, independently authenticated external release source. If `/etc/.couvrefeu-release-<id>` is absent or partial, supply another complete authenticated source through a separately reviewed staging step. Never execute partial installed helpers, old helpers or an environment-selected source/target. Source authentication includes the reviewed emitted bytes and required root ownership/modes; a manifest supplied alongside arbitrary bytes is insufficient.
3. From that source, run `<AUTHENTICATED_RELEASE>/cfctl recover-install-lock`. This administrator-only entry validates the permanent kernel mutex, boot/PID/starttime/token binding, owned locks and baseline. It refuses live workers and ambiguous, foreign or ownerless state. Success publishes a durable recovery-required fence: runtime commands and a fresh install remain refused until uninstall completes.
4. After successful recovery, run `<AUTHENTICATED_RELEASE>/uninstall.sh` once, with no arguments. This is the ordinary single uninstaller, including recovery of new-format interruption before journal `ready` when the immutable, digest-bound PREPARED baseline validates. Refusal preserves the evidence; do not repeat blindly. A separately reviewed continuation after another interruption uses the same authenticated recovery/uninstall flow.

#### What a kill leaves, and which command recovers it

None of these states is fixed by hand. Never edit or remove a lock directory, lock record, journal record or cron candidate yourself.

| Kill window | What it leaves | Recovery |
|---|---|---|
| Install/uninstall core step, inside runtime-lock publication (`cf_lock`: `mkdir`, then the owned token, then the PID, each created exclusively) | `etc/couvrefeu/runtime/lock` is empty, holds only a full or partial token, or holds the token plus a partial PID. The transaction owner stays `active`. | `cfctl recover-install-lock`, then `uninstall.sh`. Recovery accepts these states only as prefixes of the retained owner's own token and PID, under the transaction mutex it holds. A foreign PID or token, or any other entry, is still refused. |
| Cron `cfctl expire` (or another mutex-holding, non-transaction command) between `mkdir` and its PID | An empty `runtime/lock` directory | The next `cfctl expire` (the minute cron) holds the transaction mutex on its own descriptor. That proves the empty lock's creator is dead, so it removes the empty directory and proceeds. A lock with any record is never taken over this way. Until that run, install and uninstall still stop with "core operation is running". |
| Vendor admission between the platform-lock `mkdir` and its exclusive PID create | An empty `/tmp/couvrefeu-platform.lock` | `cfctl recover-platform-lock` removes it only if the directory is still empty. Once the lock is marked held, a TERM/INT/HUP in that window makes the process remove only its own empty directory. A signal in the single statement between `mkdir` and that marking takes the default action and leaves the empty directory for `recover-platform-lock`. An empty or partial `pid` file, a token or any other entry still refuses. |
| Install between `mkdir` of the journal and its `ready` marker, at any record (`.copy`, `dir_*`, `.before`, `.mtime`, `.staged`, `.after`). A profile `.staged` or `.after` may also be empty. | A pre-ready journal | `cfctl recover-install-lock`, then `uninstall.sh`. Before `ready`, the profile record is provisional: an absent or empty `.after`, or an empty or partial `.staged`, does not block admission. A non-empty `.after` must still match `.staged`, and a complete `.staged` must name the transaction's profile. The digest-bound PREPARED baseline and `prepared_partial_journal_check` own these records. |
| `uninstall.sh` inside PREPARED materialization, or a failed uninstall after it | A rebuilt (possibly pre-ready) journal. Its profile `.staged` now records the selected profile, never the original's bytes. | `cfctl recover-install-lock`, then `uninstall.sh` (after a kill), or `uninstall.sh` again (after a refusal). |
| `uninstall.sh` killed with an unpublished cron-quiescence candidate, followed by a reboot or crond restart | `cron-quiescing.pending.<token>` whose boot or daemon line no longer matches the live system | `cfctl recover-install-lock`, then `uninstall.sh`. Recovery checks the shape of the candidate's own boot and daemon lines (a changed boot or daemon means the old daemon is gone), binds the header, mode and token byte for byte, then recaptures. |

Known residuals, not fixed: PID reuse can defeat dead-PID stale-lock checks, because no process start-time identity is recorded in lock records. Orphan `.couvrefeu-prepared.<token>` candidate directories may remain as clutter. **Open, blocking for vendor profiles (pre-existing, not fixed):** `uninstall.sh` selects its profile from the journal or installed records only (`platform_choose runtime`), not from the transaction owner as `recover-install-lock` does. On a vendor profile, a pre-ready journal with no complete profile `.staged` (any kill before that record, including `prepared-bound`) therefore selects `strict`, and uninstall refuses with `transaction_profile_mismatch` after a successful recovery. The fixture coverage above uses the strict profile only.

Production legacy journals, DONE records and retirement state without new-format transaction/baseline binding refuse automatic restoration. Their generic cron/firewall callbacks cannot be proven drained by checking a daemon PID or waiting. Preserve them for a separately approved maintenance/reboot recovery design; no reboot is authorized here. Narrowing the earlier complete-legacy compatibility promise remains an outstanding scope decision. The pinned historical fixture proves isolated data restoration/authentication only, not production legacy safety.

## On FAIL or UNKNOWN

- Preserve the evidence directory unchanged. It holds `plan.json`, `stdout.log`, `stderr.log`, `exit-code.txt` and `summary.json`.
- Do not retry blindly. Do not rerun install or uninstall to "clean up".
- INSTALL or UNINSTALL failed: before `FAIL_AFTER_MUTATION`, the script takes a read-only snapshot and prints `DIFF` lines against SNAPSHOT (or `INFO post-failure snapshot equals SNAPSHOT`), showing exactly what the failed step left behind.
- INSTALL failed: the installer kept its journal. Uninstall was deliberately not attempted. Read the recovery runbook and get approval for a specific recovery command.
- UNINSTALL refused: drift protection kept the journal and the changed files. Resolve the drift explicitly. Never delete the journal.
- RESTORE failed: the `DIFF -` and `DIFF +` lines show the before and after records. Report them before doing anything else.
- UNKNOWN (ssh exit 255, timeout, Ctrl-C): the router may still be mid-transaction. Wait for `/tmp/couvrefeu-install.lock` and `/tmp/couvrefeu-platform.lock` to clear; if the install lock persists, use the separately approved [stale-lock recovery](#stale-install-lock-recovery) inspection rather than assuming the installer ended. Then, with a separately approved read-only command, read `<stage>/phase.log`, using the `INFO staging` path from local `stdout.log`. A final `FIRST_REHEARSAL_PASS` or `FAIL_AFTER_MUTATION` line, followed by `STAGE_RETAINED`, means the script finished. If neither line is present, the script did not finish. Inspect the journal state before deciding on recovery. Removing a retained staging directory needs its own approval.

## Restored and non-restored attributes

The recovery release `/etc/.couvrefeu-release-<id>` is created by `install.sh --activate`, and the journal records whether it was absent beforehand. After exact restoration, `uninstall.sh` retires it only if the baseline recorded it as absent and its contents still match the authenticated target inventory with no extra entries. The durable `CFRETIREMENT 2` receipt survives deletion of the journal, PREPARED baseline, owned release, compatibility locks, owner, recovery fence and DONE; its unlink is the final retirement operation under the permanent mutex. Drift refuses with the journal kept, like any other drift. A release that existed before installation is kept unchanged. RESTORE therefore expects exact equality for that release. The permanent `/etc/.couvrefeu-mutex` inode is intentionally retained after uninstall and must never be removed as cleanup; this exclusion artifact is outside the original-file restoration claim.

Directory mtimes (`/etc`, `/usr/sbin`, `/etc/config` and the rest) are a known non-restored attribute. Creating and removing entries changes them, and neither the installer nor the uninstaller restores them. The snapshot records directory mode, owner and existence only.

Originals are restored by rename, never by copy. For each existing original, install writes the new content to a sibling temporary file and proves it, re-checks that the live path is still the exact original, then runs two adjacent renames: the original into the journal (`backup/<key>.original`), then the temporary file over the path. It proves the journal original against the recorded sha256, mode, owner and nanosecond mtime. Between the two renames the path is briefly absent (no command runs there, and HUP/INT/TERM are ignored across the pair). If the second rename fails, or the journal original is not exact afterwards, the original is renamed straight back and proved (`original restored in place`). Only SIGKILL/power loss or a failed rollback leave the path absent; that state (journaled original plus the owned temporary file) is the only absent state preflight accepts: the authenticated recovery/uninstall flow validates the owned temporary and renames the original back. A managed path deleted after install, with no owned temporary file, is drift and refuses with the journal kept. Uninstall proves the journal original, renames it over the path (an atomic replace) and proves the result. Both refuse before any change unless the paths are on one filesystem and one mount: `stat -c '%d %m'` of the directories and their mount ID from `/proc/self/mountinfo` (a same-device bind mount has its own ID; unreadable or malformed mountinfo refuses). A rename changes ctime and may change the reported inode; RESTORE compares sha256, mode, owner, size and mtime, never inode numbers or ctime.

### Measured overlayfs identity (GL-XE3000, OpenWrt 21.02, 2026-10-14)

The 2026-10-14 00:05Z run refused at `install.sh:296` (main `7676637`) with `original hard link identity mismatch: etc/sysupgrade.conf; no installation made`; its post-failure snapshot equals the baseline. A read-only probe then measured:

- `/rom` is squashfs (dev 45831), `/overlay` is f2fs (dev 66304), and `/` is `overlay lowerdir=/,upperdir=/overlay/upper,workdir=/overlay/work` with no `index` or `xino` option (overlay dev 19).
- `/etc/sysupgrade.conf` was copied up long ago with an origin xattr. `stat -c %d:%i` reports `19:1072`: the overlay dev with the lower inode (`/rom/etc/sysupgrade.conf` is `45831:1072`; the upper file is `66304:1392`).
- `/etc/config/firewall` has no origin (it was replaced by rename). It reports the upper file's real `66304:1409`, which is why it passed.
- A new hard link to a copied-up file with an origin reports a different dev:ino than the original name. Without `index=on`, overlayfs documents such hard links as broken. Hard-linking a lower-only file also copies it up first, a write to a managed path before any refusal.
- `/etc/crontabs/root` is absent.

Every managed path may therefore be lower-only, copied up with an origin, pure upper, or absent, and dev:ino is not identity in any of them. The installer uses none: identity is exact bytes, size, mode, owner and nanosecond mtime. Reading a lower-only original does not copy it up, so the journal step writes no managed path. Renaming a lower-only original into the journal makes the kernel copy it up at that moment, after every refusal gate, with its owner, mode and timestamps; whether this kernel and f2fs keep the nanoseconds is first proved by the live run (the installer refuses, journal retained, if not). After uninstall a formerly lower-only or origin original is a pure upper file with the exact original content and metadata; its overlay state is not restored. The fixtures in `tests/fixtures/overlay.py` model these four states; they are a model of measured behaviour, not overlayfs.

The 2026-10-15 23:18Z run refused at PREREQ `touch_mtime_not_nanosecond`: the target's BusyBox 1.33.2 `touch -r` truncates nanoseconds (only `stat` is coreutils). Installing `coreutils-touch` was rejected as a permanent package change. Exact preservation therefore no longer uses `touch` (or `cp -p`) at all: originals move by rename, and neither PREREQ nor the installer calls `touch`.

A controlled failure such as ENOSPC while constructing the initial journal can
roll back that journal and leave every managed original unchanged while retaining
the digest-bound PREPARED baseline and transaction record. The diagnostic reports
recovery required. After the fault clears, run the ordinary authenticated
`uninstall.sh` to retire that proof before retrying installation. A new install
refuses this retained-baseline state even with identical options; changed RPC or
protected identities cannot redefine its inventory. A killed owner still requires
`cfctl recover-install-lock` before the ordinary uninstall.

Cron reconciliation distinguishes an installation that never published its table
from one that may have exposed it. A token-bound `CFCRON 2` record preserves that
choice before any table restoration. An untouched baseline can keep the existing
daemon after the audited reload and service-state checks; this does not prove its
in-memory table contents. A potentially published table still requires the old
instance identity to disappear, and retries retain that requirement. If checking
a saved cron original fails after successful publication, the installed table and
saved original remain as evidence; that exceptional path never rolls them back
into an apparent unpublished state. Older `CFCRON 1` records always retain the
replacement requirement.

An interruption while writing the completion record can leave a private
`DONE.next` prefix. Recovery accepts it only under the intact bound transaction,
exact restored-phase marker and complete restoration proofs. Malformed bytes,
hard links or conflicting completion state refuse before handover.

New-format installation publishes immutable PREPARED before managed writes and records integration intent before executable/include/cron publication. An unbound prepublication candidate is preserved as diagnostic residue; no prefix-based cleanup adopts it. Retirement is restartable using the durable receipt, which separately binds the authenticated source and owned target release. Historical unmarked releases remain pre-existing evidence and are never adopted or removed automatically.

### Residual risk: in-place writes during install or uninstall

The journal `.original` is the original file itself, renamed. A writer that already holds it open (`>>` in progress, an editor) writes into the journal original; the post-rename proof, every preflight and every restore detect that as `corrupt original backup` and refuse with the journal kept. An in-place write can also race the install rename. Do not edit `/etc/config/firewall`, `/etc/sysupgrade.conf` or `/etc/crontabs/root` while either script runs.

- The journal also keeps `backup/<key>.copy`, a plain byte copy read from the live path and checked against the recorded sha256. It is for manual recovery only. It does not restore mode, owner or mtime, and restore never uses it. The same guarded cleanup removes it with the journal. A write while the journal is being made refuses with `original recovery copy mismatch` or `original changed while preserving`, and the journal is removed.
- Immediately before each install rename, `install.sh` re-checks the live path: before its original is journaled it must still be the exact original (sha256, which fixes its size, mode, owner and nanosecond mtime); afterwards the journal original must be exact and the path absent or content this journal owns. On a mismatch it refuses with `original changed in place before install rename`, and the journal is retained. A write that lands between this check and the rename is not detected; the rename is the next operation.
- The uninstall side only detects. A changed restored path is drift, and drift refuses with the journal (and `.copy`) retained. Once the exact-restoration check passes, later edits count as the user's own changes: final cleanup checks that each path still exactly matches its recorded original, so it removes `.copy` with the journal even if an in-place write lands between that check and cleanup.
- To recover by hand after such a refusal, compare the live file and `.original` with `.copy` and the `.before` and `.mtime` records. Then restore the bytes from `.copy`, and the mode, owner and mtime from the records, as a separately reviewed step. Never retry blindly.

### Residue from the 2026-10-13 refusal

The first live `install.sh --activate` (main `f5dba46`, release id `bbbf1568debe492f4785043d7c69e77b6778f880acc18449bead63176418f572`; confirm against the `BEGIN ... release=` line of that run's evidence) refused with `cannot preserve exact original metadata/mtime: etc/config/firewall; no installation made`. That version created `/etc/.couvrefeu-release-<id>` before the refusal and wrote no journal or release ownership marker, so the router still holds that directory. Installers keep it unchanged: a release with a different id is never inspected, adopted or removed. Expect it in any read-only listing of `/etc`. It may be removed only by a separately reviewed and approved step that first verifies it against its own `release.sha256`; neither this rehearsal nor `uninstall.sh` removes it.

## Evidence limits

The fixture tests (`tests/test-live-rehearsal.py`) run the generated payload through a fake `ssh` against a private fixture root with simulated router tools. Fixtures opt into the recovery-release path (`CF_TEST_RELEASE_DIR=1`) and run uninstall from that directory. They do not prove real BusyBox/ash behavior on the target, coreutils `stat` output on the target filesystems, Dropbear's handling of `SSH_CONNECTION`, real fw3/iptables restoration, or real crond timing. Production eligibility now requires exact audited cron init, `rc.common`, `procd.sh` and firewall init source hashes plus the admitted procd image binding. Unknown sources refuse before managed writes. These target bytes, callable `flock`/`setsid` behavior and service behavior remain UNVERIFIED; local doubles and SIGKILL fixtures prove neither target support, power-loss/reboot durability nor packet behavior.
