# Live FIRST rehearsal

This runbook covers the one-session rehearsal that must succeed before any one-device enrollment. It installs Couvre-feu with an empty policy, verifies it, uninstalls it and proves that every original file, mode, owner, timestamp, absence and firewall object came back exactly. Prepare the operator key first with the [operator SSH agent guide](operator-ssh-agent.md).

Everything runs in one SSH invocation, so the identity and prerequisite evidence is from the same session as the mutation. The tool never retries.

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
| PREREQ | Normal-PATH `stat` and `od` (coreutils `/bin/stat` and `/usr/bin/od` on the target) are callable; their paths are printed. `stat -c %y` on a probe file the script creates in its own staging directory, and on `/etc/config/firewall`, must show nine fractional digits. `install.sh` validates and stages without `--activate` and leaves no lock or stage residue |
| SNAPSHOT | Records sha256, mode, uid, gid, size and mtime (seconds plus nanoseconds) for every installer-managed path, their `.couvrefeu-tmp` siblings, the journal, recovery, release and lock paths, and records absent paths explicitly. Records mode, owner and existence for the managed directories (not their mtimes). Hashes `iptables-save`/`ip6tables-save` (comments and counters stripped), sorted `ipset list -n` and `ipset save` (members), `uci export firewall` and the root crontab |
| INSTALL | `install.sh --activate` with the profile and `--protect` for management, JD and every historical MAC. No people are enrolled |
| VERIFY | `cfctl status --json` is ok, with no drift, no errors, revision 0 and no kids or pauses |
| UNINSTALL | `/etc/.couvrefeu-release-<id>/uninstall.sh`, run exactly once (also after a VERIFY failure). If a cron `cfctl expire` holds the runtime lock, uninstall waits up to 20 s (OS-trust admission deadlines still refuse first), then refuses fail-safe. When this installation created the recovery release, uninstall removes it as its final command after verifying it against `release.sha256` |
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

## On FAIL or UNKNOWN

- Preserve the evidence directory unchanged. It holds `plan.json`, `stdout.log`, `stderr.log`, `exit-code.txt` and `summary.json`.
- Do not retry blindly. Do not rerun install or uninstall to "clean up".
- INSTALL failed: the installer kept its journal. Uninstall was deliberately not attempted. Read the recovery runbook and get approval for a specific recovery command.
- UNINSTALL refused: drift protection kept the journal and the changed files. Resolve the drift explicitly. Never delete the journal.
- RESTORE failed: the `DIFF -` and `DIFF +` lines show the before and after records. Report them before doing anything else.
- UNKNOWN (ssh exit 255, timeout, Ctrl-C): the router may still be mid-transaction. Before any inspection, wait until both `/tmp/couvrefeu-install.lock` and `/tmp/couvrefeu-platform.lock` are gone. Then, with a separately approved read-only command, read `<stage>/phase.log`, using the `INFO staging` path from local `stdout.log`. A final `FIRST_REHEARSAL_PASS` or `FAIL_AFTER_MUTATION` line, followed by `STAGE_RETAINED`, means the script finished. If neither line is present, the script did not finish. Inspect the journal state before deciding on recovery. Removing a retained staging directory needs its own approval.

## Restored and non-restored attributes

The recovery release `/etc/.couvrefeu-release-<id>` is created by `install.sh --activate`, and the journal records whether it was absent beforehand. After an exact uninstall, `uninstall.sh` removes it as its last command, but only if the journal recorded it as absent and its contents still match `release.sha256` with no extra entries. Drift refuses with the journal kept, like any other drift. A release that existed before installation is kept unchanged. RESTORE therefore expects exact equality for it, with no allowlist.

Directory mtimes (`/etc`, `/usr/sbin`, `/etc/config` and the rest) are a known non-restored attribute. Creating and removing entries changes them, and neither the installer nor the uninstaller restores them. The snapshot records directory mode, owner and existence only.

Known residue cases: if installation stops after creating the release but before writing its journal, a later run sees the release as pre-existing and keeps it. If an interrupted uninstall removed the journal marker before the final step, the release is also kept. Both leave only the verified reviewed release.

## Evidence limits

The fixture tests (`tests/test-live-rehearsal.py`) run the generated payload through a fake `ssh` against a private fixture root with simulated router tools. Fixtures opt into the recovery-release path (`CF_TEST_RELEASE_DIR=1`) and run uninstall from that directory. They do not prove real BusyBox/ash behavior on the target, coreutils `stat` output on the target filesystems, Dropbear's handling of `SSH_CONNECTION`, real fw3/iptables restoration, or real crond timing.
