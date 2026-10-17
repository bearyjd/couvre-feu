# Live FIRST rehearsal tool

`first-rehearsal.py` builds and runs one SSH session that performs the FIRST live rehearsal: identity gate, prerequisite check, snapshot, empty install, verify, exact uninstall, restoration proof and connectivity check. `first-rehearsal.sh` is the remote POSIX/BusyBox ash script; the Python tool embeds the committed `router/` tree and the configuration values into it. Read the [runbook](../../docs/runbooks/live-first-rehearsal.md) before use.

The tool uses only the Python standard library and refuses to run unless started with `python3 -I`.

## Configuration schema

Keep the real configuration outside the repository, in a private directory. [`config.example.json`](config.example.json) uses fictional MACs (`02:00:00:00:00:xx`) and documentation IPs (`192.0.2.0/24`). The tool validates strictly: it rejects unknown keys, missing keys, duplicate keys and non-canonical values.

| Key | Type | Rule |
|---|---|---|
| `schemaVersion` | integer | Exactly `1` |
| `host` | string | Router LAN IPv4 in canonical dotted form; the tool always connects as `root@<host>` |
| `adminPublicKeyPath` | string | Absolute, normalized path to the admin **public** key. Its fingerprint must equal `adminKeyFingerprint`. The private key stays in the agent; the tool never reads it |
| `adminKeyFingerprint` | string | `SHA256:` followed by 43 base64 characters, as printed by `ssh-add -l` |
| `knownHostsPath` | string | Absolute path to a regular file holding the pinned router host key (`StrictHostKeyChecking=yes`) |
| `evidenceDir` | string | Absolute path to an existing directory you own, with no group or other write access. It is refused under `/tmp`, `/run`, `/dev/shm`, `/var/tmp` or on tmpfs. Each run creates a new `<UTC>-first-rehearsal/` directory there |
| `authorizationPath` | string | Absolute path to a regular file recording the user's approval of this exact run. Its sha256 goes into the evidence |
| `deadlineUtc` | string | `YYYY-MM-DDTHH:MM:SSZ`. `execute` refuses unless now + local timeout + 300 s is no later than this time |
| `platformProfile` | string | Optional. One of `strict`, `gl-xe3000-4.8.3-logd-011-v1`, `gl-xe3000-4.8.3-os-trust-v1` (the default) |
| `remoteTimeoutSeconds` | integer | Optional, 600–3600, default 1800. Generous last-resort router-side `timeout -s KILL`; the script bounds itself first. The local timeout is this value + 60 s |
| `roles.management` | object | `{"ip", "mac"}`. The SSH client device. Its MAC is protected |
| `roles.jd_adult` | object | `{"ip", "mac"}`. The adult device that must stay connected. Its MAC is protected |
| `roles.penn_child` | object | `{"ip", "mac"}`. The child device. It must be present, but it is **not** enrolled |
| `protectedHistoricalMacs` | array | 1–32 MACs to protect (for example Bryn's) that need not be present. None may equal a live role MAC |

MACs must be canonical lowercase `aa:bb:cc:dd:ee:ff`, unicast and non-zero. Live role MACs and IPs must be distinct from each other and from `host`.

## One-device Penn pilot (`penn-pilot.py`)

`penn-pilot.py` performs gate 3 of the [ordered live gates](../../docs/integration-004.md#ordered-live-gates) in one SSH session. It uses the same configuration schema. Use a separate config copy whose `authorizationPath` records approval of this exact pilot. Each run creates a `<UTC>-penn-pilot/` evidence directory. Here, `penn_child` **is** enrolled, and its MAC is the only MAC the policy may contain. The tool asserts this locally and again on the router before any write. `remoteTimeoutSeconds` must cover the disclosed worst case (`minimumRemoteTimeoutSeconds` in the plan); with the default timing that is 2,917 s, so raise it from the 1,800 s default. The minimum is the pre-mutation budget (360 s) + one safe-band wait and the install allowance (72 + 240 s) + the per-phase worst cases (ENROLL 431, PAUSE 465, RESUME 345, EXPIRY 624, DNS 80 s; each `cfctl` call is a 72 s safe-band wait + 45 s, each counters snapshot 80 s, each probe iteration 40 s) + the 300 s teardown reserve. On the router, each phase starts only if elapsed time plus its worst case still leaves the teardown reserve, and every observe/expiry iteration and counters snapshot re-checks this; otherwise the pilot stops into teardown (`remote_budget_reserved_for_teardown`). Every timed pause is extended by the slowest `cfctl` call measured so far in the session (capped at the 45 s `cfctl` allowance, which the budgets above already include because the call runs inside the pause window), so a pause cannot lapse inside its own `cfctl pause` on a loaded host; the call still runs exactly once. Read-only `iptables`/`ipset` reads run under `timeout -s KILL 8`. `cfctl` calls are not KILL-wrapped: a killed `cfctl` could leave its runtime or platform lock behind and make the single uninstall refuse.

```sh
python3 -I tools/live/penn-pilot.py plan CONFIG      # disclose, then:
python3 -I tools/live/penn-pilot.py execute CONFIG --expect-plan-sha256 HEX
```

The remote script is the filled `first-rehearsal.sh` with its final call removed, followed by `penn-pilot.sh`, which reuses every `cfr_*` helper. It runs these phases in order:

| Phase | What happens |
|---|---|
| PAYLOAD, IDENTITY, PREREQ, SNAPSHOT | As in the rehearsal. In addition, Penn must be REACHABLE/DELAY, own exactly one IPv4 neighbor row and one lease, and no protected MAC may appear on Penn's IP. PREREQ validates the exact `--rpc-allow` arguments |
| BASELINE | Router-side DNS (`nslookup example.com <router LAN IP>`, centisecond timing), management/JD ping and crond count (split: `etc` = crond whose crontab dir resolves to `/etc/crontabs`, `other` = any other crond such as GL firmware's `-c /tmp/gl_crontabs`; the `MEASURE crond_processes` line reports `baseline=etcN,otherM`). All read-only. Tolerance: baseline maximum + 1.5 s DNS, + 500 ms management RTT. A ping is a STOP signal only if it answered at baseline |
| INSTALL | Scoped activation `--rpc-allow <penn MAC> --activate`. No `authorized_keys` or service-key provisioning (`service_key_confinement: unmeasured, not exercised`) |
| ENROLL | `cfctl rpc-sync` with a stdin request file for a fresh generation at revision 0. Status must show only Penn observed |
| PAUSE | Timed pause (180 s). REJECT counters for Penn's MAC/IP rules, read with `-S`/`-nvxL` and never `-Z`, are sampled over 60 s while adult probes run. An increase means "router-side block observed"; otherwise "packet blocking unmeasured" |
| RESUME | Status clean, kernel set clear, and REJECT counters must not increase |
| EXPIRY | Second timed pause (120 s) with no further `cfctl` call. The kernel set is polled read-only until cron `cfctl expire` clears it, within 150 s after `until`. crond counts are recorded with the same `etcN,otherM` split; `duplicate_etc_crond` is appended to the MEASURE line (informational, no pass/fail effect) if more than one `/etc/crontabs` crond is seen after install or during expiry |
| DNS | Router-side hit counters for the DoT/DoQ/DoH/:53 rules generated for enrolled kids (they apply while enrolled, independent of pause), plus adult router DNS timing. Every changing apply builds a new `cf2_a`/`cf2_b` slot with fresh counters, so each counters snapshot records the slot and the identity (inode, nanosecond mtime) of `firewall.owned`. Hits are summed only over windows whose two snapshots share one slot instance (enrolled→prepause, pause0→pause1, resume0→resume1, expired→final; `windows=k/4`); apply transitions and the expiry wait are not counted. A slot change or a falling counter makes a window, or packet blocking, unmeasured. No DoH list is configured, so DoH stays unmeasured. Client-side redirect/DoH is always unmeasured |
| UNINSTALL, RESTORE, CONNECTIVITY | The single teardown, as in the rehearsal |

After `MUTATION_BEGIN`, every outcome ends in that one teardown. This includes an adult-probe STOP, a failed gate, an exhausted time budget and an installer failure, provided the installed recovery `uninstall.sh` exists. The teardown is part of the approved procedure, not a retry. If it ends with exact restoration, the last line is `PENN_PILOT_STOPPED_RESTORED`, or `PENN_PILOT_STOPPED_RESTORED_CONNECTIVITY_FAILED` (outcome `STOPPED_CONNECTIVITY_FAILED`) when the management or JD neighbor check failed afterwards; if the teardown itself fails, it is `FAIL_AFTER_MUTATION`. Only `PENN_PILOT_PASS` means that every phase passed and the snapshot matched exactly. Even then, packet blocking is claimed only when counters rose.

### If the single uninstall is absent or refuses

The last lines are then `PHASE UNINSTALL FAIL ...`, `PENN_KERNEL_STATE paused|clear|unknown` and `FAIL_AFTER_MUTATION UNINSTALL`, with `DIFF` lines showing what is left. Couvre-feu stays installed with its journal; do not retry and do not rerun install or uninstall to "clean up".

- `PENN_KERNEL_STATE paused` means Penn's MAC is still in the pause set and Penn is still blocked. The pause rules have no kernel time bound. Only `cfctl expire` (cron) or `cfctl resume penn` (a mutation that needs its own approval) lifts the pause. Both refuse while uninstall recovery markers exist under `/etc/couvrefeu/backup` (`uninstall_recovery_in_progress`), which happens when uninstall refused after kernel cleanup began. `unknown` means the set could not be read; treat it as paused.
- Do not run `cfctl remove-fw` by hand. Once recovery markers exist, it is refused without the installer's token, and only `uninstall.sh` runs it.
- Follow the [rehearsal runbook](../../docs/runbooks/live-first-rehearsal.md) failure guidance: wait for `/tmp/couvrefeu-install.lock` and `/tmp/couvrefeu-platform.lock` to clear, read `<stage>/phase.log` and `child.log` for the refusal reason (drift, lock contention, kernel cleanup), and resolve that cause explicitly. Then, as a separately approved step, run the installed `/etc/.couvrefeu-release-<id>/uninstall.sh` once. It takes no arguments, and it is the only supported way to remove the firewall slots, cron entry and files and to restore the originals. Never delete the journal (`/etc/couvrefeu/backup`).

Every `cfctl` call waits until the router clock is between seconds 15 and 45 of the minute and no runtime or platform lock is held. That way it never races the per-minute cron `cfctl expire`, which fails on lock contention instead of waiting.

The pause rules (`--match-set cf2_<slot>_p src -j REJECT` and `-o br-lan -d <ip> -j REJECT`) have **no** kernel `-m time --datestop` bound. Only cron `cfctl expire` ends a timed pause. For that reason the pilot uses only timed pauses.

On the host, a thread samples RTT and a direct DNS query to the router before, during and after the session. These samples are evidence only: they cannot stop the remote script, but a disruption beyond tolerance prevents PASS. `summary.json` labels each measurement `measured` or `unmeasured`.

Never commit real MACs or IPs. Protected devices are listed only in the private config (`protectedHistoricalMacs`).
