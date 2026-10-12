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
| `evidenceDir` | string | Absolute path to an existing directory you own, with no group or other write access. Use a private path that is not tmpfs: each run creates a new `<UTC>-first-rehearsal/` directory there |
| `authorizationPath` | string | Absolute path to a regular file recording the user's approval of this exact run. Its sha256 goes into the evidence |
| `deadlineUtc` | string | `YYYY-MM-DDTHH:MM:SSZ`. `execute` refuses if now + 300 s is past this time |
| `platformProfile` | string | Optional. One of `strict`, `gl-xe3000-4.8.3-logd-011-v1`, `gl-xe3000-4.8.3-os-trust-v1` (the default) |
| `remoteTimeoutSeconds` | integer | Optional, 120–1800, default 900. Router-side `timeout -s KILL`. The local timeout is this value + 60 s |
| `roles.management` | object | `{"ip", "mac"}`. The SSH client device. Its MAC is protected |
| `roles.jd_adult` | object | `{"ip", "mac"}`. The adult device that must stay connected. Its MAC is protected |
| `roles.penn_child` | object | `{"ip", "mac"}`. The child device. It must be present, but it is **not** enrolled |
| `protectedHistoricalMacs` | array | 1–32 MACs to protect (for example Bryn's) that need not be present. None may equal a live role MAC |

MACs must be canonical lowercase `aa:bb:cc:dd:ee:ff`, unicast and non-zero. Live role MACs and IPs must be distinct from each other and from `host`.
