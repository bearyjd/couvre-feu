# Runbook: deploying the parent app

Single entry point for running the integration service (`service/src/integration-main.ts`) on a host you control. Nothing here authorizes a router connection or mutation: generating the service key, adding it to the router, installing router software and enabling `dispatch` each need their own approval under `AGENTS.md` and [integration-004](../integration-004.md).

Placeholders: `<APP_IP>` (service host), `<PROXY_IP>` (TLS proxy as the service sees it), `<ROUTER_IP>` and `cf.example.invalid` (your public name). Never commit real values. The manifest, database, keys and known_hosts stay private and outside this repository.

Related: [http-behind-proxy](http-behind-proxy.md) (manifest fields, proxy recipe, residual risk), [lan-https](lan-https.md), [operator-ssh-agent](operator-ssh-agent.md).

## Choosing a deployment

| | systemd in a dedicated Proxmox LXC (default) | systemd on bare metal or a VM | Docker / Compose on a VM or host |
|---|---|---|---|
| Isolation | Own kernel namespaces; unit sandboxing on top. Use an **unprivileged** LXC; nesting is not required. | Whole host shared with other services unless the machine is dedicated | Container namespaces plus `read_only`, `cap_drop: ALL`; a VM adds a hypervisor boundary |
| Source-IP fidelity (`trustedProxies`) | Exact: the LXC has its own LAN address | Exact | **Exact only with `network_mode: host` or macvlan/ipvlan.** Bridge + published port can show every client as the bridge gateway |
| ssh-agent and service key | Dedicated `couvrefeu-agent.service` inside the LXC; key loaded by a human | Same, on the host | Agent still runs on the host (unit below); only its socket directory is mounted in |
| Upgrade / rollback | Replace `/opt/couvrefeu`, restart. Roll back code only with a pre-upgrade **database backup**; migrations are irreversible. Proxmox snapshot of the LXC is a convenient extra | Same, minus snapshots unless the VM/FS gives them | Rebuild image, recreate container. Same backup rule. Keep the previous image tag |
| Pros | Smallest moving parts, easy snapshots, strict network boundary at the hypervisor | No virtualization layer | Reproducible image; pinned Node digest |
| Cons | Needs a Proxmox host; some sandbox options may not work in every LXC (see below) | Larger blast radius | Docker networking footgun; extra daemon and image supply chain |

**Recommended default: a dedicated unprivileged LXC running the systemd units.** Docker inside a VM is supported when you already run containers; use host or macvlan networking.

## Common prerequisites

1. Node **26.13.1** and npm **11.19.0** (`package.json` `engines`). Install from the official tarball after verifying it, or use the pinned image below:

   ```sh
   V=26.13.1; T=node-v$V-linux-x64.tar.xz     # use the -linux-arm64 tarball on arm64
   curl -fsSLO https://nodejs.org/dist/v$V/$T
   curl -fsSLO https://nodejs.org/dist/v$V/SHASUMS256.txt
   curl -fsSLO https://nodejs.org/dist/v$V/SHASUMS256.txt.sig
   # Import the release signing keys listed in https://github.com/nodejs/release-keys (compare fingerprints
   # with that repository's README, not with this runbook), then:
   gpg --import <KEYRING_FROM_NODEJS_RELEASE_KEYS>
   gpg --verify SHASUMS256.txt.sig SHASUMS256.txt
   sha256sum -c --ignore-missing SHASUMS256.txt     # must report: $T: OK
   mkdir -p /opt/node-v$V && tar -xJf $T -C /opt/node-v$V --strip-components=1
   ln -sfn /opt/node-v$V/bin/node /usr/local/bin/node && node --version   # v26.13.1
   ```
2. A service user with a **fixed uid/gid 10001** so the systemd and Docker options are interchangeable: `useradd --system --uid 10001 --user-group --home-dir /var/lib/couvrefeu --shell /usr/sbin/nologin couvrefeu`.
3. Private directories, owned by that user and `0700`: `/var/lib/couvrefeu` (manifest `dataDir`) and `/etc/couvrefeu` (manifest, `known_hosts`, public key). The service rejects symlinks, wrong owners, group/world access and writable ancestors (`unsafe_private_path`, `unsafe_private_ancestor`). The manifest must be outside the source tree.
   **The service's private SSH key is not stored in either directory.** Both are readable by the service uid (and `/etc/couvrefeu` is mounted into the container), so a compromised service could copy an encrypted key and brute-force its passphrase. Keep the key in a root-only directory (`install -d -o root -g root -m 0700 /root/couvrefeu-key`, key file `0600 root:root`) and only ever hand it to the agent (below). Only the public key (`/etc/couvrefeu/service_key.pub`) and `known_hosts` live in `/etc/couvrefeu`.
4. `openssh-client` (the router transport runs `ssh` with `PATH=/usr/bin:/bin`).
5. A private manifest built from [integration-004](../integration-004.md) and [http-behind-proxy](http-behind-proxy.md): `listen.host` is `<APP_IP>`, `trustedProxies` lists exactly the address the service sees for the proxy, `publicOrigin` is `https://cf.example.invalid`, `router.agentSocket` is `/run/couvrefeu/agent.sock`.
6. Backups: install the daily backup timer (see [Backups](#backups)) before the first enrollment. Before any upgrade also stop the service and take a fresh copy with `node /opt/couvrefeu/deploy/backup.mjs` (or copy `integration.sqlite`, `integration.sqlite-wal` and `integration.sqlite-shm` together). Database migrations are not reversible; in particular migration 014 (content filtering) rebuilds `parent_audit` and raises the schema version, so rolling back the code requires restoring the pre-upgrade backup.

## Option 1: systemd (LXC, VM or bare metal)

Units: [`deploy/systemd/couvrefeu-agent.service`](../../deploy/systemd/couvrefeu-agent.service) and [`deploy/systemd/couvrefeu.service`](../../deploy/systemd/couvrefeu.service), plus the heartbeat and backup units described in [Monitoring (heartbeat)](#monitoring-heartbeat) and [Backups](#backups); example firewall [`deploy/systemd/couvrefeu.nft`](../../deploy/systemd/couvrefeu.nft).

**Firewall.** Copy `couvrefeu.nft`, replace every `<PLACEHOLDER>` (`<ADMIN_IP>`, `<PROXY_IP>`, `<ROUTER_IP>`, `<DNS_IP>`, `<NTP_IP>`), and keep package downloads done beforehand. It only manages `table inet couvrefeu` (re-running it replaces just that table). Apply it with a safety net:

```sh
nft -c -f /etc/couvrefeu.nft                 # syntax check, changes nothing
systemd-run --unit=couvrefeu-nft-rollback --on-active=5m nft delete table inet couvrefeu   # rollback timer
nft -f /etc/couvrefeu.nft
# Open a NEW SSH session (and test the proxy-to-app request) before continuing; the old session may survive on conntrack alone.
systemctl stop couvrefeu-nft-rollback.timer   # only after the new session works: cancels the rollback
```

Notes on the ruleset:

- **Static address required.** The ruleset drops DHCP. Give the host a static address, or, if you must use DHCP, add `udp dport { 67, 68 } accept` to both chains (and allow the lease server) first; otherwise the host loses its address when the lease expires. The file carries these as commented lines.
- **IPv4 only.** The allow rules (admin SSH, proxy, router, DNS, NTP) match IPv4. IPv6 is dropped except ICMPv6, which stays open so neighbor discovery works. The admin must connect over IPv4.
- **Tailscale is not combinable as written.** `tailscaled` needs outbound UDP 41641 plus control-plane/DERP access (HTTPS), and an input rule for `tailscale0`; this ruleset blocks all of that. If you run Tailscale on the host (for example to encrypt the proxy hop), add rules such as `iifname "tailscale0" ip saddr <PROXY_TAILNET_IP> tcp dport 4273 accept`, `oif "tailscale0" accept`, `udp dport 41641 accept` in both directions, outbound STUN `udp dport 3478 accept` and `tcp dport 443 accept` for the control plane and DERP relays, then re-run the check and rollback procedure. Otherwise leave Tailscale off this host.
- **Monitoring push.** If you install the heartbeat below, allow its outbound destination (`ip daddr <MONITOR_IP> tcp dport <MONITOR_PORT> accept`).

Make it persistent only after it survived a test; load it from a small unit or `nftables.conf` `include`.

```sh
# as root
install -d -o root -g root -m 0755 /opt/couvrefeu
tar -xzf couvre-feu-<COMMIT>.tar.gz -C /opt/couvrefeu          # from `git archive <COMMIT>`
(cd /opt/couvrefeu && npm ci --omit=dev --ignore-scripts)
chown -R root:root /opt/couvrefeu && chmod -R go-w /opt/couvrefeu   # service cannot modify its own code
install -m 0644 deploy/systemd/couvrefeu-agent.service deploy/systemd/couvrefeu.service /etc/systemd/system/
systemctl daemon-reload
```

Do not start yet. After the approved key and manifest steps exist:

```sh
systemctl enable --now couvrefeu-agent
# Load the key as root. root may connect to the socket (the directory is 0700 owned by the service user, but
# root bypasses it, and ssh-agent accepts root peers); the service user never reads the key file.
# SSH_ASKPASS_REQUIRE=never forces the passphrase prompt onto your terminal even if an askpass helper is installed.
env SSH_ASKPASS_REQUIRE=never SSH_AUTH_SOCK=/run/couvrefeu/agent.sock ssh-add [-t <LIFETIME>] /root/couvrefeu-key/service_key   # passphrase typed by a human
env SSH_AUTH_SOCK=/run/couvrefeu/agent.sock ssh-add -l
systemctl enable --now couvrefeu
systemctl is-enabled couvrefeu couvrefeu-agent   # both must print "enabled"; see Enable at boot check
journalctl -u couvrefeu -n 20 --no-pager   # "private LAN proxy HTTP https://cf.example.invalid via 1 trusted proxies"
```

Keep the encrypted key file root-only on the host and back it up offline.

**Key lifetime.** Choose one policy and write it into your procedure:

- *No expiry (omit `-t`)* suits an unattended service: the key stays loaded until the agent restarts or the host reboots. The key is constrained on the router (forced command, `from=` the app address), so this limits what a stolen socket can do but does not remove it.
- *`-t <LIFETIME>`* bounds exposure but silently ends router access when it lapses, so a human must re-add the key before every expiry. Use it only with the alert below and a calendar reminder.

Either way, alert when the agent is empty: the heartbeat in [Monitoring (heartbeat)](#monitoring-heartbeat) does this every minute.

**Restart semantics.** The socket directory `/run/couvrefeu` is `0700` owned by the service user (root can still traverse it). Restarting or stopping `couvrefeu.service` leaves the agent and its loaded key untouched (the agent unit has no `PartOf=`). Restarting the agent drops the key, so it must be re-added, and because the app unit `Requires=` the agent, systemd restarts the app too. `RuntimeDirectoryPreserve=restart` keeps `/run/couvrefeu` across an agent restart so a Docker bind mount of it stays valid; stopping the agent unit removes the directory, so after a stop/start run `docker compose restart` to re-mount it.

The agent starts empty after every reboot or agent restart, so router dispatch fails closed until a human re-adds the key. Do not remove the passphrase to avoid this.

The app unit uses `Restart=always`, `RestartSec=5` and `StartLimitIntervalSec=0`, so systemd restarts it after any exit and never parks it in a start-limit `failed` state. `RestartSteps=5` and `RestartMaxDelaySec=5min` back the delay off from 5 s to 5 min on repeated failures (they need systemd 254 or newer; Debian 13 ships 257), and `RestartPreventExitStatus=78` stops the loop for a deterministic startup refusal, because `integration-main.ts` exits 78 (`EX_CONFIG`) when the manifest, database version or migration, or key files are refused. There is deliberately no `WatchdogSec`; the heartbeat watches it from outside.

The units use strict sandboxing (`ProtectSystem=strict` with only the data directory writable, `NoNewPrivileges`, empty capability set, syscall and address-family filters). `MemoryDenyWriteExecute` is deliberately not set on the app because V8 needs it. In some unprivileged LXC setups a sandbox option can fail to start (`status=218/CAPABILITIES`, `226/NAMESPACE`); remove only the offending line, record it, and keep the rest.

Check with `systemd-analyze verify /etc/systemd/system/couvrefeu*.service` and `systemd-analyze security couvrefeu`.

### Proxmox LXC specifics

Create an unprivileged container (`--unprivileged 1`), `--onboot 1`, a small root disk (8 GB) and 1 GB RAM, with a static address and your LAN resolver as nameserver (not a stale tailnet resolver). No nesting, TUN device or Docker is needed. Then follow Option 1 inside it. Snapshot before upgrades.

## Option 2: Docker / Compose

Files: [`deploy/docker/Dockerfile`](../../deploy/docker/Dockerfile), [`deploy/docker/compose.yaml`](../../deploy/docker/compose.yaml), [`.dockerignore`](../../.dockerignore). The image is `node:26.13.1-slim` pinned by the multi-arch index digest, runs as uid/gid 10001, has no build step and contains only the runtime tree plus `openssh-client`.

```sh
docker build -f deploy/docker/Dockerfile -t couvrefeu:local .    # or: podman build ...
docker compose -f deploy/docker/compose.yaml up -d
```

Host side (same layout as Option 1): `/var/lib/couvrefeu` and `/etc/couvrefeu` owned by uid 10001, mode `0700`; the ssh-agent runs on the host as `couvrefeu-agent.service` (uid 10001) and its directory `/run/couvrefeu` is mounted read-only (connecting to a socket does not need a writable mount). Manifest, `known_hosts` and the public key are mounted read-only; only the data directory is writable. The container root filesystem is read-only, all capabilities are dropped and `no-new-privileges` is set.

### The source-address problem (read before using Docker)

`trustedProxies` trusts the TCP source address the service sees. With Docker's default bridge network and a published port, the userland proxy or NAT can make **every client** appear as the bridge gateway (its gateway address). That either breaks the proxy (rejected) or, if you list the gateway, admits every host that can reach the port. Therefore:

- The compose example uses `network_mode: host` and no `ports:`. Bind `listen.host` to `<APP_IP>` in the manifest. As a second option give the container its own LAN address with a macvlan or ipvlan network and set `listen.host` to that address.
- Never list a Docker bridge gateway address in `trustedProxies`.
- **Verify before enrolling anyone:** load the page through the proxy and run `ss -tn sport = :4273` on the host. The peer must be exactly `<PROXY_IP>`. From another LAN host `curl -sv http://<APP_IP>:4273/` must be reset with no HTTP response. Add the host firewall rule from Option 1 regardless.

### Healthcheck

The image healthcheck (`healthcheck.mjs`) only opens a TCP connection to the manifest's `listen` address and sends no HTTP, so it needs no allowlist exception. It proves only that the listener accepts TCP: the TCP handshake completes before the service drops an untrusted source, so a healthy container does **not** show that the allowlist is in force. Verify that separately with the `ss` and off-proxy `curl` checks above. Do not add an HTTP healthcheck or put the host's own address in `trustedProxies`.

### Health and version (`GET /health`)

`GET /health` (HEAD also works; every other method is 405) is unauthenticated by design and content-free. It needs no cookie and no feature flag, never contacts the router, and is rate limited (1200 per minute, one shared budget). It answers exactly:

```json
{"ok":true,"version":"<release>","uptimeSeconds":123,"schemaVersion":14,"inventoryFresh":null}
```

`ok` means the process answers and the database answers a trivial read; a database failure is a bare `503 {"ok":false}`. `inventoryFresh` is `true` when the last good inventory poll was within 3 poll intervals (180 s), `false` when older, and `null` when inventory is off or has not polled; the exact age is deliberately not public and appears only in the admin-only `/auth/session` response. Use it for a heartbeat or monitor: `curl -fsS https://<name>/health`. It carries no person, device, MAC, hostname, account, address, path or router data; keep it that way (the key set is pinned by `service/tests/health.test.ts`). The budget is global because callers behind the proxy share its address and forwarded headers are not trusted, so one noisy client could exhaust it: **a monitor must treat HTTP 429 from `/health` as "process is up"** (the service answered), and per-client limiting belongs in the reverse proxy (NPM). It is not a replacement for the TCP image healthcheck below, which is unchanged.

`version` is read from a `VERSION` file next to `package.json` (the Dockerfile copies it when present; the deploy writes it, for example `git rev-parse --short HEAD > VERSION` before `docker build`), else `<package.json version>-dev`. The service never runs `git`. The signed-in UI shows the same value and the schema version in its footer.

### Agent socket exposure

Any process in the container, and anyone who can `docker exec` into it, can use the mounted agent socket to run the service's constrained `cfctl` commands on the router as root. Restrict `docker exec` and membership of the `docker` group to the operator, and give the loaded key a lifetime where practical (`ssh-add -t <LIFETIME>`; the key must then be re-added by a human after it expires). `ssh-add -c` (confirm every use) needs an askpass program reachable by the agent and so does not suit a headless service; use it only if you provide one. The same applies to local users who can reach `/run/couvrefeu` in Option 1: keep it `0700`.

## First-admin enrollment

Passkeys are bound to the RP ID, which is the hostname of `publicOrigin` (`cf.example.invalid`). Changing it later invalidates every enrolled passkey.

- **Loopback or an SSH tunnel to the loopback address cannot enroll the real credential.** `Host` must equal the `publicOrigin` host (otherwise `403 host_rejected`), proxy mode refuses a loopback listener, and a loopback `origin` manifest would create credentials for RP ID `localhost`.
- **A throw-away manifest does not help.** The database records the exact manifest digest, target and generation (`integration_state`); a database used under one manifest is refused under any other byte-different manifest. Enroll under the final manifest, and treat any later manifest edit (including `dispatch`, `timeRequests` and a renewed `scheduleClock.conformance`) as a re-enrollment event unless you restore through a reviewed backup procedure.
- **Use a real TLS name.** Enroll from a trusted device through the TLS proxy at `https://cf.example.invalid` (a secure context). Mint the one-use token on the service host: `sudo -u couvrefeu node /opt/couvrefeu/service/src/integration-bootstrap.ts /etc/couvrefeu/manifest.json <ACCOUNT_ID>` (Docker: `docker compose exec couvrefeu node /app/service/src/integration-bootstrap.ts /etc/couvrefeu/manifest.json <ACCOUNT_ID>`). The token is valid for 10 minutes; keep it out of logs and chats.
- **The proxy-to-service hop is plaintext** in proxy mode, and the token and session cookie cross it (see *Residual risk* in [http-behind-proxy](http-behind-proxy.md)). Reduce the exposure: restrict the proxy host to the enrolling device's address with an access list during enrollment, enroll in a short window when untrusted devices are off the LAN, pin the proxy's MAC in the service host's neighbor table (`ip neigh replace <PROXY_IP> lladdr <PROXY_MAC> dev <IFACE> nud permanent`), and keep the firewall rule. Prefer an encrypted hop chosen **before** the manifest is finalized, for example `listen.host` on a Tailscale `100.x` address with the proxy's tailnet address in `trustedProxies`.
- Enroll one account at a time and prove a fresh sign-in works before enrolling the next.

## Monitoring (heartbeat)

[`deploy/heartbeat.sh`](../../deploy/heartbeat.sh) runs every minute from `couvrefeu-heartbeat.timer` (`OnBootSec=2min`, `OnUnitActiveSec=1min`) and pushes one result to a monitor you operate. It reports `status=up` only if `couvrefeu` and `couvrefeu-agent` are both **enabled** at boot, `couvrefeu` is active, the agent holds a key and, when `HEARTBEAT_HEALTH_URL` is set, a content-free `GET` of it returns 200 with `"ok":true`. Otherwise it reports `status=down` with one fixed `msg` token: `service-disabled`, `service-down`, `agent-empty` or `health-failed`.

Keep the **bare monitor push URL** (no query string) in a root-only file, because it is a credential: the script refuses a symlink or anything not owned by root with mode `0600`, so `chmod 0600` it. The script reads it inside, hands it to `curl` on stdin (`-K -`) and never prints it or puts it in argv (`ps` and `/proc/<pid>/cmdline` would show it). A missing, unsafe or malformed file makes the run log to the journal and exit non-zero without pushing. URLs (push and health) must be `https://` and use only `A-Za-z0-9._~:/@+%-`; anything else is refused (a bad health URL reports `health-failed`). `curl` runs with `-q` (ignores `~/.curlrc`), pinned to https, a 10 s limit and, for `/health`, a 64 KiB size limit. Plain `http://` is accepted only with `HEARTBEAT_ALLOW_HTTP=1` in the same drop-in; that is fine on a LAN for the content-free `/health` (`http://<APP_IP>:4273/health`) but do not use it for a push URL that crosses the internet.

```sh
# as root, from the unpacked release in /opt/couvrefeu
install -m 0700 -o root -g root /opt/couvrefeu/deploy/heartbeat.sh /usr/local/sbin/couvrefeu-heartbeat
install -m 0600 -o root -g root /dev/null /root/couvrefeu-key/<PUSH_URL_FILE>   # then put the bare push URL in it
install -m 0644 deploy/systemd/couvrefeu-heartbeat.service deploy/systemd/couvrefeu-heartbeat.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now couvrefeu-heartbeat.timer
journalctl -u couvrefeu-heartbeat -n 5 --no-pager   # "status=up msg=ok"
```

Defaults are `HEARTBEAT_URL_FILE=/root/couvrefeu-key/heartbeat-push-url` and the agent socket `/run/couvrefeu/agent.sock`; set `HEARTBEAT_URL_FILE=/root/couvrefeu-key/<PUSH_URL_FILE>` (and optionally `HEARTBEAT_HEALTH_URL=https://cf.example.invalid/health`, or `http://<APP_IP>:4273/health` together with `HEARTBEAT_ALLOW_HTTP=1`, once /health is deployed) with `systemctl edit couvrefeu-heartbeat.service`. The unit is sandboxed but keeps `CapabilityBoundingSet=CAP_DAC_OVERRIDE` (root needs it to reach the agent socket in `/run/couvrefeu`, which is `0700` owned by the service user) and `ProtectHome=read-only` (the push URL file lives under `/root`). To also restrict where it can connect, add an optional drop-in (`systemctl edit couvrefeu-heartbeat.service`) with placeholders:

```ini
[Service]
IPAddressDeny=any
IPAddressAllow=<MONITOR_IP> <APP_IP>
```

Configure the monitor to alert on `status=down` **and** on missing beats, which also covers a dead host. If the app exits with code 78 (it refused to start: bad manifest, database version or migration, key files) systemd deliberately does not restart it (`RestartPreventExitStatus=78`); the heartbeat then reports `service-down` until a human reads `journalctl -u couvrefeu`, fixes the cause and runs `systemctl start couvrefeu`. Do not add a check that sends router commands unless it is a reviewed, read-only status call.

## Backups

`couvrefeu-backup.timer` runs `deploy/backup.mjs` daily (03:30 plus up to 30 minutes of random delay, `Persistent=true` so a missed run happens at next boot) as the service user. It needs no `sqlite3` CLI: it opens the live database read-only, makes a consistent online copy with `VACUUM INTO`, syncs it, verifies it (`PRAGMA integrity_check` is `ok` and `user_version` equals the source) and only then renames it to `/var/backups/couvrefeu/integration-YYYY-MM-DD.sqlite` (mode `0600`). It keeps the newest 14 and never deletes or overwrites anything that is not named exactly `integration-YYYY-MM-DD.sqlite`. A second run on the same day is a no-op while the existing copy is good; a same-day file that is damaged or from an older schema is replaced only by a verified new copy. The script never modifies the database, but the unit lists the data directory under `ReadWritePaths` because a WAL reader must maintain the `-shm` file; the service user already owns that directory, so this adds no uid-level privilege. The backup directory must be owned by the service user with no group/other access, or the script refuses to run.

```sh
install -d -o couvrefeu -g couvrefeu -m 0700 /var/backups/couvrefeu
install -m 0644 deploy/systemd/couvrefeu-backup.service deploy/systemd/couvrefeu-backup.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now couvrefeu-backup.timer
systemctl start couvrefeu-backup.service && journalctl -u couvrefeu-backup -n 5 --no-pager
ls -l /var/backups/couvrefeu
```

**Off-host copy is required.** A backup on the same host dies with the host. The backups hold children, device and audit data, so copy them off the LXC with an **encrypted** tool such as `age` or `restic`, with the encryption key held off the LXC (never in `/var/lib/couvrefeu` or `/etc/couvrefeu`), and test that you can decrypt one. Never ship the plain `.sqlite` files.

**Restore.** Restoring replaces the whole database, so every enrolled session and policy returns to the backup's state.

```sh
systemctl stop couvrefeu
ASIDE=/var/lib/couvrefeu/aside-$(date +%F)
mkdir "$ASIDE" && mv /var/lib/couvrefeu/integration.sqlite* "$ASIDE"/
install -m 0600 -o couvrefeu -g couvrefeu /var/backups/couvrefeu/integration-<YYYY-MM-DD>.sqlite /var/lib/couvrefeu/integration.sqlite
node --input-type=module -e "import {DatabaseSync} from 'node:sqlite'; const d = new DatabaseSync(process.argv[1], {readOnly: true}); console.log(d.prepare('PRAGMA user_version').get(), d.prepare('PRAGMA integrity_check').get())" /var/lib/couvrefeu/integration.sqlite   # user_version = expected schema, integrity_check = ok
systemctl start couvrefeu
```

The `user_version` must be the schema your deployed code expects (a newer code version migrates forward; older code than the backup refuses to start). Move the live `-wal` and `-shm` files aside together with the main file, never restore over them. The manifest digest check still applies, so restore under the same manifest.

**Quarterly restore test.** Once a quarter, restore the newest backup into a scratch directory on the demo stack (never over the live files), run the integrity and `user_version` check above and start the demo service against it. Put the date in your calendar; an untested backup is not a backup.

## Enable at boot check

Lesson from the roughly two-day production outage: `couvrefeu.service` was never enabled, so it did not start after a reboot, and nothing watched it. A service that is running now is not a service that survives a reboot. After every install or change of units run, as root:

```sh
systemctl is-enabled couvrefeu couvrefeu-agent couvrefeu-heartbeat.timer couvrefeu-backup.timer   # four lines, all "enabled"
systemctl is-active couvrefeu couvrefeu-agent couvrefeu-heartbeat.timer couvrefeu-backup.timer
```

The heartbeat repeats the `is-enabled` check for the two services every minute and reports `service-disabled`, so a unit that loses its enablement is seen within a minute, not at the next reboot. The agent starts empty after a reboot, so `agent-empty` after boot is expected until a human loads the key.

## Proxy upstream check

The heartbeat runs on the app host, so it cannot see a dead host, a dead CT107 or a reverse proxy pointing at a stale upstream. Add a check from a different machine (for example the proxy host or another always-on server), once /health is deployed:

```sh
# daily or hourly from cron/systemd on the proxy-side host; alert on non-zero exit
curl -fsS -m 10 -o /dev/null https://cf.example.invalid/health
```

`-f` makes any non-2xx fail, so a 502 from a proxy with a stale upstream alerts. Use your public name in place of `cf.example.invalid`, and keep the monitor URL for that check in a root-only file like the heartbeat's.

## Verify

1. `systemd-analyze verify` (Option 1) or `docker compose config -q` (Option 2) passes.
2. From the proxy host: `curl -s -o /dev/null -D - -H 'Host: cf.example.invalid' http://<APP_IP>:4273/` returns `HTTP/1.1 200` and a `Strict-Transport-Security` header. Do not use `curl -I`.
3. From any other host the port is unreachable or reset.
4. `ss -tn sport = :4273` shows the real proxy address.
5. Router access (dispatch) is a separate approval; with `dispatch.enabled` false the service never opens SSH.
6. `systemctl is-enabled couvrefeu couvrefeu-agent couvrefeu-heartbeat.timer couvrefeu-backup.timer` prints `enabled` four times, and `ls -l /var/backups/couvrefeu` shows today's `integration-YYYY-MM-DD.sqlite` after one manual backup run (Option 1; see [Enable at boot check](#enable-at-boot-check)).
