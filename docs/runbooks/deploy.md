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

1. Node **26.8.1** and npm **11.19.0** (`package.json` `engines`). Install from the official tarball after verifying it, or use the pinned image below:

   ```sh
   V=26.8.1; T=node-v$V-linux-x64.tar.xz     # use the -linux-arm64 tarball on arm64
   curl -fsSLO https://nodejs.org/dist/v$V/$T
   curl -fsSLO https://nodejs.org/dist/v$V/SHASUMS256.txt
   curl -fsSLO https://nodejs.org/dist/v$V/SHASUMS256.txt.sig
   # Import the release signing keys listed in https://github.com/nodejs/release-keys (compare fingerprints
   # with that repository's README, not with this runbook), then:
   gpg --import <KEYRING_FROM_NODEJS_RELEASE_KEYS>
   gpg --verify SHASUMS256.txt.sig SHASUMS256.txt
   sha256sum -c --ignore-missing SHASUMS256.txt     # must report: $T: OK
   mkdir -p /opt/node-v$V && tar -xJf $T -C /opt/node-v$V --strip-components=1
   ln -sfn /opt/node-v$V/bin/node /usr/local/bin/node && node --version   # v26.8.1
   ```
2. A service user with a **fixed uid/gid 10001** so the systemd and Docker options are interchangeable: `useradd --system --uid 10001 --user-group --home-dir /var/lib/couvrefeu --shell /usr/sbin/nologin couvrefeu`.
3. Private directories, owned by that user and `0700`: `/var/lib/couvrefeu` (manifest `dataDir`) and `/etc/couvrefeu` (manifest, `known_hosts`, public key). The service rejects symlinks, wrong owners, group/world access and writable ancestors (`unsafe_private_path`, `unsafe_private_ancestor`). The manifest must be outside the source tree.
   **The service's private SSH key is not stored in either directory.** Both are readable by the service uid (and `/etc/couvrefeu` is mounted into the container), so a compromised service could copy an encrypted key and brute-force its passphrase. Keep the key in a root-only directory (`install -d -o root -g root -m 0700 /root/couvrefeu-key`, key file `0600 root:root`) and only ever hand it to the agent (below). Only the public key (`/etc/couvrefeu/service_key.pub`) and `known_hosts` live in `/etc/couvrefeu`.
4. `openssh-client` (the router transport runs `ssh` with `PATH=/usr/bin:/bin`).
5. A private manifest built from [integration-004](../integration-004.md) and [http-behind-proxy](http-behind-proxy.md): `listen.host` is `<APP_IP>`, `trustedProxies` lists exactly the address the service sees for the proxy, `publicOrigin` is `https://cf.example.invalid`, `router.agentSocket` is `/run/couvrefeu/agent.sock`.
6. Backups: before any upgrade stop the service and copy `integration.sqlite`, `integration.sqlite-wal` and `integration.sqlite-shm` from the data directory together. Database migrations are not reversible.

## Option 1: systemd (LXC, VM or bare metal)

Units: [`deploy/systemd/couvrefeu-agent.service`](../../deploy/systemd/couvrefeu-agent.service) and [`deploy/systemd/couvrefeu.service`](../../deploy/systemd/couvrefeu.service); example firewall [`deploy/systemd/couvrefeu.nft`](../../deploy/systemd/couvrefeu.nft).

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
- **Tailscale is not combinable as written.** `tailscaled` needs outbound UDP 41641 plus control-plane/DERP access (HTTPS), and an input rule for `tailscale0`; this ruleset blocks all of that. If you run Tailscale on the host (for example to encrypt the proxy hop), add rules such as `iifname "tailscale0" ip saddr <PROXY_TAILNET_IP> tcp dport 4273 accept`, `udp dport 41641 accept` in both directions and outbound `tcp dport 443 accept` for the control plane, then re-run the check and rollback procedure. Otherwise leave Tailscale off this host.
- **Monitoring push.** If you add the agent-expiry check below, allow its outbound destination (`ip daddr <MONITOR_IP> tcp dport <MONITOR_PORT> accept`).

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
journalctl -u couvrefeu -n 20 --no-pager   # "private LAN proxy HTTP https://cf.example.invalid via 1 trusted proxies"
```

Keep the encrypted key file root-only on the host and back it up offline.

**Key lifetime.** Choose one policy and write it into your procedure:

- *No expiry (omit `-t`)* suits an unattended service: the key stays loaded until the agent restarts or the host reboots. The key is constrained on the router (forced command, `from=` the app address), so this limits what a stolen socket can do but does not remove it.
- *`-t <LIFETIME>`* bounds exposure but silently ends router access when it lapses, so a human must re-add the key before every expiry. Use it only with the alert below and a calendar reminder.

Either way, alert when the agent is empty. A systemd timer runs a root-owned check every minute and pushes the result to a monitor you operate (placeholders; keep the push URL in a root-only file because it is a credential):

```sh
#!/bin/sh
# /usr/local/sbin/couvrefeu-agent-check (0700 root)
URL=$(cat /root/couvrefeu-key/<PUSH_URL_FILE>)      # <MONITOR_PUSH_URL>?status=...
if env SSH_AUTH_SOCK=/run/couvrefeu/agent.sock ssh-add -l >/dev/null 2>&1 && systemctl is-active --quiet couvrefeu; then
    status=up; msg=agent-loaded
else
    status=down; msg=agent-empty-or-app-down
fi
curl -fsS -m 10 "$URL?status=$status&msg=$msg" >/dev/null
```

Run it from a `Type=oneshot` service triggered by a timer (`OnBootSec=2min`, `OnUnitActiveSec=1min`). Configure the monitor to alert on `status=down` and on missing heartbeats, which also covers a dead host. Do not add a check that sends router commands unless it is a reviewed, read-only status call.

**Restart semantics.** The socket directory `/run/couvrefeu` is `0700` owned by the service user (root can still traverse it). Restarting or stopping `couvrefeu.service` leaves the agent and its loaded key untouched (the agent unit has no `PartOf=`). Restarting the agent drops the key, so it must be re-added, and because the app unit `Requires=` the agent, systemd restarts the app too. `RuntimeDirectoryPreserve=restart` keeps `/run/couvrefeu` across an agent restart so a Docker bind mount of it stays valid; stopping the agent unit removes the directory, so after a stop/start run `docker compose restart` to re-mount it.

The agent starts empty after every reboot or agent restart, so router dispatch fails closed until a human re-adds the key. Do not remove the passphrase to avoid this.

The units use strict sandboxing (`ProtectSystem=strict` with only the data directory writable, `NoNewPrivileges`, empty capability set, syscall and address-family filters). `MemoryDenyWriteExecute` is deliberately not set on the app because V8 needs it. In some unprivileged LXC setups a sandbox option can fail to start (`status=218/CAPABILITIES`, `226/NAMESPACE`); remove only the offending line, record it, and keep the rest.

Check with `systemd-analyze verify /etc/systemd/system/couvrefeu*.service` and `systemd-analyze security couvrefeu`.

### Proxmox LXC specifics

Create an unprivileged container (`--unprivileged 1`), `--onboot 1`, a small root disk (8 GB) and 1 GB RAM, with a static address and your LAN resolver as nameserver (not a stale tailnet resolver). No nesting, TUN device or Docker is needed. Then follow Option 1 inside it. Snapshot before upgrades.

## Option 2: Docker / Compose

Files: [`deploy/docker/Dockerfile`](../../deploy/docker/Dockerfile), [`deploy/docker/compose.yaml`](../../deploy/docker/compose.yaml), [`.dockerignore`](../../.dockerignore). The image is `node:26.8.1-slim` pinned by the multi-arch index digest, runs as uid/gid 10001, has no build step and contains only the runtime tree plus `openssh-client`.

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

### Agent socket exposure

Any process in the container, and anyone who can `docker exec` into it, can use the mounted agent socket to run the service's constrained `cfctl` commands on the router as root. Restrict `docker exec` and membership of the `docker` group to the operator, and give the loaded key a lifetime where practical (`ssh-add -t <LIFETIME>`; the key must then be re-added by a human after it expires). `ssh-add -c` (confirm every use) needs an askpass program reachable by the agent and so does not suit a headless service; use it only if you provide one. The same applies to local users who can reach `/run/couvrefeu` in Option 1: keep it `0700`.

## First-admin enrollment

Passkeys are bound to the RP ID, which is the hostname of `publicOrigin` (`cf.example.invalid`). Changing it later invalidates every enrolled passkey.

- **Loopback or an SSH tunnel to the loopback address cannot enroll the real credential.** `Host` must equal the `publicOrigin` host (otherwise `403 host_rejected`), proxy mode refuses a loopback listener, and a loopback `origin` manifest would create credentials for RP ID `localhost`.
- **A throw-away manifest does not help.** The database records the exact manifest digest, target and generation (`integration_state`); a database used under one manifest is refused under any other byte-different manifest. Enroll under the final manifest, and treat any later manifest edit (including `dispatch`, `timeRequests` and a renewed `scheduleClock.conformance`) as a re-enrollment event unless you restore through a reviewed backup procedure.
- **Use a real TLS name.** Enroll from a trusted device through the TLS proxy at `https://cf.example.invalid` (a secure context). Mint the one-use token on the service host: `sudo -u couvrefeu node /opt/couvrefeu/service/src/integration-bootstrap.ts /etc/couvrefeu/manifest.json <ACCOUNT_ID>` (Docker: `docker compose exec couvrefeu node /app/service/src/integration-bootstrap.ts /etc/couvrefeu/manifest.json <ACCOUNT_ID>`). The token is valid for 10 minutes; keep it out of logs and chats.
- **The proxy-to-service hop is plaintext** in proxy mode, and the token and session cookie cross it (see *Residual risk* in [http-behind-proxy](http-behind-proxy.md)). Reduce the exposure: restrict the proxy host to the enrolling device's address with an access list during enrollment, enroll in a short window when untrusted devices are off the LAN, pin the proxy's MAC in the service host's neighbor table (`ip neigh replace <PROXY_IP> lladdr <PROXY_MAC> dev <IFACE> nud permanent`), and keep the firewall rule. Prefer an encrypted hop chosen **before** the manifest is finalized, for example `listen.host` on a Tailscale `100.x` address with the proxy's tailnet address in `trustedProxies`.
- Enroll one account at a time and prove a fresh sign-in works before enrolling the next.

## Verify

1. `systemd-analyze verify` (Option 1) or `docker compose config -q` (Option 2) passes.
2. From the proxy host: `curl -s -o /dev/null -D - -H 'Host: cf.example.invalid' http://<APP_IP>:4273/` returns `HTTP/1.1 200` and a `Strict-Transport-Security` header. Do not use `curl -I`.
3. From any other host the port is unreachable or reset.
4. `ss -tn sport = :4273` shows the real proxy address.
5. Router access (dispatch) is a separate approval; with `dispatch.enabled` false the service never opens SSH.
