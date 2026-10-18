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

1. Node **26.8.1** and npm **11.19.0** (`package.json` `engines`). Install from the official tarball and verify its SHA-256 (and the GPG-signed `SHASUMS256.txt`) before use, or use the pinned image below.
2. A service user with a **fixed uid/gid 10001** so the systemd and Docker options are interchangeable: `useradd --system --uid 10001 --user-group --home-dir /var/lib/couvrefeu --shell /usr/sbin/nologin couvrefeu`.
3. Private directories, owned by that user and `0700`: `/var/lib/couvrefeu` (manifest `dataDir`) and `/etc/couvrefeu` (manifest, `known_hosts`, public key). The service rejects symlinks, wrong owners, group/world access and writable ancestors (`unsafe_private_path`, `unsafe_private_ancestor`). The manifest must be outside the source tree.
4. `openssh-client` (the router transport runs `ssh` with `PATH=/usr/bin:/bin`).
5. A private manifest built from [integration-004](../integration-004.md) and [http-behind-proxy](http-behind-proxy.md): `listen.host` is `<APP_IP>`, `trustedProxies` lists exactly the address the service sees for the proxy, `publicOrigin` is `https://cf.example.invalid`, `router.agentSocket` is `/run/couvrefeu/agent.sock`.
6. Backups: before any upgrade stop the service and copy `integration.sqlite`, `integration.sqlite-wal` and `integration.sqlite-shm` from the data directory together. Database migrations are not reversible.

## Option 1: systemd (LXC, VM or bare metal)

Units: [`deploy/systemd/couvrefeu-agent.service`](../../deploy/systemd/couvrefeu-agent.service) and [`deploy/systemd/couvrefeu.service`](../../deploy/systemd/couvrefeu.service); example firewall [`deploy/systemd/couvrefeu.nft`](../../deploy/systemd/couvrefeu.nft).

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
sudo -u couvrefeu env SSH_AUTH_SOCK=/run/couvrefeu/agent.sock ssh-add /etc/couvrefeu/<SERVICE_KEY>   # passphrase typed by a human
systemctl enable --now couvrefeu
journalctl -u couvrefeu -n 20 --no-pager   # "private LAN proxy HTTP https://cf.example.invalid via 1 trusted proxies"
```

The agent starts empty after every reboot or restart, so router dispatch fails closed until a human re-adds the key. Do not remove the passphrase to avoid this. The service unit `Requires=` the agent, so restarting the agent restarts the service.

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

`trustedProxies` trusts the TCP source address the service sees. With Docker's default bridge network and a published port, the userland proxy or NAT can make **every client** appear as the bridge gateway (for example `172.17.0.1`). That either breaks the proxy (rejected) or, if you list the gateway, admits every host that can reach the port. Therefore:

- The compose example uses `network_mode: host` and no `ports:`. Bind `listen.host` to `<APP_IP>` in the manifest. As a second option give the container its own LAN address with a macvlan or ipvlan network and set `listen.host` to that address.
- Never list a Docker gateway (`172.16.0.0/12` bridge addresses) in `trustedProxies`.
- **Verify before enrolling anyone:** load the page through the proxy and run `ss -tn sport = :4273` on the host. The peer must be exactly `<PROXY_IP>`. From another LAN host `curl -sv http://<APP_IP>:4273/` must be reset with no HTTP response. Add the host firewall rule from Option 1 regardless.

### Healthcheck

The image healthcheck (`healthcheck.mjs`) only opens a TCP connection to the manifest's `listen` address. It sends no HTTP, so it needs no allowlist exception; the service destroys that connection unread because its source (the host itself) is not a trusted proxy. A healthy container therefore also means the allowlist is still in force. Do not add an HTTP healthcheck or put the host's own address in `trustedProxies`.

## First-admin enrollment

Passkeys are bound to the RP ID, which is the hostname of `publicOrigin` (`cf.example.invalid`). Changing it later invalidates every enrolled passkey.

- **Loopback or an SSH tunnel to `127.0.0.1` cannot enroll the real credential.** `Host` must equal the `publicOrigin` host (otherwise `403 host_rejected`), proxy mode refuses a loopback listener, and a loopback `origin` manifest would create credentials for RP ID `localhost`.
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
