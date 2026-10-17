# Runbook: plain HTTP on the LAN behind a TLS-terminating proxy (Nginx Proxy Manager)

Use this mode when the integration service runs on one LAN host and Nginx Proxy Manager (NPM), on a **different** host, terminates TLS for the parent app. The service listens with plain HTTP on one private address and accepts TCP connections only from the proxy address(es) you list. The fictional demo is unchanged.

If NPM runs on the **same** host as the service, do not use this mode: use the loopback `origin` mode (`docs/integration-004.md`), so no cleartext crosses the wire. If the service should serve TLS itself, use `docs/runbooks/lan-https.md`.

Placeholders: `<APP_IP>` (service host), `<NPM_IP>` (NPM host as seen by the service) and `cf.example.invalid` (your public name). Both IPs must be specific RFC 1918 addresses (`10/8`, `172.16/12`, `192.168/16`) or Tailscale `100.64/10` addresses. Never commit real values.

## Manifest fields

All three are required together. They exclude `tls` and the loopback `origin` field:

```json
"listen": {"host": "<APP_IP>", "port": 4273},
"publicOrigin": "https://cf.example.invalid",
"trustedProxies": ["<NPM_IP>"]
```

- `listen.host`: one specific private IPv4. `0.0.0.0`, loopback and public addresses are refused. `listen.port` must equal the manifest `port`.
- `publicOrigin`: `https://` plus a lowercase DNS name, with **no port**, path, query, fragment or credentials (`lan_proxy_public_origin_must_be_portless`, `invalid_private_https_origin`). NPM forwards `Host: $host`, which has no port, so an origin with a port would reject every request. This value is the WebAuthn origin and `rpId`. Changing it later invalidates every enrolled passkey.
- `trustedProxies`: 1 to 8 exact private IPv4 literals. No CIDR, no names, no IPv6, no duplicates, and none may equal `listen.host` (`invalid_trusted_proxies`). There is no open-LAN variant: the field is mandatory in this mode.
- If `trustedProxies` is present without `listen` and `publicOrigin`, or together with `tls` or `origin`, startup fails with `lan_proxy_requires_listen_public_origin_trusted_proxies`.

Startup prints `private LAN proxy HTTP https://cf.example.invalid via 1 trusted proxies`.

## Runtime behaviour

- A connection whose TCP source address is not in `trustedProxies` is destroyed before any request byte is parsed. Nothing about it is logged, and no response is sent. Every request is checked again as well. IPv4-mapped `::ffff:` sources are normalized before the exact match.
- `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host` and `Forwarded` are never read. The only trust signal is the TCP source address.
- All existing checks still apply. `Host` must equal the `publicOrigin` host exactly, so `http://<APP_IP>:4273` gets 403 `host_rejected` even from NPM. `Origin` must match and is mandatory on POST. `Sec-Fetch-Site: cross-site` and identity headers are refused. The CSRF token is checked against the session.
- Cookies are `HttpOnly; SameSite=Strict; Secure`, and `Strict-Transport-Security` is sent. Browsers see only the NPM HTTPS hop, where both take effect. This change also adds HSTS to the loopback `origin` proxy mode.

## NPM proxy-host recipe

1. **Hosts > Proxy Hosts > Add Proxy Host.**
   - Domain name: `cf.example.invalid`.
   - Scheme `http`, forward hostname `<APP_IP>`, forward port `4273`.
   - Leave *Websockets Support* off. The app uses none.
   - *Block Common Exploits* may stay on.
2. **SSL tab:** pick or request the certificate for `cf.example.invalid`. Enable *Force SSL* and *HSTS Enabled*. HTTP/2 is fine.
3. **Advanced tab:** leave it empty. NPM's default `proxy_set_header Host $host` passes the public name unchanged, which is required.
   - Do not rewrite or strip `Origin`.
   - Do not add `proxy_set_header Host $proxy_host` or a custom `Host`.
   - Do not add `X-Forwarded-*` expecting it to matter. It is ignored.
4. **Source address:** `trustedProxies` must be the address the service actually sees, normally the NPM host's LAN IP.
   - If NPM runs in Docker with a bridged network, outbound traffic is NATed to the Docker host's LAN IP. List that address.
   - Confirm it on the service host while loading the page: `ss -tn sport = :4273` shows the peer address.
5. **DNS:** `cf.example.invalid` must resolve to NPM for parent devices, through a LAN DNS entry or public DNS for a public-CA certificate. Do not change dnsmasq on the pilot router without the approvals in `AGENTS.md`.

## Host hardening

- Allow the port only from NPM in the host firewall as well, for defense in depth:
  - nftables: `nft add rule inet filter input ip saddr != <NPM_IP> tcp dport 4273 drop`
  - firewalld: a rich rule accepting `source address=<NPM_IP> port 4273/tcp` in a zone without other access to the port.
- Example systemd unit fragment:

```ini
[Service]
ExecStart=/usr/bin/node service/src/integration-main.ts /home/couvre/private/manifest.json
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/home/couvre/private/data
PrivateTmp=yes
```

## Verify

1. From the NPM host: `curl -sI -H 'Host: cf.example.invalid' http://<APP_IP>:4273/` returns 200 with `Strict-Transport-Security`. Without the Host header it returns 403.
2. From any other LAN host: `curl -sv http://<APP_IP>:4273/` gets a connection reset with no HTTP response.
3. From a parent phone: `https://cf.example.invalid` shows a valid lock. Sign-in works, and `rpId` equals `cf.example.invalid`.

## Residual risk (read before enrolling)

The NPM-to-service hop is **plaintext on the LAN**, and that LAN is shared with the children's devices.

- **Session cookies.** Anyone who can observe that hop, for example by ARP spoofing on a flat LAN, can read the `cf_session` and `cf_browser` cookies and the CSRF token. They can then act as that parent until the session expires: **up to 1 hour, including pause and resume**. The source-address allowlist does not stop a sniffer. It only stops direct connections from other hosts, and it cannot stop a spoofed source address on the same L2 segment.
- **Enrollment tokens.** A one-use enrollment token (valid 10 minutes) also crosses the hop when a parent registers a passkey. Until the planned step-up and pairing-code work lands, an attacker who sees it could race the real parent and bind their own passkey to that account. That would be a takeover, including of an admin account. **Enroll passkeys only over an encrypted path:** temporarily use mode (a) or (b) below, or enroll from the service host itself.
- **What stays safe.** Passkey assertions cannot be replayed: the challenge is one-use, and the assertion is bound to the origin and `rpId`.

Mitigations, best first:

- **(a)** Run NPM on the service host and use the loopback `origin` mode. No cleartext crosses the wire.
- **(b)** Bind `listen.host` to the service host's Tailscale `100.x` address, and list NPM's tailnet address in `trustedProxies`. The hop is then WireGuard-encrypted.
- **(c)** Point NPM at the HTTPS listener from `lan-https.md` and verify the upstream certificate.
- **(d)** Accept the plaintext hop, restrict the port with the host firewall rule above, and keep sessions short. This mode ships for (d). Prefer (a) or (b).

Keep one public origin. To reach the same app over Tailscale later, resolve the same `cf.example.invalid` to NPM over the tailnet, and add NPM's tailnet source address to `trustedProxies`. Never add a second origin.
