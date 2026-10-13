# Runbook: private LAN HTTPS for the household parent app

Passkeys (WebAuthn) require a secure context, so a parent phone cannot use the integration service over plain HTTP on the LAN. This runbook serves the **integration** service directly over HTTPS on a private address. The fictional demo (`npm run demo:start`) is unchanged: loopback HTTP only.

## Manifest fields

Add all three to the private integration manifest (they are all-or-nothing, and exclude the proxy-mode `origin` field):

```json
"tls": {"certPath": "/home/couvre/tls/parent.crt", "keyPath": "/home/couvre/tls/parent.key"},
"listen": {"host": "192.168.1.20", "port": 4273},
"publicOrigin": "https://couvre-feu.home.example:4273"
```

- `listen.host` must be one specific RFC 1918 IPv4 (`10/8`, `172.16/12`, `192.168/16`) or a Tailscale address (`100.64.0.0/10`). `0.0.0.0`, loopback, and public addresses are refused. `listen.port` must equal the manifest `port`.
- `publicOrigin` is `https://name[:port]` with a lowercase DNS name that contains a dot. It becomes the WebAuthn origin and `rpId` (the hostname). Requests whose `Host` or `Origin` differ are rejected with 403. Use the exact name you will type on the phone; changing it later invalidates enrolled passkeys.
- Paths are absolute, normalized, and use only `[A-Za-z0-9_./-]`.

The service then uses `node:https` (TLS 1.2+), sends `Strict-Transport-Security`, and marks cookies `Secure` in addition to `HttpOnly; SameSite=Strict`. Without these fields behavior is unchanged (loopback HTTP).

## File permissions

The private key must be a regular file (not a symlink) owned by the service user with no group or world access (`chmod 600`), inside directories that others cannot write. Startup refuses otherwise (`tls_key_permissions`). The certificate may be world-readable. Startup also fails with a specific code if a file is missing (`tls_cert_unreadable`, `tls_key_unreadable`) or the certificate and key do not match (`tls_cert_key_invalid_or_mismatched`). Keep keys and certificates out of the repository.

```sh
install -d -m 700 ~/tls
chmod 600 ~/tls/parent.key
```

## Option A: local CA (mkcert-style)

1. On an admin machine, create a CA and a certificate for the name and LAN IP, e.g. `mkcert -cert-file parent.crt -key-file parent.key couvre-feu.home.example 192.168.1.20`.
2. Make the name resolve on the LAN (router DNS entry or per-device hosts entry). Do not change dnsmasq on the pilot router without the approvals in `AGENTS.md`.
3. Copy `parent.crt` and `parent.key` to the service host; `chmod 600` the key.
4. Install only the **root CA certificate** (`rootCA.pem`, never `rootCA-key.pem`) on the phone: iOS, install the profile and enable it under Settings > General > About > Certificate Trust Settings; Android, Settings > Security > Install a certificate > CA certificate. Keep the CA private key off the phone and offline.

## Option B: Tailscale

1. Enable HTTPS certificates in the tailnet and run `sudo tailscale cert host.tailnet-name.ts.net`.
2. Copy the resulting files to a service-owned directory with `chmod 600` on the key (the default Tailscale state directory is root-owned and is not accepted).
3. Set `listen.host` to the host's `100.x` Tailscale address and `publicOrigin` to `https://host.tailnet-name.ts.net:4273`. The phone needs the Tailscale app connected; no root install is needed because the certificate is publicly trusted.
4. Certificates expire (about 90 days). Renew, copy the files, then `kill -HUP <pid>`.

## Renewal

`SIGHUP` reloads the certificate and key without restarting. A bad pair is rejected and the previous certificate stays active (`tls_reload_failed` on stderr).

## Verify from the phone

1. Connect the phone to the home Wi-Fi (or Tailscale). Open `publicOrigin`; the browser must show a valid lock with no warning.
2. Sign in or register a passkey; `rpId` equals the hostname of `publicOrigin`.
3. From any LAN host: `curl --cacert rootCA.pem -sI https://name:port/` returns `Strict-Transport-Security`; `curl --cacert rootCA.pem -H 'Host: other.example' https://name:port/` (with `--resolve`) returns 403.
4. `nmap -p <port> <other-interface-ip>` shows the port closed: the service binds only `listen.host`.

## Security notes

HTTPS protects the parent-to-service hop only. The LAN is still shared with the children's devices; a child device that trusts the local root CA could be impersonated against, so install it only on parent devices. Any host that can reach `listen.host` can attempt requests; authentication still requires an enrolled passkey. Router packet behavior remains unverified as documented elsewhere.
