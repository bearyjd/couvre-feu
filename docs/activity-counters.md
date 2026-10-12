# Router activity counters

`cfctl activity --json` (and `cfctl rpc-activity --json` for RPC mode) reports byte and packet counters for each child device MAC enrolled in policy. The data is read-only. These counters show that a device sent or received forwarded traffic through the router. They do not show what the traffic was. Fixture tests check how the counter rules are built and how the listings are parsed. They do not measure real packets, and no measurement has been made on the real router.

## What is counted

- Only MACs assigned to a person in accepted policy are counted. Protected adult or management MACs, the SSH client that controls the router, and unknown devices never get a rule. Under RPC scope, only the bound MAC is counted.
- **Outbound** traffic is counted by source MAC on `-i br-lan`, in both IPv4 and IPv6.
- **Inbound** traffic is counted by IPv4 destination on `-o br-lan`. The child must have a fresh, unambiguous address mapping: the same mapping rules enforcement uses (a current DHCP lease, or a REACHABLE/PERMANENT neighbor, with one owner per address). Inbound IPv6 is not counted.
- `blocked_packets` adds up hits on rules that Couvre-feu attributes to the child:
  - per-MAC schedule rejects;
  - per-address inbound pause and schedule rejects;
  - the manual-pause set reject, but only when the active generation's immutable pause set has exactly one member.
- Some reject hits are never attributed: the shared pause set when several MACs are paused, and DNS/DoH rejects. When a hit cannot be attributed, `blocked_unattributed` is reported and nothing is guessed.

Not counted: app use, URLs, domains, DNS queries, screen time, or presence. Also not counted: traffic over cellular, a VPN that bypasses the router, a randomized or rotated MAC that is not enrolled, LAN-local traffic that is never forwarded, and IPv6 inbound traffic.

## Placement and verdict safety

The owned chain `cf_acct` lives in the **mangle** table and is reached by `-I FORWARD 1 -m comment --comment cfa/hook -j cf_acct` in both families. Mangle FORWARD runs before filter FORWARD on the same netfilter hook. That means packets are counted before any verdict, including packets that `cf2_<slot>_f` later rejects.

The rules carry no `-j`/`-g` target, not even `RETURN`, so they cannot change a verdict. The filter table is never changed. That leaves the `forwarding_rule`/`cf_fwd` hook-order checks untouched, and slot sets and chains are never referenced.

**Flow offloading bypasses these counters.** Offloaded flows skip netfilter after setup. The output includes `offload`, read from `uci get firewall.@defaults[0].flow_offloading` and `flow_offloading_hw`:

- `on`: either option is set to `1`;
- `off`: the defaults section exists and both options are unset or `0`;
- `unknown`: the section is missing or a value cannot be interpreted.

With `on`, the counters undercount. Vendor acceleration that is not configured through these options is not detected.

## Lifecycle

The chain is created and updated from the confirmed-apply hook, so it follows every successful `sync`, `pause`, `resume`, `expire`, `apply-fw`, `rpc-sync` and firewall-include reconstruction. Unchanged rules are left alone, so the minute cron keeps counter values. The hook runs in a subshell. If it fails, enforcement results stay as they are, and the next `activity` read reports the problem. `remove-fw`, used during uninstall, deletes the owned hooks and chain in both families and proves they are gone. Zero-owned-kernel proofs treat `cf_acct` as an owned object.

## Counter epoch

`counter_epoch` comes from a persisted monotonic generation, `/etc/couvrefeu/runtime/activity.epoch`. It is a root-owned `0600` file that holds one integer, and it lives on persistent flash, not `/tmp`.

Each family's chain starts with a stamp rule, `cfa/epoch/<N>/<slot>`. A new `N` is issued in these cases:

- the chain is created, rebuilt or found missing (address churn, full restart, reboot, external flush);
- the enforcement generation changes slot, or a transition has just finished, because that recreates the blocked-rule counters.

The new value is `max(persisted + 1, live stamp + 1, router clock)`. It is written to the file with the same sync–rename–sync journal used for other runtime records, before any counter object is reset or restamped. After a slot swap the stamp is replaced in place with `-R`, so byte counters survive.

The epoch therefore never repeats while the installation exists, even across chain loss with an unchanged clock, several resets in one second, or reboot. A failed kernel step after the record only skips values.

The installer and uninstaller runtime allowlists recognize the file. `remove-fw` deletes it after removing the chain, and uninstall removes the runtime directory. After a reinstall, the clock term keeps new values above earlier ones unless the clock has moved backwards.

Consumers treat any epoch change as a reset. They compute deltas only between samples that have the same `counter_epoch` and no `errors`. `router_epoch` is the router clock (Unix seconds) at read time. An external `iptables -Z` that leaves the rules in place cannot be detected.

## Output

```json
{"version":1,"router_epoch":1736204400,"counter_epoch":1736204400,"offload":"off",
 "devices":[{"person":"alice","mac":"02:00:00:00:00:01","ip":"192.168.1.20","neighbor":"REACHABLE",
             "tx_bytes":0,"rx_bytes":0,"tx_packets":0,"rx_packets":0,"blocked_packets":0}],
 "errors":[]}
```

- Devices are sorted by person, then by MAC, and capped at 256 (`devices_truncated`).
- `ip` is the lowest fresh unambiguous IPv4 address, or `null`. Rx is summed over all of the device's counted addresses.
- `neighbor` is the strongest raw IPv4/IPv6 neighbor state for the MAC, with PERMANENT reported as REACHABLE. It is `ABSENT` when there is no entry, or when the entry has no link-layer address.

Error codes:

| Code | Meaning |
|---|---|
| `accounting_unavailable` | The chain or stamp is missing in a family; `counter_epoch` is 0 and counters may be zero |
| `accounting_hook_missing` | The mangle FORWARD hook is not first or not unique |
| `counter_epoch_stale` | The stamp slot differs from the active generation; blocked counters may have reset |
| `counter_epoch_ambiguous` | The family stamps disagree |
| `rx_mapping_stale` | An inbound rule's address no longer maps freshly to that MAC; it is excluded until the next rebuild |
| `blocked_unattributed`, `blocked_counters_unavailable` | Blocked hits could not be attributed or read |
| `operation_in_progress` | A mutation holds the lock; the read did not wait for it |
| `invalid_clock`, `address_inspection_failed`, `neighbor_inspection_failed` | Inputs were unavailable |

The read takes no lock, writes no files and changes no kernel state. It runs `-S`, `-nvxL`, `ipset save`, `ip neigh`, `ip addr` and `uci get`, and never runs `-Z`. Like `status`, it exits zero with uncertainty listed in `errors`. It exits nonzero only when admission is refused. `rpc-activity` also requires an enabled RPC generation and a valid scope binding.
