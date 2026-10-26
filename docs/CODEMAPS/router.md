<!-- Generated: 2026-10-17 | Files scanned: ~200 | Token estimate: ~379 -->
# Router (router/)
| Path | Role |
|---|---|
| install.sh / uninstall.sh | immutable PREPARED before managed writes; exact restore by rename; restartable receipt-bound retirement |
| cfctl | root-only entry; test mode only under /tmp/couvre-feu-* roots |
| cfctl-ssh | dropbear forced command; `--rpc-only` limits to rpc-sync/status/activity |
| generated cron / firewall include | immutable `/etc/.couvrefeu-release-<id>/cfctl --installation-generation <generation> expire\|apply-fw`; stale generations refuse |
| release.sha256 | frozen manifest (tools/freeze-router-release.py [--check \| --emit DIR]); `--emit` refuses unless router/ is frozen, then writes the shippable tree (cfctl-ssh and cfctl-scope stripped of their CF_TEST_MODE block) to a new DIR. Emitted files are operator-owned (dirs 0700, scripts 0755, lib 0644, release.sha256 0600): copy them to the router as root. Only these two wrappers are stripped; other CF_TEST_MODE gates remain in the tree but are unreachable over SSH because the wrappers `exec env -i` |
| lib/core.sh | validation, backend wrappers, state load/edit, pause/resume, CLI dispatch |
| lib/firewall.sh | plan/apply/verify, slots, transition journal, guards, cleanup |
| lib/rpc.sh | rpc-sync/status envelope, checkpoints, receipts, scope check |
| lib/activity.sh | byte/blocked counters, `rpc-activity` |
| lib/install-common.sh | shared install/uninstall, admin recovery, immutable baseline and `CFRETIREMENT 2` retirement |
| lib/platform-bootstrap.sh, vendor-platform.sh | platform admission profiles (strict, logd, os-trust) |
| lib/json.awk, rules.awk, state.awk | JSON parse, strict `iptables -S` token verifier, state metadata validation |

Slot model: two slots a/b. Static hooks cf_fwd, cf_input, cf_dns (filter v4/v6 + nat v4) jump (`cf:v2` comment) to active `cf2_{s}_f|i|d`; `cf2_{s}_g` guard chain. ipsets `cf2_{s}_{k,p,d4,d6,u}` (kids, paused, DoH v4/v6, allowance). Apply builds the idle slot, verifies, swaps hooks, flushes conntrack, tears down the old slot. Owned names matched by cf_owned_chain/cf_owned_set only.

State under /etc/couvrefeu: state (versioned policy + history), rpc-allowed (live scope MACs: a valid superset of the immutable install-time floor `backup/*rpc-allowed.staged`), protected, runtime/ (firewall.owned: line 2 = slot), backup/ (originals, ready/complete markers, *.staged, restoring, kernel-cleaned, no-kernel-mutations). Installed code: /usr/sbin/cfctl, /usr/lib/couvrefeu/, /etc/crontabs/root entry.

Exactness: uninstall validates ownership/baseline and drift, restores originals by same-filesystem rename and retires all owned transients with the durable receipt unlinked last. The permanent `/etc/.couvrefeu-mutex` inode remains; owner/PREPARED/fence/receipt and owned recovery release do not. `remove-fw` refuses without installer authority. A complete authenticated external source runs `cfctl recover-install-lock` then the single `uninstall.sh`; no age-based takeover or manual lock deletion. Production legacy/ambiguous ownership refuses; historical fixture restoration is data-only. See [recovery](../runbooks/vendor-platform-admission.md).
