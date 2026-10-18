<!-- Generated: 2026-10-17 | Files scanned: ~200 | Token estimate: ~379 -->
# Router (router/)
| Path | Role |
|---|---|
| install.sh / uninstall.sh | transactional install; exact restore of originals by rename, journaled |
| cfctl | root-only entry; test mode only under /tmp/couvre-feu-* roots |
| cfctl-ssh | dropbear forced command; `--rpc-only` limits to rpc-sync/status/activity |
| cron | `* * * * * /usr/sbin/cfctl expire` |
| firewall.include | fw3 reload hook -> `cfctl apply-fw` |
| release.sha256 | frozen manifest (tools/freeze-router-release.py [--check]) |
| lib/core.sh | validation, backend wrappers, state load/edit, pause/resume, CLI dispatch |
| lib/firewall.sh | plan/apply/verify, slots, transition journal, guards, cleanup |
| lib/rpc.sh | rpc-sync/status envelope, checkpoints, receipts, scope check |
| lib/activity.sh | byte/blocked counters, `rpc-activity` |
| lib/install-common.sh | shared install/uninstall steps, file list |
| lib/platform-bootstrap.sh, vendor-platform.sh | platform admission profiles (strict, logd, os-trust) |
| lib/json.awk, rules.awk, state.awk | JSON parse, strict `iptables -S` token verifier, state metadata validation |

Slot model: two slots a/b. Static hooks cf_fwd, cf_input, cf_dns (filter v4/v6 + nat v4) jump (`cf:v2` comment) to active `cf2_{s}_f|i|d`; `cf2_{s}_g` guard chain. ipsets `cf2_{s}_{k,p,d4,d6,u}` (kids, paused, DoH v4/v6, allowance). Apply builds the idle slot, verifies, swaps hooks, flushes conntrack, tears down the old slot. Owned names matched by cf_owned_chain/cf_owned_set only.

State under /etc/couvrefeu: state (versioned policy + history), rpc-allowed (scope MACs), protected, runtime/ (firewall.owned: line 2 = slot), backup/ (originals, ready/complete markers, *.staged, restoring, kernel-cleaned, no-kernel-mutations). Installed code: /usr/sbin/cfctl, /usr/lib/couvrefeu/, /etc/crontabs/root entry.

Exactness: uninstall runs drift preflight, same-filesystem rename-only restore, persists kernel-cleanup before touching helpers, retires journal last; refuses on drift. `remove-fw` refused without installer token.
