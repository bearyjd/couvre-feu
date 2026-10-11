# Router transitions — bounded design decision

Decision, 2026-10-11: **design only; no router implementation change**. The selected future mutation class is an IPv4 DoH destination-list replacement from a healthy, freshly verified generation. Candidate preparation could preserve that generation, but adding temporary kernel objects safely requires ownership, interruption recovery and exact uninstall changes. That work is deferred instead of adding a swap without those safeguards. The session orchestrator accepted this scope; an independent architecture/security reviewer approved the documentation and reproduced both baseline probes. This approval covers the design decision, not implementation or packet behavior.

Changed-policy, drift and reload reconstruction remain **non-atomic**. Production activation is blocked. This document grants no live-operation permission, claims no packet continuity and changes none of [PRP-001](prp/PRP-001-enforcement-core.md), the [enforcement contract](enforcement-contract.md) or [acceptance gates](acceptance-001.md).

## Existing sequence and failure surfaces

Source anchors refer to function names, so minor line movement does not change the map. All paths below are in [firewall.sh](../router/lib/firewall.sh) unless stated otherwise.

| Phase | Existing behavior | Failure consequence |
|---|---|---|
| Validation and desired-state persistence | `cf_preflight` checks dependencies, hooks, ownership, UCI, references and address evidence; `cf_mutate` in `core.sh` persists desired state before `cf_apply` | Preflight rejection precedes policy application. A later failure may leave a newer durable desired revision and an older confirmation. |
| Healthy unchanged observation | `cf_unchanged_verified` checks ownership, confirmation/digests, exact snapshot, actual rules/sets/hooks and native witnesses | Valid unchanged reconciliation avoids reconstruction. Failed eligibility must not become confirmation. |
| Intent | `cf_apply` records expiry, expected plan and `firewall.intent`; establishes ownership when absent | Metadata errors must stop before subsequent mutations. Intent is recovery evidence, not confirmation. |
| Native schedule staging | `cf_native_apply` stages UCI in private config/delta directories, then uses installer journal where present | Staging failure precedes native file replacement. Existing kernel objects have not yet been rebuilt by this invocation. |
| Native commit/reload | Replacement of `/etc/config/firewall`, journal commit and `fw3 -q reload` precede set application | Persistent and kernel states can diverge; reload can remove old hooks/chains before later failure. No old-path preservation promise can start after this phase. |
| Four live sets | `cf_sets_apply` visits `cf_kids`, `cf_paused`, `cf_doh`, `cf_doh6`; each create-or-exist is followed by live flush and sequential additions | Failed creation or addition can occur after earlier sets changed. Failed population leaves a set empty or partial. |
| Owned chains | `cf_chain_prepare` creates if absent and flushes; rules are then appended individually | Existing hooks can reach empty/partial chains. The two families and IPv4 NAT are separate operations. |
| Hooks | `cf_hook` deletes the exact commented jump and inserts it at position one | Failed insertion after deletion leaves that path detached; other families/tables may differ. |
| Connections | `cf_flush_connections` deletes source and destination flows for validated paused-child addresses in both families | Failure does not undo changed rules. Protected/uncertain address safeguards must remain intact. |
| Confirmation | `cf_verify`, then `cf_confirm_apply` writes snapshot/confirmation and clears error/intent | Failed verification or persistence cannot acknowledge the new desired revision. Existing confirmation is historical evidence only. |
| Uninstall | `cf_cleanup_inventory`, `cf_cleanup_verify` and `cf_remove_fw` journal and remove exact allowed remaining objects | Current fixed set inventory excludes any new candidate name. A candidate cannot safely be added without extending this protocol and the zero-owned-mutation proof. |

Current live types are `hash:mac` for `cf_kids`/`cf_paused`, `hash:ip family inet` for `cf_doh`, and `hash:ip family inet6` for `cf_doh6`. `cf_snapshot` retains both `SETDEF` create headers and membership, plus owned chain rules and schedule specifications. It does not represent a temporary-set transaction or prove that every external set reference belongs to Couvre-feu.

The [upstream ipset manual](https://ipset.netfilter.org/ipset.man.html) requires both swap operands to exist and have compatible types. Referenced sets cannot be destroyed; `restore` does not implicitly erase existing objects. These are primitive constraints, not an aggregate transaction guarantee.

The inspected [upstream fw3 reload implementation](https://github.com/openwrt/firewall3/blob/master/main.c) clears and repopulates tables while iterating address families; [fw3's iptables wrapper](https://github.com/openwrt/firewall3/blob/master/iptables.c) commits through the selected family's table handle. This supports treating native reload as a distinct boundary. Upstream `master` was consulted on 2026-10-11; it is not a source/version match for the GL vendor firmware. The [spike](spike-001.md) records target hook order and unresolved GL includes/offload/DNS behavior.

## Selected future candidate and strict eligibility

Only the normalized IPv4 DoH list and the increasing revision may differ. The currently confirmed generation must first be revalidated under the mutation lock against its own policy and actual objects, before treating it as a baseline. The existing desired-policy no-op check alone is insufficient for this old-generation validation.

Required equalities include child ownership/MACs, manual pauses and effective expiry, schedules/native selectors, IPv6 DoH contents, address/protected-device evidence, router DNS addresses, expected rules/hooks and configuration ownership. Require an existing owned compatible `cf_doh`, an unchanged healthy native configuration, no pending intent/cleanup/recovery and no observed drift. An expiry boundary or fresh address change invalidates eligibility. No WAN, DNS service, native UCI or reload operation belongs in this candidate path.

The existing same-policy/same-revision healthy no-op remains ahead of this candidate. Pause/resume and their conntrack semantics remain outside the optimization. Initial installation, missing sets, changed children/schedules, IPv6 updates, drift repair and reload reconstruction remain outside its preservation promise. Existing behavior for those paths would retain its documented risk.

Proposed sequence, **not implemented**:

1. Revalidate the old confirmed generation and establish strict eligibility. Inventory candidate-name absence and all relevant references with checked reads. Any uncertainty refuses the optimized path.
2. Atomically persist a private transaction record describing exact owned names, old/new normalized headers and membership digests, previous confirmation and intended revision. Reservation is not proof that an existing kernel object is owned.
3. Create a distinct unreferenced candidate with compatible `hash:ip family inet` parameters; populate only it. Do not use `-exist` to adopt a colliding candidate. Verify exact candidate content and metadata, and recheck the old live generation. No live set flush, native reload, chain/hook edit or conntrack deletion may have occurred.
4. Persist switch intent, then perform the single compatible-set swap. A command error or interruption has an uncertain outcome until both names are inspected. Do not infer outcome merely from the last written phase or perform a blind second swap.
5. Inspect both set contents, all required old-path invariants and desired-state witnesses. Retire the now-unreferenced old-content candidate only after exact ownership/reference validation. Complete confirmation only after cleanup and required journal updates succeed.

The preparation guarantee sought is narrow: failures before switch leave previous live sets, rules, hooks and native config unchanged and reachable in the inspected model. Temporary-object leakage still counts as a failed operation requiring recovery. After switch, the live list may be new while confirmation remains old/pending. This design does not promise rollback or global atomicity across sets, tables, address families, files or fw3.

## Ownership and recovery work that prevents a small patch

- Candidate-name collisions must preserve foreign objects. A reserved name and matching content alone do not establish ownership after a crash between kernel creation and durable phase recording. The implementation needs a reviewed ambiguity/refusal rule and a stated external-writer/concurrency assumption; the Couvre-feu lock does not serialize GL tools or root administrators.
- Recovery must distinguish old-live/new-candidate, new-live/old-candidate, absent candidate, identical old/new contents, failed observations and foreign modification. Any unsupported combination blocks mutation and preserves evidence. Digests need normalized, bounded data and exact metadata checks, not only set members.
- Foreign rules or other sets referring to either name must be detected before swap/destruction. Existing chain-jump ownership checks do not substitute for this set-reference audit. Kernel refusal to destroy a referenced set is a final guard, not an ownership proof.
- Cleanup intent, cleanup inventory/verification, ordinary-mutation barriers, snapshots and uninstall must understand the transaction. Interruption during candidate creation is already a kernel mutation and cannot qualify for the installer's zero-owned-mutation shortcut. Exact original-file restoration and foreign-object refusal must survive all phases.
- The fake backend currently implements `swap` as a dictionary exchange. It does not check compatible type/family or model set-reference destruction constraints. Tests must strengthen those semantics before swap fixtures could offer meaningful evidence.

Rejected shortcuts: swapping all four sets sequentially and calling the result atomic; preparing only after native reload; trap-only cleanup; reusing a fixed temporary name with `-exist`; deleting every `cf_*` set; treating `ipset restore` as a rollback transaction; or automatically swapping again after an uncertain first attempt. Each loses either scope honesty, old-path preservation or foreign/exact-uninstall safety.

## Required failure matrix for an implementation

Every row is **pending** for the proposed candidate. Inject each command, member insertion and journal write/rename boundary separately, including process interruption after a successful command but before its phase record. Failures must return unsuccessful/uncertain status, never confirmation of the requested revision.

| Boundary | Required observation | Recovery/cleanup expectation |
|---|---|---|
| Eligibility reads, old-policy validation, candidate inventory | Previous live objects and hooks unchanged; no candidate creation | Preserve evidence; failed read is not absence. |
| Reservation write/chmod/rename | Previous live path unchanged | Refuse unsafe file/symlink/metadata collisions; validated interrupted records remain recoverable. |
| Candidate creation | Previous live path unchanged | Pre-existing foreign name untouched; creation/record ambiguity explicitly blocked. |
| Each candidate addition, including first/last | Previous live path unchanged; candidate may be partial | Destroy only demonstrably owned unreferenced candidate; cleanup failure remains pending. |
| Candidate save/type/family/content/reference verification | Previous live path unchanged | Wrong type, incompatible family, failed read, unexpected member or foreign reference refuses switch. |
| Final old-generation recheck / switch-intent persistence | Previous live path unchanged | Changed address/protection/expiry/native state defeats eligibility; no switch. |
| Swap rejection or lost outcome | Inspect old/new content under both names; retain unchanged chain/hook path | Resolve by observations; no blind retry swap or fabricated confirmation. |
| Post-swap verification | Live list may be new; old confirmation remains historical | Record failed/unknown outcome; unsupported/foreign states require explicit recovery. |
| Candidate destroy and transaction cleanup | Active list remains the observed switched list if otherwise healthy | Failed destruction retains exact recovery evidence; never force foreign-reference removal. |
| Snapshot/confirmation persistence | Actual list and files may differ in generation | Failure stays visible; reconcile exact observations and desired revision before success. |
| Restart and uninstall at every phase | Protected adults and foreign objects preserved; exact file originals recoverable | Include transaction objects in cleanup proof; refuse ambiguous state, test second interruption during recovery. |

Regression requirements include the existing full installer/core suite, healthy no-op with zero kernel mutations, active pause conntrack eviction, dual-family/address protection, foreign object preservation and exact uninstall. Add candidate collision, incompatible type/family, empty list, equal-content revision, expiry during preparation, changed protected bindings, reload/drift ineligibility and external-reference cases. Fixture rule reachability is still a model, not packet evidence.

## Actual bounded baseline observations

Two probes ran on 2026-10-11 around 04:11 UTC through `RouterFixture` and its fake command directory under `/tmp`, using host `sh` and Python. No host firewall commands, network traffic, SSH, containers, installation or live router action ran. Both began with confirmed revision 1, fictional Alice paused, and IPv4 DoH list `192.0.2.53`; revision 2 changed only that list to `192.0.2.54`.

| Injected existing-backend failure | Observed result |
|---|---|
| First `ipset add cf_doh` during revision 2 | Exit 1, `ok=false`, `set_apply_failed`, desired revision 2 / confirmed revision 1. Live modeled `cf_doh` became empty; tables stayed equal and the IPv4 forward hook remained. |
| IPv4 `iptables -I forwarding_rule` during revision 2 | Exit 1, `ok=false`, `hook_apply_failed`, desired revision 2 / confirmed revision 1. Modeled `cf_doh` contained the new address; the IPv4 forwarding hook list became empty. |

The confirmation file stayed byte-for-byte unchanged in both probes. These observations demonstrate existing failure states and truthful rejection; they do **not** demonstrate the proposed improvement or preservation. No full regression rerun was needed for this documentation-only decision.

Reproduction uses the existing harness, entirely in its private fake root:

```python
import json, sys
sys.path.insert(0, "tests/fixtures")
from harness import RouterFixture, policy

for command, contains in [
    ("ipset", ["add", "cf_doh"]),
    ("iptables", ["-I", "forwarding_rule"]),
]:
    fixture = RouterFixture()
    try:
        old = policy()
        old["pauses"] = [{"person": "alice", "until": 0}]
        old["doh"]["ipv4"] = ["192.0.2.53"]
        initial = fixture.run("sync", document=old)
        assert initial.returncode == 0 and json.loads(initial.stdout)["ok"]
        before = fixture.backend()
        record = fixture.root / "etc/couvrefeu/runtime/confirmed"
        confirmation = record.read_bytes()
        new = policy(2)
        new["pauses"] = old["pauses"]
        new["doh"]["ipv4"] = ["192.0.2.54"]
        fixture.update_backend(failures=[{
            "command": command, "contains": contains, "remaining": 1,
        }])
        result = fixture.run("sync", document=new)
        after = fixture.backend()
        print(result.returncode, result.stdout.strip(),
              after["sets"]["cf_doh"]["members"],
              after["tables"] == before["tables"],
              after["tables"]["iptables"]["filter"]["forwarding_rule"],
              record.read_bytes() == confirmation)
    finally:
        fixture.close()
```

## Isolated packet-test proposal and evidence gates

No compatible lab is assumed available. Previously denied Docker and read-only Podman paths are not retried. The following is a run specification for a separately provisioned disposable compatible OpenWrt VM/runner, not an executable host-network setup or authorization to provision one.

Prerequisites: snapshot/console rollback, an isolated LAN and simulated WAN with no household uplink, genuine fw3/iptables/ip6tables/ipset/conntrack and BusyBox runtimes, required match modules, usable IPv4/IPv6 and a recorded offload setting. Record all versions and the degree of similarity to GL-XE3000 firmware. Provision one synthetic child, one protected adult and owned/foreign sentinel objects using documentation-only addresses. Endpoint A stays in both old and new lists; B is removed and C is added. Keep a harmless external-DNS/ordinary-traffic endpoint for adult controls.

Procedure for the future reviewed implementation:

1. Snapshot the VM and record exact configuration bytes/modes, set headers/members, hooks/rules, references, revisions and status. Prove the initial child policy and simultaneous adult connectivity with actual packets.
2. Send timestamped, sequenced probes to A/B/C through established and new flows while exercising the single eligible update. Include both directions where applicable. Correlate captures and command/journal timestamps; no sampling interval may be omitted from the evidence.
3. Inject each preparation boundary from the matrix. Require no changed live objects, no loss of the inspected old hook path, continuous rejection at A/B and unchanged adult DNS/access. A gap between captured probes bounds confidence; zero observed leaks is not universal atomicity proof.
4. Inject switch-outcome, post-switch verification, destroy, journal and confirmation failures; terminate the process after each successful command before recording completion. Record which list is active, status truth and recovery outcome. Repeat interruption during recovery and uninstall; compare original file bytes/modes/absence and foreign sentinel objects.
5. Separately demonstrate ineligible pause/schedule/IPv6/drift/reload paths remain classified as non-atomic; measure any transient or persistent gap. Do not relabel their results as covered by the DoH-only candidate. Re-run the unchanged no-op and manual-pause five-second packet-cutoff cases as separate regressions.

| Evidence level | Current status | What could satisfy it |
|---|---|---|
| Design and source mapping | Independently reviewed; both baseline probes reproduced | Documentation-only approval; proposed implementation and packet behavior remain pending. |
| Existing fake-backend failure reproduction | Two baseline probes completed above | Reproducible command/error/object observations only. |
| Candidate preparation/switch/recovery fixtures | Pending; candidate not implemented | Reviewed implementation and every required injected boundary plus regressions. |
| Compatible isolated packet continuity | Pending; no available lab claimed | Captures, versions, bounded timing, adult controls and interrupted recovery in the isolated lab. |
| Household target / production activation | Blocked | Exact-script/target/test-MAC/protected-identity/rollback approval and remaining acceptance gates; isolated evidence cannot replace these. |

The bounded lane ends with this design/evidence decision. Router code and fixture semantics remain unchanged; independent service/PWA work can proceed.
