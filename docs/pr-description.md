# Add router-local pause, schedules and recoverable installation

Pauses and schedules must hold when a future service is offline while preserving parent access. This PR adds a shell router core for assigned devices, with strict bounded policy/command validation, persisted protection, early bidirectional enforcement, local expiry, observed status and exact-original recovery. No service/PWA, companion, telemetry or authentication-key installation is included; no router action or deployment occurred.

Healthy unchanged expire/apply-fw and identical same-revision sync verify actual sets/rules/hooks, fresh addresses/protection, persistent native configuration and kernel witnesses before leaving kernel objects and conntrack intact. Changed policy, higher revisions, drift or missing objects require reconstruction. Active address gaps remain explicit; expiry/resume can clear obsolete enforcement without falsely confirming missing coverage. Installation stages by default; activation is explicit, and resumable uninstall refuses foreign drift, retains cleanup intent and durable recovery barriers, and restores exact originals.

## PRP deviations

- Native fw3 schedules use early bidirectional time mirrors before established acceptance; persistent section/full-selector validation and concrete WAN reject-path witnesses prevent metadata-only health claims.
- Bounded ASCII JSON without escapes becomes one atomic normalized TSV policy file, with revision checks, persisted protection and a ten-second pre-lock input deadline. Expanded native windows are capped at 256.
- IPv4 kids DNS uses scoped redirection/INPUT handling; IPv6 external DNS is blocked instead of NAT6 redirected. No dnsmasq/WAN configuration edits. Bonus/Allow-until and future service/PWA work remain deferred.

## Validation and remaining gates

A prior complete local run passed 43 installer and 64 core fixtures plus ShellCheck/syntax checks. Candidate `8dcaa…` also passed genuine BusyBox CI: 43 installer (70.564 s), 64 core (600.825 s) and ShellCheck 0.9. These results predate the final unchanged-reconciliation fix and do not validate a later head. Final source fixture/static results and independent review are governed by [current PR checks](https://github.com/bearyjd/couvre-feu/pull/1/checks); merge requires green latest-head CI and independent approval. Fixtures use simulated router tools and cannot prove packet behavior.

Changed-policy/drift/reload reconstruction is **non-atomic**: enforcement can briefly open, and mid-apply failure can leave it open until successful repair. Production activation is blocked pending explicit design acceptance and actual compatible integration evidence for this residual behavior. Actual OpenWrt packet tests, target timeout/runtime compatibility, five-second cutoff, offload, GL DNS/adult safety, IPv6, reload/reboot, dedicated-key restrictions and firmware upgrade remain acceptance gates. Every live run needs separate approval of its exact script, one supplied test MAC, protected identities and rollback. This PR makes no production-readiness claim.
