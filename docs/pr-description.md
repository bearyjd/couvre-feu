# Add router-local pause, schedules and recoverable installation

Assigned-device pauses and schedules must hold when the future control service is offline, and must not lock out protected parents. Address gaps remain explicit in status: uncertain child IPs are omitted, protected plausible bindings retain exclusions, and expiry/resume/reconstruction remove obsolete restrictions without false active-coverage confirmation. This PR adds a shell router core with strict policy/command validation, protected-client refusal, atomic durable state, early forwarding enforcement, local expiry, observed status and a recoverable installer/uninstaller.

Included: `router/cfctl`, restricted `cfctl-ssh`, shell libraries/awk policy parser, include/cron integration, default staging with explicit activation, original-content/checksum journal, validated zero-owned rollback reload suppression, durable kernel-cleanup intent, persistent recovery barriers, resumable uninstall phases and drift-refusing restoration, isolated fixtures/CI, acceptance runbook and proposed service/companion documentation. The installer never installs an authentication key. This is the public AGPL-3.0 router-core PR; no service/PWA/companion implementation or Fengard source is included.

## Changes from PRP-001

- Native confirmation validates complete selectors, earlier chain reachability and concrete WAN reject-path coverage through read-only fw3 inspection. Native fw3 schedules have early bidirectional time-match mirrors, using fresh unambiguous child address mappings, before established acceptance; native zone rules alone cannot promise existing-stream cutoff.
- Sync stdin has a ten-second pre-lock deadline with a new target-unverified timeout dependency. The strict parser accepts bounded ASCII JSON without escaped strings/keys and caps expanded per-device native windows at 256. Versioned JSON becomes one normalized, atomically replaced TSV state file with revision checks and separate runtime observations; protection persists for cron/include and uniquely resolved SSH clients.
- Kids IPv6 external DNS is blocked rather than redirected with NAT6. GL leak marks/order require real validation; dnsmasq/WAN settings are not changed.
- Bonus/Allow-until, telemetry and the policy service are deferred. PRP-002 remains the PWA; the future service contract is a proposal.

## Validation and limits

Fixture/static evidence is recorded by the actual final run. The latest installer-only run passed 43 tests; final core totals, complete CI and review approval remain pending. Earlier overlapping-source runs are not final evidence. Genuine BusyBox ash/awk/timeout fixture execution checks local runtime behavior, with real OpenWrt packet acceptance still pending. Installer recovery and core tests exercise simulated tools and cannot establish real packet behavior. Independent adversarial review and green CI are merge gates under the user's PR workflow.

Actual compatible OpenWrt integration, BusyBox target runtime behavior, five-second existing-stream cutoff, offload, GL DNS interoperability/adult access, durable IPv6, service-off cron expiry, reload/reboot, dedicated-key restrictions and firmware upgrade remain explicit acceptance gates. No SSH, router activation, device enrollment or deployment occurred. The next live test requires separate approval of its exact script, one supplied test MAC, protected identities and rollback. This PR makes no production-readiness claim.
