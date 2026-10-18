<!-- Generated: 2026-10-17 | Files scanned: ~200 | Token estimate: ~198 -->
# Live tools (tools/live; python3 -I, stdlib only)
- `first-rehearsal.py` + `.sh`: one SSH session; phases identity gate, prereq, snapshot, empty install, verify, exact uninstall, restore proof, connectivity. Subcommands plan/execute; config keeps real data outside repo (`config.example.json` uses 02:00:00:00:00:xx, 192.0.2.0/24).
- `penn-pilot.py` + `.sh`: gate 3 of docs/integration-004.md; reuses rehearsal helpers (`cfr_*`).
  Phases: PAYLOAD, IDENTITY, PREREQ, SNAPSHOT, BASELINE, INSTALL (scoped `--rpc-allow <mac> --activate`), ENROLL (rpc-sync), PAUSE (180 s), RESUME, EXPIRY (120 s, cron clears), DNS, UNINSTALL, RESTORE, CONNECTIVITY.
  Usage: `plan CONFIG` then `execute CONFIG --expect-plan-sha256 HEX`. After MUTATION_BEGIN every outcome ends in the single teardown.
  Result lines: PENN_PILOT_PASS / PENN_PILOT_STOPPED_RESTORED[_CONNECTIVITY_FAILED]; PENN_KERNEL_STATE paused|clear|unknown.
- Config: host, admin key fingerprint pinned, knownHosts, evidenceDir (not tmpfs), authorizationPath, deadlineUtc, platformProfile, roles{management,jd_adult,penn_child}, protectedHistoricalMacs.
- `tools/freeze-router-release.py`: module pins + router/release.sha256.
- Tests: tests/test-live-rehearsal.py, tests/test-penn-pilot.py. Runbook: docs/runbooks/live-first-rehearsal.md.
