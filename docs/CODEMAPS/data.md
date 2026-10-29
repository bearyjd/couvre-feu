<!-- Generated: 2026-10-29 | Files scanned: ~200 | Token estimate: ~229 -->
# Data (SQLite, STRICT tables; db.ts `Store`, migrations in service/migrations)
Main DB migrations 001..012 (`PRAGMA user_version`; integration mode runs 001, 002, 005..012, db.ts:9). The integration DB adds integration-001..007 (integration-db.ts).

| Migration | Adds |
|---|---|
| 001 | accounts (role admin/parent, person_ids, permission_version), credentials (1 per account), bootstrap_tokens, challenges, sessions, service_state (desired_json, highwater, observation), operations, audit |
| 002 | auth_contexts; browser_epoch/generation on challenges, browser_hash/epoch on sessions |
| 003 | operations rebuilt: actions pause/resume/schedule_{create,update,delete}; state pending/confirmed/unknown/failed/conflict; UNIQUE(actor,idempotency_key) |
| 004 | parent_alerts (6 kinds; open/acknowledged/resolved; one unresolved per kind+person) |
| 005 | activity_samples (delta_state baseline/valid/reset/gap; PK person,mac,sampled_at) |
| 006 | request_links (one active per person), time_requests (state machine incl. approving, repause_state) |
| 007 | credentials rebuilt without UNIQUE(account_id) (many passkeys per account; label, state active/pending); sessions.credential_id; bootstrap_tokens purpose/created_by/label/first_enrollment; step_ups (passkey confirmation bound to one change) |
| 008 | accounts.scope_all; people (kind child/device_group); devices (state enrolling/active/removing) |
| 009 | time_requests.apply_via (resume/allowance), grant_operation_id |
| 010 | parent_audit (ids and closed enums only; no free text, domains, MACs or addresses; pruned after 90 days) |
| 011, 012 | parent_audit rebuilt to admit action `reward_add` (011) and `focus_start` (012); ids and AUTOINCREMENT counter carried over |
| integration-001 | integration_state (singleton, generation, dispatch_epoch, dispatch_stopped), operation_rpc (phase queued/claimed/uncertain/resolved; delivery), dispatch_batches, dispatch_steps |
| integration-002 | dispatch_steps rebuilt (single ordinal, kinds observe/apply/receipt/activity, states consumed/resolved/uncertain/revoked); index dispatch_live_claims |
| integration-003 | operations.action admits device enrollment (`enroll`) |
| integration-004 | router scope tracking, operation_people, bulk/move operation shapes (`pause_all`) |
| integration-005 | devices state `moving` (move_to) |
| integration-006 | network inventory tables, `inventory` step kind, `new_device` alert kind |
| integration-007 | operations.action admits `allow` (router allowance for ask-for-time grants and Reward Time; a focus window is a labelled timed pause, not a new kind) |

Also referenced: automatic_read_summary (created in integration-db.ts).
Highest numbered migration: 012 (service/migrations). Features that write to `parent_audit` are flagged off by default (`auditLog.enabled`).
Router-side state: see [router.md](router.md).
