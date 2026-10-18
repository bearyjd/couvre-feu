<!-- Generated: 2026-10-17 | Files scanned: ~200 | Token estimate: ~229 -->
# Data (SQLite, STRICT tables; db.ts `Store`, migrations in service/migrations)
Main DB migrations 001..006; integration DB adds integration-001..002.

| Migration | Adds |
|---|---|
| 001 | accounts (role admin/parent, person_ids, permission_version), credentials (1 per account), bootstrap_tokens, challenges, sessions, service_state (desired_json, highwater, observation), operations, audit |
| 002 | auth_contexts; browser_epoch/generation on challenges, browser_hash/epoch on sessions |
| 003 | operations rebuilt: actions pause/resume/schedule_{create,update,delete}; state pending/confirmed/unknown/failed/conflict; UNIQUE(actor,idempotency_key) |
| 004 | parent_alerts (6 kinds; open/acknowledged/resolved; one unresolved per kind+person) |
| 005 | activity_samples (delta_state baseline/valid/reset/gap; PK person,mac,sampled_at) |
| 006 | request_links (one active per person), time_requests (state machine incl. approving, repause_state) |
| integration-001 | integration_state (singleton, generation, dispatch_epoch, dispatch_stopped), operation_rpc (phase queued/claimed/uncertain/resolved; delivery), dispatch_batches, dispatch_steps |
| integration-002 | dispatch_steps rebuilt (single ordinal, kinds observe/apply/receipt/activity, states consumed/resolved/uncertain/revoked); index dispatch_live_claims |

Also referenced: automatic_read_summary (created in integration-db.ts).
Pending #48 adds migration 007 (accounts/passkeys); not on main.
Router-side state: see [router.md](router.md).
