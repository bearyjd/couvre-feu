-- Estimated network activity samples for enrolled children only. No IP address, neighbor state, domain or packet-content field exists.
-- Counters are cumulative router values; delta_* are derived at ingest and are NULL unless delta_state='valid'.
CREATE TABLE activity_samples (
 person_id TEXT NOT NULL, mac TEXT NOT NULL, sampled_at INTEGER NOT NULL CHECK(sampled_at>=0),
 router_epoch INTEGER NOT NULL, counter_epoch INTEGER NOT NULL,
 offload TEXT NOT NULL CHECK(offload IN ('on','off','unknown')),
 tx_bytes INTEGER NOT NULL, rx_bytes INTEGER NOT NULL, blocked_packets INTEGER NOT NULL,
 delta_state TEXT NOT NULL CHECK(delta_state IN ('baseline','valid','reset','gap')),
 interval_seconds INTEGER, delta_bytes INTEGER, delta_blocked INTEGER,
 CHECK((delta_state='valid')=(interval_seconds IS NOT NULL AND delta_bytes IS NOT NULL AND delta_blocked IS NOT NULL)),
 PRIMARY KEY(person_id,mac,sampled_at)
) STRICT, WITHOUT ROWID;
CREATE INDEX activity_samples_by_time ON activity_samples(sampled_at);
