-- Ask-for-time grants as router allowances. A request approved through a router-side allowance records how it is applied
-- ('allowance') and the allowance operation it waits on; older rows keep the resume + re-pause path ('resume') and drain as before.
ALTER TABLE time_requests ADD COLUMN apply_via TEXT NOT NULL DEFAULT 'resume' CHECK(apply_via IN ('resume','allowance'));
ALTER TABLE time_requests ADD COLUMN grant_operation_id TEXT;
