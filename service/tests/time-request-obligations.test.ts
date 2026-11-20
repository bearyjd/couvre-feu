import test from 'node:test';
import assert from 'node:assert/strict';
import { integrationFixture } from './fixtures/integration.ts';
import { hasObligation } from '../src/time-request-obligations.ts';

const CASES: {state: string; repause: string; any: boolean; pending: boolean; approvedOnly: boolean}[] = [
    {state: 'pending', repause: 'not_needed', any: false, pending: true, approvedOnly: false},
    {state: 'approving', repause: 'waiting', any: true, pending: true, approvedOnly: true},
    {state: 'approved', repause: 'waiting', any: true, pending: true, approvedOnly: true},
    {state: 'approved', repause: 'applying', any: true, pending: true, approvedOnly: true},
    {state: 'apply_failed', repause: 'waiting', any: true, pending: true, approvedOnly: true},
    {state: 'approved', repause: 'done', any: false, pending: false, approvedOnly: false},
    {state: 'declined', repause: 'waiting', any: true, pending: true, approvedOnly: false},
];

test('hasObligation covers every state combination and option', () => {
    const f = integrationFixture();
    try {
        f.store.run("INSERT INTO request_links(id,person_id,token_hash,created_by,created_at) VALUES('link1','pilot','h','operator',1)");
        assert.equal(hasObligation(f.store), false);
        for (const c of CASES) {
            f.store.run('DELETE FROM time_requests');
            f.store.run("INSERT INTO time_requests(id,link_id,person_id,minutes,reason,state,created_at,expires_at,repause_state) VALUES('r1','link1','pilot',15,'',?,1,2,?)", c.state, c.repause);
            const label = `${c.state}/${c.repause}`;
            assert.equal(hasObligation(f.store), c.any, `${label} default`);
            assert.equal(hasObligation(f.store, {includePending: true}), c.pending, `${label} includePending`);
            assert.equal(hasObligation(f.store, {approvedRepauseOnly: true}), c.approvedOnly, `${label} approvedRepauseOnly`);
            assert.equal(hasObligation(f.store, {person: 'pilot', includePending: true}), c.pending, `${label} own person`);
            assert.equal(hasObligation(f.store, {person: 'other', includePending: true}), false, `${label} other person`);
        }
    } finally { f.cleanup(); }
});
