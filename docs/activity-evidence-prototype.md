# Fictional focused-browser activity evaluator

This offline prototype evaluates preconstructed fictional browser-focus intervals. It has no collector, event adapter, upload, persistence, enrollment or UI integration. Its only provenance is `synthetic-browser-focus`; its scope is `focused-browser`. The result estimates observed focused-browser time for one fictional device, never device presence, network use, website visits or general screen time.

Router byte-counter estimates of network activity are a separate feature described in [activity-service.md](activity-service.md); this prototype does not feed it.

Run its deterministic fixtures with the repository's Node 26.8.1:

```sh
node --test shared/tests/activity-evidence.test.ts
```

`evaluateActivityEvidence(input: unknown)` is exported from `shared/src/activity-evidence.ts`. The complete payload is validated before arithmetic. Malformed input throws `ActivityEvidenceValidationError` with the stable message `invalid_activity_evidence`; errors contain no supplied identifiers or values. Inputs are copied during validation and never mutated.

## Version 1 contract

Objects must have exactly the listed own enumerable data properties and the ordinary object prototype. Arrays must be dense ordinary arrays without extra properties. Accessors, extra fields, symbols, missing fields, unsupported versions and other provenance are rejected. This is an in-memory JSON-shaped contract, not a transport parser or authentication boundary.

| Field | Required value |
|---|---|
| `version` | `1` |
| `source` | `"synthetic-browser-focus"` |
| `deviceId` | `synthetic-device-` followed by 1–32 lowercase hexadecimal characters |
| `query` | Exactly `{start, end}`, the half-open requested window `[start,end)` |
| `context` | Exactly `{assignmentEpoch, clockEpoch}`; expected synthetic assignment epoch or `null`, and expected synthetic clock epoch |
| `coverage` | Array of observer coverage intervals |
| `focus` | Array of focused-domain intervals |

Each coverage interval has exactly `{start, end, assignmentEpoch, clockEpoch}`. Each focus interval has those fields plus `domain`. Assignment epochs use `synthetic-assignment-` plus 1–32 lowercase hexadecimal characters; clock epochs use `synthetic-clock-` plus the same bounded suffix. Interval epochs may be `null`, meaning unknown. Context clock epoch must be supplied. Device/source are inherited from the single payload, so separate devices or sources cannot be combined in one evaluation. Identifiers carry no person names, profiles or MAC addresses and are omitted from the result.

All times are nonnegative finite safe-integer milliseconds, with `start < end`. Query duration is at most 86,400,000 ms (24 hours). Times belong to the caller-declared clock coordinate; they are not an established mapping to real wall time. Absolute times may reach `Number.MAX_SAFE_INTEGER`. There are at most **256 intervals total across both arrays**, not 256 per array. Canonical validated JSON must be at most 65,536 ASCII bytes. The evaluator uses at most 514 segment boundaries and bounded quadratic interval checks.

Domains are normalized lowercase ASCII DNS hostnames, at most 128 characters, with labels of 1–63 characters containing letters, digits and internal hyphens. They must end in `.invalid`, with at least one preceding label, such as `study.example.invalid`. Full URLs, ports, paths, queries, fragments, titles, private identities and adult-profile fields are outside the contract and rejected. A synthetic hostname is a fixture label, not evidence of a real visit.

The qualification context is **caller-supplied fictional context**, not proof of a real child assignment, trustworthy time or collector authenticity. A non-null assignment epoch declares a single fictional child-assignment period; changing assignment requires another epoch. A clock epoch declares a single uninterrupted clock coordinate; discontinuity requires another epoch. Evidence retains the assignment and clock epochs that applied to its interval. Changing the expected context never relabels historical evidence. To evaluate a different epoch, make a separate request with its own query/context; do not sum the results into screen time.

## Coverage and uncertainty

Coverage asserts that the fictional observer could observe its focused-browser scope throughout an interval, including periods with no focused tab. It says nothing about other browsers, applications, network traffic, sleeping devices or overall device activity. All records, including those outside the query, must validate. Valid records are then intersected with the query **before** qualification/conflict calculation, so out-of-window conflicts or epoch mismatches cannot poison in-window evidence.

Within the query, a segment is qualified only when observer coverage exists and every overlapping coverage/focus interval has the expected non-null assignment and clock epochs. Unknown or mismatched evidence conservatively removes its overlapping segment from coverage, even if another overlapping observer record claims coverage. A disqualified focus interval therefore cannot become claimed idle time under valid observer coverage. Unambiguous surrounding portions remain usable.

Duplicates, same-domain overlaps and touching intervals are unioned by partitioning the query into atomic segments. Different domains touching at an endpoint are compatible. Simultaneously focused **different** domains contradict the single focused-browser source: the ambiguous overlap is removed from qualified coverage and activity, with `domain_conflict`. Surrounding unambiguous intervals are preserved. Conflicts in portions without observer coverage cannot produce observed activity.

The result contains exactly `source`, `scope`, `coverageState`, `coveredMs`, `reasons` and `activity`:

- `complete`: qualified coverage spans the entire query.
- `partial`: some qualified coverage exists, but part of the query remains unknown.
- `unavailable`: no qualified coverage; `coveredMs` is `0` and `activity` is **`null`**.
- Non-null `activity` contains `estimatedObservedFocusedMs` and lexically sorted `domains`, each with `domain` and `estimatedObservedFocusedMs`. Explicit covered browser-idle periods contribute zero focus. No focus records with no coverage produce null activity, never known-idle zero.

Domain subtotals sum to the focused total; the focused total never exceeds `coveredMs`, which never exceeds query duration. Partial results describe only qualified observed portions. Gaps and omitted segments remain unknown; there is no extrapolation or daily usage claim.

`reasons` contains deduplicated codes in this fixed order:

| Reason | Meaning |
|---|---|
| `assignment_unknown` | Expected assignment is unknown, or a query-intersecting interval has unknown assignment |
| `assignment_epoch_mismatch` | A query-intersecting interval differs from the known expected assignment epoch |
| `clock_unknown` | A query-intersecting interval has unknown clock epoch |
| `clock_epoch_mismatch` | A query-intersecting interval differs from the expected uninterrupted clock epoch |
| `observer_coverage_missing` | Some queried time has no supplied observer coverage interval at all |
| `domain_conflict` | Multiple distinct focused domains overlap in otherwise qualified observer coverage |

Epoch reasons can describe records in query portions that also lack coverage. A covered segment disqualified by an epoch or domain contradiction uses the specific reason, rather than claiming missing observer records. Reasons are explanations of the supplied data, not real platform diagnostics.

## Worked example

Run this from the repository root:

```sh
node --input-type=module <<'EOF'
import { evaluateActivityEvidence } from './shared/src/activity-evidence.ts';
const epochs = {assignmentEpoch: 'synthetic-assignment-01', clockEpoch: 'synthetic-clock-01'};
const interval = (start, end) => ({start, end, ...epochs});
console.log(JSON.stringify(evaluateActivityEvidence({
    version: 1, source: 'synthetic-browser-focus', deviceId: 'synthetic-device-01',
    query: {start: 0, end: 1000}, context: epochs,
    coverage: [interval(0, 1000)],
    focus: [
        {...interval(100, 700), domain: 'study.example.invalid'},
        {...interval(400, 900), domain: 'games.example.invalid'},
    ],
}), null, 2));
EOF
```

The ambiguous `[400,700)` overlap removes 300 ms from coverage. The result is `partial`, with `coveredMs: 700`, `reasons: ["domain_conflict"]` and 500 ms estimated observed focus: 300 ms for `study.example.invalid` and 200 ms for `games.example.invalid`. The remaining 200 covered milliseconds are browser-idle. The excluded 300 milliseconds are unknown. If the two contradictory domains spanned the whole query, activity would be null.

Real device presence, network-byte accounting, DNS/website visits, actual application/browser collection, activity-derived alerts, cross-device screen time, upload/storage, enrollment credentials and companion controls remain unavailable. Current UI labels and policy/enrollment behavior are unchanged. Collection adapters, consent/revocation, retention/deletion, replay/authenticity, clock mapping and real-device checks require separate approved designs. No router or Home Assistant invocation is involved.
