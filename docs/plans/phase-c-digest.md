# Phase C plan: weekly blocked-lookup counts from NextDNS analytics (PRP-006 §5.6, §5.6a, D5)

Status: **plan only.** Nothing here is built. No router is touched by any step in this plan. Every step that calls
the real NextDNS API with the household key is a live step and needs the owner's approval like any other live read.
Written 2026-11-13 against the repo as it stands (Phase A merged behind `contentFilter.mode`, migration 014,
integration-008, `ContentFilterWatch`, B7 digest behind `digest.enabled`).

Files read first: `AGENTS.md`, `docs/content-filtering-stack.md`, `docs/prp/PRP-006-content-filtering.md`,
`docs/ROADMAP.md` (privacy design gate), `docs/service-contract.md` (B7 digest, content filter sections),
`service/src/nextdns-client.ts`, `content-filter-{config,state,reconcile,watch,wiring,http}.ts`, `parent-alerts.ts`,
`alert-rules.ts`, `digest.ts`, `push-runtime.ts`, `push-sender.ts`, `migrations/014.sql`, `migrations/integration-008.sql`,
`integration-db.ts`, `db.ts`, `tests/content-filter-http.test.ts` (G7), `tests/push-digest.test.ts`,
`web/public/content-filter.js`.

---

## 0. Decision in one paragraph

Use the NextDNS **analytics aggregate endpoints only** (`/analytics/status` and `/analytics/reasons`), never `/logs`,
`/logs/stream`, `/logs/download`, `/analytics/domains`, `/analytics/devices`, `/analytics/ips` or `/analytics/destinations`.
Fetch **one finished local day at a time** per child (America/New_York, the digest's zone), map every reason id
through a **closed code table** to a fixed class code (unknown → `other`, the id discarded), and store **integers
only** in a new table: per child, per day, per class. The digest and the UI sum stored days; they never call NextDNS.
The ntfy push carries one household-wide integer ("N blocked lookups"), never a child or a class. Per-child and
per-class numbers are visible only in the signed-in app. Behind `contentFilter.counts` (absent = off), and the alert
(§5.6a) behind its own sub-flag, off until a measurement week sets the threshold.

---

## 1. What the NextDNS API actually offers (checked 2026-11-13)

Source: the official API doc, <https://nextdns.github.io/api> (fetched 2026-11-13), plus NextDNS help-forum
threads cited inline. Anything not stated there is marked UNVERIFIED and is handled defensively.

CONFIRMED from the API doc:

- Analytics live at `https://api.nextdns.io/profiles/:profile/analytics/*`; endpoints are `status`, `domains`,
  `reasons`, `ips`, `devices`, `protocols`, `queryTypes`, `ipVersions`, `dnssec`, `encryption`, `destinations`
  (`type=countries|gafam`).
- Query parameters: `from` (inclusive) and `to` (exclusive) dates; `limit` default 10, range 1–500; `cursor` for the
  next page; `device` filter (`__UNIDENTIFIED__` for unidentified devices). `status`, `root`, `reason` filters apply to
  `domains` only.
- Date formats accepted: ISO 8601, **Unix timestamp in seconds**, relative (`-6h`, `-1d`, `now`), common dates
  (`2021-03-15`).
- Response: `{"data":[...]}`, each item has `queries`. `status` items are `{status, queries}` (example
  `"status":"default"`). `reasons` items are `{id, name, queries}`, example `id: "blocklist:nextdns-recommended"`,
  `name: "NextDNS Ads & Trackers Blocklist"`.
- Time series: append `;series` (`interval`, `alignment` start|end|clock, `timezone` IANA default GMT, `partials`),
  `meta.series.times` and `meta.series.interval`.
- Logs are a separate family (`/logs`, `/logs/stream` SSE, `/logs/download`, `DELETE /logs`) whose entries carry
  `domain`, `root`, `clientIp`, `device`, `reasons`. **We never call these.**
- "Most endpoints that return an array for the `data` key are paginated"; `cursor` is `null` on the last page.
- Errors: `400` with `{"errors":[...]}`.
- The API "is currently in beta and is subject to breaking changes without notice".
- The doc does **not** mention rate limits or 429, and gives no retention for analytics.

From third-party mirrors of the same API (withone.ai knowledge page for "Profile Analytics Reasons"): reason ids
seen in examples are `blocklist:nextdns-recommended`, `native:apple`, `disguised-trackers` (prefixed and unprefixed
forms). **No example shows a parental-control category, service, block-bypass or denylist reason id.** UNVERIFIED.

From the NextDNS help forum:

- "Blocked Reasons" in the dashboard is described as "Security, Privacy and/or Parental Control settings that
  blocked the most queries" (help.nextdns.io/t/60yt1bl, 2024-08-22); the dashboard shows only the top 6
  (help.nextdns.io/t/35hf2t9). The API's `limit` up to 500 should not have this cap (UNVERIFIED).
- Logs are kept only for the configured retention; when logs are disabled they are "never created"
  (staff, help.nextdns.io/t/p8hpdsa, 2021). Whether **analytics** follow the log retention is not stated by staff.
  UNVERIFIED; this plan assumes they do (worst case) and is built to survive it.
- Free plan: after 300k queries a month "all features except basic DNS resolution are disabled" and "nothing is
  logged anymore" (staff, help.nextdns.io/t/p8hmvaw). So over the limit, **filtering itself is off and analytics
  would read near zero**, which a naive digest would report as "0 blocked". §6 handles this.

Consequences for the design:

1. `status` gives a blocked total (status `blocked`) and a total; `reasons` gives the per-reason split. Two GETs per
   child per day. Both are aggregates with no domain or device field in their documented shape.
2. Reason ids are an open, vendor-defined set, and their forms for parental control are unknown. They must never be
   stored, logged or shown verbatim; only a closed class code derived from them.
3. With one-week log retention (D4) and possibly the same for analytics, a digest that asks NextDNS for "the last 7
   days" at send time can lose its oldest hours (and a digest deferred from Sunday 18:00 to Monday 07:00 by quiet
   hours asks for 7.5 days). Daily snapshots taken soon after each day ends avoid this.
4. Beta API: strict parsing that refuses unknown shapes, so a change shows "counts unavailable", never wrong numbers.

---

## 2. Scope and non-scope

In scope:

- C-counts: daily per-child blocked counts by class, stored as integers.
- Digest: one household-wide integer added to the existing push digest text.
- In-app: a "Last 7 days" block on each child's existing Content filter card.
- Later, separately flagged: `blocked_category_attempts` alert (§5.6a).

Not in scope (and refused by construction):

- Any log entry, domain, root domain, device name, client IP, protocol or destination country.
- The `device` analytics filter (profiles are already per child; device names are household-identifying).
- The strict default profile (D1): its counts mix unmapped kids-path devices and possibly guests; not attributable
  to a child. Open decision O5.
- Per-service breakdown (TikTok vs Discord): aggregated into one `apps` class by default. Open decision O3.
- Anything on the router. `traffic_without_dns`, `dns_bypass_attempts` etc. are other Phase C items.

---

## 3. Manifest key (absent = off)

Extend `contentFilter` (strict keys in `parseContentFilter`, `content-filter-config.ts`):

```json
"contentFilter": {
  "mode": "owner",
  "apiKeyFile": "/etc/couvrefeu/private/nextdns.key",
  "defaultProfile": "<id>",
  "profiles": { "<personId>": "<profileId>" },
  "counts": { "enabled": true, "alert": false }
}
```

- `counts` absent, or `counts.enabled` false: no fetch, no timer, no route (404 `route_not_found` as today's gate),
  digest unchanged byte for byte.
- `counts` present with `mode: "off"` is accepted and ignored (other keys are accepted under `off` today, so the owner's "set mode off" rollback must never fail validation). The refusal pattern used elsewhere is
  `digest_requires_push`.
- `counts.alert` (strict boolean, absent = false): turns on the `blocked_category_attempts` rule. Refused unless
  `counts.enabled` is true. Ships in the last PR; the key is not accepted before that PR (unknown key → refused).
- Visibility follows `contentFilter.mode` exactly (owner only, then parents), via `ContentFilterRoutes.visible`.
- The digest line additionally needs `digest.enabled` (which already needs `push.enabled`).
- Any manifest edit needs a rebind (service contract "how to turn a flag on"); documented in the PR.

Thresholds and schedule are code constants, not manifest knobs (PRP-006 §2.2 rule).

---

## 4. Data model and migration

### 4.1 Class codes (closed enum, code constant, shared with web)

`service/src/content-filter-classes.ts`:

| Class code | Meaning in UI | Counts toward "blocked by your filter" headline |
|---|---|---|
| `adult` | Adult content (category `porn`) | yes |
| `gambling` | Gambling | yes |
| `dating` | Dating | yes |
| `piracy` | Piracy | yes |
| `social` | Social networks | yes |
| `gaming` | Gaming | yes |
| `video` | Video streaming | yes |
| `apps` | Blocked apps and services (all services summed) | yes |
| `bypass` | Ways around the filter (Block Bypass) | yes |
| `denylist` | Sites you blocked by hand (count only) | yes |
| `ads_trackers` | Ads and trackers (privacy blocklists, natives, disguised trackers) | no ("background") |
| `security` | Security protections (threat feeds, NRD, rebinding, ...) | no ("background") |
| `other` | Any reason id not in the table | no, shown as "other" |

Mapping rule `classOf(reasonId: string): ClassCode`, pure and exhaustive:

- exact-match table first (to be filled from the probe in PR C0; candidates UNVERIFIED: `porn`,
  `parentalcontrol:porn`, `category:porn`, ...);
- prefix families: `blocklist:` and `native:` → `ads_trackers`; `disguised-trackers` → `ads_trackers`;
  any id starting with `denylist` (exact `denylist` or `denylist:<anything>`) → `denylist` **with the suffix
  discarded** (a `denylist:<domain>` form is possible and would carry a domain);
- service ids from `content-filter.js` `SERVICES` and the client's `SERVICE_ID` shape, when the probe shows how
  services appear → `apps`;
- everything else → `other`.
- Classification never echoes input: no string built from the id leaves the function.

Why codes, not NextDNS names: names are vendor free text (could change, could contain anything); codes are a CHECK
constraint and a test fixture. PRP-006 §9 already requires "a fixed class code and count, never free text".

### 4.2 Migration 015 (`service/migrations/the next free numbered migration after #139 (which already adds 015)`, added to both lists in `db.ts`)

```sql
-- PRP-006 C (D5): NextDNS analytics counts per child per local day. Integers and fixed codes only: no domain, reason id,
-- reason name, device or profile id is stored. Rows are written by the counts fetcher only; read by the counts route and the digest.
CREATE TABLE content_filter_day (
 person_id TEXT NOT NULL CHECK(length(person_id) BETWEEN 1 AND 64),
 day TEXT NOT NULL CHECK(day GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),   -- America/New_York calendar day
 state TEXT NOT NULL CHECK(state IN ('ok','unavailable','logs_off','suspect_zero')),
 total INTEGER CHECK(total IS NULL OR total >= 0),            -- all lookups (status endpoint), NULL unless ok/suspect_zero
 blocked INTEGER CHECK(blocked IS NULL OR blocked >= 0),      -- status=blocked
 attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
 fetched_at INTEGER NOT NULL,
 PRIMARY KEY(person_id, day),
 CHECK((state IN ('ok','suspect_zero')) = (total IS NOT NULL AND blocked IS NOT NULL))
) STRICT;
CREATE TABLE content_filter_day_class (
 person_id TEXT NOT NULL,
 day TEXT NOT NULL,
 class TEXT NOT NULL CHECK(class IN ('adult','gambling','dating','piracy','social','gaming','video','apps','bypass',
   'denylist','ads_trackers','security','other')),
 queries INTEGER NOT NULL CHECK(queries >= 0),
 PRIMARY KEY(person_id, day, class),
 FOREIGN KEY(person_id, day) REFERENCES content_filter_day(person_id, day) ON DELETE CASCADE
) STRICT;
CREATE INDEX content_filter_day_day ON content_filter_day(day);
```

Notes:

- Additive tables only; created by the numbered migration like `content_filter_desired` in 014. With the flag off
  the tables exist but stay empty (same as 014). Migration test: from 014 → 015 on a populated fixture DB, rows and
  `user_version` as expected; `content-filter-migration.test.ts` extended.
- No `profile_id` column: the manifest maps person → profile; storing the id adds an identifier for no benefit.
- `day` is a local date string, not an epoch, so DST days (23 h, 25 h) are one row each.
- No raw JSON, no `name`, no reason id column: there is nothing to leak from a DB dump beyond integers and codes.
- Retention: rows older than `COUNTS_RETENTION_DAYS` (proposal **56 days**, matching the roadmap's 8-week rule for
  online-time estimates) are deleted by the fetcher's own pass. Open decision O2.
- The alert kind (§8, PR C5) needs `integration-009.sql` rebuilding `parent_alerts` to admit
  `blocked_category_attempts`, exactly as integration-008 did for `filter_drift`, marker `'blocked_category_attempts'`.

### 4.3 Store API (`service/src/content-filter-counts.ts`)

```ts
export type DayState = 'ok' | 'unavailable' | 'logs_off' | 'suspect_zero';
export interface DayCounts { day: string; state: DayState; total: number | null; blocked: number | null;
    classes: Partial<Record<ClassCode, number>> }
export class ContentFilterCountsStore {
    put(person: string, counts: DayCounts, now: number): void;          // one transaction: day row + class rows replaced
    markUnavailable(person: string, day: string, now: number): void;    // attempts+1, keeps an earlier ok row untouched
    days(person: string, from: string, to: string): DayCounts[];        // inclusive local days
    householdBlocked(from: string, to: string): {blocked: number; okDays: number; expectedDays: number};
    prune(oldestKeptDay: string): number;
}
```

---

## 5. Fetch contract

### 5.1 Client additions (`nextdns-client.ts`)

Two methods, nothing else:

```ts
getAnalyticsStatus(profile, range: {from: number; to: number}, call?): Promise<{total: number; blocked: number}>;
getAnalyticsReasons(profile, range: {from: number; to: number}, call?): Promise<readonly {class: ClassCode; queries: number}[]>;
```

- Paths are built only from a frozen table `{status: '/analytics/status', reasons: '/analytics/reasons'}` behind
  `profilePath`; there is **no generic analytics(path) method**, so `domains`, `devices`, `ips`, `logs` cannot be
  reached from the service. A test enumerates the client's own keys and asserts no method name or path contains
  `log`, `domain`, `device`, `ip`, `destination`, `stream`, `download`.
- Query string: `from=<unix seconds>&to=<unix seconds>` (both integers, `from < to`, `to - from <= 90000`),
  `limit=500` for reasons. No `device`, `status`, `root`, `reason` or `search` parameter is ever sent. Pagination is
  read through the existing `readAll` (cursor loop guard, page cap), so a paginated reasons answer is summed fully.
- Parse strictly with the existing `obj/arr/str` validators:
  - status item: `obj(v, ['status','queries'])`, `status` matches `/^[a-z_]{1,32}$/`, `queries` safe integer ≥ 0.
  - reasons item: `obj(v, ['id','name','queries'])`; `id` matches `/^[\x21-\x7e]{1,256}$/` (shape only), `name` is
    type-checked (string ≤ 200) and **dropped in the parser** (never in the returned object), `queries` safe int ≥ 0.
  - Unknown keys → `bad_response` (the beta-API rule the client already follows).
- Errors are the client's closed codes only (`rate_limited`, `unauthorized`, `bad_response`, ...). No server text.
- `GET` is retried by the client on 429/5xx/transport with backoff and Retry-After, inside its deadline.
- As built (C1): `getAnalyticsStatus` returns integers `{total, blocked}` (`blocked` = status `blocked`, `total` = all statuses);
  `getAnalyticsReasons` maps each id through `classOf` inside the client and returns per-class sums `{class, queries}`
  (stable `CLASS_CODES` order, zero classes omitted). The raw reason id and `name` never leave the client. The range must be a
  finished period: `to` not after the client clock (equality allowed); a non-finite clock fails closed (`invalid_request`).

### 5.2 Fetcher (`ContentFilterCounts`, scheduled like `ContentFilterWatch`)

- Hourly tick (unref'd timers; first tick a few minutes after start; same `running` guard as the watch).
- **Which days:** for each child in `contentFilter.profiles` (not the default profile), each local day `D` from
  `today-6` to `yesterday` whose row is missing or `unavailable`, and only once local time is past **03:00 on D+1**
  (settling margin for NextDNS aggregation lag; lag UNVERIFIED, measured in C0). Today's partial day is never
  stored. Days older than `today-6` are not attempted (presumed beyond the one-week retention).
- **Range:** `from` = epoch of local midnight starting `D`, `to` = epoch of local midnight starting `D+1`, computed by a
  DST-safe helper factored out of `digest.ts` (`zoned`/`local` become an exported `localDayBounds(day)`), so 23 h and
  25 h days are exact. Unix seconds avoid any time-zone parsing on NextDNS's side.
- **Per child per day:** `getSettings(profile)` once per pass (cached for the pass): if `logs.enabled` is false →
  store `logs_off` (no analytics call). Else `getAnalyticsStatus` then `getAnalyticsReasons`; sum `queries` by
  `classOf(id)`; `blocked` = sum of status items with `status === 'blocked'`; `total` = sum of all status items.
- **suspect_zero:** if `total === 0` for a child whose devices showed network activity that day (activity store
  daily estimate above a constant, only when the activity feature is on), store `suspect_zero` instead of `ok`. It
  means "NextDNS saw no lookups while the device was online": over the plan limit, logs paused, delivery not in path
  (Phase B not live), or the child used another resolver. Never shown as "0 blocked".
- **Budget:** at most `children × 7 × 3` GETs per pass, sequential, inside one overall pass budget (e.g. 60 s), the
  client's deadline per call. A pass that runs out stops; the next hour continues.
- **Failures:** any client error → `markUnavailable` (attempts+1). Never overwrites an existing `ok` row.
  After the day falls out of the 7-day window it stays `unavailable` forever (honest gap).
- **Re-fetch:** an `ok` day is final; it is not re-read (keeps calls low; analytics finality UNVERIFIED, checked in C0).
- **Prune:** at the end of each pass, delete days older than retention.
- **Logging:** none. Like the watch and reconciler: never throws, never writes stdout/stderr. One optional fixed tag
  `content_filter_counts_failed` on a pass-level exception (no code, no child, no profile).

### 5.3 Route

`GET /people/:id/filter/counts` (same gate as `/people/:id/filter`: `visible(actor)`, `authorize`, child configured;
identical 404s; no NextDNS call is ever made by a request):

```json
{
  "note": "unverified on this router",
  "days": [
    {"day": "2026-11-08", "state": "ok", "total": 4210, "blocked": 63,
     "classes": {"adult": 2, "social": 11, "apps": 9, "bypass": 1, "ads_trackers": 40}},
    {"day": "2026-11-09", "state": "unavailable"},
    {"day": "2026-11-10", "state": "logs_off"},
    {"day": "2026-11-11", "state": "suspect_zero", "total": 0, "blocked": 0}
  ],
  "week": {"filterBlocked": 23, "background": 40, "okDays": 5, "days": 7}
}
```

- Always the last 7 complete local days (no query parameters in the first version; nothing to validate or abuse).
- `classes` keys are class codes; values integers; zero classes omitted.
- `week.filterBlocked` sums only headline classes (§4.1) over `ok` days; `background` sums `ads_trackers`+`security`.

---

## 6. Failure modes

| # | Failure | What the service does | What the parent sees |
|---|---|---|---|
| F1 | NextDNS unreachable / 5xx / timeout | Client retries GETs; then `unavailable`, retried hourly while within 7 days | Day shows "No count (NextDNS did not answer)"; week total says "5 of 7 days" |
| F2 | 429 rate limited (limits undocumented) | Client honours Retry-After up to 30 s, else stops; pass ends early, resumes next hour | Same as F1 if it persists |
| F3 | 401/403 (key rotated, file unsafe) | `unavailable`; the existing watch already raises `filter_drift` `unreachable` after 3 failures | Filter card already shows the drift alert |
| F4 | Beta API shape change (new field, renamed key) | Strict parse → `bad_response` → `unavailable` | Counts missing, never wrong. Fix = client update + fixture |
| F5 | New reason id (e.g. new category) | Counted in `other` | "Other: N"; a test fixture is added once identified |
| F6 | Logs turned off on the profile | `logs_off`, no analytics call | "Logging is off for this profile in NextDNS, so there are no counts" |
| F7 | Free-plan 300k limit hit (filtering and logging stop per NextDNS staff) | `total` ≈ 0 while the child was online → `suspect_zero` (when activity is on); otherwise `ok` with zeros | "NextDNS saw no lookups while the device was online. Filtering may be off (plan limit, outage, or the device is not using it)." Recommend a paid plan (O7) |
| F8 | Analytics retention shorter than 7 days or analytics lag | Days missed while down are re-tried only within the window; lag margin 03:00 | Honest gaps; C0 measures both |
| F9 | Service down over a weekend | Backfills up to 6 days back on start | Gap only for days older than that |
| F10 | Phase B not live (devices not using the profile) | Counts are real but cover only what reached the profile | Card copy: "Counts cover only lookups that reached this child's NextDNS profile" |
| F11 | Store failure (disk full) | Pass ends; nothing logged with data | Missing days |
| F12 | Digest due while some days unavailable | Digest sums ok days only and says so | "N blocked lookups (5 of 7 days)" |
| F13 | Flag turned off then on | Rows kept until pruned; backfill again up to 6 days | Older gaps stay gaps |

Nothing in this feature changes enforcement, pauses, or filters. A total outage of the feature is cosmetic.

---

## 7. Digest and UI

### 7.1 Push digest (ntfy, leaves the service host)

`DigestCounts` gains an optional `blocked?: {count: number; okDays: number; days: number}`. `pushText` appends, only
when present:

- all days ok: `Last 7 days: 3 requests, 2 grants, 1 pauses, 63 blocked lookups.`
- partial: `..., 63 blocked lookups (5 of 7 days).`
- no ok day: `..., blocked lookups unavailable.`

Rules:

- Household sum over all configured children, headline classes only (filter blocks, not ads/trackers). **No child
  name or id, no class name, no per-child split** in the push (ROADMAP: "No child names, no reason text ... in the
  payload"; PRP-006 §9 keeps class names in-app). A class word such as "adult content" on a lock screen is exactly
  the kind of text the push rule forbids. Open decision O4 if the owner wants per-child numbers in the push
  (would need anonymous ordinal labels like "child 1", still not recommended).
- Window: the 7 local days ending with the Saturday before the slot's Sunday (the digest fires Sunday 18:00, so
  Sunday is incomplete). Stated in the service contract; differs from the requests/grants window (slot to slot) by
  18 hours. Accepted; the alternative (ask NextDNS at send time) fails F8.
- Numbers pass the existing `count()` coercion; text is constants + integers only.

### 7.2 In-app (filter card, `web/public/content-filter.js`)

Below the existing state pill, a collapsed "Last 7 days" block per child, fetched from the counts route:

- Headline: "23 lookups blocked by this filter (5 of 7 days counted)".
- Up to 5 classes by count, using the same labels as the card's `CATEGORIES` ("Adult content 2, Social networks 11,
  Apps 9, Ways around the filter 1"), then "Also blocked: 40 ads and trackers, 0 security".
- Day strip: 7 cells, number or a short state word (no count / logging off / check NextDNS).
- Fixed copy, always shown: "Counts only. Couvre-feu does not see or keep which sites. Blocked lookups also come from
  ads, app prefetching and accidental taps; a number is a reason to talk, not proof. To see sites, open the NextDNS
  Logs tab (kept one week)." plus "unverified on this router".
- All text via `textContent`; class codes not in the web table are shown as "Other".
- 404 `route_not_found` hides the block for the session (same as the card).

---

## 8. Alert `blocked_category_attempts` (§5.6a), last and separately flagged

- Rule in `alert-rules.ts`: input `DayCounts` for the last complete day per child; candidate when a headline class
  count ≥ `CLASS_ALERT_THRESHOLD[class]` (code constants, set from C0's measurement week; `bypass` and `adult`
  likely lowest). Severity `info` (never `critical`; PRP R14).
- `details`: `{class: '<code>', count: n, day: 'YYYY-MM-DD', threshold: n}` (≤ 1024 bytes; class from the closed
  enum, validated before write). One alert per child (existing unique key `(kind, person)`); a standing condition
  resolved after a clean day, like the activity kinds.
- Visibility: same as `filter_drift` (follows `contentFilter.mode`); owner-only for two weeks before parents mode
  (PRP Phase C exit rule).
- Push: the existing content-free "New alert" only.
- Web `parent-alerts.js` label: "Several blocked lookups in one category"; body renders the class label from the
  closed web table and the count, plus the benign-causes sentence.

---

## 9. Privacy analysis

The gate (ROADMAP privacy design gate, PRP-006 G7): no domains/URLs/browsing data stored except D8 lists; counts and
action types only; alert details ≤ 1024 bytes, never MACs, addresses, domains, diagnostics; push content-free; no
household identities in logs, alerts, digests.

| # | What could leak | Where | How it is prevented | How the gate catches a regression (test) |
|---|---|---|---|---|
| P1 | A domain via the logs API | DB, logs | No client method or path for `/logs*`, `/analytics/domains`; path table frozen | T-client-surface: enumerate methods/paths; fake server fails the test on any request outside the two allowed paths |
| P2 | A domain inside a reason id (`denylist:<domain>` is possible) | DB, logs, UI | Ids never stored; `classOf` maps to a code; denylist prefix discarded | T-classof: fuzz ids including `denylist:secret-domain.test`, `blocklist:secret-domain.test`, unicode, 256-char; assert output ∈ enum; G7 haystack has no `secret-domain` |
| P3 | Vendor free text (`name`) | DB, UI | Dropped in the parser; never in the returned type | T-parse: returned objects are exactly `{total, blocked}` and `{class, queries}` (every returned string is a class code); G7 haystack check for a sentinel placed in `name` |
| P4 | Device names / client IPs | DB | No `device` param, no devices/ips endpoints; status/reasons items with extra keys are refused | T-parse: an item carrying `device`/`clientIp` → `bad_response`; sentinel not in haystack |
| P5 | Profile id (household identifier at NextDNS) | DB, logs, route, errors | No profile column; errors are closed codes; route answers have no profile | G7: `PROFILE_ID` sentinel absent from stdout/stderr/route bodies/DB dump of the two new tables |
| P6 | API key | logs, errors | Existing getter + closed codes | Existing snapshot test extended to counts fetcher paths (401, unsafe file) |
| P7 | Child identity in push | ntfy | Household sum only; text from constants + integers | T-push-snapshot: exact-string table for all three digest variants; regex `^[A-Za-z ,.:()0-9]+$`; no person id, display name or class word from a fixture |
| P8 | Class words in push (sensitive about a child) | ntfy | Not included | Same snapshot: none of the class labels/codes appear |
| P9 | Alert details carrying text | parent_alerts | Closed enum validated before write; DB CHECK on kind; details shape test | T-alert-details: only keys `class,count,day,threshold`; `class` ∈ enum; JSON ≤ 1024 |
| P10 | Logs written on failure | stderr | Fetcher never logs except a fixed pass tag | G7: capture stdout/stderr across a run with every failure (400 with domain in `detail`, 429, timeout, bad JSON, unknown id) and assert none of the sentinels and no NextDNS error text |
| P11 | Error bodies to parents | route | Route reads the DB only; NextDNS errors never reach it | G7: route bodies collected for 404s and 200s contain no sentinel |
| P12 | Too-fine data (behaviour timeline) | DB, UI | Daily granularity only, no hours; 56-day retention; no per-service split by default | T-schema: no column finer than day; T-prune; review rule |
| P13 | Default profile (guests/adults) counted | DB | Not fetched | T-fetch: default profile id never in any request path |
| P14 | DB backup holds per-child sensitive counts (e.g. adult: 3 on a date) | backups | Treated as private like the rest of the DB; retention bound | Doc only (service contract + R20-style row); not testable |

New G7 test (`content-filter-counts.test.ts`, modelled on the existing G7 in `content-filter-http.test.ts`):
a fake NextDNS that returns status/reasons whose ids, names and error details contain `SECRET_DOMAIN`, a device
name sentinel and the profile id; run a full backfill pass, the counts route for an authorised and an
unauthorised parent, the digest text builder, and the alert rule; then join captured stdout, stderr, all non-200
and 200 route bodies, the push text, `parent_alerts` rows, `parent_audit` rows and a dump of the two new tables,
and assert none of the sentinels appear. The 200 counts body is included (unlike the filter GET, it must never
carry a domain).

Residual risk (stated in docs): NextDNS still holds the logs for a week and sees every query (vendor trade-off the
owner accepted in R15). The counts themselves are sensitive about a child even without domains; they are shown
only to the parents the mode allows and are not pushed.

---

## 10. PR breakdown (one PR per step, tests first, flags off)

### C0: probe and measurement (live read, owner-approved; no repo write)

- The owner runs a small read-only script (kept outside the repo, or under `tools/` with no real ids) against each
  child profile with the household key: `analytics/status` and `analytics/reasons` for each of the last 7 days, and
  the same `from/to` re-read 24 h later.
- Records, privately: the set of reason **ids** observed (to fill the exact-match table; review that none carries a
  domain before anything is copied into the repo), the oldest day that still returns data (retention), whether a
  day's numbers change after it ends (lag/finality), whether `reasons` paginates, any 429 seen.
- Output into a private spike note; only the id **forms** (e.g. "categories appear as `parentalcontrol:<id>`") and
  numbers go into the repo doc. Exit: mapping table and lag margin decided; D5's "UNVERIFIED reason-class counts at
  one-week retention" closed one way or the other. If reasons do not split parental-control categories, the plan
  shrinks to `blocked` totals plus `apps/ads_trackers/security/other` and §8 is dropped.

### C1: client analytics methods + class mapping (no wiring)

- `nextdns-client.ts`: `getAnalyticsStatus`, `getAnalyticsReasons`, frozen path table, range validation, strict
  parsers (name dropped), pagination via `readAll`.
- `content-filter-classes.ts`: `ClassCode`, `classOf`, `HEADLINE_CLASSES`, labels shared with web (or duplicated with
  a test asserting equality, as `PROFILE_ID_PATTERN` is today).
- Tests (`nextdns-client.test.ts`, new `content-filter-classes.test.ts`): request path and query exact
  (`from`/`to` integers, `limit=500`, no other params); 200 shapes; extra key → `bad_response`; negative/float/huge
  `queries` → `bad_response`; `from >= to` and span > 25 h → `invalid_request` before any request; pagination
  sum and cursor loop; 429 with Retry-After; 400 with `errors[].detail` containing a domain → code only;
  surface test (P1); `classOf` table, prefixes, denylist suffix discard, fuzz (P2), totality.

### C2: config flag, the next free numbered migration after #139 (which already adds 015), store, fetcher

- `content-filter-config.ts`: optional `counts: {enabled}`; accept-and-ignore with `mode: off`; config tests (strict keys,
  types, absent = off).
- `migrations/the next free numbered migration after #139 (which already adds 015)`; `db.ts` lists; migration test from a 014 DB.
- `content-filter-counts.ts`: store + `ContentFilterCounts` fetcher + `startContentFilterCounts`.
- `digest.ts`: export `localDayBounds(day)` and `localDay(epoch)`; tests on both 2026 DST change days
  (23 h and 25 h ranges) and New Year.
- `content-filter-wiring.ts`: build the fetcher only when `counts.enabled`; reuse the same client instance.
  `main.ts` starts/stops it next to the watch.
- Tests (`content-filter-counts.test.ts`): flag off → zero requests, no timer, no rows; first pass backfills 7 days in
  order; today never stored; not before 03:00 local next day; ok row never overwritten by a later failure;
  `unavailable` retried and becomes ok; day older than 6 days not attempted; `logs_off` path makes no analytics call;
  `suspect_zero` with and without activity; budget stop and resume; one child failing does not stop others; the
  default profile never requested; prune at 56 days; concurrent tick guard; no stdout/stderr on any path; G7 haystack.

### C3: counts route + web block

- `content-filter-http.ts`: `GET /people/:id/filter/counts`; gate identical to the filter GET; 404 parity tests
  (unknown child, out of scope, unconfigured, mode excludes actor, `counts` off → `route_not_found`).
- `web/public/content-filter.js`: "Last 7 days" block; Playwright scenario on the demo with seeded rows covering each
  state; screenshot in the PR; text-content-only check (a class code with markup renders inert).
- G7 extended to the route (P11).

### C4: digest line

- `push-sender.ts` `DigestCounts.blocked?`, `pushText` variants; `push-runtime.ts` `weeklyCounts` reads
  `householdBlocked` only when counts are on (passed in, so push-runtime does not import content-filter code when
  off).
- Tests (`push-digest.test.ts`): exact strings for absent/full/partial/none; flag off → digest body byte-identical to
  today (regression snapshot); P7/P8 snapshot; window = Sunday..Saturday before the slot across DST weeks; a
  deferred Monday 07:00 send uses the same window.

### C5: alert (after C0's measurement week; `counts.alert`)

- `integration-009.sql` (+ migration test), `AlertKind` union, `blockedCategoryAttempts` rule, `ParentAlerts`
  reconcile input `filterCounts`, resolution rule, visibility as `filter_drift`, web label.
- Tests: thresholds per class; details shape (P9); `info` only; owner-only visibility in owner mode; resolves after
  a clean day; flag off → no candidates; G7.

### C6: docs

- `docs/service-contract.md`: new section (flag, route, digest window, states, retention, failure table, "unverified
  on this router").
- `docs/content-filtering-stack.md` §2.6: "Nothing is copied into Couvre-feu" → "Only daily counts by class are
  copied; never sites"; §2.2 manifest example; risk register rows for P14 and F7.
- `docs/prp/PRP-006-content-filtering.md`: D5 updated with C0 findings; §5.6 marked built behind the flag.
- `docs/ROADMAP.md` privacy gate: one line naming the counts tables as allowed integer-only data.

Every PR description states how it meets the privacy design gate (ROADMAP rule) and its deviations from PRP-006.

---

## 11. Rollout

1. C1–C4 merged, flag absent. 2. Owner adds `counts.enabled` in owner mode, rebinds. 3. One week: owner compares
the card's numbers with the NextDNS Analytics page for the same days (by eye, in NextDNS). 4. Two Sunday digests
checked against the app (B7 rule). 5. `parents` mode only after that. 6. C5 alert enabled owner-only for two weeks.
Stop rule: any sentinel/domain/child name seen in a push, alert or log → flag off, report.

---

## 12. Open decisions for the owner

| Id | Question | Options | Recommendation |
|---|---|---|---|
| O1 | Run the C0 live probe with the household key | yes / no (build blind with `other`) | **Yes**; read-only, a few dozen GETs; nothing committed but id forms |
| O2 | Retention of daily counts | 7 days / 56 days / 1 year | **56 days** (roadmap's 8-week rule for estimates); long enough for "is this new?" |
| O3 | Per-service breakdown (TikTok, Discord, ...) | one `apps` class / per service | **One class.** Per-app counts describe the child's behaviour more finely than needed for a conversation |
| O4 | Anything per child in the push digest | none / ordinal labels / names | **None**: household integer only; per child in the app |
| O5 | Count the strict default profile | no / household "unmapped devices" line | **No** until roadmap item 3; it mixes guests and is not a child |
| O6 | Include ads/trackers and security in headline totals | yes / background only | **Background only**: they reflect apps and ads, not the child |
| O7 | NextDNS plan | free (300k/month, filtering stops at the cap) / Pro | **Pro** for a whole household: at the cap filtering stops, not just counts (staff, help.nextdns.io/t/p8hmvaw). Out of code scope but F7 depends on it |
| O8 | Show total lookups (`total`) in the app | yes / no | **Yes, small print**: makes "0 blocked" meaningful and exposes F7; it is a count, not browsing data |
| O9 | Digest window | Sun–Sat local days / slot-to-slot via live query | **Sun–Sat days** (survives one-week retention and quiet-hours deferral) |
| O10 | Tell the children what is counted | yes / no | **Yes** (consistent with D4's "tell the children what is logged") |

---

## 13. Unverified (to keep labelled in code and docs)

- Reason id forms for parental-control categories, services, Block Bypass and denylist (C0).
- Whether analytics follow log retention (one week under D4), and NextDNS aggregation lag/finality (C0).
- Whether `/analytics/reasons` paginates in practice at `limit=500`.
- Rate limits and 429 behaviour (undocumented).
- Exact `status` values beyond `default`/`blocked`/`allowed` (e.g. a relayed or error status) — summed into `total`.
- Behaviour of analytics after the free-plan cap (staff say nothing is logged; analytics presumably zero).
- Everything about counts reflecting real child traffic depends on Phase B delivery, which is not live.

## 14. Sources (read 2026-11-13)

- NextDNS API (official): https://nextdns.github.io/api — analytics endpoints, parameters, date formats, `;series`,
  logs family, pagination, errors, beta notice.
- Reasons example ids (third-party mirror of the API): https://www.withone.ai/knowledge/next-dns/conn_mod_def%3A%3AGLOiyvipIQg%3A%3AwXIa7DKERCyOK6uNU76D8g/md
- Blocked Reasons panel description: https://help.nextdns.io/t/60yt1bl/analytics-allow-blocked-category-drilldown ;
  top-6 cap: https://help.nextdns.io/t/35hf2t9/blocked-reasons
- Log retention and "never created" when disabled: https://help.nextdns.io/t/p8hpdsa/navigation-logs-retention
- Free plan 300k cap disables features and logging: https://help.nextdns.io/t/p8hmvaw/what-happens-after-300k-queries
