# NextDNS blocked-lookup counts (PRP-006 phase C)

Status: built through C4, **off by default**, **unverified on this router and against a live NextDNS account**. Every statement about what NextDNS returns is UNVERIFIED until the C0 probe (below) has run. What the service does with an answer is checked against the code on `main` and cited by file.

Plan: [phase-c-digest.md](../plans/phase-c-digest.md). Contract: [service-contract.md](../service-contract.md#nextdns-daily-counts-prp-006-phase-c-off-unverified-on-this-router). Parent decision record: [PRP-006](../prp/PRP-006-content-filtering.md) (D4, D5).

## 1. What it is

Once an hour the service asks NextDNS for the **aggregate** analytics of each child's profile, for each finished local day of the last seven, and stores **integers only**: per child, per day, a total, a blocked total, and a count per class from a closed set (adult, gambling, dating, piracy, social, gaming, video, apps, bypass, denylist, ads_trackers, security, other). The tables are `content_filter_day` and `content_filter_day_class` (`service/migrations/016.sql`).

Never stored, never read: domains, URLs, device names, client addresses, query logs, reason ids or names (sorted into a class and dropped), the NextDNS profile id. The client has no method for the logs endpoints and no `device` parameter (`service/src/content-filter-counts.ts`, `service/src/nextdns-client.ts`). Parents see numbers by kind of block, never sites. NextDNS itself still holds the logs for its own retention (D4: one week) and sees every query; that vendor trade-off was accepted by the owner and is unchanged.

## 2. Prerequisites

1. The content filter itself is configured: `contentFilter.mode` is `owner` or `parents`, with `apiKeyFile`, `defaultProfile` and a non-empty `profiles` map (`service/src/content-filter-config.ts`). See the [content filter manifest section](../service-contract.md#content-filter-manifest-key-prp-006-a2-off-nothing-enforces-yet).
2. **NextDNS plan (open decision O7).** The free plan stops filtering, not just counting, at 300,000 queries a month (NextDNS staff, source in the plan). For a household, Pro is the recommendation. Not something the code can check; a capped month looks like zero or missing days here (see section 5).
3. **Logs enabled on every child's profile** (Settings, Logs). With logs off at NextDNS the day is recorded as `logs_off` and nothing is counted. Retention is the owner's call (D4 chose one week).
4. The API key file: the same one the filter already uses (`contentFilter.apiKeyFile`, regular file, mode `0600` or `0400`, owned by the service user, in a private directory; see the service contract). Counts add no new key and no new setting for it. A missing, unsafe or invalid key file surfaces as `unauthorized` and every day stays a gap.
5. Phase B (router delivery of child devices to their NextDNS profile) is **not live**. Until children's traffic actually goes through their profiles, the counts describe only whatever does use those profiles. UNVERIFIED end to end.

## 3. How to enable

Edit the private manifest (flags are strict booleans):

```
"contentFilter": { "mode": "owner", ..., "counts": { "enabled": true } }
```

- `contentFilter.counts` absent = off. `counts` is accepted and ignored when `mode` is `off` (no fetcher is built: `service/src/content-filter-wiring.ts`).
- For the weekly digest line also set `"push": {"enabled": true}` and `"digest": {"enabled": true}`; the digest requires push (`digest_requires_push`).
- **Rebind, do not just restart.** The database binds the exact manifest bytes, so any edit is refused at start; follow step 4 of [How to turn a flag on](../service-contract.md#how-to-turn-a-flag-on) (`npm run integration:rebind -- ...`, service and dispatch stopped). Take a backup first (see [deploy.md Backups](deploy.md#backups)); migration 016 is applied on first start of the new code.
- Rollout order from the plan: enable in `owner` mode first; after one week compare the card's numbers with the NextDNS Analytics page for the same days (by eye, in NextDNS); check two Sunday digests against the app; only then consider `parents` mode. Stop rule: any domain, child name or class word seen in a push, alert or log means flag off and report.

The first pass runs about five minutes after start, then hourly. A pass fills missing days oldest first, never today, never before 03:00 local on the next day (`COUNTS_SETTLE_SECONDS`, because NextDNS aggregation lag is UNVERIFIED), within a 60 second pass budget (`COUNTS_PASS_BUDGET_MS`).

## 4. What each day state means

All days are America/New_York calendar days. The app shows the last seven finished days (yesterday and the six before it).

| State | Plain language | Counted in totals and the digest? |
|---|---|---|
| `ok` | NextDNS answered; the numbers are real for that day. A day with zero blocked lookups is still `ok` when there was other traffic. | Yes |
| `suspect_zero` | NextDNS answered but saw **no lookups at all** that day. That can mean the phone was off, the filter was bypassed or paused, or the plan limit was hit; it is not "clean". The wiring passes no activity callback today, so every zero-lookup day is `suspect_zero` (`content-filter-wiring.ts`, `ContentFilterCounts.online`: unknown counts as suspect). | No |
| `logs_off` | Logging was off at NextDNS, so nothing could be counted. Retried on later passes while the day is in the window, in case logs were switched back on. Only stamped for days after the newest answered day; an earlier day with no answer stays a gap. | No |
| `gap` | The service has no answer for that day: NextDNS did not respond, the key was rejected, or the pass ran out of budget. Retried each hour while the day is inside the seven-day window. In the database this is `unavailable` or no row; the route reports both as `gap`. | No |

A day is written all or nothing, and a day that already has an answer other than a gap is not overwritten by a later failure (`markUnavailable`).

## 5. What parents see, and do not see

Parents see, in the filter card's collapsed "Last 7 days" block (`web/public/content-filter.js`, `GET /people/:id/filter/counts` in `service/src/content-filter-http.ts`):

- Per child: "N lookups blocked by this filter (x of 7 days counted)", the headline classes by count with the card's labels, "Also blocked in the background: N ads and trackers, N security protections", and a day-by-day list with each state in words.
- Fixed small print: counts only, Couvre-feu does not see or keep which sites; a number is a reason to talk, not proof (ads, app prefetching and accidental taps also count); to see sites, open NextDNS's own Logs tab (kept per D4); unverified on this router.
- The route reads the local database only; it never calls NextDNS. It answers the same gate as the filter card: `off` or an excluded actor gets `404 route_not_found`; an unknown or out-of-scope child gets the same `404 person_not_found`. With `counts` off the route does not exist (`404 route_not_found`).
- In the weekly digest (Sunday 18:00 New York, quiet hours respected): one extra line, `N blocked lookups last week.` or `N blocked lookups last week (x of 7 days counted).` Details in the [service contract](../service-contract.md#push-and-weekly-digest-b7-service-only-off).

Parents do **not** see: any domain or site, any device, any time of day (daily granularity only), any per-app split, any profile id. The push digest carries one **household** integer: no child name or id, no class, no per-child number (owner decision O4). Headline classes only: ads/trackers and security are background and excluded from that integer.

Not built: the "several blocked lookups in one category" alert (C5). No count raises an alert today.

## 6. Window and retention

- Window: the digest covers the Sunday to Saturday local days before the digest slot's Sunday (the digest fires Sunday 18:00, so Sunday is incomplete). A deferred Monday 07:00 send uses the same week. The app shows a rolling seven finished days.
- The fetcher never reads a day older than seven days back, so a service outage longer than a week leaves permanent gaps.
- Retention: rows older than **56 days** are deleted every pass (`COUNTS_RETENTION_DAYS`, owner decision O2).

## 7. Disable and roll back

- **Disable:** set `contentFilter.counts.enabled` to `false` (or remove `counts`), rebind. No fetcher is built, no timer starts, no NextDNS analytics call is made, the counts route disappears and the digest body is byte-identical to the one without the line. The two tables and their rows remain on disk until the 56 day prune (which only runs while the fetcher runs) or manual deletion with the service stopped; delete rows only deliberately.
- Setting `contentFilter.mode` to `off` also stops the fetcher and the route.
- **Migration 016 is additive** (two new tables and an index) but raises `user_version` to 16, like the other one-way migrations. Rolling the **code** back to a version before 016 requires restoring the pre-upgrade backup ([deploy.md Backups](deploy.md#backups)); older code refuses a newer database. Turning the flag off needs no restore.

## 8. Privacy notes

- **Tell the children what is counted** (owner decision O10, consistent with D4): that blocked lookups are counted per day by kind, that sites are not kept by Couvre-feu, that NextDNS keeps its own logs for its retention period, and who reads the numbers.
- The counts are sensitive about a child even without domains (for example "adult content: 3" on a date). They are shown only to the parents the mode allows, never pushed per child, and the database and its backups should be treated as private like the rest of the database. A backup holds up to 56 days of them.
- The service writes nothing to stdout or stderr for the fetcher. The one fixed log tag on this path is `digest_blocked_failed` (a failing digest read; the line is dropped, the digest still sends).

## 9. Troubleshooting

| Symptom | Likely cause | Remedy |
|---|---|---|
| The digest never shows the blocked line | The line needs `push`, `digest` and `counts` on, mode not `off`, **and** a day on which **every** configured child is `ok`. One child stuck in `logs_off`, `suspect_zero` or gaps hides the line every week. A week with zero counted days omits the line. | Check the card per child. Enable NextDNS logs on every profile in `contentFilter.profiles`; check that child's profile id. Note that a child with a profile in the map is always required, even one who is away. |
| Card says "Logging was off" | Logs disabled in that NextDNS profile (or never enabled) | Enable logs in NextDNS; the next hourly pass retries days still in the window |
| Every day is "No lookups recorded" | Zero lookups at NextDNS: device not using the profile (Phase B not live), filter bypassed, or a capped free plan | Look at NextDNS Analytics for that profile; confirm O7 plan; this is also what the day looks like when nothing is delivered to the profile |
| Days stay "Not counted" | NextDNS unreachable, key rejected (`unauthorized`), profile unknown (`not_found`), or rate limited (`rate_limited`, HTTP 429; behaviour UNVERIFIED) | The fetcher records gaps quietly and logs nothing. A 429 ends the whole pass and the next hourly pass resumes; a rejected key or unknown profile ends only that child. Check the key file ownership and mode, the profile ids, and NextDNS status |
| The counts block is missing in the app | `counts` off, mode `off`, or this account is excluded by `owner` mode | Expected; see section 3 |
| A number looks too high | Blocked lookups include ads, app prefetching and accidental taps | The card says so; compare with the NextDNS Logs tab, which only NextDNS and the parent logged into it can see |
| Numbers differ from NextDNS Analytics | Aggregation lag or a day that changed after it ended (UNVERIFIED, C0 question) | Days are read once, 3 hours after local midnight, and an `ok` day is final; a later change at NextDNS is not picked up |

## 10. The C0 live probe (NOT yet run; needs the owner's approval)

Status: **not run.** It needs the owner's explicit approval naming the exact script and sha, with the invocation logged first in `.omc/research/live-log.txt` (`.omc/STATE.md` rules; see plan open decision O1).

What it would read, and only that:

- For each child's NextDNS profile, the two **read-only aggregate analytics endpoints** (blocked and total status, and blocked reasons) for each of the last seven days, and the same ranges once more 24 hours later. A few dozen `GET` requests with the household API key.
- No log, domain or device endpoint is touched, and nothing is written to NextDNS or to the router.

What it would record, privately and outside the repo:

- The set of reason id **forms** observed, to complete the exact-match class table (reviewed so that no id carries a domain before anything is copied anywhere).
- The oldest day that still returns data (retention), whether a day's numbers change after it ends (lag and finality), whether the reasons list paginates, and any 429 seen.

Only id forms and numbers may then go into the repo. The probe closes the UNVERIFIED items in the next section and decides whether C5 (alert) is worth building; its thresholds come from a measurement week after the probe.

## 11. Unverified (carried from the plan, section 13)

- Reason id forms for parental-control categories, services, Block Bypass and denylist (C0).
- Whether analytics follow log retention (one week under D4), and NextDNS aggregation lag and finality (C0).
- Whether the reasons endpoint paginates in practice at the page size used.
- Rate limits and 429 behaviour (undocumented).
- Exact `status` values beyond `default`, `blocked` and `allowed` (anything else is summed into the total).
- Behaviour of analytics after the free-plan cap (staff say nothing is logged; analytics presumably zero).
- Everything about counts reflecting real child traffic depends on Phase B delivery, which is not live.
