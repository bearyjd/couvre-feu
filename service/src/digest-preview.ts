import { contentFilterVisible } from './content-filter-config.ts';
import { AppError } from '../../shared/src/errors.ts';
import { addDays, localDay } from './content-filter-day.ts';
import { digestBlockedReader, DIGEST_WEEK_DAYS } from './digest-blocked.ts';
import { latestDigestSlot } from './digest.ts';
import type { IntegrationConfig } from './integration-config.ts';
import type { IntegrationStore } from './integration-db.ts';
import { weeklyCounts } from './push-runtime.ts';

interface DigestPreview {
    period: {start: number; end: number};
    counts: {requests: number; grants: number; pauses: number};
    blockedLookups?: {firstDay: string; lastDay: string; count: number; daysCounted: number};
}

/** Read only the closed weekly aggregate and optional local C4 counts. */
export function readDigestPreview(config: IntegrationConfig, store: IntegrationStore, now: number, accountId: string): DigestPreview {
    const end = latestDigestSlot(now), start = latestDigestSlot(end - 1);
    const filter = config.contentFilter;
    const blockedReader = filter?.counts?.enabled === true && contentFilterVisible(filter.mode, config.ownerAccountId, accountId) ? digestBlockedReader(config, store) : undefined;
    try {
        const {requests, grants, pauses, blocked} = weeklyCounts(store, start, end, blockedReader);
        const preview: DigestPreview = {period: {start, end}, counts: {requests, grants, pauses}};
        if (blocked && blocked.daysCounted > 0) {
            const lastDay = addDays(localDay(end), -1);
            preview.blockedLookups = {firstDay: addDays(lastDay, 1 - DIGEST_WEEK_DAYS), lastDay, count: blocked.count, daysCounted: blocked.daysCounted};
        }
        return preview;
    } catch {
        throw new AppError(503, 'digest_preview_unavailable');
    }
}
