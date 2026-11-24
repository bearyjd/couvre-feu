import { AppError } from '../../shared/src/errors.ts';
import { contentFilterVisible } from './content-filter-config.ts';
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

interface PreviewOptions {
    /** Whether the viewer may see this child; the blocked-lookups total sums every configured child, so one out-of-scope child omits it. */
    canSee?: (person: string) => boolean;
    log?: (line: string) => unknown;
}

/** Read only the closed weekly aggregate and optional local C4 counts. */
export function readDigestPreview(config: IntegrationConfig, store: IntegrationStore, now: number, accountId: string, options: PreviewOptions = {}): DigestPreview {
    const log = options.log ?? (line => process.stderr.write(line));
    try {
        const end = latestDigestSlot(now), start = latestDigestSlot(end - 1);
        const filter = config.contentFilter;
        const everyChildVisible = Object.keys(filter?.profiles ?? {}).every(person => options.canSee?.(person) ?? true);
        const blockedReader = filter?.counts?.enabled === true && contentFilterVisible(filter.mode, config.ownerAccountId, accountId) && everyChildVisible
            ? digestBlockedReader(config, store) : undefined;
        const {requests, grants, pauses, blocked} = weeklyCounts(store, start, end, blockedReader, log);
        const preview: DigestPreview = {period: {start, end}, counts: {requests, grants, pauses}};
        if (blocked && blocked.daysCounted > 0) {
            const lastDay = addDays(localDay(end), -1);
            preview.blockedLookups = {firstDay: addDays(lastDay, 1 - DIGEST_WEEK_DAYS), lastDay, count: blocked.count, daysCounted: blocked.daysCounted};
        }
        return preview;
    } catch {
        log('digest_preview_failed\n');
        throw new AppError(503, 'digest_preview_unavailable');
    }
}
