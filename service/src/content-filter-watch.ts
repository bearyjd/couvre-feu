import type { ParentAlerts } from './parent-alerts.ts';
import type { ContentFilterReconciler } from './content-filter-reconcile.ts';

export const WATCH_INTERVAL_SECONDS = 3600;
/** Consecutive failed reads before "could not check" is raised, then again every UNREACHABLE_REPEAT checks. */
export const UNREACHABLE_AFTER = 3;
export const UNREACHABLE_REPEAT = 24;

/**
 * PRP-006 A5: once an hour, read each child's NextDNS profile (read-only) and compare it with the filter set here. A difference raises
 * `filter_drift` (cause `changed`) and is then put right by the normal reconcile; repeated failed reads raise it with cause `unreachable`.
 * Alerts carry the child and a cause only: no category, service, domain or count from NextDNS. Never throws, never logs.
 */
export class ContentFilterWatch {
    private readonly reconciler: ContentFilterReconciler;
    private readonly alerts: Pick<ParentAlerts, 'raise'>;
    private readonly failures = new Map<string, number>();
    private running = false;
    constructor(reconciler: ContentFilterReconciler, alerts: Pick<ParentAlerts, 'raise'>) { this.reconciler = reconciler; this.alerts = alerts; }

    async tick(): Promise<void> {
        if (this.running) return;
        this.running = true;
        try {
            for (const person of this.reconciler.people()) {
                try { await this.watch(person); } catch { /* one child's failure never stops the others */ }
            }
        } finally { this.running = false; }
    }

    private async watch(person: string): Promise<void> {
        const result = await this.reconciler.check(person);
        if (result === 'skipped' || result === 'none') return;
        if (result === 'unreachable') {
            const failed = (this.failures.get(person) ?? 0) + 1;
            this.failures.set(person, failed);
            if (failed === UNREACHABLE_AFTER || (failed > UNREACHABLE_AFTER && (failed - UNREACHABLE_AFTER) % UNREACHABLE_REPEAT === 0)) this.raise(person, 'unreachable');
            return;
        }
        this.failures.delete(person);
        if (result === 'differs') this.raise(person, 'changed');
        // A difference is put right now; a match whose stored state is not 'applied' (pending, not confirmed) is retried too.
        if (result === 'differs') await this.reconciler.reconcile(person);
    }
    private raise(person: string, cause: 'changed' | 'unreachable'): void {
        try { this.alerts.raise({kind: 'filter_drift', personId: person, severity: cause === 'changed' ? 'warning' : 'info', details: {cause}}); } catch { /* alerts are best effort */ }
    }
}

/** Starts the hourly check; the first one runs after `firstDelayMs`. The timers never keep the process alive. Returns a stop function. */
export function startContentFilterWatch(watch: ContentFilterWatch, intervalMs = WATCH_INTERVAL_SECONDS * 1000, firstDelayMs = 60_000): () => void {
    const run = () => { void watch.tick(); };
    const first = setTimeout(run, firstDelayMs), every = setInterval(run, intervalMs);
    first.unref(); every.unref();
    return () => { clearTimeout(first); clearInterval(every); };
}
