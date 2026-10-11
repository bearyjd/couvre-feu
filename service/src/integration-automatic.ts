import { randomUUID } from 'node:crypto';
import { AppError } from '../../shared/src/errors.ts';
import { IntegrationWorker } from './integration-worker.ts';

/** One serialized supervisor. Expiry of a local claim never permits another apply. */
export class AutomaticDispatch {
    readonly worker: IntegrationWorker;
    readonly owner: {token: string; epoch: number};
    private timer: ReturnType<typeof setTimeout> | null = null;
    private flight: Promise<void> | null = null;
    private stopped = false;
    private delay: number;
    constructor(worker: IntegrationWorker) {
        this.worker = worker;
        const {store, now} = worker, settings = store.config.dispatch;
        if (!settings?.enabled) throw new AppError(403, 'automatic_dispatch_disabled');
        this.delay = settings.pollSeconds;
        // Restart fences every older callback/permit but retains possible remote delivery.
        store.stopDispatch(now());
        this.owner = store.transaction(() => {
            const owner = {token: randomUUID(), epoch: store.integrationState().dispatch_epoch};
            store.run('INSERT INTO automatic_dispatch(singleton,epoch,owner_token,enabled) VALUES(1,?,?,1) ON CONFLICT(singleton) DO UPDATE SET epoch=excluded.epoch,owner_token=excluded.owner_token,enabled=1', owner.epoch, owner.token);
            store.run("INSERT INTO audit(actor_id,action,timestamp,outcome) VALUES('operator','automatic_dispatch_enabled',?,'manifest_bound_epoch')", now());
            return owner;
        });
    }
    private authorized(): boolean {
        const store = this.worker.store;
        const state = store.get<{enabled: number; owner_token: string; epoch: number}>('SELECT * FROM automatic_dispatch WHERE singleton=1');
        return !this.stopped && !!state?.enabled && state.owner_token === this.owner.token && state.epoch === this.owner.epoch && store.integrationState().dispatch_epoch === this.owner.epoch;
    }
    /** Useful for supervision and deterministic tests; concurrent ticks share one flight. */
    tick(): Promise<void> {
        if (this.flight) return this.flight;
        const flight = this.cycle().finally(() => { if (this.flight === flight) this.flight = null; });
        this.flight = flight;
        return flight;
    }
    private async cycle(): Promise<void> {
        if (!this.authorized()) return;
        const {store, policy} = this.worker;
        let active = store.integrationState().active_operation_id;
        const rpc = active ? store.get<{attempt_count: number}>('SELECT attempt_count FROM operation_rpc WHERE operation_id=?', active) : null;
        await this.worker.executeAutomatic(rpc?.attempt_count ? 'receipt' : 'observe', this.owner, rpc?.attempt_count ? active! : undefined);
        if (!this.authorized() || !policy.fresh()) return;
        active = store.integrationState().active_operation_id;
        const pending = active ? store.get<{phase: string; attempt_count: number}>('SELECT phase,attempt_count FROM operation_rpc WHERE operation_id=?', active) : null;
        if (pending?.phase === 'queued' && pending.attempt_count === 0) await this.worker.executeAutomatic('apply', this.owner, active!);
    }
    start(): void {
        if (this.timer || this.stopped) return;
        const poll = async () => {
            this.timer = null;
            try { await this.tick(); }
            catch (error) {
                // A race/fence is local, sanitized evidence. Never retry an apply here.
                if (this.authorized()) this.worker.store.run('UPDATE integration_state SET observation_error=? WHERE singleton=1', error instanceof AppError ? error.code : 'automatic_dispatch_failed');
            }
            if (!this.authorized()) return;
            const settings = this.worker.store.config.dispatch!;
            this.delay = this.worker.store.integrationState().observation_error ? Math.min(settings.maxBackoffSeconds, this.delay * 2) : settings.pollSeconds;
            this.timer = setTimeout(poll, this.delay * 1000);
        };
        this.timer = setTimeout(poll, 0);
    }
    /** Waits for the bounded local invocation; this is not proof of remote drain. */
    async stop(): Promise<void> {
        const authorized = this.authorized();
        this.stopped = true;
        if (this.timer) clearTimeout(this.timer);
        this.timer = null;
        if (authorized) this.worker.store.stopDispatch(this.worker.now());
        await this.flight;
    }
}
