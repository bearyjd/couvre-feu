import { createServer } from 'node:net';
import { once } from 'node:events';

/** A loopback port the OS just proved free. Probe-listen on 0, read it, close; the rebind race is tiny, a fixed or pid-derived port collides with ephemeral ports. */
export async function freePort(): Promise<number> {
    const probe = createServer(); probe.listen(0, '127.0.0.1'); await once(probe, 'listening');
    const port = (probe.address() as {port: number}).port;
    await new Promise<void>(resolve => probe.close(() => resolve()));
    return port;
}
