import { resolve } from 'node:path';
export interface DemoConfig {
    port: number;
    origin: string;
    host: string;
    dataDir: string;
}
export function demoConfig(env: NodeJS.ProcessEnv = process.env): DemoConfig {
    // No production mode or transport exists. Only a local port and data directory are configurable.
    const input = env.CF_DEMO_PORT ?? '4173';
    if (!/^[1-9][0-9]{3,4}$/.test(input) || +input < 1024 || +input > 65535) {
        throw new Error('invalid_demo_port');
    }
    if (Object.keys(env).some(key => /^CF_(?:ROUTER|SSH|TARGET|PRODUCTION|AUTH_BYPASS|TEST_IDENTITY)/.test(key))) {
        throw new Error('production_configuration_forbidden');
    }
    return {
        port: +input, origin: `http://localhost:${input}`, host: `localhost:${input}`, dataDir: resolve(env.CF_DEMO_DATA_DIR ?? '.demo-data')
    };
}
