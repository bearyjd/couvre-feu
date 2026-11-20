export type CopyRewrite = readonly [needle: string, replacement: string];

// Demo copy that the integration variant replaces. Every needle must exist in the shipped file: a copy edit that drops one fails startup instead of silently serving demo copy.
export function integrationHTMLRewrites(scope: string, automatic: boolean): readonly CopyRewrite[] {
    return [
        ['<html lang="en">', `<html lang="en" data-source="real-router-integration" data-integration-scope="${scope}" data-automatic-dispatch="${automatic}">`],
        ['Fictional, local Couvre-feu parent-control prototype.', 'Private one-device Couvre-feu router integration.'],
        ['Couvre-feu · synthetic demo', 'Couvre-feu · private router integration'],
        ['<strong>Synthetic demo</strong><span>Fictional people · fake router · target compatibility unverified</span>', `<strong>Private router integration</strong><span>One test device · ${automatic ? 'owner-enabled automatic dispatch' : 'operator approval required'} · packet behavior unverified</span>`],
        ['Local prototype / 002', 'Private one-device pilot'],
        ['This demo changes a fake router. It does not control a household connection.', automatic ? 'Authenticated requests dispatch automatically while the owner authorization is active. Unknown outcomes remain blocked for review.' : 'Requests wait for an operator-approved router invocation. Router observations and packet measurements are separate.'],
        ['Sign in to the fictional account bound to your passkey.', 'Sign in to the private account bound to your passkey.'],
        ['Use the token from the local demo bootstrap. It already identifies your fictional account.', 'Use the token from the private integration bootstrap. It fixes your account and permissions.'],
        ['Create a demo passkey', 'Create a passkey'],
        ['Source: synthetic fake router. Confirmation describes this fixture only. Real packet cutoff, router compatibility and phone deployment remain unverified.', 'Source: real router integration. Accepted policy, current runtime health and packet acceptance are distinct. Packet cutoff and target compatibility remain unverified.'],
        ['Local, fictional prototype', 'Private one-device pilot'],
    ];
}

export function integrationManifestRewrites(automatic: boolean): readonly CopyRewrite[] {
    return [
        ['Couvre-feu synthetic demo', 'Couvre-feu private integration'],
        ['Local fictional parent-control prototype. Fake router only.', automatic ? 'Private router integration with owner-enabled dispatch.' : 'Private one-device router pilot. Operator-approved dispatch only.'],
    ];
}

export function applyRewrites(source: string, rewrites: readonly CopyRewrite[], label: string): string {
    return rewrites.reduce((text, [needle, replacement]) => {
        if (!text.includes(needle)) throw new Error(`integration_copy_needle_missing:${label}:${needle.slice(0, 60)}`);
        return text.replace(needle, () => replacement);
    }, source);
}
