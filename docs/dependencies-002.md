# Local demo dependency review

Reviewed on 2026-10-11 against `package-lock.json` SHA-256
`8c50a6545ce2ac327bc46a9a0f63179609074d527f45d07c329151e8f09a8933`.
The project remains AGPL-3.0-only. Dependencies are installed through the
lockfile; their source and browser binaries are not vendored into this repository.

| Direct dependency | Locked version | Declared license | Purpose |
|---|---|---|---|
| `@simplewebauthn/server` | 13.3.3 | MIT | Server-side passkey verification |
| `@levischuck/tiny-cbor` | 0.2.11 | MIT | Signed test-credential encoding |
| `@playwright/test` | 1.61.0 | Apache-2.0 | Browser acceptance tests |
| `@types/node` | 26.6.5 | MIT | Development types |
| `typescript` | 7.0.2 | Apache-2.0 | Type checking |

All 50 locked package entries have declared licenses: 22 MIT, 25 Apache-2.0,
one BSD-3-Clause and two 0BSD, including optional platform packages. These
permissive declarations are compatible with this AGPLv3 source project; see
the GNU project's [license compatibility guidance](https://www.gnu.org/licenses/license-compatibility.en.html).
Retain each dependency's license and attribution when distributing its files.
There is no copied Fengard source.

`npm audit --json --cache /tmp/couvre-feu-npm-cache` returned exit 0 and
zero reported advisories in all severity categories for this snapshot.
The audit response is private task evidence, not a source file. Independent
application review and the acceptance runbooks cover behavior and deployment
gates separately.

The demo pins Node 26.8.1 and npm 11.19.0. It uses Node's built-in SQLite API;
the [version-matched documentation](https://nodejs.org/download/release/v26.8.1/docs/api/sqlite.html)
labels that API release candidate. The acceptance tests must establish the
tested durability behavior; this runtime selection makes no target-router or
production deployment claim.
