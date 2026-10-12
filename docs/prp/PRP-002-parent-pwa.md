# PRP-002 — authenticated synthetic parent PWA

Status: implemented local synthetic slice with 14 passing browser scenarios under the user-approved session 002 scope; independent final review/CI remain pending. This is a loopback, fictional-data prototype, not a deployed household application.

## Purpose and scope

Give an authenticated permitted parent a phone-sized view of assigned fictional people, their fictional devices, manual pause and schedule reasons, observed status and operation outcomes. Show an amber synthetic banner throughout; fake confirmation never establishes packet behavior or router compatibility. Usage, domains and app history are unavailable. No telemetry, companions, enrollment of household devices or production router transport is included.

The design uses parchment surfaces, navy text and restrained green/amber/red state markers with explicit text labels. System fonts and local assets avoid third-party requests. Native HTML, CSS and browser ES modules are served by the same-origin loopback service; there is no separate frontend server or frontend build dependency.

## Authentication and controls

Enrollment accepts a one-use token created by the local fixture bootstrap. The service binds it to a fictional account and permissions. The form never selects a role, account or assigned person and never sends secrets in a URL. Native `navigator.credentials.create/get` calls use server challenges and actual WebAuthn credential responses. Session cookies remain HttpOnly; session details and CSRF tokens live only in page memory, outside application caches.

The UI consumes the shared session, people and operation DTOs. One-tap Pause 15/30/60 min presets (and the custom duration menu) submit an absolute Unix expiry through the same timed-pause route; an active timed pause shows its remaining time and an End now control (the existing resume). "Extra time" is shown disabled with an explanation because the router policy has no allowance concept; it is a deferred follow-up. Pause submits an absolute Unix expiry (zero for indefinite); resume removes only manual pause and retains schedule explanations. Every mutation requires fresh session validation and status, the server-issued opaque revision token sent unchanged as `If-Match`, a new idempotency key and CSRF protection. A changed token cancels the action and requires a fresh deliberate click. No mutation is retried, stored or queued automatically.

Logout, account/scope changes and unauthorized refresh cancel outstanding passkey requests and authentication fetches. Generation guards prevent an old authentication continuation from sending verification after the view was reset. The service independently binds challenges/sessions to a browser episode and cancels that episode on logout; browser cancellation alone does not replace server revocation.

The schedule editor (`web/public/schedule-editor.js`) lists each assigned person's weekly windows and adds, edits or deletes one with the same fresh-status, `If-Match`, idempotency and CSRF discipline as pause. It validates bounds client-side for feedback, previews cross-midnight windows in plain language (for example Mon 22:00 → Tue 06:30), explains overlaps, and treats the server as authoritative. A stale revision cancels the click, reloads the schedules and keeps the draft for a new deliberate save. It is hidden where the installation does not permit schedule edits.

Pending acceptance is shown until the exact operation becomes confirmed. Failed, unknown and conflict states remain distinct; an unknown result does not promise that the action failed or succeeded. Repeated controls are disabled during pending work and whenever status is offline, stale, conflicted or unrefreshed.

## Offline and shared-browser behavior

The service worker caches only an explicit public asset allowlist. It never intercepts authentication, API responses or mutation requests. Read-only snapshots contain only permitted status and non-secret actor metadata, keyed by actor identity, server permission version, role and assigned resources, with a saved timestamp and session expiry. Previous snapshots are purged on account/permission changes and logout. No session identifier, passkey response, enrollment token or CSRF token enters storage.

An offline snapshot is labeled read-only with its observation/cache age and synthetic source. Reconnection validates the session and refreshes status before enabling controls. Offline logout removes local status immediately and records only that server logout is still required; the interface does not claim server revocation until an online logout succeeds. Shared-tab logout invalidates local views. No background synchronization is registered.

## Acceptance and boundaries

Required browser evidence: real virtual-authenticator enrollment and sign-in with server verification; parent scope and unauthorized controls; pause → pending → healthy fake confirmation; timed expiry owned by fake router while service is stopped; resume during an active schedule; failed/unknown/conflict; offline and reconnect; logout and permission-cache isolation; primary phone viewport, keyboard focus, accessible labels and meaningful operation messages. Evidence belongs in [acceptance-002](../acceptance-002.md).

Private HTTPS installation, an actual phone/browser matrix, stable hostname/recovery, packet cutoff, target router behavior and production deployment remain separate gates.

References consulted before implementation: [MDN credentials create](https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/create), [MDN service workers](https://developer.mozilla.org/en-US/docs/Web/API/Service_Worker_API/Using_Service_Workers), [Playwright CDP session](https://playwright.dev/docs/api/class-cdpsession), [Chrome WebAuthn protocol](https://chromedevtools.github.io/devtools-protocol/tot/WebAuthn/).
