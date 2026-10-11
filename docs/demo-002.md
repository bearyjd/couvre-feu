# Local parent PWA demo

This runnable prototype uses fictional people, genuine passkey authentication and an independent file-backed fake router. It never connects to a production router. Fake confirmation does not establish packet cutoff or target compatibility.

Use the runtime, dependency, data-directory and reset instructions in [service-demo-003](service-demo-003.md). With dependencies installed, run the fake router and HTTP service in separate terminals:

```sh
npm run demo:router
npm run demo:start
```

Create a server-bound one-use fictional parent enrollment token in a third terminal:

```sh
npm run demo:bootstrap -- bryn
```

Open **http://localhost:4173**, paste the token into the password-style enrollment field and select **Create a demo passkey**. The server binds Bryn to Alex; no account, role or person selector exists. The fictional admin token is created with `jd` instead of `bryn`. Tokens expire and cannot enroll an already enrolled account. Use the isolated reset instructions to start a new fixture. Keep tokens out of URLs, screenshots and public logs.

After enrollment, sign out and use **Sign in with a passkey** for subsequent visits. Browser user verification is required. This is genuine WebAuthn against a loopback synthetic service; automated tests use only virtual, fictional credentials. Actual-device enrollment/recovery, a stable private HTTPS hostname and installation remain separate work.

## Try the controls

Pause Alex with **Until I resume**. The request first shows pending, then confirmed when the exact operation receives a healthy fake-router observation. Choose **1 minute · demo** for a short timed pause. Its absolute expiry is owned by the fake router; the countdown is advisory and cannot confirm expiry. Stop only the HTTP service while leaving the fake-router process running to observe router-owned expiry, then restart and refresh.

Resume removes only the manual pause. During the fictional UTC schedule (22:00–06:30), the schedule continues to block; the UI explains this. It does not promise restored access. Outside that window, no schedule block is shown. Advanced demo status and operation details expose revision/operation diagnostics without crowding the main controls.

Use the CLI scenarios in [service-demo-003](service-demo-003.md) to produce pending, failure, timeout/unknown, drift, incomplete coverage or local revision advance. No scenario selector or test identity is exposed through HTTP. An unknown result may have applied; refresh and review instead of assuming failure. A revision conflict disables controls until an explicit refresh and a fresh deliberate action. Requests are never automatically retried or queued.

## Offline and shared browsers

After a successful online visit, disconnect using browser developer tools. The public shell can load offline and display only the previous account’s scoped, timestamped read-only snapshot. Pause/resume stay disabled. Reconnection validates the session and refreshes status before controls become available; it sends no queued mutations.

Sign out offline to clear local status immediately. The notice distinguishes local clearing from unconfirmed server logout; reconnection completes server logout before another sign-in. Logout and permission/account changes clear old snapshots across tabs. Session cookies are HttpOnly; enrollment, credential and CSRF/session secrets are never stored in application caches. Usage, domains and app history remain unavailable.

## Browser verification

```sh
npx playwright install chromium
npm run test:web
npm run typecheck
```

Browser tests bind an isolated localhost service on port 4273 (override with `CF_WEB_TEST_PORT`), seed fictional SQLite fixtures, exercise real server WebAuthn verification, and run an independent fake-engine tick. They do not use an HTTP identity bypass. Browser binaries require only a project/user-local installation, without system-package changes. Test traces are disabled to avoid capturing credential responses; failure screenshots and the phone screenshot contain only fictional status.

If an already installed Chromium is needed, set `CF_BROWSER_EXECUTABLE` to its executable. A host Fontconfig cache caused a rendering crash in the measured environment; `CF_BROWSER_FONTCONFIG` optionally supplies an isolated temporary font configuration using already installed fonts and a temporary cache. These are test-process settings, not changes to the system or production UI. For example:

For the measured Linux host, `/tmp/couvre-feu-fonts.conf` contained the following. Adjust only the existing font-directory paths on another host; do not modify its system Fontconfig files or caches.

```xml
<?xml version="1.0"?>
<!DOCTYPE fontconfig SYSTEM "urn:fontconfig:fonts.dtd">
<fontconfig>
  <dir>/usr/share/fonts/liberation-sans-fonts</dir>
  <dir>/usr/share/fonts/liberation-serif-fonts</dir>
  <dir>/usr/share/fonts/google-noto-color-emoji-fonts</dir>
  <cachedir>/tmp/couvre-feu-font-cache</cachedir>
  <alias><family>sans-serif</family><prefer><family>Liberation Sans</family></prefer></alias>
  <alias><family>serif</family><prefer><family>Liberation Serif</family></prefer></alias>
</fontconfig>
```

```sh
CF_BROWSER_EXECUTABLE=/path/to/cached/chrome \
CF_BROWSER_FONTCONFIG=/tmp/couvre-feu-fonts.conf \
npm run test:web
```

See [acceptance-002](acceptance-002.md) for measured scope and pending gates. A phone-sized browser viewport is not actual phone/HTTPS installation acceptance.
