// PWA upkeep: update prompt, a timeout/abort composite that works without AbortSignal.any (iOS < 17.4), and the pre-expiry notice.

// Aborts when `signal` aborts or after `ms`, whichever is first. Call release() once the response is fully read.
export function composeAbort(signal, ms) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new DOMException('The operation timed out.', 'TimeoutError')), ms);
  const onAbort = () => controller.abort(signal.reason);
  if (signal?.aborted) onAbort(); else signal?.addEventListener('abort', onAbort, { once: true });
  return { signal: controller.signal, release: () => { clearTimeout(timer); signal?.removeEventListener('abort', onAbort); } };
}

const GRACE_SECONDS = 60;

// Seconds left when the session is inside the warning window, otherwise null.
export function graceRemaining(expiresAt, nowSeconds) {
  const left = Number(expiresAt) - nowSeconds;
  return Number.isFinite(left) && left > 0 && left <= GRACE_SECONDS ? left : null;
}

export function createUpdatePrompt({ banner, reloadButton, registration = () => navigator.serviceWorker?.getRegistration?.() }) {
  let loaded = null;
  reloadButton.addEventListener('click', async () => {
    reloadButton.disabled = true;
    try {
      const waiting = (await registration())?.waiting;
      if (waiting) {
        navigator.serviceWorker.addEventListener('controllerchange', () => location.reload(), { once: true });
        waiting.postMessage('skipWaiting');
        setTimeout(() => location.reload(), 3000); // The new worker may already be active; never leave the button dead.
        return;
      }
    } catch { /* Fall through to a plain reload. */ }
    location.reload();
  });
  return {
    // The first version answered is the build this page loaded with; a different one later means a newer release is live.
    observe(version) {
      if (typeof version !== 'string' || !version) return;
      if (loaded === null) loaded = version;
      banner.hidden = version === loaded;
    },
  };
}

export function createSessionGrace({ root, text, dismiss, now = () => Math.floor(Date.now() / 1000) }) {
  let dismissedFor = null;
  dismiss.addEventListener('click', () => { dismissedFor = root.dataset.expiresAt; root.hidden = true; });
  return {
    update(session) {
      const left = session ? graceRemaining(session.expiresAt, now()) : null;
      if (left === null || dismissedFor === String(session.expiresAt)) { root.hidden = true; root.dataset.expiresAt = ''; return; }
      root.dataset.expiresAt = String(session.expiresAt);
      text.textContent = `Signing out soon: this session ends in ${left}s. Anything you have typed and not saved will be lost. Sign in again to continue.`;
      root.hidden = false;
    },
  };
}
