# Push settings and test push

Off by default; **unverified on this router and on a real ntfy server or phone.** Service only, no router change. Contract: [service-contract.md](../service-contract.md#push-settings-and-test-push).

## Check

1. Push is on (`"push": {"enabled": true}`) and the `COUVRE_NTFY_*` environment is set, as in the contract's "How to turn push and the digest on".
2. Signed in as an admin, `GET /push/settings`: `configured` must be `true`. `false` means the environment was missing or invalid; the startup log names which setting (`notifications_disabled invalid_ntfy_*`), never its value.
3. `POST /push/test` (with the session's CSRF token). Expect `{"result": "sent_to_push_service"}`, then the phone shows `Couvre-feu` / `Test notification. Nothing needs your attention.` Receipt on the phone is the real check; the service only knows ntfy accepted it.
4. Results: `push_failed:http_401` or `http_403` is a bad token or ACL; `push_failed:timeout` or `network_error` is the ntfy host unreachable; `not_configured` is as step 2.
5. One test per 30 s per account; a second call earlier answers `429 push_test_cooldown`.

## Stop

Any name, MAC, address or domain on the phone, or the ntfy URL, topic or token in a response or log: set `push.enabled` to false, rebind and restart, and report it.
