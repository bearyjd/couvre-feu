These backends are deterministic command doubles. They record argv, fake command
outputs and model selected state transitions. Passing them does not verify the
OpenWrt JSON parser, fw3 behavior, packet rejection, DNS, connection cutoff,
offload, router persistence, or forced-command behavior in Dropbear.

Each fixture uses a fresh private root, backend state and PATH. Host networking
tools are replaced before any router script executes. Failure injection and
delays are stored in backend JSON so interrupted apply and backend errors can be
tested without touching the host network. Unknown modeled operations fail with
exit 97 rather than running the corresponding host command.

The harness gives commands a bounded 60-second host watchdog by default. An
isolated cross-midnight schedule sync measured 432 Python backend invocations;
shared CI host slowdown can exhaust the previous 20-second watchdog while the
same policy passes on another run. Explicit caller deadlines remain unchanged. This fixture
watchdog is separate from the router's 10-second stdin deadline and does not
measure the five-second packet cutoff acceptance gate or real router performance.

`overlay.py` models the overlayfs identity measured read-only on the GL-XE3000
(OpenWrt 21.02, no `index`/`xino`) for installer fixtures. A `stat` shim answers
`%d`/`%i` queries: a lower-only or copied-up-with-origin file reports the
overlay dev and its lower inode, and while it has more than one link any name
other than the original reports its real dev:ino (only "differs" was measured,
not the link's exact value). Pure-upper and new files report their real
identity. `ln`, `chmod`, `chown` and `touch` shims log any operation that would
copy a lower-only managed path up. This is a model, not overlayfs: it does not
prove copy-up timing, dentry-cache eviction or behaviour after reboot.
