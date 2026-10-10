These backends are deterministic command doubles. They record argv, fake command
outputs and model selected state transitions. Passing them does not verify the
OpenWrt JSON parser, fw3 behavior, packet rejection, DNS, connection cutoff,
offload, router persistence, or forced-command behavior in Dropbear.

Each fixture uses a fresh private root, backend state and PATH. Host networking
tools are replaced before any router script executes. Failure injection and
delays are stored in backend JSON so interrupted apply and backend errors can be
tested without touching the host network. Unknown modeled operations fail with
exit 97 rather than running the corresponding host command.
