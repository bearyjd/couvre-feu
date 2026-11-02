# Pinned router setsid helper

The reviewed payload includes `router/lib/busybox-static`, Alpine v3.14
`busybox-static` 1.33.1-r8 for aarch64 (static ELF, musl/Cortex-A53 target).
No package manager runs on the router. The owner selected shipping this helper
because the target BusyBox 1.33.2 has no setsid applet.

Provenance supplied by the owner and checked locally, without network access:

- APK: https://dl-cdn.alpinelinux.org/alpine/v3.14/main/aarch64/busybox-static-1.33.1-r8.apk
- APK size: 625632 bytes.
- APK SHA-256: `0540b7da4f1d2449282fedbb6ebf646905d799b5779f556bde4001b041ec468e`.
- Extracted `bin/busybox.static`: 1058512 bytes.
- Binary SHA-256: `c25f66e5ac29ea3e373b8fb2d3549a59d058fbef9ed11b67fdaba1dc37bf75f5`.

BusyBox is GPL-2.0 licensed. Upstream license and source are at
https://busybox.net/license.html and https://busybox.net/downloads/ .
The Alpine packaging recipe, patches and configuration for the corresponding
build are in https://gitlab.alpinelinux.org/alpine/aports/-/tree/3.14-stable/main/busybox .
Before redistribution, provide the complete corresponding source and build
materials, or another GPLv2-compliant source provision; these reference URLs
alone do not constitute a written source offer. Source retrieval and license
fulfilment were not verified during this offline change.

The fixed installed path is `/usr/lib/couvrefeu/busybox-static`, root:root0755,
under the existing non-world-writable owned directory on persistent overlay.
The install journal records prior absence or original bytes, mode, owner and
exact mtime. Uninstall removes or restores the helper. Session launches check
every source ancestor through `/` with the system metadata reader, then copy
the helper into a fresh private directory under sticky `/tmp`. Only that copy
is hashed, probed and executed, so uninstall cannot replace the executable
between verification and launch. Ancestors use the selected platform profile's
directory trust rules: root ownership, no world write or symlinks, and group
write only for the profile's exact admitted paths and modes. Vendor `/etc`
root:root0775 therefore supports teardown from its retained release tree.
Install upgrades with
an existing inventory that lacks helper backup records are refused before
persistent admission; finish the old release's uninstall before a fresh install.
Committed helper-aware installs can be reinstalled using their retained before
and after records, including an explicit prior-absence record. Pending uninstall
recovery must finish first. Private copies use PID-tagged directories: exit and
signal traps remove them, and a later entry sweeps owned copies whose PID has
exited after an untrappable kill. Older random-only names have no liveness proof
and are retained rather than risking deletion of another active launch's copy.
The 16-entry release closure binds the binary,
and a helper change requires a new release identity and review.

Local/CI fixtures substitute an x86_64 BusyBox only in temporary staged source
copies through `tests/fixtures/pinned_helper.py`, then regenerate the complete
release pins. This test seam is outside `router/` and is never emitted into the
router payload. The real aarch64 bytes are hash-checked, not executed on x86_64.
