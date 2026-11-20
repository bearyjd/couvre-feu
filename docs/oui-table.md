# Vendored OUI table (vendor hints)

`shared/src/oui-table.ts` maps MAC prefixes (OUI, the first three octets) to a short brand for the admin inventory (`vendor` in
`docs/service-contract.md`, "Hint fields"). It is data, vendored in the repository; the service never fetches anything at runtime.

- **Source:** the IEEE MA-L registry as packaged by hwdata (`/usr/share/hwdata/oui.txt`, the input's sha256 and mtime are recorded in the generated file's header; there is no free-text label).
- **Generation:** `python3 -B tools/gen-oui.py /usr/share/hwdata/oui.txt > shared/src/oui-table.ts`. Offline; deterministic for a given input.
  The generator keeps only organisations matched by its `RULES` list (consumer and home-network brands) under a short brand name. Add a brand by
  adding a rule, then regenerate and commit both files.
- **Incomplete on purpose:** a missing prefix means "not in this table", never "no maker". A registered prefix names whoever bought it (often a
  module maker such as Espressif or Realtek, not the product brand). Nothing is guessed or filled in by hand.
- **Randomized addresses** (locally-administered bit set, as phones use for "private" Wi-Fi addresses) never get a vendor. The only exception is the
  documented hypervisor default `52:54:00` (`QEMU/KVM (virtual)`), a convention rather than a registered prefix.
- **Licence note (owner to confirm; not legal advice):** the entries are facts (prefix -> organisation name) derived from the IEEE OUI registry
  as redistributed in the hwdata package, whose package data is GPL-2.0-or-later. Here they are used only as a lookup table, a trimmed
  extract of facts rather than hwdata code. Our reading is that this is a data aggregation that does not change the licence of this
  AGPL-3.0-only project's code, but the owner should confirm that, and IEEE's current terms, before relying on or redistributing the table.
- **Tests:** `shared/tests/oui.test.ts` checks the table's shape (hex prefixes, globally administered, no duplicates) and the lookup rules.
