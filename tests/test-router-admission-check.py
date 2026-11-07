#!/usr/bin/env python3
"""Offline admission evidence checks; no router or network calls."""
import contextlib
import importlib.util
import io
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
REPO = Path(__file__).resolve().parents[1]
COMMAND_TIMEOUT = 30
TOOL = REPO / "tools/live/router-admission-check.py"
spec = importlib.util.spec_from_file_location("router_admission_check", TOOL)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)

# Independent literals from the source-reviewed service parent gate. The good
# witness is not manufactured from the checker's chosen allowed values.
GOOD_METADATA = {
    "path:/etc:metadata": "0:0:775",
    "path:/etc/init.d:metadata": "0:0:775",
    "path:/lib:metadata": "0:0:755",
    "path:/lib/functions:metadata": "0:0:755",
    "path:/lib/config:metadata": "0:0:775",
    "path:/usr:metadata": "0:0:755",
    "path:/usr/share:metadata": "0:0:755",
    "path:/usr/share/libubox:metadata": "0:0:755",
    "path:/sbin:metadata": "0:0:775",
    "path:/tmp:metadata": "0:0:1777",
}
REAL_METADATA = dict(GOOD_METADATA, **{"path:/usr/share:metadata": "0:0:775"})
PIN_WITNESSES = {
    "path:/lib/libc.so:sha256": "c7ad6aff9300a5810e33ed8099057ef4515c0e711e9570309161d4014a5768ce",
    "path:/lib/libgcc_s.so.1:sha256": "6baf0c0086b0bd2915019e942a2fa7b2b4dfb4e0935db43a71fc54add13d1a69",
    "path:/usr/libexec/stat-coreutils:sha256": "774eaa80136871de03ea7c94ef713aac209cea00eddb8e7d07c7036e511499a0",
    "path:/usr/share/libubox/jshn.sh:sha256": "c5056cf87f47d12625a5695cfc1f5b48df4807b9095665dd9c682ca977d1eb59",
}


def capture(facts):
    return "".join(f"FACT {key} {value}\n" for key, value in facts.items()).encode("ascii")


class AdmissionCheckerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = checker.load_expectations()

    def subset_rows(self, facts):
        rules = {key: self.rules[key] for key in facts}
        return checker.assess(checker.parse_facts(capture(facts), rules), rules)

    def test_independent_good_service_parent_fixture(self):
        rows = self.subset_rows(GOOD_METADATA)
        self.assertEqual([row[0] for row in rows], ["PASS"] * 10)

    def test_user_real_metadata_fails_exactly_usr_share(self):
        rows = checker.assess(checker.parse_facts(capture(REAL_METADATA), self.rules), self.rules)
        self.assertEqual([row[1] for row in rows if row[0] == "FAIL"], ["path:/usr/share:metadata"])
        self.assertEqual(sum(row[0] == "PASS" for row in rows), 9)
        self.assertTrue(any(row[0] == "MISSING" for row in rows))
        self.assertTrue(any(row[0] == "SKIP" and row[1] == "runtime:supervisor" for row in rows))

    def test_pinned_digest_literals_match_table_and_source(self):
        rows = self.subset_rows(PIN_WITNESSES)
        self.assertTrue(all(row[0] == "PASS" for row in rows))
        source = (REPO / "router/lib/platform-bootstrap.sh").read_text()
        for digest in PIN_WITNESSES.values():
            self.assertIn(digest, source)

    def test_service_parent_exception_does_not_spread(self):
        for path in ("/lib", "/lib/functions", "/usr", "/usr/share", "/usr/share/libubox"):
            with self.subTest(path=path):
                rows = self.subset_rows({f"path:{path}:metadata": "0:0:775"})
                self.assertEqual(rows[0][0], "FAIL")

    def test_owner_change_is_not_an_exception(self):
        rows = self.subset_rows({"path:/etc:metadata": "0:1:775"})
        self.assertEqual(rows[0][0], "FAIL")

    def test_generic_metadata_mask_and_exact_exception(self):
        rule = {"owner": "0:0", "safe_mode": True, "exceptions": ["775"]}
        for value in ("0:0:700", "0:0:750", "0:0:755", "0:0:644", "0:0:775"):
            self.assertTrue(checker.matches(value, rule), value)
        for value in ("0:0:777", "0:0:6755", "0:0:1775", "0:1:775", "0:0:664"):
            self.assertFalse(checker.matches(value, rule), value)

    def test_file_group_write_exception_keeps_pin(self):
        facts = {
            "path:/lib/functions.sh:metadata": "0:0:664",
            "path:/lib/functions.sh:sha256": "0" * 64,
        }
        rows = self.subset_rows(facts)
        self.assertEqual([row[0] for row in rows], ["PASS", "FAIL"])

    def test_missing_is_never_a_pass(self):
        rows = checker.assess({}, self.rules)
        self.assertFalse(any(row[0] == "PASS" for row in rows))
        self.assertTrue(any(row[0] == "MISSING" for row in rows))

    def test_unobservable_is_never_a_pass(self):
        facts = {"path:/usr/share:metadata": "UNOBSERVABLE"}
        rows = self.subset_rows(facts)
        self.assertEqual(rows[0][0], "MISSING")

    def test_runtime_unknown_is_explicit_skip(self):
        rows = self.subset_rows({"runtime:supervisor": "UNOBSERVABLE"})
        self.assertEqual(rows[0][0], "SKIP")
        self.assertTrue(rows[0][2])

    def test_runtime_claim_cannot_forge_a_pass(self):
        with self.assertRaises(ValueError):
            checker.parse_facts(b"FACT runtime:supervisor yes\n", self.rules)

    def test_optional_absence_skips_only_its_dependent_rows(self):
        facts = {"path:/etc/nsswitch.conf:type": "missing"}
        rows = checker.assess(facts, self.rules)
        scoped = {key: status for status, key, _ in rows if key.startswith("path:/etc/nsswitch.conf:")}
        self.assertEqual(scoped["path:/etc/nsswitch.conf:type"], "PASS")
        self.assertEqual(scoped["path:/etc/nsswitch.conf:metadata"], "SKIP")
        self.assertEqual(scoped["path:/etc/nsswitch.conf:size"], "SKIP")

    def test_missing_required_type_is_a_failure(self):
        rows = self.subset_rows({"path:/usr/share:type": "missing"})
        self.assertEqual(rows[0][0], "FAIL")

    def test_known_symlink_targets_and_canonical_ancestry(self):
        rows = self.subset_rows({
            "path:/bin/stat:link": "OTHER",
            "path:/usr/share:canonical": "no",
            "path:/usr/share:type": "link",
        })
        self.assertEqual([row[0] for row in rows], ["FAIL", "FAIL", "FAIL"])

    def test_numeric_bounds(self):
        rule = self.rules["path:/etc/passwd:size"]
        self.assertTrue(checker.matches(str(rule["max"]), rule))
        self.assertFalse(checker.matches(str(rule["max"] + 1), rule))

    def test_rejects_duplicates_unknown_ids_controls_and_bad_shapes(self):
        invalid = (
            b"FACT path:/usr/share:metadata 0:0:755\n" * 2,
            b"FACT path:/unreviewed:metadata 0:0:755\n",
            b"FACT path:/usr/share:surprise yes\n",
            b"FACT path:/usr/share:metadata 0:0:755\x00\n",
            b"FACT path:/usr/share:metadata 0:0:999\n",
            b"FACT path:/usr/share:metadata 0:0:755 extra\n",
            b"FACT path:/usr/share:metadata 0:0:755\xff\n",
            *[b"FACT probe:format 1" + separator + b"FACT path:/usr/share:metadata 0:0:755\n"
              for separator in (b"\r", b"\v", b"\f", b"\x1c", b"\x7f")],
            b"not a fact\n",
        )
        for data in invalid:
            with self.subTest(data=data):
                with self.assertRaises(ValueError):
                    checker.parse_facts(data, self.rules)

    def test_input_byte_and_line_limits(self):
        for data in (b"x" * (checker.MAX_INPUT + 1), b"\n" * (checker.MAX_LINES + 1)):
            with self.assertRaises(ValueError):
                checker.parse_facts(data, self.rules)

    def test_cli_real_fixture_reports_rule_and_incomplete(self):
        result = subprocess.run([sys.executable, "-B", str(TOOL)], input=capture(REAL_METADATA),
                                capture_output=True, timeout=COMMAND_TIMEOUT)
        self.assertEqual(result.returncode, 1, result.stderr)
        failures = [line for line in result.stdout.decode().splitlines() if line.startswith("FAIL ")]
        self.assertEqual(len(failures), 1)
        self.assertIn('FAIL path:/usr/share:metadata observed=0:0:775 rule=["0:0:755"]', failures[0])
        self.assertIn(b"RESULT INCOMPLETE", result.stdout)
        self.assertIn(b"MISSING ", result.stdout)

    def test_good_observable_fixture_keeps_intrinsic_unknown_explicit(self):
        facts = dict(GOOD_METADATA, **{"runtime:supervisor": "UNOBSERVABLE"})
        rules = {key: self.rules[key] for key in facts}
        stream = io.TextIOWrapper(io.BytesIO(capture(facts)), encoding="ascii")
        output = io.StringIO()
        with mock.patch.object(checker, "load_expectations", return_value=rules), mock.patch.object(sys, "stdin", stream), contextlib.redirect_stdout(output):
            result = checker.main(["-"])
        self.assertEqual(result, 0)
        self.assertIn("RESULT INCOMPLETE pass=10 fail=0 missing=0 skip=1", output.getvalue())
        self.assertIn("SKIP runtime:supervisor observed=UNOBSERVABLE", output.getvalue())

    def test_cli_invalid_input_does_not_echo_arbitrary_contents(self):
        result = subprocess.run([sys.executable, "-B", str(TOOL)], input=b"private-secret\n",
                                capture_output=True, timeout=COMMAND_TIMEOUT)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(b"private-secret", result.stdout + result.stderr)

    def test_audit_table_rejects_duplicate_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            table = Path(directory) / "table.md"
            table.write_text('| probe:format | `["1"]` |\n' * 2)
            with self.assertRaises(ValueError):
                checker.load_expectations(table)

    def test_probe_shell_syntax(self):
        # Runtime read-only proof is a separate snapshot check, not this syntax test.
        result = subprocess.run(["sh", "-n", str(REPO / "tools/live/router-admission-probe.sh")],
                                capture_output=True, text=True, timeout=COMMAND_TIMEOUT)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_probe_fact_inventory_matches_the_reviewed_table(self):
        source = (REPO / "tools/live/router-admission-probe.sh").read_text()
        path_loop = source.split("for probe_entry in ", 1)[1].split("\ndo\n", 1)[0]
        paths = shlex.split(path_loop.replace("\\\n", " "))
        selector = source.split('    case "$probe_path" in\n', 1)[1].split('    if [ -L "$probe_path" ]', 1)[0]
        # Execute only the literal field-selection case. No observation command
        # or real absolute path read is part of this inventory check.
        script = 'for probe_path do\ncase "$probe_path" in\n' + selector + '\nprintf "%s %s\\n" "$probe_path" "$probe_fields"\ndone\n'
        result = subprocess.run(["sh", "-c", script, "field-inventory", *paths],
                                capture_output=True, text=True, timeout=COMMAND_TIMEOUT)
        self.assertEqual(result.returncode, 0, result.stderr)
        emitted = set()
        for line in result.stdout.splitlines():
            path, *fields = line.split()
            emitted.update(f"path:{path}:{field}" for field in fields)
        for loop, prefix, suffix in (("probe_tool", "tool:", ":present"), ("probe_gate", "runtime:", "")):
            values = source.split(f"for {loop} in ", 1)[1].split("\ndo\n", 1)[0]
            emitted.update(prefix + value + suffix for value in shlex.split(values.replace("\\\n", " ")))
        emitted.update(re.findall(r"^fact ((?:system|probe):[A-Za-z0-9-]+) ", source, re.M))
        self.assertEqual(emitted, set(self.rules),
                         f"undocumented={sorted(emitted-self.rules.keys())}; uncollected={sorted(self.rules.keys()-emitted)}")


if __name__ == "__main__":
    unittest.main()

