#!/usr/bin/env python3
"""Behavioral core fixtures. Passing is not packet/OpenWrt/live-router proof."""
import copy
import ipaddress
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import tempfile
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent / "fixtures"))
from harness import KID, OTHER_KID, PROTECTED, REPO, RouterFixture, policy, run_owned_process


def run_fixture_process(command, *, env, raw=None, timeout=60, started=None):
    return run_owned_process(command, env=env, input=raw, timeout=timeout, started=started,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def evaluate_fixture_chain(chains, chain, packet, sets, depth=0):
    """Small argv-rule model for regression attacks; not a kernel packet test."""
    if depth > 10:
        raise AssertionError("fixture chain recursion")
    for row in chains[chain]:
        matches, negate, target = True, False, None
        index = 0
        while index < len(row):
            token = row[index]
            if token == "!":
                negate = not negate
                index += 1
                continue
            if token in ("--kerneltz", "--contiguous"):
                index += 1
                continue
            if token in ("-m", "--comment", "--reject-with"):
                index += 2
                continue
            if token == "-j":
                target = row[index + 1]
                index += 2
                continue
            value = row[index + 1]
            if token in ("-i", "-o", "-p", "--mac-source", "--dport"):
                key = {"-i": "in", "-o": "out", "-p": "protocol", "--mac-source": "mac", "--dport": "dport"}[token]
                valid = packet[key].lower() == value.lower() or token == "-p" and value == "all"
            elif token in ("-s", "-d"):
                valid = ipaddress.ip_address(packet["src" if token == "-s" else "dst"]) in ipaddress.ip_network(value, strict=False)
            elif token == "--match-set":
                metadata = sets[value]
                direction = row[index + 2]
                source = packet["mac"] if metadata["type"] == "hash:mac" else packet[direction]
                valid = source in metadata["members"]
                index += 1
            elif token == "--weekdays":
                valid = packet["weekday"] in value.split(",")
            elif token == "--timestart":
                valid = packet["time"] >= value
            elif token == "--timestop":
                valid = packet["time"] <= value
            elif token == "--ctstate":
                valid = packet["ctstate"] in value.split(",")
            elif token == "--dports":
                valid = packet["dport"] in value.split(",")
            else:
                raise AssertionError(f"unmodeled fixture selector: {token!r} in {row!r}")
            matches = matches and (not valid if negate else valid)
            negate = False
            index += 2
        if not matches:
            continue
        if target == "RETURN":
            return None
        if target in ("ACCEPT", "REJECT", "DROP"):
            return target
        if target in chains:
            decision = evaluate_fixture_chain(chains, target, packet, sets, depth + 1)
            if decision is not None:
                return decision
        else:
            raise AssertionError(f"unmodeled fixture target: {target!r}")
    return None


class CoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Refusal assertions are meaningful only after a valid policy can execute.
        fixture = RouterFixture()
        try:
            result = fixture.run("sync", document=policy())
            if result.returncode != 0:
                raise RuntimeError("valid-policy smoke gate failed; negative tests withheld: "
                                   + result.stderr + result.stdout)
            if json.loads(result.stdout).get("ok") is not True:
                raise RuntimeError("valid-policy smoke gate did not confirm observed state")
        finally:
            fixture.close()

    def setUp(self):
        self.fixture = RouterFixture()

    def tearDown(self):
        self.fixture.close()

    def success(self, result):
        self.assertEqual(result.returncode, 0, result.stderr + "\n" + result.stdout)
        try:
            document = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            self.fail(f"command returned success without JSON status: {error}; {result.stdout!r}")
        self.assertIs(document["ok"], True, document)
        return document

    def sync(self, document=None):
        return self.success(self.fixture.run("sync", document=document or policy()))

    def paused(self):
        return self.fixture.backend()["sets"][self.fixture.active_set("p")]["members"]

    def reject_without_mutation(self, document=None, raw=None):
        before_files = self.fixture.durable_snapshot()
        before_calls = len(self.fixture.mutation_calls())
        result = self.fixture.run("sync", document=document, raw=raw)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(len(self.fixture.mutation_calls()), before_calls, result.stderr)
        self.assertEqual(self.fixture.durable_snapshot(), before_files, result.stderr)

    def test_initial_sync_confirms_observed_sets(self):
        status = self.sync()
        self.assertEqual(status["desiredRevision"], 1)
        self.assertEqual(status["confirmedRevision"], 1)
        self.assertCountEqual(status["observed"]["kids"], [KID, OTHER_KID])
        self.assertEqual(status["observed"]["paused"], [])
        self.assertNotIn(PROTECTED, self.fixture.backend()["sets"][self.fixture.active_set("k")]["members"])

    def test_malformed_json_and_duplicate_keys_never_mutate(self):
        for raw in ("", "null", "[]", "{", '{"version":1,"version":1}',
                    json.dumps(policy()).replace('"revision": 1', '"revision": 1, "revision": 1')):
            with self.subTest(raw=raw[:70]):
                self.reject_without_mutation(raw=raw)

    def test_schema_rejects_wrong_types_unknown_fields_and_bounds(self):
        cases = []
        for key, value in (("version", 2), ("revision", True), ("revision", -1),
                           ("revision", 1.5), ("revision", 10**30),
                           ("people", {}), ("pauses", "bad"), ("schedules", None),
                           ("unexpected", "value")):
            candidate = policy()
            candidate[key] = value
            cases.append(candidate)
        candidate = policy()
        del candidate["pauses"]
        cases.append(candidate)
        for candidate in cases:
            with self.subTest(candidate=candidate):
                self.reject_without_mutation(document=candidate)

    def test_invalid_identity_and_command_injection_rejected(self):
        for identity in ("Alice", "../root", "alice;touch /tmp/cf-injected", "a" * 33):
            document = policy()
            document["people"][0]["id"] = identity
            with self.subTest(identity=identity):
                self.reject_without_mutation(document=document)
        for mac in ("zz:00:00:00:00:01", "01:00:00:00:00:01", "00:00:00:00:00:00",
                    "FF:FF:FF:FF:FF:FF", KID + ";touch /tmp/cf-injected"):
            document = policy()
            document["people"][0]["macs"] = [mac]
            with self.subTest(mac=mac):
                self.reject_without_mutation(document=document)

    def test_duplicate_people_macs_assignments_and_undefined_pause_rejected(self):
        documents = []
        duplicate = policy()
        duplicate["people"].append(copy.deepcopy(duplicate["people"][0]))
        documents.append(duplicate)
        duplicate = policy()
        duplicate["people"][0]["macs"].append(KID)
        documents.append(duplicate)
        shared = policy()
        shared["people"].append({"id": "bob", "macs": [KID]})
        documents.append(shared)
        unknown = policy()
        unknown["pauses"] = [{"person": "bob", "until": 0}]
        documents.append(unknown)
        duplicate = policy()
        duplicate["pauses"] = [{"person": "alice", "until": 0}] * 2
        documents.append(duplicate)
        for document in documents:
            with self.subTest(document=document):
                self.reject_without_mutation(document=document)

    def test_nested_unknown_fields_and_duplicate_keys_rejected(self):
        document = policy()
        document["people"][0]["extra"] = "unsupported"
        self.reject_without_mutation(document=document)
        raw = json.dumps(policy()).replace('"id": "alice"', '"id": "alice", "id": "alice"')
        self.reject_without_mutation(raw=raw)
        document = policy()
        document["people pauses"] = []
        self.reject_without_mutation(document=document)
        document = policy()
        document["people"][0]["id macs"] = []
        self.reject_without_mutation(document=document)

    def test_protected_mac_overlap_never_mutates(self):
        document = policy()
        document["people"][0]["macs"] = [PROTECTED]
        self.reject_without_mutation(document=document)

    def test_missing_protection_never_mutates(self):
        (self.fixture.root / "etc/couvrefeu/protected").unlink()
        self.reject_without_mutation(document=policy())

    def test_unresolved_ssh_client_never_mutates(self):
        self.fixture.env["SSH_CONNECTION"] = "192.168.1.250 12345 192.168.1.1 22"
        self.reject_without_mutation(document=policy())

    def test_ambiguous_ssh_client_never_mutates(self):
        state = self.fixture.backend()
        state["neighbors"].append({"ip": "192.168.1.10", "mac": "02:00:00:00:00:99"})
        self.fixture.update_backend(neighbors=state["neighbors"])
        self.fixture.env["SSH_CONNECTION"] = "192.168.1.10 12345 192.168.1.1 22"
        self.reject_without_mutation(document=policy())

    def test_known_protected_ssh_client_can_sync(self):
        self.fixture.env["SSH_CONNECTION"] = "192.168.1.10 12345 192.168.1.1 22"
        self.sync()

    def test_known_protected_ipv6_ssh_client_can_sync(self):
        self.fixture.env["SSH_CONNECTION"] = "2001:db8::10 12345 2001:db8::1 22"
        self.sync()

    def test_selected_neighbor_explicit_other_device_refuses_ssh_client(self):
        state = self.fixture.backend()
        for row in state["neighbors"]:
            if row["mac"] == PROTECTED:
                row["dev"] = "eth0"
        self.fixture.update_backend(neighbors=state["neighbors"])
        for client in ("192.168.1.10", "2001:db8::10"):
            with self.subTest(client=client):
                self.fixture.env["SSH_CONNECTION"] = client + " 12345 192.168.1.1 22"
                self.reject_without_mutation(document=policy())

    def test_selected_neighbor_explicit_lan_device_is_accepted(self):
        self.fixture.update_backend(neighbor_explicit_dev=True)
        self.fixture.env["SSH_CONNECTION"] = "2001:db8::10 12345 2001:db8::1 22"
        self.sync()

    def test_unresolved_ipv6_ssh_client_never_mutates(self):
        self.fixture.env["SSH_CONNECTION"] = "2001:db8::ffff 12345 2001:db8::1 22"
        self.reject_without_mutation(document=policy())

    def test_current_ssh_client_cannot_be_enrolled(self):
        self.fixture.env["SSH_CONNECTION"] = "192.168.1.20 12345 192.168.1.1 22"
        self.reject_without_mutation(document=policy())

    def test_missing_backend_cannot_fall_through_to_host(self):
        (self.fixture.bin / "conntrack").unlink()
        self.reject_without_mutation(document=policy())

    def test_test_root_requires_explicit_test_mode(self):
        environment = dict(self.fixture.env)
        environment.pop("CF_TEST_MODE")
        result = self.fixture.run("sync", document=policy(), env=environment)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.fixture.calls(), [])

    def test_missing_backend_marker_refuses_before_any_call(self):
        (self.fixture.bin / ".couvrefeu-test-backend").unlink()
        result = self.fixture.run("sync", document=policy())
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.fixture.calls(), [])

    def test_pause_resume_all_person_devices_increment_revision(self):
        self.sync()
        paused = self.success(self.fixture.run("pause", "alice"))
        self.assertEqual(paused["desiredRevision"], 2)
        self.assertCountEqual(self.paused(), [KID, OTHER_KID])
        resumed = self.success(self.fixture.run("resume", "alice"))
        self.assertEqual(resumed["desiredRevision"], 3)
        self.assertEqual(self.paused(), [])

    def test_pause_flushes_every_known_ipv4_ipv6_source_and_destination(self):
        self.sync()
        for repeat in range(2):
            offset = len(self.fixture.calls())
            self.success(self.fixture.run("pause", "alice"))
            calls = [call["argv"] for call in self.fixture.calls()[offset:] if call["command"] == "conntrack"]
            for address in ("192.168.1.20", "192.168.1.21", "192.168.1.22", "2001:db8::20", "2001:db8::21"):
                for direction in ("-s", "-d"):
                    with self.subTest(repeat=repeat, address=address, direction=direction):
                        self.assertTrue(any(direction in args and address in args for args in calls), calls)
            self.assertFalse(any("192.168.1.10" in args for args in calls))

    def test_expiry_is_local_and_same_revision_replay_cannot_resurrect(self):
        document = policy()
        expiry = int(self.fixture.env["CF_NOW"]) + 120
        document["pauses"] = [{"person": "alice", "until": expiry}]
        self.sync(document)
        self.assertCountEqual(self.paused(), [KID, OTHER_KID])
        self.fixture.env["CF_NOW"] = str(expiry + 1)
        before = len(self.fixture.mutation_calls())
        self.success(self.fixture.run("expire"))
        self.assertGreater(len(self.fixture.mutation_calls()), before, "a newly elapsed timer must defeat the no-op shortcut")
        self.assertEqual(self.paused(), [])
        status = self.sync(document)
        self.assertEqual(status["desiredRevision"], 1)
        self.assertEqual(self.paused(), [])
        self.assertEqual(status["effectivePauses"], [])

    def test_past_pause_never_becomes_indefinite(self):
        document = policy()
        document["pauses"] = [{"person": "alice", "until": int(self.fixture.env["CF_NOW"]) - 1}]
        self.sync(document)
        self.assertEqual(self.paused(), [])

    def test_backward_clock_jump_does_not_resurrect_already_expired_pause(self):
        document = policy()
        initial = int(self.fixture.env["CF_NOW"])
        document["pauses"] = [{"person": "alice", "until": initial + 30}]
        self.sync(document)
        self.fixture.env["CF_NOW"] = str(initial + 31)
        self.success(self.fixture.run("expire"))
        self.fixture.env["CF_NOW"] = str(initial)
        self.success(self.fixture.run("apply-fw"))
        self.assertEqual(self.paused(), [])

    # Allowances: router-local temporary unblocking that expires without the service.
    SCHOOL_NIGHT = {"person": "alice", "id": "night", "weekdays": ["Mon"], "start": "22:00", "stop": "06:30"}

    def kid_outbound_blocked(self, family="iptables"):
        state = self.fixture.backend()
        source = "2001:db8::20" if family == "ip6tables" else "192.168.1.20"
        target = "2001:db8:ffff::1" if family == "ip6tables" else "198.51.100.1"
        # Fixture CF_NOW is Monday 23:00 UTC, inside SCHOOL_NIGHT.
        packet = {"in": "br-lan", "out": "eth0", "src": source, "dst": target, "mac": KID, "protocol": "tcp",
                  "dport": "443", "weekday": "Mon", "time": "23:00:00", "ctstate": "NEW"}
        return evaluate_fixture_chain(state["tables"][family]["filter"], "FORWARD", packet, state["sets"]) in ("DROP", "REJECT")

    def test_allowance_unblocks_schedule_and_local_expiry_reblocks_without_service(self):
        now = int(self.fixture.env["CF_NOW"])
        document = policy()
        document["schedules"] = [dict(self.SCHOOL_NIGHT)]
        self.sync(document)
        self.assertTrue(self.kid_outbound_blocked())
        until = now + 120
        document = policy(2)
        document["schedules"] = [dict(self.SCHOOL_NIGHT)]
        document["allowances"] = [{"person": "alice", "until": until}]
        status = self.sync(document)
        self.assertEqual(status["desiredAllowances"], [{"person": "alice", "until": until}])
        self.assertEqual(status["effectiveAllowances"], [{"person": "alice", "until": until, "remaining": 120}])
        for family in ("iptables", "ip6tables"):
            with self.subTest(family=family):
                self.assertFalse(self.kid_outbound_blocked(family))
        # DNS/DoT semantics are unchanged: the child remains a kid during an allowance.
        self.assertCountEqual(status["observed"]["kids"], [KID, OTHER_KID])
        nat = self.fixture.backend()["tables"]["iptables"]["nat"]
        self.assertTrue(any("DNAT" in row and self.fixture.active_set("k") in row for rows in nat.values() for row in rows))
        filters = self.fixture.backend()["tables"]["iptables"]["filter"]
        self.assertTrue(any("853" in row and self.fixture.active_set("k") in row for rows in filters.values() for row in rows))
        # No service: only the minute cron runs after the deadline.
        self.fixture.env["CF_NOW"] = str(until + 1)
        expired = self.success(self.fixture.run("expire"))
        self.assertEqual(expired["desiredRevision"], 2)
        self.assertEqual(expired["effectiveAllowances"], [])
        self.assertEqual(expired["desiredAllowances"], [{"person": "alice", "until": until}])
        for family in ("iptables", "ip6tables"):
            with self.subTest(family=family, phase="expired"):
                self.assertTrue(self.kid_outbound_blocked(family))
        # Same-revision replay stays idempotent and cannot resurrect the allowance.
        replay = self.sync(document)
        self.assertEqual(replay["desiredRevision"], 2)
        self.assertEqual(replay["effectiveAllowances"], [])
        self.assertTrue(self.kid_outbound_blocked())

    def test_allowance_overrides_manual_pause_and_expiry_restores_it(self):
        now = int(self.fixture.env["CF_NOW"])
        document = policy()
        document["pauses"] = [{"person": "alice", "until": 0}]
        document["allowances"] = [{"person": "alice", "until": now + 60}]
        status = self.sync(document)
        self.assertEqual(self.paused(), [])
        self.assertEqual(status["observed"]["paused"], [])
        self.assertEqual(status["effectivePauses"], [{"person": "alice", "until": 0}])
        self.assertFalse(self.kid_outbound_blocked())
        unchanged = self.success(self.fixture.run("expire"))
        self.assertEqual(unchanged["observed"]["paused"], [])
        self.fixture.env["CF_NOW"] = str(now + 61)
        before = len(self.fixture.mutation_calls())
        expired = self.success(self.fixture.run("expire"))
        self.assertGreater(len(self.fixture.mutation_calls()), before, "an elapsed allowance must defeat the no-op shortcut")
        self.assertCountEqual(self.paused(), [KID, OTHER_KID])
        self.assertCountEqual(expired["observed"]["paused"], [KID, OTHER_KID])
        self.assertEqual(expired["desiredRevision"], 1)
        self.assertTrue(self.kid_outbound_blocked())

    def test_allowance_timed_pause_rides_through_and_cli_pause_does_not_clear_it(self):
        now = int(self.fixture.env["CF_NOW"])
        document = policy()
        document["allowances"] = [{"person": "alice", "until": now + 60}]
        self.sync(document)
        paused = self.success(self.fixture.run("pause", "alice"))
        self.assertEqual(paused["desiredRevision"], 2)
        self.assertEqual(paused["desiredAllowances"], [{"person": "alice", "until": now + 60}])
        self.assertEqual(self.paused(), [])
        self.fixture.env["CF_NOW"] = str(now + 61)
        self.success(self.fixture.run("expire"))
        self.assertCountEqual(self.paused(), [KID, OTHER_KID])

    def test_invalid_allowances_rejected_without_mutation(self):
        self.sync()
        now = int(self.fixture.env["CF_NOW"])
        bad = [
            [{"person": "alice", "until": now + 60}, {"person": "alice", "until": now + 90}],
            [{"person": "bob", "until": now + 60}],
            [{"person": "alice", "until": 0}],
            [{"person": "alice", "until": 2147483648}],
            [{"person": "alice", "until": now + 14401}],
            [{"person": "alice", "until": "1736204460"}],
            [{"person": "alice", "until": now + 60.5}],
            [{"person": "alice", "until": now + 60, "extra": 1}],
            [{"person": "alice"}],
            [{"person": "Alice", "until": now + 60}],
            {"person": "alice", "until": now + 60},
            [{"person": "alice", "until": now + 60}] * 65,
        ]
        for value in bad:
            document = policy(2)
            document["allowances"] = value
            with self.subTest(value=str(value)[:80]):
                self.reject_without_mutation(document=document)
        self.reject_without_mutation(raw=json.dumps(policy(2)).replace('"pauses"', '"allowances":[],"allowances":[],"pauses"'))

    def test_allowance_horizon_boundary_and_expired_allowance_is_inert(self):
        now = int(self.fixture.env["CF_NOW"])
        document = policy()
        document["allowances"] = [{"person": "alice", "until": now + 14400}]
        status = self.sync(document)
        self.assertEqual(status["effectiveAllowances"], [{"person": "alice", "until": now + 14400, "remaining": 14400}])
        document = policy(2)
        document["pauses"] = [{"person": "alice", "until": 0}]
        document["allowances"] = [{"person": "alice", "until": now - 1}]
        status = self.sync(document)
        self.assertEqual(status["effectiveAllowances"], [])
        self.assertCountEqual(self.paused(), [KID, OTHER_KID])

    def test_allowance_without_allowances_key_keeps_legacy_shape(self):
        status = self.sync()
        self.assertEqual(status["desiredAllowances"], [])
        self.assertEqual(status["effectiveAllowances"], [])
        state = (self.fixture.root / "etc/couvrefeu/state").read_text()
        self.assertNotIn("\nU\t", "\n" + state)

    def test_invalid_clock_never_honors_allowance(self):
        now = int(self.fixture.env["CF_NOW"])
        document = policy()
        document["pauses"] = [{"person": "alice", "until": 0}]
        document["allowances"] = [{"person": "alice", "until": now + 60}]
        self.sync(document)
        for clock in ("not-an-epoch;id", "1500000000"):
            self.fixture.env["CF_NOW"] = clock
            with self.subTest(clock=clock):
                result = self.fixture.run("status", "--json")
                status = json.loads(result.stdout)
                self.assertIs(status["ok"], False)
                self.assertEqual(status["effectiveAllowances"], [])
                self.assertNotEqual(self.fixture.run("expire").returncode, 0)
                fresh = policy(2)
                fresh["allowances"] = [{"person": "alice", "until": now + 60}]
                self.reject_without_mutation(document=fresh)

    def test_backward_clock_jump_does_not_resurrect_expired_allowance(self):
        initial = int(self.fixture.env["CF_NOW"])
        document = policy()
        document["pauses"] = [{"person": "alice", "until": 0}]
        document["allowances"] = [{"person": "alice", "until": initial + 30}]
        self.sync(document)
        self.assertEqual(self.paused(), [])
        self.fixture.env["CF_NOW"] = str(initial + 31)
        self.success(self.fixture.run("expire"))
        self.fixture.env["CF_NOW"] = str(initial)
        status = self.success(self.fixture.run("apply-fw"))
        self.assertEqual(status["effectiveAllowances"], [])
        self.assertCountEqual(self.paused(), [KID, OTHER_KID])

    def test_invalid_test_clock_refuses_before_mutation(self):
        self.fixture.env["CF_NOW"] = "not-an-epoch;id"
        self.reject_without_mutation(document=policy())

    def test_bounded_json_payload_rejected_before_backend_mutation(self):
        self.reject_without_mutation(raw=" " * 1048577 + json.dumps(policy()))

    def test_stale_and_conflicting_equal_revision_refuse_without_mutation(self):
        self.sync(policy(2))
        self.reject_without_mutation(document=policy(1))
        conflict = policy(2)
        conflict["pauses"] = [{"person": "alice", "until": 0}]
        self.reject_without_mutation(document=conflict)

    def test_repeat_sync_and_apply_fw_are_idempotent(self):
        document = policy()
        document["pauses"] = [{"person": "alice", "until": 0}]
        self.sync(document)
        before = self.fixture.backend()
        self.sync(document)
        self.success(self.fixture.run("apply-fw"))
        after = self.fixture.backend()
        for key in ("sets", "tables", "uci"):
            self.assertEqual(after[key], before[key], key)

    def test_healthy_unchanged_expire_and_apply_verify_without_kernel_mutations(self):
        document = policy()
        document["pauses"] = [{"person": "alice", "until": int(self.fixture.env["CF_NOW"]) + 3600}]
        document["schedules"] = [{"person": "alice", "id": "day", "weekdays": ["Mon"], "start": "10:00", "stop": "11:00"}]
        document["doh"] = {"ipv4": ["1.1.1.1"], "ipv6": ["2606:4700:4700::1111"]}
        self.sync(document)
        confirmed = self.fixture.root / "etc/couvrefeu/runtime/confirmed"
        original_confirmation = confirmed.read_bytes()
        original = self.fixture.backend()
        for action in ("expire", "apply-fw", "expire"):
            with self.subTest(action=action):
                offset = len(self.fixture.calls())
                mutation_offset = len(self.fixture.mutation_calls())
                status = self.success(self.fixture.run(action))
                self.assertEqual(status["desiredRevision"], 1)
                self.assertEqual(status["confirmedRevision"], 1)
                writes = [call for call in self.fixture.mutation_calls()[mutation_offset:]
                          if call["command"] != "conntrack"]
                self.assertEqual(writes, [],
                                 "healthy unchanged policy must not flush sets, rebuild chains or reload")
                reads = self.fixture.calls()[offset:]
                self.assertTrue(any(call["command"] == "ipset" and "save" in call["argv"] for call in reads))
                for family in ("iptables", "ip6tables"):
                    self.assertTrue(any(call["command"] == family and "-S" in call["argv"] for call in reads))
                self.assertTrue(any(call["command"] == "uci" for call in reads))
                self.assertEqual(confirmed.read_bytes(), original_confirmation)
                after = self.fixture.backend()
                for key in ("sets", "tables", "uci"):
                    self.assertEqual(after[key], original[key], key)

    def test_observation_accepts_equivalent_iptables_serialization(self):
        self.fixture.update_backend(canonical_rules=True)
        self.sync()
        self.success(self.fixture.run("pause", "alice"))
        self.success(self.fixture.run("status", "--json"))
        self.success(self.fixture.run("apply-fw"))

    def test_changed_child_address_rebuilds_inbound_guards(self):
        document = policy()
        document["pauses"] = [{"person": "alice", "until": 0}]
        self.sync(document)
        state = self.fixture.backend()
        for row in state["neighbors"]:
            if row["ip"] == "2001:db8::21":
                row["ip"] = "2001:db8::23"
        self.fixture.update_backend(neighbors=state["neighbors"])
        before = len(self.fixture.mutation_calls())
        self.success(self.fixture.run("expire"))
        self.assertGreater(len(self.fixture.mutation_calls()), before)
        rules = self.fixture.backend()["tables"]["ip6tables"]["filter"][self.fixture.active_chain("f")]
        self.assertTrue(any("2001:db8::23" in row and "-d" in row and "REJECT" in row for row in rules))
        self.assertFalse(any("2001:db8::21" in row for row in rules))

    def test_set_drift_rebuilds_instead_of_skipping_actual_verification(self):
        document = policy()
        document["pauses"] = [{"person": "alice", "until": 0}]
        self.sync(document)
        state = self.fixture.backend()
        state["sets"][self.fixture.active_set("p")]["members"] = [KID]
        self.fixture.update_backend(sets=state["sets"])
        before = len(self.fixture.mutation_calls())
        repaired = self.success(self.fixture.run("apply-fw"))
        self.assertGreater(len(self.fixture.mutation_calls()), before)
        self.assertCountEqual(repaired["observed"]["paused"], [KID, OTHER_KID])

    def test_higher_revision_with_same_effective_rules_updates_confirmation(self):
        document = policy()
        document["pauses"] = [{"person": "alice", "until": 0}]
        self.sync(document)
        before = self.fixture.backend()
        document["revision"] = 2
        updated = self.sync(document)
        self.assertEqual(updated["desiredRevision"], 2)
        self.assertEqual(updated["confirmedRevision"], 2)
        self.assertEqual((self.fixture.root / "etc/couvrefeu/runtime/confirmed").read_text().split()[0], "2")
        after = self.fixture.backend()
        for key in ("sets", "tables", "uci"):
            self.assertEqual(after[key], before[key], key)

    def test_pending_apply_records_and_missing_confirmation_require_recovery_work(self):
        self.sync()
        runtime = self.fixture.root / "etc/couvrefeu/runtime"
        for pending in ("error", "confirmed"):
            with self.subTest(pending=pending):
                path = runtime / pending
                if pending == "confirmed":
                    path.unlink()
                elif pending == "error":
                    path.write_text("chain_apply_failed\n")
                    path.chmod(0o600)
                else:
                    records = []
                    for line in (runtime / "firewall.snapshot").read_text().splitlines():
                        parts = line.split(" ", 6)
                        if len(parts) == 7 and parts[0] == "RULE" and parts[4] == "-A":
                            records.append("\t".join((parts[1], parts[2], parts[3], parts[6])))
                    self.assertTrue(records)
                    path.write_text("\n".join(records) + "\n")
                    path.chmod(0o600)
                before = len(self.fixture.mutation_calls())
                self.success(self.fixture.run("apply-fw"))
                self.assertGreater(len(self.fixture.mutation_calls()), before,
                                   "an unconfirmed or interrupted apply must not use the healthy shortcut")
                self.assertFalse((runtime / "firewall.intent").exists())
                self.assertFalse((runtime / "error").exists())
                self.assertTrue((runtime / "confirmed").is_file())

    def test_failed_empty_owned_chain_read_cannot_confirm_a_new_revision(self):
        self.sync()
        self.assertEqual(self.fixture.backend()["tables"]["ip6tables"]["filter"][self.fixture.active_chain("i")], [["-m", "comment", "--comment", "cf:v2", "-j", "RETURN"]])
        confirmed = self.fixture.root / "etc/couvrefeu/runtime/confirmed"
        before = confirmed.read_bytes()
        # Allow the existing-chain check to succeed; fail the subsequent
        # verification read, where a pipeline once mistook errors for emptiness.
        self.fixture.update_backend(failures=[{"command": "ip6tables", "contains": ["-S", "cf_input"], "skip": 1, "remaining": 100}])
        result = self.fixture.run("sync", document=policy(2))
        self.assertNotEqual(result.returncode, 0, "an unreadable empty chain is not verified absence of rules")
        self.assertIs(json.loads(result.stdout)["ok"], False)
        self.assertEqual(confirmed.read_bytes(), before)

    def test_failed_set_observation_during_apply_cannot_replace_confirmation(self):
        self.sync()
        confirmed = self.fixture.root / "etc/couvrefeu/runtime/confirmed"
        before = confirmed.read_bytes()
        calls = len(self.fixture.calls())
        mutations = len(self.fixture.mutation_calls())
        # The complete inventory now uses `ipset save` without a set name.
        # Unreadable inventory must retain the prior confirmation.
        self.fixture.update_backend(failures=[{"command": "ipset", "contains": ["save"], "remaining": 100}])
        result = self.fixture.run("sync", document=policy(2))
        self.assertNotEqual(result.returncode, 0)
        self.assertIs(json.loads(result.stdout)["ok"], False)
        self.assertEqual(confirmed.read_bytes(), before)
        self.assertTrue(any(call["command"] == "ipset" and call["argv"] == ["save"]
                            for call in self.fixture.calls()[calls:]), "must exercise the actual full inventory read")
        self.assertLess(self.fixture.backend()["failures"][0]["remaining"], 100)
        self.assertEqual(len(self.fixture.mutation_calls()), mutations)

    def test_latent_native_selector_cannot_be_blessed_by_healthy_kernel_witness(self):
        document = policy()
        document["schedules"] = [{"person": "alice", "id": "day", "weekdays": ["Mon"], "start": "10:00", "stop": "11:00"}]
        self.sync(document)
        firewall = self.fixture.root / "etc/config/firewall"
        sections = [key.split(".")[1] for key, value in self.fixture.backend()["uci"].items()
                    if key.count(".") == 1 and key.startswith("firewall.cf_sched_") and value == "rule"]
        self.assertTrue(sections)
        section = sorted(sections)[0]
        contents = firewall.read_text()
        headers = [line for line in contents.splitlines(keepends=True)
                   if line in (f"config rule {section}\n", f"config rule '{section}'\n")]
        self.assertEqual(len(headers), 1)
        header = headers[0]
        firewall.write_text(contents.replace(header, header + "\toption src_ip '192.0.2.222'\n", 1))
        selector = subprocess.run([str(self.fixture.bin / "uci"), "-q", "get", f"firewall.{section}.src_ip"],
                                  env=self.fixture.env, text=True, capture_output=True, timeout=20)
        self.assertEqual(selector.returncode, 0, selector.stderr)
        self.assertEqual(selector.stdout.strip(), "192.0.2.222", "attack must narrow an owned native section")
        before = (self.fixture.root / "etc/couvrefeu/runtime/confirmed").read_bytes()
        result = self.fixture.run("apply-fw")
        if result.returncode == 0:
            self.assertNotIn("option src_ip", firewall.read_text(), "successful apply must repair latent native narrowing")
            self.assertIs(json.loads(result.stdout)["ok"], True)
        else:
            self.assertIs(json.loads(result.stdout)["ok"], False)
            self.assertEqual((self.fixture.root / "etc/couvrefeu/runtime/confirmed").read_bytes(), before)

    def test_surplus_owned_native_section_cannot_survive_healthy_empty_schedule(self):
        self.sync()
        firewall = self.fixture.root / "etc/config/firewall"
        firewall.write_text(firewall.read_text() + "\nconfig rule 'cf_sched_surplus'\n\toption couvrefeu_owner 'v1'\n\toption target 'REJECT'\n\toption src 'lan'\n\toption dest 'wan'\n")
        before = (self.fixture.root / "etc/couvrefeu/runtime/confirmed").read_bytes()
        result = self.fixture.run("expire")
        if result.returncode == 0:
            self.assertNotIn("cf_sched_surplus", firewall.read_text(), "successful expiry must remove surplus persistent policy")
            self.assertIs(json.loads(result.stdout)["ok"], True)
        else:
            self.assertIs(json.loads(result.stdout)["ok"], False)
            self.assertEqual((self.fixture.root / "etc/couvrefeu/runtime/confirmed").read_bytes(), before)

    def test_host_prefix_equivalence_is_family_specific(self):
        state = self.fixture.backend()
        for row in state["neighbors"]:
            if row["ip"] == "2001:db8::10":
                row["ip"] = "2001:db8::"
        self.fixture.update_backend(neighbors=state["neighbors"])
        self.sync()
        state = self.fixture.backend()
        adult6 = None
        for command, suffix in (("iptables", "/32"), ("ip6tables", "/128")):
            for rows in state["tables"][command]["filter"].values():
                for row in rows:
                    for flag in ("-s", "-d"):
                        if flag in row:
                            index = row.index(flag) + 1
                            if "/" not in row[index]:
                                if command == "ip6tables" and row[index] == "2001:db8::" and "RETURN" in row:
                                    adult6 = row
                                row[index] += suffix
        self.assertIsNotNone(adult6, "fixture must contain the protected adult host exemption")
        self.fixture.update_backend(tables=state["tables"])
        self.success(self.fixture.run("status", "--json"))
        adult6[adult6.index("-d") + 1] = "2001:db8::/32"
        self.fixture.update_backend(tables=state["tables"])
        before = len(self.fixture.mutation_calls())
        status = json.loads(self.fixture.run("status", "--json").stdout)
        self.assertIs(status["ok"], False)
        self.assertIs(status["drift"], True)
        self.assertEqual(len(self.fixture.mutation_calls()), before)

    def test_expiry_removes_mac_pause_when_ipv6_neighbor_is_not_fresh(self):
        document = policy()
        expiry = int(self.fixture.env["CF_NOW"]) + 30
        document["pauses"] = [{"person": "alice", "until": expiry}]
        self.sync(document)
        state = self.fixture.backend()
        state["neighbors"] = [row for row in state["neighbors"] if row["mac"] != OTHER_KID]
        for row in state["neighbors"]:
            if row["mac"] == KID:
                row["state"] = ("STALE" if row["ip"].endswith("::20") else "DELAY") if ":" in row["ip"] else "PROBE"
        self.fixture.update_backend(neighbors=state["neighbors"])
        (self.fixture.root / "tmp/dhcp.leases").write_text("")  # Other device is fully offline.
        self.fixture.env["CF_NOW"] = str(expiry + 1)
        self.success(self.fixture.run("expire"))
        self.assertEqual(self.paused(), [])
        adult = {"192.168.1.10", "2001:db8::10"}
        self.assertFalse(any(adult.intersection(call["argv"]) for call in self.fixture.calls() if call["command"] == "conntrack"))

    def test_reload_reconstructs_owned_rules_and_sets(self):
        document = policy()
        document["pauses"] = [{"person": "alice", "until": 0}]
        self.sync(document)
        state = self.fixture.backend()
        state["sets"] = {}
        for family in state["tables"].values():
            family["filter"] = {"FORWARD": family["filter"]["FORWARD"],
                                "INPUT": family["filter"]["INPUT"],
                                "forwarding_rule": [], "input_rule": []}
            family["nat"] = {"PREROUTING": family["nat"]["PREROUTING"],
                             "prerouting_rule": []}
        self.fixture.update_backend(sets=state["sets"], tables=state["tables"])
        before = len(self.fixture.mutation_calls())
        self.success(self.fixture.run("apply-fw"))
        self.assertGreater(len(self.fixture.mutation_calls()), before, "missing objects require reconstruction")
        self.assertCountEqual(self.paused(), [KID, OTHER_KID])
        self.assertCountEqual(self.success(self.fixture.run("status", "--json"))["observed"]["kids"], [KID, OTHER_KID])

    def test_status_observes_actual_drift_without_mutating(self):
        self.sync()
        state = self.fixture.backend()
        state["sets"][self.fixture.active_set("k")]["members"] = [KID]
        self.fixture.update_backend(sets=state["sets"])
        calls_before = len(self.fixture.mutation_calls())
        result = self.fixture.run("status", "--json")
        status = json.loads(result.stdout)
        self.assertIs(status["ok"], False)
        self.assertIs(status["drift"], True)
        self.assertEqual(status["observed"]["kids"], [KID])
        self.assertEqual(len(self.fixture.mutation_calls()), calls_before)

    def test_status_rejects_missing_hook_and_extra_owned_accept(self):
        self.sync()
        state = self.fixture.backend()
        chain = state["tables"]["iptables"]["filter"]["forwarding_rule"][0]
        target = chain[chain.index("-j") + 1]
        state["tables"]["iptables"]["filter"][target].append(["-j", "ACCEPT"])
        self.fixture.update_backend(tables=state["tables"])
        status = json.loads(self.fixture.run("status", "--json").stdout)
        self.assertIs(status["ok"], False)
        self.assertIs(status["drift"], True)
        state["tables"]["iptables"]["filter"][target].pop()
        state["tables"]["ip6tables"]["filter"]["forwarding_rule"] = []
        self.fixture.update_backend(tables=state["tables"])
        status = json.loads(self.fixture.run("status", "--json").stdout)
        self.assertIs(status["ok"], False)

    def test_failed_observation_never_reports_healthy_confirmation(self):
        self.sync()
        self.fixture.update_backend(failures=[{"command": "ipset", "contains": ["save", self.fixture.active_set("k")], "remaining": 1}])
        status = json.loads(self.fixture.run("status", "--json").stdout)
        self.assertIs(status["ok"], False)
        self.assertTrue(status["errors"])

    def test_apply_failure_cannot_report_confirmed_success_and_can_retry(self):
        self.fixture.update_backend(failures=[{"command": "ip6tables", "contains": ["-A"], "remaining": 1}])
        result = self.fixture.run("sync", document=policy())
        self.assertNotEqual(result.returncode, 0, result.stdout)
        status = json.loads(self.fixture.run("status", "--json").stdout)
        self.assertIs(status["ok"], False)
        self.assertNotEqual(status["confirmedRevision"], status["desiredRevision"])
        self.sync()

    def test_unknown_person_cli_and_shell_payload_never_mutate(self):
        self.sync()
        calls_before = len(self.fixture.mutation_calls())
        for command in (("pause", "bob"), ("resume", "bob"), ("pause", "alice;id"),
                        ("pause", "alice", "--until", "0;id"), ("bonus", "alice", "60")):
            with self.subTest(command=command):
                self.assertNotEqual(self.fixture.run(*command).returncode, 0)
        self.assertEqual(len(self.fixture.mutation_calls()), calls_before)

    def test_cross_midnight_schedule_rotates_weekdays_and_excludes_stop(self):
        document = policy()
        document["schedules"] = [{"person": "alice", "id": "night", "weekdays": ["Mon"], "start": "22:00", "stop": "06:30"}]
        self.sync(document)
        rules = [call["argv"] for call in self.fixture.calls() if call["command"] in ("iptables", "ip6tables") and "--timestart" in call["argv"] and "-A" in call["argv"]]
        self.assertTrue(any("Mon" in args and "23:59:59" in args for args in rules), rules)
        self.assertTrue(any("Tue" in args and "06:29:59" in args for args in rules), rules)
        self.assertTrue(all("--kerneltz" in args for args in rules), rules)
        self.assertTrue(all("ACCEPT" not in args for args in rules))
        self.success(self.fixture.run("resume", "alice"))
        rules_after = self.fixture.backend()["tables"]["iptables"]["filter"]
        self.assertTrue(any("--timestart" in row for rows in rules_after.values() for row in rows))
        includes = self.fixture.backend()["reload_includes"]
        self.assertTrue(includes)
        for result in includes:
            self.assertEqual(result["returncode"], 0, result)
            self.assertIs(json.loads(result["stdout"])["deferred"], True)

    def test_native_metadata_without_dual_family_witness_cannot_confirm(self):
        document = policy()
        document["schedules"] = [{"person": "alice", "id": "day", "weekdays": ["Mon"], "start": "10:00", "stop": "11:00"}]
        self.fixture.update_backend(native_witness=False)
        result = self.fixture.run("sync", document=document)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        status = json.loads(self.fixture.run("status", "--json").stdout)
        self.assertIs(status["ok"], False)
        self.assertIs(status["capabilities"]["nativeKernelConfirmed"], False)
        self.fixture.update_backend(native_witness=True)
        self.success(self.fixture.run("apply-fw"))
        state = self.fixture.backend()
        state["tables"]["ip6tables"]["filter"]["zone_lan_forward"] = []
        self.fixture.update_backend(tables=state["tables"])
        status = json.loads(self.fixture.run("status", "--json").stdout)
        self.assertIs(status["ok"], False)
        self.assertIs(status["capabilities"]["nativeKernelConfirmed"], False)

    def test_native_schedule_hidden_by_earlier_accept_cannot_confirm(self):
        document = policy()
        document["schedules"] = [{"person": "alice", "id": "day", "weekdays": ["Mon"], "start": "10:00", "stop": "11:00"}]
        self.sync(document)
        state = self.fixture.backend()
        for family in ("iptables", "ip6tables"):
            state["tables"][family]["filter"]["forwarding_lan_rule"] = []
            state["tables"][family]["filter"]["zone_lan_forward"].insert(0, ["-j", "forwarding_lan_rule"])
        self.fixture.update_backend(tables=state["tables"])
        self.success(self.fixture.run("status", "--json"))
        for family in ("iptables", "ip6tables"):
            state["tables"][family]["filter"]["zone_lan_forward"].insert(0, ["-j", "ACCEPT"])
        self.fixture.update_backend(tables=state["tables"])
        status = json.loads(self.fixture.run("status", "--json").stdout)
        self.assertIs(status["ok"], False)
        self.assertIs(status["capabilities"]["nativeKernelConfirmed"], False)

    def test_native_reject_requires_real_wan_device_and_complete_multiwan_coverage(self):
        document = policy()
        document["schedules"] = [{"person": "alice", "id": "day", "weekdays": ["Mon"], "start": "10:00", "stop": "11:00"}]
        self.fixture.update_backend(wan_devices=["eth0", "wwan0"])
        self.sync(document)
        good = self.fixture.backend()
        for attack in ("bogus", "partial", "empty-resolver"):
            with self.subTest(attack=attack):
                state = copy.deepcopy(good)
                if attack == "empty-resolver":
                    state["wan_devices"] = []
                else:
                    for family in ("iptables", "ip6tables"):
                        rules = state["tables"][family]["filter"]["zone_wan_dest_REJECT"]
                        if attack == "bogus":
                            rules[0][rules[0].index("-o") + 1] = "bogus0"
                        else:
                            del rules[1:]
                self.fixture.update_backend(tables=state["tables"], wan_devices=state["wan_devices"])
                status = json.loads(self.fixture.run("status", "--json").stdout)
                self.assertIs(status["ok"], False)
                self.assertIs(status["capabilities"]["nativeKernelConfirmed"], False)

    def test_foreign_pending_uci_deltas_refuse_before_any_mutation(self):
        self.fixture.update_backend(uci_deltas="firewall.foreign.option='operator-pending'\n")
        self.reject_without_mutation(document=policy())

    def test_invalid_schedule_and_resolver_addresses_rejected(self):
        window = {"person": "alice", "id": "night", "weekdays": ["Mon"], "start": "22:00", "stop": "06:30"}
        for key, value in (("weekdays", []), ("weekdays", ["Funday"]), ("start", "24:01"),
                           ("stop", "22:00"), ("start", "22:00;id"), ("extra", True)):
            document = policy()
            invalid = dict(window)
            invalid[key] = value
            document["schedules"] = [invalid]
            with self.subTest(key=key, value=value):
                self.reject_without_mutation(document=document)
        for family, address in (("ipv4", "999.1.1.1"), ("ipv4", "8.8.8.8;id"),
                                ("ipv6", "2001:db8::zz"), ("ipv6", "8.8.8.8")):
            document = policy()
            document["doh"][family] = [address]
            self.reject_without_mutation(document=document)
        document = policy()
        document["schedules"] = [window, dict(window)]
        self.reject_without_mutation(document=document)

    def test_dns_redirect_and_input_exception_are_kids_only_and_lan_scoped(self):
        self.sync()
        tables = self.fixture.backend()["tables"]["iptables"]
        nat_hook = tables["nat"]["prerouting_rule"][0]
        nat_target = nat_hook[nat_hook.index("-j") + 1]
        nat_dispatch = tables["nat"][nat_target][0]
        nat_rules = tables["nat"][nat_dispatch[nat_dispatch.index("-j") + 1]]
        dnat = [row for row in nat_rules if "DNAT" in row]
        self.assertEqual(len(dnat), 2)
        for rule in dnat:
            self.assertIn(self.fixture.active_set("k"), rule)
            self.assertIn("53", rule)
            self.assertIn("192.168.1.1", rule)
            self.assertIn("!", rule)
            self.assertIn("br-lan", rule + nat_hook)
        input_hook = tables["filter"]["input_rule"][0]
        input_target = input_hook[input_hook.index("-j") + 1]
        input_dispatch = tables["filter"][input_target][0]
        accepts = [row for row in tables["filter"][input_dispatch[input_dispatch.index("-j") + 1]] if "ACCEPT" in row]
        self.assertEqual(len(accepts), 1)
        for token in ("udp", "53", "192.168.1.1", self.fixture.active_set("k")):
            self.assertIn(token, accepts[0])
        self.assertIn("br-lan", accepts[0] + input_hook)

    def test_owned_hooks_are_first_lan_scoped_and_have_no_forward_accept(self):
        self.sync()
        state = self.fixture.backend()
        for family in ("iptables", "ip6tables"):
            table = state["tables"][family]["filter"]
            hook = table["forwarding_rule"][0]
            target = hook[hook.index("-j") + 1]
            selectors = list(hook)
            for option in ("-m", "--comment"):
                while option in selectors:
                    index = selectors.index(option)
                    if option == "-m":
                        self.assertEqual(selectors[index + 1], "comment")
                    del selectors[index:index + 2]
            self.assertEqual(selectors, ["-j", target], "owned forwarding jump must cover inbound established flows")
            self.assertTrue(target.startswith(("CF_", "cf_")), hook)
            self.assertFalse(any("ACCEPT" in rule for rule in table[target]))

    def test_parent_hook_narrowed_to_tcp_cannot_confirm(self):
        self.sync()
        state = self.fixture.backend()
        for family in ("iptables", "ip6tables"):
            state["tables"][family]["filter"]["FORWARD"][0] = ["-p", "tcp", "-j", "forwarding_rule"]
        self.fixture.update_backend(tables=state["tables"])
        status = json.loads(self.fixture.run("status", "--json").stdout)
        self.assertIs(status["ok"], False)
        calls = len(self.fixture.mutation_calls())
        result = self.fixture.run("apply-fw")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(len(self.fixture.mutation_calls()), calls)

    def test_known_target_input_prefixes_are_safe_disjoint_from_kid_dns(self):
        state = self.fixture.backend()
        state["tables"]["iptables"]["filter"]["INPUT"] = [
            ["-i", "br-lan", "-p", "icmp", "-m", "icmp", "--icmp-type", "8",
             "-m", "limit", "--limit", "1/sec", "-j", "ACCEPT"],
            ["-p", "icmp", "-m", "icmp", "--icmp-type", "8", "-j", "LOG"],
            ["-p", "icmp", "-m", "icmp", "--icmp-type", "8", "-j", "DROP"],
            ["-i", "lo", "-j", "ACCEPT"],
            ["-j", "input_rule"], ["-j", "GL_DNS_LEAK"]]
        state["tables"]["ip6tables"]["filter"]["INPUT"] = [
            ["-i", "lo", "-j", "ACCEPT"], ["-j", "input_rule"], ["-j", "GL_DNS_LEAK"]]
        self.fixture.update_backend(tables=state["tables"])
        self.sync()
        self.success(self.fixture.run("status", "--json"))
        # A DNS ACCEPT before the input hook can hide the GL exception and is not disjoint.
        state = self.fixture.backend()
        state["tables"]["iptables"]["filter"]["INPUT"].insert(0, ["-p", "udp", "--dport", "53", "-j", "ACCEPT"])
        self.fixture.update_backend(tables=state["tables"])
        status = json.loads(self.fixture.run("status", "--json").stdout)
        self.assertIs(status["ok"], False)

    def test_forward_prefix_cannot_borrow_safe_input_loopback_exception(self):
        state = self.fixture.backend()
        for family in ("iptables", "ip6tables"):
            state["tables"][family]["filter"]["FORWARD"].insert(0, ["-i", "lo", "-j", "ACCEPT"])
        self.fixture.update_backend(tables=state["tables"])
        self.reject_without_mutation(document=policy())

    def test_existing_gl_mac_drop_before_forward_hook_is_preserved(self):
        state = self.fixture.backend()
        state["sets"]["GL_MAC_BLOCK"] = {"type": "hash:mac", "members": []}
        rule = ["-m", "set", "--match-set", "GL_MAC_BLOCK", "src", "-j", "DROP"]
        state["tables"]["iptables"]["filter"]["FORWARD"].insert(0, rule)
        self.fixture.update_backend(tables=state["tables"], sets=state["sets"])
        self.sync()
        self.assertEqual(self.fixture.backend()["sets"]["GL_MAC_BLOCK"], state["sets"]["GL_MAC_BLOCK"])
        self.assertEqual(self.fixture.backend()["tables"]["iptables"]["filter"]["FORWARD"][0], rule)

    def test_native_schedule_extra_source_narrowing_cannot_confirm(self):
        document = policy()
        document["schedules"] = [{"person": "alice", "id": "night", "weekdays": ["Mon"], "start": "22:00", "stop": "06:30"}]
        self.sync(document)
        state = self.fixture.backend()
        for family in ("iptables", "ip6tables"):
            for row in state["tables"][family]["filter"]["zone_lan_forward"]:
                row[0:0] = ["-s", "192.0.2.222" if family == "iptables" else "2001:db8:ffff::222"]
        self.fixture.update_backend(tables=state["tables"])
        status = json.loads(self.fixture.run("status", "--json").stdout)
        self.assertIs(status["ok"], False)
        self.assertIs(status["capabilities"]["nativeKernelConfirmed"], False)

    def test_expired_kid_lease_cannot_flush_current_protected_adult(self):
        self.sync()
        leases = self.fixture.root / "tmp/dhcp.leases"
        leases.write_text(leases.read_text() + f"{int(self.fixture.env['CF_NOW']) - 1} {KID} 192.168.1.10 expired-kid *\n")
        result = self.fixture.run("pause", "alice")
        status = json.loads(result.stdout)
        if result.returncode == 0:
            self.assertIs(status["ok"], True)
        else:
            self.assertIs(status["ok"], False)
        calls = [call["argv"] for call in self.fixture.calls() if call["command"] == "conntrack"]
        self.assertFalse(any("192.168.1.10" in args for args in calls), calls)
        self.assertFalse(any("2001:db8::10" in args for args in calls), calls)

    def test_sync_open_stdin_cannot_lock_out_local_expiry(self):
        document = policy()
        initial = int(self.fixture.env["CF_NOW"])
        document["pauses"] = [{"person": "alice", "until": initial + 30}]
        self.sync(document)
        self.fixture.env["CF_NOW"] = str(initial + 31)
        desired = policy(2)
        desired["pauses"] = [{"person": "alice", "until": 0}]
        process = subprocess.Popen(self.fixture.shell + [str(REPO / "router/cfctl"), "sync"],
                                   env=self.fixture.env, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, start_new_session=True)
        expiry_process = None
        try:
            payload = json.dumps(desired)
            process.stdin.write(payload)
            process.stdin.flush()  # Intentionally keep a complete JSON document's stream open.
            # Synchronize on the reader consuming this document, rather than
            # guessing how long shell startup takes on a shared CI runner.
            input_file = self.fixture.root / "tmp" / f"couvrefeu-input.{process.pid}" / "input"
            deadline = time.monotonic() + 20
            while not input_file.exists() or input_file.stat().st_size != len(payload.encode()):
                self.assertIsNone(process.poll(), "open stdin sync exited before reader readiness")
                self.assertLess(time.monotonic(), deadline, "bounded stdin reader never became ready")
                time.sleep(0.01)
            self.assertFalse((self.fixture.root / "etc/couvrefeu/runtime/lock").exists(),
                             "incomplete input must not acquire the mutation mutex")
            desired_before = (self.fixture.root / "etc/couvrefeu/state").read_bytes()
            expiry_log = self.fixture.root / "expiry-work.jsonl"
            expiry_env = dict(self.fixture.env, CF_BACKEND_LOG=str(expiry_log))
            expiry_started = time.monotonic()
            expiry_process = subprocess.Popen(self.fixture.shell + [str(REPO / "router/cfctl"), "expire"],
                                              env=expiry_env, text=True, stdout=subprocess.PIPE,
                                              stderr=subprocess.PIPE, start_new_session=True)
            deadline = time.monotonic() + 20
            while not expiry_log.exists() or expiry_log.stat().st_size == 0:
                self.assertIsNone(process.poll(), "sync deadline elapsed before concurrent expiry began work")
                self.assertTrue(input_file.exists(), "expiry waited for the blocked reader to finish")
                self.assertIsNone(expiry_process.poll(), "expiry refused instead of beginning backend work")
                self.assertLess(time.monotonic(), deadline, "expiry never began backend work")
                time.sleep(0.01)
            self.assertIsNone(process.poll(), "expiry work began only after sync terminated")
            self.assertTrue(input_file.exists(), "expiry work must overlap the blocked stdin reader")
            # Reader admission/deadline stays independent of the expensive
            # mocked backend reconciliation, which uses the usual 60s budget.
            process.wait(timeout=18)
            self.assertNotEqual(process.returncode, 0, "unterminated sync stream was accepted")
            stdout, stderr = expiry_process.communicate(timeout=max(0.001, expiry_started + 60 - time.monotonic()))
            expired = self.success(subprocess.CompletedProcess(expiry_process.args, expiry_process.returncode,
                                                              stdout, stderr))
            self.assertEqual(expired["desiredRevision"], 1)
            self.assertEqual(expired["observed"]["paused"], [])
            self.assertEqual((self.fixture.root / "etc/couvrefeu/state").read_bytes(), desired_before)
            status = self.success(self.fixture.run("status", "--json"))
            self.assertEqual(status["desiredRevision"], 1)
        finally:
            if expiry_process is not None:
                if expiry_process.poll() is None:
                    os.killpg(expiry_process.pid, signal.SIGKILL)
                    expiry_process.wait(timeout=5)
                expiry_process.stdout.close()
                expiry_process.stderr.close()
            process.stdin.close()
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
            process.stdout.close()
            process.stderr.close()

    def test_persisted_recovery_phase_blocks_enforcement_recreation(self):
        self.sync()
        for relative in ("etc/couvrefeu/backup/kernel-cleaned", "etc/couvrefeu/backup/restoring",
                         ".couvrefeu-recovery", ".couvrefeu-recovery.done"):
            with self.subTest(marker=relative):
                marker = self.fixture.root / relative
                marker.parent.mkdir(parents=True, exist_ok=True)
                if relative.startswith("etc/couvrefeu/backup/"):
                    marker.parent.chmod(0o700)
                marker.touch()
                marker.chmod(0o600)
                before = len(self.fixture.mutation_calls())
                for command in ("expire", "apply-fw", "sync"):
                    result = self.fixture.run(command, document=policy(2) if command == "sync" else None)
                    self.assertNotEqual(result.returncode, 0, f"{command} bypassed persisted recovery gate {relative}")
                    self.assertEqual(len(self.fixture.mutation_calls()), before, result.stdout)
                marker.unlink()

    def test_early_schedule_covers_inbound_ipv4_ipv6_without_blocking_adults(self):
        document = policy()
        document["schedules"] = [{"person": "alice", "id": "night", "weekdays": ["Mon"], "start": "22:00", "stop": "06:30"}]
        self.sync(document)
        state = self.fixture.backend()
        # A WAN UDP reply has the upstream MAC, so src-MAC-only scheduling cannot match.
        for family, kid, adult in (("iptables", "192.168.1.20", "192.168.1.10"),
                                   ("ip6tables", "2001:db8::20", "2001:db8::10")):
            for destination, should_block in ((kid, True), (adult, False)):
                packet = {"in": "eth0", "out": "br-lan", "src": "2001:db8:ffff::1" if family == "ip6tables" else "198.51.100.1",
                          "dst": destination, "mac": "02:ff:ff:ff:ff:01", "protocol": "udp", "dport": "5000",
                          "weekday": "Mon", "time": "23:00:00", "ctstate": "ESTABLISHED"}
                decision = evaluate_fixture_chain(state["tables"][family]["filter"], "FORWARD", packet, state["sets"])
                with self.subTest(family=family, destination=destination):
                    self.assertEqual(decision in ("DROP", "REJECT"), should_block, decision)

    def stopped_sync(self, checkpoint):
        marker = self.fixture.root / "rpc-stopped"
        marker.unlink(missing_ok=True)
        process = subprocess.Popen(self.fixture.shell + [str(REPO / "router/cfctl"), "sync"],
                                   env=dict(self.fixture.env, CF_TEST_RPC_STOP=checkpoint),
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, start_new_session=True)
        try:
            process.stdin.write(json.dumps(policy()))
            process.stdin.close()
            process.stdin = None
            deadline = time.monotonic() + 60
            while not marker.exists():
                self.assertIsNone(process.poll(), "sync exited before checkpoint")
                self.assertLess(time.monotonic(), deadline, "sync checkpoint not reached")
                time.sleep(0.02)
            return process
        except BaseException:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=10)
            raise

    def test_wholly_absent_interrupted_initial_staging_recovers_old_policy(self):
        state = (self.fixture.root / "etc/couvrefeu/state").read_bytes()
        backend = self.fixture.backend()
        for tables in backend["tables"].values():
            tables.setdefault("mangle", {})
            tables.setdefault("raw", {})
        process = self.stopped_sync("after_initial_intent")
        try:
            runtime = self.fixture.root / "etc/couvrefeu/runtime"
            intent = runtime / "firewall.intent"
            self.assertIn("PHASE staging", intent.read_text())
            self.assertEqual(self.fixture.backend()["sets"], backend["sets"])
            self.assertEqual(self.fixture.backend()["tables"], backend["tables"])
            self.assertEqual(self.fixture.mutation_calls(), [])
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=10)
            self.assertNotEqual(process.returncode, 0)
            recovered = self.success(self.fixture.run("apply-fw"))
            self.assertEqual(recovered["desiredRevision"], 0)
            self.assertEqual((self.fixture.root / "etc/couvrefeu/state").read_bytes(), state)
            self.assertFalse(intent.exists())
            self.assertEqual(recovered["confirmedRevision"], 0)
            self.assertEqual(recovered["observed"]["kids"], [])
            self.assertEqual(recovered["observed"]["paused"], [])
            rebuilt = self.fixture.backend()
            self.assertEqual(set(rebuilt["sets"]),
                             {self.fixture.active_set(suffix) for suffix in ("k", "p", "d4", "d6")})
            self.assertTrue(all(not metadata["members"] for metadata in rebuilt["sets"].values()))
            # Rebuilding empty revision zero may install owned infrastructure.
            # Every preexisting rule remains in order, and new chains are owned.
            for family, tables in backend["tables"].items():
                for table, chains in tables.items():
                    current = rebuilt["tables"][family][table]
                    for chain, rules in chains.items():
                        original = iter(current[chain])
                        for rule in rules:
                            self.assertTrue(any(candidate == rule for candidate in original))
                    self.assertTrue(all(chain.startswith("cf") for chain in current.keys() - chains.keys()))
            # Compare with normal initialization: revision zero installs the
            # owned input defaults as well as empty enforcement infrastructure.
            reference = RouterFixture()
            try:
                self.success(reference.run("apply-fw"))
                for field in ("sets", "tables", "uci"):
                    self.assertEqual(rebuilt[field], reference.backend()[field], field)
                self.assertEqual(rebuilt.get("conntrack_deletions", []),
                                 reference.backend().get("conntrack_deletions", []))
            finally:
                reference.close()
            self.assertGreater(len(self.fixture.mutation_calls()), 0)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate(timeout=10)

    def test_missing_prepared_set_refuses_recovery_and_preserves_journal(self):
        process = self.stopped_sync("transition_staged")
        try:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=10)
            intent = self.fixture.root / "etc/couvrefeu/runtime/firewall.intent"
            before = intent.read_bytes()
            self.assertIn(b"PHASE staged", before)
            slot = next(line.split()[1] for line in before.decode().splitlines() if line.startswith("SLOT "))
            backend = self.fixture.backend()
            backend["sets"].pop("cf2_" + slot + "_k")
            self.fixture.update_backend(sets=backend["sets"])
            mutations = len(self.fixture.mutation_calls())
            result = self.fixture.run("apply-fw")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("transition_object_drift", json.loads(result.stdout)["errors"])
            self.assertEqual(intent.read_bytes(), before)
            self.assertEqual(self.fixture.backend()["sets"], backend["sets"])
            self.assertEqual(self.fixture.backend()["tables"], backend["tables"])
            self.assertEqual(len(self.fixture.mutation_calls()), mutations)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate(timeout=10)

    def test_transition_inventory_parser_refuses_unknown_and_explicit_blank_records(self):
        # Exercise the source-identical parser with controlled snapshot output.
        # Empty inventory is zero records; a real blank/unknown record is drift.
        script = '''
. "$1"
CF_TRANSITION=$CF_TEST_TRANSITION CF_SLOT=a
cf_snapshot() { printf '%s' "$CF_TEST_SNAPSHOT"; }
cf_reference_guard_v2() { :; }
cf_fail() { printf '%s\n' "$1"; }
cf_transition_inventory_check
'''
        record = "RULE 4 filter cf2_a_f -N cf2_a_f"
        transition = "PHASE staging\nAFTER " + record
        for snapshot, valid in (("", True), (record, True), ("\n" + record, False), ("UNKNOWN owned\n" + record, False)):
            with self.subTest(snapshot=repr(snapshot)):
                result = subprocess.run(self.fixture.shell + ["-c", script, "fixture", str(REPO / "router/lib/firewall.sh")],
                                        env=dict(self.fixture.env, CF_TEST_SNAPSHOT=snapshot, CF_TEST_TRANSITION=transition), capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, valid, result.stdout + result.stderr)
                if not valid:
                    self.assertIn("transition_object_drift", result.stdout)

    def test_alive_lock_refuses_concurrent_mutation_then_interruption_recovers(self):
        self.fixture.update_backend(delays=[{"command": "ipset", "contains": ["create"], "seconds": 10}])
        process = subprocess.Popen(self.fixture.shell + [str(REPO / "router/cfctl"), "sync"],
                                   env=self.fixture.env, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, start_new_session=True)
        try:
            process.stdin.write(json.dumps(policy()))
            process.stdin.close()
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if any(call["command"] == "ipset" and "create" in call["argv"] for call in self.fixture.calls()):
                    break
                if process.poll() is not None:
                    self.fail("sync exited before reaching delayed apply: " + process.stderr.read())
                time.sleep(0.02)
            else:
                self.fail("sync never reached delayed backend call")
            second = self.fixture.run("expire", timeout=3)
            self.assertNotEqual(second.returncode, 0, "concurrent mutation ignored live owner lock")
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=5)
            self.fixture.update_backend(delays=[])
            status = json.loads(self.fixture.run("status", "--json").stdout)
            self.assertIs(status["ok"], False)
            self.success(self.fixture.run("apply-fw"))
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
            process.stdout.close()
            process.stderr.close()


class FixtureProcessTests(unittest.TestCase):
    def test_timeout_terminates_owned_descendants_and_reaps_owner(self):
        script = """
import os, subprocess, sys, time
child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
from pathlib import Path
Path(sys.argv[1]).write_text(str(child.pid))
print(child.pid, flush=True)
time.sleep(60)
"""
        with tempfile.TemporaryDirectory(prefix='couvre-feu-core-ready-', dir='/tmp') as directory:
            ready = Path(directory) / 'child'
            def started(process, raw):
                deadline = time.monotonic() + 60
                while not ready.exists() or not ready.read_text():
                    self.assertIsNone(process.poll(), 'owner exited before its child was ready')
                    self.assertLess(time.monotonic(), deadline, 'child startup exceeded fixture budget')
                    time.sleep(0.01)
                return raw
            with self.assertRaises(subprocess.TimeoutExpired) as caught:
                run_fixture_process([sys.executable, "-c", script, str(ready)], env=os.environ, timeout=3, started=started)
            self.assertEqual(caught.exception.timeout, 3)
            child_pid = int(ready.read_text())
        status = Path('/proc') / str(child_pid) / 'stat'
        try:
            state = status.read_text().split(')', 1)[1].split()[0]
        except (FileNotFoundError, ProcessLookupError):
            state = None
        self.assertIn(state, (None, 'Z'), 'the timed-out descendant must be terminated before fixture cleanup')


class AcceptanceScopeTests(unittest.TestCase):
    def run_acceptance(self, *args, **extra):
        environment = dict(os.environ)
        environment.pop("CF_ACCEPT_LIVE", None)
        environment.pop("TEST_MAC", None)
        environment.update(extra)
        return subprocess.run(["sh", str(REPO / "tests/acceptance.sh"), *args],
                              env=environment, capture_output=True, text=True)

    def test_default_only_lists_pending_gates(self):
        result = self.run_acceptance()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("read-only local preflight", result.stdout)
        self.assertIn("Mock results cannot satisfy", result.stdout)

    def test_live_scope_refuses_missing_or_protected_mac(self):
        with tempfile.NamedTemporaryFile(mode="w") as protected:
            protected.write(PROTECTED + "\n")
            protected.flush()
            for mac in ("", PROTECTED, "01:00:00:00:00:01", "00:00:00:00:00:00", KID + ";id"):
                with self.subTest(mac=mac):
                    result = self.run_acceptance("--live", CF_ACCEPT_LIVE="1", TEST_MAC=mac,
                                                 PROTECTED_MAC_FILE=protected.name)
                    self.assertEqual(result.returncode, 2)

    def test_environment_scope_never_authorizes_live_execution(self):
        with tempfile.NamedTemporaryFile(mode="w") as protected:
            protected.write(PROTECTED + "\n")
            protected.flush()
            result = self.run_acceptance("--live", CF_ACCEPT_LIVE="1", TEST_MAC=KID,
                                         PROTECTED_MAC_FILE=protected.name)
        self.assertEqual(result.returncode, 3)
        self.assertIn("not authorization", result.stderr)
        self.assertIn("No live actions are implemented", result.stderr)

    def test_live_scope_requires_runtime_protected_list(self):
        result = self.run_acceptance("--live", CF_ACCEPT_LIVE="1", TEST_MAC=KID)
        self.assertEqual(result.returncode, 2)
        self.assertIn("PROTECTED_MAC_FILE", result.stderr)


class RestrictedCommandTests(unittest.TestCase):
    def setUp(self):
        self.fixture = RouterFixture()
        self.wrapper_log = self.fixture.root / "wrapper.json"
        fake = self.fixture.bin / "cfctl"
        # The fixture cfctl records the allowlisted argv and cleared environment.
        fake.write_text("#!" + sys.executable + "\nimport json,os,sys\n"
                        + "open(" + repr(str(self.wrapper_log)) + ",'w').write(json.dumps({"
                        + "'argv':sys.argv[1:],'cf':{k:v for k,v in os.environ.items() if k.startswith('CF_')}}))\n"
                        + "print('{\"ok\":true}')\n")
        fake.chmod(0o700)

    def tearDown(self):
        self.fixture.close()

    def run_wrapper(self, command):
        environment = dict(self.fixture.env, SSH_ORIGINAL_COMMAND=command, CF_SNEAK="injected")
        environment["CF_BAD-NAME"] = "injected"
        return subprocess.run(self.fixture.shell + [str(REPO / "router/cfctl-ssh")],
                              env=environment, text=True, capture_output=True, timeout=5)

    def test_allowlisted_commands_and_environment_clearing(self):
        for command, expected in (("cfctl status --json", ["status", "--json"]),
                                  ("cfctl sync", ["sync"]),
                                  ("cfctl pause alice", ["pause", "alice"]),
                                  ("cfctl pause alice --until 1736204500", ["pause", "alice", "--until", "1736204500"]),
                                  ("cfctl resume alice", ["resume", "alice"]),
                                  ("cfctl expire", ["expire"]),
                                  ("cfctl apply-fw", ["apply-fw"])):
            with self.subTest(command=command):
                result = self.run_wrapper(command)
                self.assertEqual(result.returncode, 0, result.stderr)
                record = json.loads(self.wrapper_log.read_text())
                self.assertEqual(record["argv"], expected)
                self.assertEqual(record["cf"], {})

    def test_shell_syntax_extra_options_and_internal_commands_refused(self):
        for command in ("", "sh", "cfctl status", "cfctl status --json; id",
                        "cfctl pause alice$(id)", "cfctl pause 'alice'", "cfctl pause alice\n",
                        "cfctl pause alice --until -1", "cfctl pause alice --until 01",
                        "cfctl pause alice --until 2147483648", "cfctl sync extra",
                        "cfctl remove-fw", "cfctl check", "cfctl bonus alice 60",
                        "cfctl status --json --root /tmp", "cfctl resume ../../root"):
            with self.subTest(command=command):
                self.assertNotEqual(self.run_wrapper(command).returncode, 0)
                self.assertFalse(self.wrapper_log.exists())


class InstalledPackageTests(unittest.TestCase):
    def fresh_fixture(self):
        fixture = RouterFixture()
        self.addCleanup(fixture.close)
        private = fixture.root / "etc/couvrefeu"
        (private / "state").unlink()
        (private / "protected").unlink()
        private.rmdir()
        fixture.env["CF_TEST_INSTALL_KERNEL"] = "1"
        return fixture

    def package_command(self, fixture, name, *args):
        # Match the existing private-backend fixture budget and owned cleanup.
        # Router input/SSH deadlines and explicit interruption bounds stay fixed.
        return run_fixture_process(fixture.shell + [str(REPO / "router" / name), *args],
                                   env=fixture.env, timeout=60)

    def assert_restored(self, fixture, original):
        firewall = fixture.root / "etc/config/firewall"
        self.assertEqual((firewall.read_bytes(), firewall.stat().st_mode & 0o7777), original)
        for relative in ("usr/sbin/cfctl", "usr/sbin/cfctl-ssh", "usr/lib/couvrefeu",
                         "etc/firewall.couvrefeu", "etc/crontabs/root", "etc/sysupgrade.conf", "etc/couvrefeu"):
            self.assertFalse((fixture.root / relative).exists(), relative)

    def test_actual_uninstall_partial_kernel_cleanup_then_retry(self):
        fixture = self.fresh_fixture()
        firewall = fixture.root / "etc/config/firewall"
        original = (firewall.read_bytes(), firewall.stat().st_mode & 0o7777)
        install = self.package_command(fixture, "install.sh", "--activate", "--protect", PROTECTED)
        self.assertEqual(install.returncode, 0, install.stdout + install.stderr)
        fixture.update_backend(failures=[{"command": "iptables", "contains": ["-X", "cf_input"], "remaining": 1}])
        first = self.package_command(fixture, "uninstall.sh")
        self.assertNotEqual(first.returncode, 0, first.stdout)
        partial = fixture.backend()["tables"]["iptables"]["filter"]
        self.assertNotIn("cf_fwd", partial)
        self.assertIn("cf_input", partial)
        self.assertTrue((fixture.root / "etc/couvrefeu/runtime/firewall.cleanup").is_file())
        self.assertTrue((fixture.root / "usr/sbin/cfctl").is_file())
        second = self.package_command(fixture, "uninstall.sh")
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assert_restored(fixture, original)
        self.assertEqual(fixture.backend()["sets"], {})

    def test_failed_activation_without_owned_mutation_restores_and_preserves_foreign_chain(self):
        fixture = self.fresh_fixture()
        firewall = fixture.root / "etc/config/firewall"
        original = (firewall.read_bytes(), firewall.stat().st_mode & 0o7777)
        state = fixture.backend()
        foreign = [["-j", "ACCEPT"]]
        state["tables"]["iptables"]["filter"]["cf_fwd"] = foreign
        fixture.update_backend(tables=state["tables"])
        install = self.package_command(fixture, "install.sh", "--activate", "--protect", PROTECTED)
        self.assertNotEqual(install.returncode, 0, install.stdout)
        self.assertEqual(fixture.mutation_calls(), [], "preflight refusal must precede all owned kernel mutations")
        self.assertTrue((fixture.root / "etc/couvrefeu/runtime/firewall.preflight").is_file())
        before = fixture.backend()
        uninstall = self.package_command(fixture, "uninstall.sh")
        self.assertEqual(uninstall.returncode, 0, uninstall.stdout + uninstall.stderr)
        self.assert_restored(fixture, original)
        self.assertEqual(fixture.backend()["tables"]["iptables"]["filter"]["cf_fwd"], foreign)
        self.assertEqual(fixture.backend()["tables"], before["tables"])
        self.assertEqual(fixture.backend()["sets"], before["sets"])
        self.assertEqual(fixture.mutation_calls(), [], "verified preflight-only recovery must not reload foreign objects")

    def test_failed_activation_preflight_baseline_drift_preserves_journal_until_exact_retry(self):
        fixture = self.fresh_fixture()
        firewall = fixture.root / "etc/config/firewall"
        original = (firewall.read_bytes(), firewall.stat().st_mode & 0o7777)
        state = fixture.backend()
        state["tables"]["iptables"]["filter"]["cf_fwd"] = [["-j", "ACCEPT"]]
        fixture.update_backend(tables=state["tables"])
        install = self.package_command(fixture, "install.sh", "--activate", "--protect", PROTECTED)
        self.assertNotEqual(install.returncode, 0)
        baseline = fixture.backend()
        drift = fixture.backend()
        drift["tables"]["ip6tables"]["filter"]["foreign"] = [["-j", "DROP"]]
        fixture.update_backend(tables=drift["tables"])
        first = self.package_command(fixture, "uninstall.sh")
        self.assertNotEqual(first.returncode, 0)
        self.assertTrue((fixture.root / "usr/sbin/cfctl").exists())
        self.assertTrue((fixture.root / "etc/couvrefeu/runtime/firewall.preflight").exists())
        self.assertFalse((fixture.root / "etc/couvrefeu/backup/kernel-cleaned").exists())
        self.assertEqual(fixture.backend()["tables"], drift["tables"])
        self.assertEqual(fixture.mutation_calls(), [])
        fixture.update_backend(tables=baseline["tables"])
        retry = self.package_command(fixture, "uninstall.sh")
        self.assertEqual(retry.returncode, 0, retry.stdout + retry.stderr)
        self.assert_restored(fixture, original)
        self.assertEqual(fixture.backend()["tables"], baseline["tables"])
        self.assertEqual(fixture.mutation_calls(), [])

    def test_preflight_only_uninstall_retains_proof_across_sync_failure_and_process_kill(self):
        for interruption in ("sync", "kill"):
            with self.subTest(interruption=interruption):
                fixture = self.fresh_fixture()
                firewall = fixture.root / "etc/config/firewall"
                original = (firewall.read_bytes(), firewall.stat().st_mode & 0o7777)
                state = fixture.backend()
                state["tables"]["iptables"]["filter"]["cf_fwd"] = [["-j", "ACCEPT"]]
                fixture.update_backend(tables=state["tables"])
                install = self.package_command(fixture, "install.sh", "--activate", "--protect", PROTECTED)
                self.assertNotEqual(install.returncode, 0)
                proof = fixture.root / "etc/couvrefeu/runtime/firewall.preflight"
                proof_bytes = proof.read_bytes()
                baseline = fixture.backend()
                if interruption == "sync":
                    fixture.update_backend(failures=[{"command": "sync", "remaining": 1}])
                    first = self.package_command(fixture, "uninstall.sh")
                    self.assertNotEqual(first.returncode, 0)
                else:
                    # In a sourced ash subshell $$ names the outer installer.
                    # Stop the real backend after its successful durability barrier,
                    # before returning to core or acknowledging zero-owned proof.
                    marker = fixture.root / "zero-owned-sync-ready.json"
                    wrapper = fixture.bin / "sync"
                    wrapper.write_text(f'''#!{sys.executable}
import json, os, runpy, signal, sys
from pathlib import Path
backend = {str(REPO / "tests/fixtures/backend.py")!r}
sys.argv = [backend, "sync", *sys.argv[1:]]
status = runpy.run_path(backend)["main"]()
if status:
    raise SystemExit(status)
root = Path(os.environ["CF_ROOT"])
private = root / "etc/couvrefeu"
assert (private / "runtime/firewall.preflight").is_file()
assert not (private / "runtime/firewall.owned").exists()
assert not (private / "backup/kernel-cleaned").exists()
assert not (private / "backup/no-kernel-mutations").exists()
owner = int((private / "runtime/lock/pid").read_text())
def identity(pid):
    fields = (Path("/proc") / str(pid) / "stat").read_text().split(")", 1)[1].split()
    return {{"pid": pid, "ppid": int(fields[1]), "group": int(fields[2]), "start": int(fields[19])}}
chain = []
pid = os.getpid()
for _ in range(8):
    record = identity(pid)
    chain.append(record)
    if pid == owner:
        break
    pid = record["ppid"]
else:
    raise AssertionError("backend does not descend from runtime owner")
assert len(chain) >= 3
fd = os.open({str(marker) + '.next'!r}, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w") as stream:
    json.dump({{"owner": owner, "chain": chain}}, stream)
os.rename({str(marker) + '.next'!r}, {str(marker)!r})
os.kill(os.getpid(), signal.SIGSTOP)
''')
                    wrapper.chmod(0o700)

                    def identity(pid):
                        fields = (Path("/proc") / str(pid) / "stat").read_text().split(")", 1)[1].split()
                        return {"pid": pid, "ppid": int(fields[1]), "group": int(fields[2]),
                                "start": int(fields[19]), "state": fields[0]}

                    def interrupt_core(process, raw):
                        deadline = time.monotonic() + 60
                        checkpoint = None
                        while time.monotonic() < deadline:
                            if marker.exists():
                                checkpoint = json.loads(marker.read_text())
                                if identity(checkpoint["chain"][0]["pid"])["state"] == "T":
                                    break
                            self.assertIsNone(process.poll(), "uninstall exited before zero-owned sync")
                            time.sleep(0.02)
                        else:
                            self.fail("zero-owned sync checkpoint was not reached")
                        chain = checkpoint["chain"]
                        self.assertGreaterEqual(len(chain), 3)
                        self.assertEqual(checkpoint["owner"], process.pid)
                        self.assertEqual(chain[-1]["pid"], process.pid)
                        self.assertEqual(int((fixture.root / "etc/couvrefeu/runtime/lock/pid").read_text()), process.pid)
                        for index, record in enumerate(chain):
                            observed = identity(record["pid"])
                            self.assertEqual({key: observed[key] for key in record}, record)
                            self.assertEqual(record["group"], process.pid)
                            if index + 1 < len(chain):
                                self.assertEqual(record["ppid"], chain[index + 1]["pid"])
                        self.assertEqual(proof.read_bytes(), proof_bytes)
                        self.assertGreater(fixture.backend()["durability_barriers"], baseline["durability_barriers"])
                        self.assertFalse((fixture.root / "etc/couvrefeu/backup/kernel-cleaned").exists())
                        self.assertFalse((fixture.root / "etc/couvrefeu/backup/no-kernel-mutations").exists())
                        self.assertEqual(fixture.backend()["tables"], baseline["tables"])
                        self.assertEqual(fixture.backend()["sets"], baseline["sets"])
                        self.assertEqual(fixture.mutation_calls(), [])
                        backend_pid, core_pid = chain[0]["pid"], chain[1]["pid"]
                        self.assertNotEqual(core_pid, process.pid)
                        os.kill(core_pid, signal.SIGKILL)
                        # The stopped child cannot change PID/start time while
                        # the killed core unwinds. Revalidate before draining it.
                        self.assertEqual(identity(backend_pid)["start"], chain[0]["start"])
                        os.kill(backend_pid, signal.SIGKILL)
                        return raw

                    first = run_fixture_process(fixture.shell + [str(REPO / "router/uninstall.sh")],
                                                env=fixture.env, timeout=15, started=interrupt_core)
                    self.assertNotEqual(first.returncode, 0, first.stdout + first.stderr)
                    self.assertFalse((fixture.root / ".couvrefeu-install.lock").exists())
                    # Retry uses the ordinary backend; its successful sync must
                    # not encounter this deliberately stopped fixture wrapper.
                    wrapper.write_text("#!/bin/sh\nexec " + repr(sys.executable) + " "
                                       + repr(str(REPO / "tests/fixtures/backend.py")) + ' sync "$@"\n')
                    # Existing reconciliation clears the dead core lock, then
                    # the retained installer baseline fences all kernel effects.
                    reconcile = fixture.run("apply-fw")
                    self.assertNotEqual(reconcile.returncode, 0)
                    self.assertIn("preflight_baseline_requires_installer", reconcile.stdout)
                self.assertEqual(proof.read_bytes(), proof_bytes)
                self.assertTrue((fixture.root / "usr/sbin/cfctl").exists())
                self.assertFalse((fixture.root / "etc/couvrefeu/backup/kernel-cleaned").exists())
                self.assertFalse((fixture.root / "etc/couvrefeu/backup/no-kernel-mutations").exists())
                self.assertEqual(fixture.backend()["tables"], baseline["tables"])
                self.assertEqual(fixture.backend()["sets"], baseline["sets"])
                self.assertEqual(fixture.mutation_calls(), [])
                retry = self.package_command(fixture, "uninstall.sh")
                self.assertEqual(retry.returncode, 0, retry.stdout + retry.stderr)
                self.assert_restored(fixture, original)
                self.assertEqual(fixture.backend()["tables"], baseline["tables"])
                self.assertEqual(fixture.backend()["sets"], baseline["sets"])
                self.assertEqual(fixture.mutation_calls(), [])

    def test_actual_installed_core_lifecycle_and_exact_recovery(self):
        fixture = RouterFixture()
        try:
            private = fixture.root / "etc/couvrefeu"
            (private / "state").unlink()
            (private / "protected").unlink()
            private.rmdir()
            firewall = fixture.root / "etc/config/firewall"
            original_firewall = (firewall.read_bytes(), firewall.stat().st_mode & 0o7777)
            install = subprocess.run(fixture.shell + [str(REPO / "router/install.sh"),
                                     "--activate", "--protect", PROTECTED],
                                     env=fixture.env, capture_output=True, text=True, timeout=20)
            self.assertEqual(install.returncode, 0, install.stderr + install.stdout)
            installed = fixture.root / "usr/sbin/cfctl"
            self.assertEqual(installed.read_bytes(), (REPO / "router/cfctl").read_bytes())
            for helper in ("core.sh", "firewall.sh", "json.awk", "rules.awk", "install-common.sh"):
                self.assertEqual((fixture.root / "usr/lib/couvrefeu" / helper).read_bytes(),
                                 (REPO / "router/lib" / helper).read_bytes())

            def run_installed(*args, document=None):
                result = run_fixture_process(fixture.shell + [str(installed), *args], env=fixture.env,
                                             raw=json.dumps(document) if document is not None else None)
                self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
                status = json.loads(result.stdout)
                self.assertIs(status["ok"], True, status)
                return status

            run_installed("check")
            empty = run_installed("apply-fw")
            self.assertEqual(empty["desiredRevision"], 0)
            self.assertEqual(empty["observed"]["kids"], [])
            run_installed("sync", document=policy())
            expiry = int(fixture.env["CF_NOW"]) + 30
            paused = run_installed("pause", "alice", "--until", str(expiry))
            self.assertCountEqual(paused["observed"]["paused"], [KID, OTHER_KID])
            fixture.env["CF_NOW"] = str(expiry + 1)
            expired = run_installed("expire")
            self.assertEqual(expired["observed"]["paused"], [])
            fixture.update_backend(failures=[{"command": "iptables", "contains": ["-X", "cf_input"], "remaining": 1}])
            interrupted = subprocess.run(fixture.shell + [str(installed), "remove-fw"],
                                         env=fixture.env, capture_output=True, text=True, timeout=20)
            self.assertNotEqual(interrupted.returncode, 0, "partial cleanup failure was silently accepted")
            partially_removed = fixture.backend()["tables"]["iptables"]["filter"]
            self.assertNotIn("cf_fwd", partially_removed, "failure injection must follow a real earlier deletion")
            self.assertIn("cf_input", partially_removed)
            run_installed("remove-fw")
            self.assertEqual(fixture.backend()["sets"], {})
            uninstall = subprocess.run(fixture.shell + [str(REPO / "router/uninstall.sh")],
                                       env=fixture.env, capture_output=True, text=True, timeout=20)
            self.assertEqual(uninstall.returncode, 0, uninstall.stderr + uninstall.stdout)
            self.assertEqual((firewall.read_bytes(), firewall.stat().st_mode & 0o7777), original_firewall)
            for relative in ("usr/sbin/cfctl", "usr/sbin/cfctl-ssh", "usr/lib/couvrefeu",
                             "etc/firewall.couvrefeu", "etc/crontabs/root", "etc/sysupgrade.conf", "etc/couvrefeu"):
                self.assertFalse((fixture.root / relative).exists(), relative)
        finally:
            fixture.close()


if __name__ == "__main__":
    if not (REPO / "router/cfctl").is_file():
        sys.exit("FAIL: core source missing; fixtures cannot prove unfinished implementation.")
    print("Evidence: mocked subprocess/state behavior; no real OpenWrt packets or live router.")
    unittest.main(verbosity=2)
