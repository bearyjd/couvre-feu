#!/usr/bin/env python3
"""Owned fixture process cleanup; no packet or live-router evidence."""
import os
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent / "fixtures"))
from harness import RouterFixture, policy, run_owned_process
import harness

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("fixture_runner", REPO / "tests/run-fixtures.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def process_state(pid):
    status = Path("/proc") / str(pid) / "stat"
    try:
        return status.read_text().split(")", 1)[1].split()[0]
    except FileNotFoundError:
        return None


class FixtureProcessTests(unittest.TestCase):
    def assert_stopped(self, pid):
        deadline = time.monotonic() + 2
        while process_state(pid) not in (None, "Z") and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertIn(process_state(pid), (None, "Z"), "owned descendant is still running")

    def test_router_timeout_stops_actual_backend_before_fixture_cleanup(self):
        fixture = RouterFixture()
        child_pid = None
        root = fixture.root
        try:
            wrapper = fixture.bin / "sync"
            wrapper.write_text("#!/bin/sh\nprintf '%s\\n' \"$$\" > \"$CF_ROOT/backend-pid\"\nexec "
                               + shlex.quote(sys.executable) + " "
                               + shlex.quote(str(Path(__file__).resolve().parent / "fixtures/backend.py"))
                               + " sync \"$@\"\n")
            fixture.update_backend(delays=[{"command": "sync", "seconds": 60}])
            with self.assertRaises(subprocess.TimeoutExpired):
                fixture.run("sync", document=policy(), timeout=3)
            child_pid = int((root / "backend-pid").read_text())
            self.assertIn(process_state(child_pid), (None, "Z"), "backend can still write during fixture cleanup")
            fixture.close()
            self.assertFalse(root.exists())
            self.assertIn(process_state(child_pid), (None, "Z"))
        finally:
            marker = root / "backend-pid"
            if child_pid is None and marker.exists():
                child_pid = int(marker.read_text())
            if child_pid is not None and process_state(child_pid) not in (None, "Z"):
                os.kill(child_pid, signal.SIGKILL)
            fixture.close()

    def test_router_success_preserves_result_and_confirmation(self):
        fixture = RouterFixture()
        try:
            result = fixture.run("sync", document=policy())
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            status = json.loads(result.stdout)
            self.assertTrue(status["ok"])
            self.assertEqual(status["confirmedRevision"], 1)
        finally:
            fixture.close()

    def test_exited_owner_group_is_terminated_on_success_and_failure(self):
        with tempfile.TemporaryDirectory(prefix="couvre-feu-process-", dir="/tmp") as directory:
            for status in (0, 7):
                with self.subTest(status=status):
                    marker = Path(directory) / "child"
                    command = 'sleep 60 >/dev/null 2>&1 & printf "%s\\n" "$!" > "$CHILD_PID"; printf "trace\\n"; printf "diagnostic\\n" >&2; exit "$EXIT_STATUS"'
                    fixture = RouterFixture()
                    try:
                        result = run_owned_process(fixture.shell + ["-c", command], timeout=3,
                                                   env=dict(fixture.env, CHILD_PID=str(marker), EXIT_STATUS=str(status)),
                                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                        self.assertEqual(result.returncode, status)
                        self.assertEqual(result.stdout, "trace\n")
                        self.assertEqual(result.stderr, "diagnostic\n")
                        self.assert_stopped(int(marker.read_text()))
                    finally:
                        if marker.exists():
                            pid = int(marker.read_text())
                            if process_state(pid) not in (None, "Z"):
                                os.kill(pid, signal.SIGKILL)
                        fixture.close()

    def test_timeout_preserves_output_after_owner_exits(self):
        fixture = RouterFixture()
        try:
            marker = fixture.root / "child"
            command = 'sleep 60 & printf "%s\\n" "$!" > "$CHILD_PID"; printf "trace\\n"; printf "diagnostic\\n" >&2; exit 7'
            with self.assertRaises(subprocess.TimeoutExpired) as caught:
                run_owned_process(fixture.shell + ["-c", command], timeout=3,
                                  env=dict(fixture.env, CHILD_PID=str(marker)),
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(caught.exception.stdout, b"trace\n")
            self.assertEqual(caught.exception.stderr, b"diagnostic\n")
            self.assert_stopped(int(marker.read_text()))
        finally:
            marker = fixture.root / "child"
            if marker.exists() and process_state(int(marker.read_text())) not in (None, "Z"):
                os.kill(int(marker.read_text()), signal.SIGKILL)
            fixture.close()

    def test_lane_interrupt_during_real_spawn_waits_for_owned_cleanup(self):
        fixture = RouterFixture()
        marker = fixture.root / "child"
        owners = []
        real_popen = subprocess.Popen
        previous_handler = signal.signal(signal.SIGTERM, harness._interrupt_lane)
        def delayed_popen(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            owners.append(process.pid)
            deadline = time.monotonic() + 2
            while not marker.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(marker.exists(), "actual child did not fork before interruption")
            os.kill(os.getpid(), signal.SIGTERM)
            time.sleep(0.05)
            return process
        try:
            command = 'sleep 60 & printf "%s\\n" "$!" > "$CHILD_PID"; read payload'
            with patch.object(harness, "_pending_lane_shutdown", False), patch.object(subprocess, "Popen", delayed_popen):
                with self.assertRaises(KeyboardInterrupt):
                    run_owned_process(fixture.shell + ["-c", command], timeout=3,
                                      env=dict(fixture.env, CHILD_PID=str(marker)), stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assert_stopped(owners[0])
            self.assert_stopped(int(marker.read_text()))
        finally:
            signal.signal(signal.SIGTERM, previous_handler)
            for pid in owners:
                try:
                    os.killpg(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            fixture.close()

    def run_timed_lane(self, script, directory):
        repository = Path(directory)
        (repository / "tests").mkdir()
        (repository / "tests/lane.py").write_text(script)
        with patch.object(runner, "REPO", repository):
            result = runner.run_lane(("lane.py", 0, ["case"]), repository, timeout=3)
        self.assertEqual(result[3], 124)
        return result[4].read_text()

    def test_lane_timeout_unwinds_nested_fixture_before_root_cleanup(self):
        with tempfile.TemporaryDirectory(prefix="couvre-feu-lane-", dir="/tmp") as directory:
            root = Path(directory)
            script = f'''
import sys
from pathlib import Path
sys.path.insert(0, {str(REPO / 'tests/fixtures')!r})
from harness import RouterFixture, policy
fixture = RouterFixture()
Path({str(root / 'fixture-root')!r}).write_text(str(fixture.root))
wrapper = fixture.bin / 'sync'
wrapper.write_text('#!/bin/sh\\nprintf "%s\\\\n" "$$" > ' + {shlex.quote(str(root / 'backend-pid'))!r} + '\\nexec ' + {shlex.quote(sys.executable)!r} + ' ' + {shlex.quote(str(REPO / 'tests/fixtures/backend.py'))!r} + ' sync "$@"\\n')
fixture.update_backend(delays=[{{'command': 'sync', 'seconds': 60}}])
print('nested-fixture-trace', flush=True)
try:
    fixture.run('sync', document=policy())
finally:
    fixture.close()
    Path({str(root / 'cleanup')!r}).write_text('done')
'''
            try:
                log = self.run_timed_lane(script, directory)
                self.assertIn("nested-fixture-trace", log)
                self.assertIn("KeyboardInterrupt", log)
                self.assertTrue((root / "cleanup").exists())
                self.assertFalse(Path((root / "fixture-root").read_text()).exists())
                self.assert_stopped(int((root / "backend-pid").read_text()))
            finally:
                marker = root / "backend-pid"
                if marker.exists() and process_state(int(marker.read_text())) not in (None, "Z"):
                    os.kill(int(marker.read_text()), signal.SIGKILL)

    def test_lane_timeout_unwinds_manual_session_with_open_stdin(self):
        with tempfile.TemporaryDirectory(prefix="couvre-feu-lane-", dir="/tmp") as directory:
            root = Path(directory)
            script = f'''
import os, signal, subprocess, sys, time
from pathlib import Path
sys.path.insert(0, {str(REPO / 'tests/fixtures')!r})
from harness import RouterFixture
fixture = RouterFixture()
command = 'sleep 60 & printf "%s\\\\n" "$!" > "$CHILD_PID"; read payload'
child = subprocess.Popen(fixture.shell + ['-c', command], env=dict(fixture.env, CHILD_PID={str(root / 'child-pid')!r}), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
Path({str(root / 'owner-pid')!r}).write_text(str(child.pid))
try:
    while not Path({str(root / 'child-pid')!r}).exists():
        time.sleep(0.01)
    print('manual-open-stdin', flush=True)
    time.sleep(60)
finally:
    os.killpg(child.pid, signal.SIGKILL)
    child.communicate(timeout=5)
    fixture.close()
    Path({str(root / 'cleanup')!r}).write_text('done')
'''
            try:
                log = self.run_timed_lane(script, directory)
                self.assertIn("manual-open-stdin", log)
                self.assertTrue((root / "cleanup").exists())
                self.assert_stopped(int((root / "owner-pid").read_text()))
                self.assert_stopped(int((root / "child-pid").read_text()))
            finally:
                marker = root / "owner-pid"
                if marker.exists():
                    try:
                        os.killpg(int(marker.read_text()), signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_runner_preserves_all_cases_and_success_failure_outcomes(self):
        for fail in (False, True):
            with self.subTest(fail=fail), tempfile.TemporaryDirectory(prefix="couvre-feu-runner-", dir="/tmp") as directory:
                root = Path(directory)
                (root / "tests").mkdir()
                for filename in ("test-transition.py", "test-rpc.py", "test-core.py", "test-fixture-process.py"):
                    body = "import unittest\nfrom pathlib import Path\nclass Cases(unittest.TestCase):\n"
                    for index in range(4):
                        body += f"    def test_{index}(self):\n        with Path({str(root / 'executed')!r}).open('a') as stream: stream.write({(filename + ':' + str(index) + chr(10))!r})\n"
                        body += f"        self.assertFalse({fail and filename == 'test-core.py' and index == 0!r})\n"
                    body += "if __name__ == '__main__': unittest.main()\n"
                    (root / "tests" / filename).write_text(body)
                logs = root / "logs"
                def make_logs(**kwargs):
                    logs.mkdir()
                    return str(logs)
                output = io.StringIO()
                with patch.object(runner, "REPO", root), patch.object(runner.tempfile, "mkdtemp", make_logs), contextlib.redirect_stdout(output):
                    self.assertEqual(runner.main(), 1 if fail else 0)
                self.assertEqual(len((root / "executed").read_text().splitlines()), 16)
                self.assertEqual(len(set((root / "executed").read_text().splitlines())), 16)
                self.assertEqual(logs.exists(), fail)
                if fail:
                    self.assertIn("FAIL: test-core.py", output.getvalue())
                    self.assertIn("Private fixture failure logs retained:", output.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
