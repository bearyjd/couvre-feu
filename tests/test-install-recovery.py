#!/usr/bin/env python3
"""Public administrator recovery regressions in private filesystem fixtures.

Successful recovery always proceeds through the ordinary uninstall. These tests
never repair a fixture by deleting a lock, and establish no packet/live evidence.
"""
import importlib.util
import contextlib
import json
import os
from pathlib import Path
import shlex
import shutil
import selectors
import signal
import stat
import subprocess
import sys
import unittest


REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("install_fixture_support", REPO / "tests/test-install.py")
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)
from harness import KID, PROTECTED, RouterFixture
primitive_spec = importlib.util.spec_from_file_location(
    "recovery_primitive_support", REPO / "tests/test-install-recovery-primitives.py")
primitives = importlib.util.module_from_spec(primitive_spec)
primitive_spec.loader.exec_module(primitives)


class InstallRecoveryTests(unittest.TestCase):
    # Reuse only fixture helpers, never inherit the existing test collection.
    tearDown = support.InstallerTests.tearDown
    write_originals = support.InstallerTests.write_originals
    originals_state = support.InstallerTests.originals_state
    install = support.InstallerTests.install
    stop_worker = primitives.InstallRecoveryPrimitiveTests.stop_worker
    reap_worker = primitives.InstallRecoveryPrimitiveTests.reap_worker

    @classmethod
    def setUpClass(cls):
        primitives.InstallRecoveryPrimitiveTests.setUpClass.__func__(cls)

    def setUp(self):
        frozen = support.emitted_router()
        support.InstallerTests.setUp(self)
        # Keep every case on the verified snapshot even if a separate executor
        # continues editing router/ while this suite is running.
        for module in ("platform-bootstrap.sh", "vendor-platform.sh", "install-common.sh"):
            shutil.copy2(frozen / "lib" / module, self.source / "lib" / module)

    def command(self, name, *args):
        return [*shlex.split(os.environ.get("CF_TEST_SHELL", "sh")),
                str(support.emitted_router() / name), *args]

    def run_script(self, name, *args):
        return subprocess.run(self.command(name, *args), env=self.env, capture_output=True,
                              text=True, timeout=30, start_new_session=True)

    @contextlib.contextmanager
    def barrier(self, point):
        paths = [self.root / f".barrier-{point}.{suffix}" for suffix in ("entered", "release")]
        for path in paths:
            os.mkfifo(path, 0o600)
        streams = [os.fdopen(os.open(path, os.O_RDWR | os.O_NONBLOCK), "r+b", buffering=0)
                   for path in paths]
        self.env["CF_TEST_TRANSACTION_BARRIER"] = point
        try:
            yield primitives.Barrier(streams[0]), streams[1]
        finally:
            self.env.pop("CF_TEST_TRANSACTION_BARRIER")
            for stream in streams:
                stream.close()

    @contextlib.contextmanager
    def running(self, name, *args, pass_fds=()):
        process = subprocess.Popen(self.command(name, *args), env=self.env,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True,
                                   pass_fds=pass_fds)
        owner_identity = primitives.proc_identity(process.pid)
        workers = {}
        try:
            yield process, workers
        finally:
            try:
                if process.poll() is None:
                    current = primitives.proc_identity(process.pid)
                    self.assertEqual(current["starttime"], owner_identity["starttime"])
                    self.assertEqual(current["session"], process.pid)
                    for entry in Path("/proc").iterdir():
                        if not entry.name.isdigit() or int(entry.name) == process.pid:
                            continue
                        try:
                            identity = primitives.proc_identity(int(entry.name))
                        except (FileNotFoundError, ProcessLookupError):
                            continue
                        if identity["session"] == process.pid:
                            workers[int(entry.name)] = identity
                for pid, identity in workers.items():
                    self.stop_worker(pid, identity)
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)
                for pid in workers:
                    self.reap_worker(pid)
            finally:
                process.stdout.close()
                process.stderr.close()

    def install_arguments(self):
        return ("--source-dir", str(self.source), "--protect", "02:00:00:00:00:01", "--activate")

    def evidence_snapshot(self):
        result = {}
        for path in sorted(self.root.rglob("*")):
            info = path.lstat()
            rel = str(path.relative_to(self.root))
            if stat.S_ISFIFO(info.st_mode):
                result[rel] = ("fifo", info.st_mode, info.st_uid, info.st_gid, info.st_ino)
            elif path.is_symlink():
                result[rel] = ("symlink", os.readlink(path), info.st_uid, info.st_gid)
            elif path.is_dir():
                result[rel] = ("directory", info.st_mode, info.st_uid, info.st_gid)
            else:
                result[rel] = ("file", path.read_bytes(), support.exact_signature(path), info.st_ino)
        return result

    def recover(self):
        return self.run_script("cfctl", "recover-install-lock")

    def originals_and_directories(self, present=True):
        originals = self.write_originals() if present else self.originals_state()
        directories = {}
        for rel in support.DIRS:
            path = self.root / rel
            if path.exists():
                info = path.stat()
                directories[rel] = (info.st_mode & 0o7777, info.st_uid, info.st_gid)
            else:
                directories[rel] = None
        return originals, directories

    def killed_install(self, point, present=True):
        before = self.originals_and_directories(present)
        if point == "prepared-bound":
            with self.barrier(point) as (entered, _):
                with self.running("install.sh", *self.install_arguments()) as (owner, _):
                    self.assertEqual(int(entered.line()), owner.pid)
                    owner.kill()
                    self.assertEqual(owner.wait(timeout=5), -signal.SIGKILL)
        else:
            self.env["CF_TEST_INSTALL_CRASH_AT"] = point
            try:
                result = self.install("--activate")
            finally:
                self.env.pop("CF_TEST_INSTALL_CRASH_AT")
            self.assertEqual(result.returncode, -signal.SIGKILL, result.stdout + result.stderr)
        self.assertTrue((self.root / ".couvrefeu-transaction").is_file(),
                        "crash must leave new-format provenance")
        return before

    def assert_refused_without_changes(self, operation):
        before = self.evidence_snapshot()
        result = operation()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn('"invalid_command"', result.stdout + result.stderr,
                         "missing public recovery interface is not a safety refusal")
        after = self.evidence_snapshot()
        changed = sorted(path for path in before.keys() | after.keys()
                         if before.get(path) != after.get(path))
        self.assertEqual(changed, [], "refusal changed managed data or recovery evidence")
        return result

    def assert_restored(self, originals, directories):
        self.assertEqual(self.originals_state(), originals)
        for rel, expected in directories.items():
            path = self.root / rel
            if expected is None:
                self.assertFalse(path.exists(), rel)
            else:
                info = path.stat()
                self.assertEqual((info.st_mode & 0o7777, info.st_uid, info.st_gid), expected, rel)
        for rel in support.NEW_FILES:
            if rel not in originals:
                self.assertFalse((self.root / rel).exists(), rel)
        for rel in (".couvrefeu-install.lock", ".couvrefeu-recovery-required",
                    ".couvrefeu-prepared", "etc/couvrefeu/backup",
                    ".couvrefeu-recovery", ".couvrefeu-recovery.done"):
            self.assertFalse((self.root / rel).exists(), rel)
        # A permanent mutex is intentionally retained; never unlink to retry.
        mutex = self.root / ".couvrefeu-mutex"
        self.assertTrue(mutex.is_file())
        self.assertEqual(mutex.stat().st_mode & 0o7777, 0o600)
        self.assertEqual(mutex.stat().st_nlink, 1)

    def recover_and_uninstall(self, before):
        recovered = self.recover()
        self.assertEqual(recovered.returncode, 0, recovered.stdout + recovered.stderr)
        self.uninstall_after_recovery(before)

    def uninstall_after_recovery(self, before):
        self.assertTrue((self.root / ".couvrefeu-recovery-required").is_file())
        self.assert_refused_without_changes(lambda: self.install("--activate"))
        self.assert_refused_without_changes(lambda: self.run_script("cfctl", "apply-fw"))
        removed = self.run_script("uninstall.sh")
        self.assertEqual(removed.returncode, 0, removed.stdout + removed.stderr)
        self.assert_restored(*before)

    def test_fresh_install_creates_and_retains_permanent_mutex(self):
        mutex = self.root / ".couvrefeu-mutex"
        self.assertFalse((self.root / ".couvrefeu-transaction").exists())
        self.assertEqual(mutex.read_bytes(), b"")
        self.assertEqual(mutex.stat().st_nlink, 1)
        mutex.unlink()  # Remove only empty fixture infrastructure, before install.
        before = self.originals_and_directories()
        installed = self.install("--activate")
        self.assertEqual(installed.returncode, 0, installed.stderr)
        info = mutex.stat()
        self.assertEqual((info.st_mode & 0o7777, info.st_nlink, info.st_size), (0o600, 1, 0))
        identity = (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mtime_ns)
        removed = self.run_script("uninstall.sh")
        self.assertEqual(removed.returncode, 0, removed.stdout + removed.stderr)
        self.assert_restored(*before)
        retained = mutex.stat()
        self.assertEqual((retained.st_dev, retained.st_ino, retained.st_uid,
                          retained.st_gid, retained.st_mtime_ns), identity)

    def test_bound_prepared_baseline_restores_without_a_ready_journal(self):
        before = self.killed_install("prepared-bound")
        self.assertEqual(self.originals_state(), before[0])
        self.assertFalse((self.root / "etc/couvrefeu/backup/ready").exists())
        self.recover_and_uninstall(before)

    def test_bound_prepared_baseline_restores_original_absence(self):
        self.recover_and_uninstall(self.killed_install("prepared-bound", present=False))

    def crash_completion(self, point):
        before = self.originals_and_directories()
        installed = self.install("--activate")
        self.assertEqual(installed.returncode, 0, installed.stderr)
        self.env["CF_TEST_UNINSTALL_CRASH_AT"] = point
        try:
            removed = self.run_script("uninstall.sh")
        finally:
            self.env.pop("CF_TEST_UNINSTALL_CRASH_AT")
        self.assertEqual(removed.returncode, -signal.SIGKILL, removed.stderr)
        candidate = self.root / ".couvrefeu-recovery.done.next"
        self.assertEqual(candidate.read_bytes(), b"" if point == "completion-empty" else b"3\n")
        self.assertEqual(self.originals_state(), before[0])
        return before, candidate

    def test_empty_completion_candidate_recovers_after_sigkill(self):
        before, _ = self.crash_completion("completion-empty")
        self.recover_and_uninstall(before)

    def test_partial_completion_candidate_recovers_after_sigkill(self):
        before, _ = self.crash_completion("completion-prefix")
        self.recover_and_uninstall(before)

    def test_foreign_completion_candidate_refuses_before_handover(self):
        _, candidate = self.crash_completion("completion-prefix")
        candidate.write_bytes(b"3\nforeign\n")
        self.assert_refused_without_changes(self.recover)

    def test_hardlinked_completion_candidate_refuses_before_handover(self):
        _, candidate = self.crash_completion("completion-prefix")
        os.link(candidate, self.root / "foreign-completion-alias")
        self.assert_refused_without_changes(self.recover)

    def retained_prepared_after_enospc(self, require_diagnostic=True):
        before = self.originals_and_directories()
        support.InstallerTests.copy_fail_tool(self, "etc_crontabs_root.copy")
        failed = self.install("--activate")
        self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)
        self.assertIn("No space left on device", failed.stderr)
        if require_diagnostic:
            self.assertIn("recovery required", failed.stderr)
        self.assertEqual(self.originals_state(), before[0])
        self.assertTrue((self.root / ".couvrefeu-prepared/manifest").is_file())
        self.assertFalse((self.root / "etc/couvrefeu/backup").exists())
        owner = (self.root / ".couvrefeu-transaction").read_text().splitlines()
        self.assertNotEqual(owner[8], "none")
        (self.root / "bin/cp").unlink()
        return before

    def test_enospc_preserves_bound_baseline_then_ordinary_uninstall_restores(self):
        before = self.retained_prepared_after_enospc()
        removed = self.run_script("uninstall.sh")
        self.assertEqual(removed.returncode, 0, removed.stdout + removed.stderr)
        self.assert_restored(*before)

    def test_retained_prepared_refuses_same_policy_install_without_changes(self):
        self.retained_prepared_after_enospc(require_diagnostic=False)
        self.assert_refused_without_changes(lambda: self.install("--activate"))

    def test_retained_prepared_refuses_requested_rpc_inventory_drift(self):
        self.retained_prepared_after_enospc(require_diagnostic=False)
        self.assert_refused_without_changes(
            lambda: self.install("--activate", "--rpc-allow", "02:00:00:00:00:02"))

    def test_retained_prepared_refuses_requested_protection_drift(self):
        self.retained_prepared_after_enospc(require_diagnostic=False)
        self.assert_refused_without_changes(
            lambda: self.install("--activate", "--protect", "02:00:00:00:00:03"))

    def production_cron_tools(self):
        support.InterruptedRecoveryTests.production_tools(self)
        # Ubus service-list is a read. Keep its diagnostic log outside the
        # modeled filesystem so raw refusal snapshots remain exact.
        ubus = self.root / "bin/ubus"
        private_log = self.cp_log.parent / "cron-service-reads.log"
        ubus.write_text(ubus.read_text().replace('>> "$CF_ROOT/cron-log"',
                                                '>> ' + shlex.quote(str(private_log))))

    def test_intent_crash_with_unchanged_baseline_cron_recovers(self):
        before = self.originals_and_directories()
        self.production_cron_tools()
        baseline = (self.root / "etc/crontabs/root").read_bytes()
        (self.root / "crond-table").write_bytes(baseline)
        self.env["CF_TEST_INSTALL_CRASH_AT"] = "intent"
        try:
            failed = self.install("--activate")
        finally:
            self.env.pop("CF_TEST_INSTALL_CRASH_AT")
        self.assertEqual(failed.returncode, -signal.SIGKILL, failed.stderr)
        self.assertEqual((self.root / "crond-table").read_bytes(), baseline)
        self.recover_and_uninstall(before)
        self.assertEqual((self.root / "crond-table").read_bytes(), baseline)

    def interrupted_cron_reconciliation(self, point, installed=True, candidate=False):
        before = self.originals_and_directories()
        self.production_cron_tools()
        (self.root / "crond-table").write_bytes((self.root / "etc/crontabs/root").read_bytes())
        if not installed:
            self.env["CF_TEST_INSTALL_CRASH_AT"] = "intent"
        try:
            result = self.install("--activate")
        finally:
            self.env.pop("CF_TEST_INSTALL_CRASH_AT", None)
        self.assertEqual(result.returncode, 0 if installed else -signal.SIGKILL, result.stderr)
        if not installed:
            recovered = self.recover()
            self.assertEqual(recovered.returncode, 0, recovered.stderr)
        key = "CF_TEST_INSTALL_CRASH_AT" if candidate else "CF_TEST_UNINSTALL_CRASH_AT"
        self.env[key] = point
        try:
            killed = self.run_script("uninstall.sh")
        finally:
            self.env.pop(key)
        self.assertEqual(killed.returncode, -signal.SIGKILL, killed.stderr)
        journal = self.root / ".couvrefeu-recovery"
        if not candidate:
            record = (journal / "cron-quiescing").read_text().splitlines()
            self.assertEqual(record[0], "CFCRON 2")
            self.assertEqual(record[3], "replace" if installed else "unpublished")
            self.assertEqual(record[4], (self.root / ".couvrefeu-transaction").read_text().splitlines()[5])
        return before, journal

    def test_cron_replace_mode_survives_crash_after_table_restoration(self):
        before, _ = self.interrupted_cron_reconciliation("cron-table-restored")
        self.recover_and_uninstall(before)

    def test_cron_unpublished_mode_survives_crash_before_table_restoration(self):
        before, _ = self.interrupted_cron_reconciliation("cron-quiescing", installed=False)
        self.recover_and_uninstall(before)

    def test_empty_cron_quiescence_candidate_recovers(self):
        before, _ = self.interrupted_cron_reconciliation(
            "marker-empty-cron-quiescing", installed=False, candidate=True)
        self.recover_and_uninstall(before)

    def test_complete_cron_quiescence_candidate_recovers(self):
        before, _ = self.interrupted_cron_reconciliation(
            "marker-cron-quiescing", installed=False, candidate=True)
        self.recover_and_uninstall(before)

    def test_foreign_cron_quiescence_candidate_refuses_without_handover(self):
        _, journal = self.interrupted_cron_reconciliation(
            "marker-empty-cron-quiescing", installed=False, candidate=True)
        pending, = journal.glob("cron-quiescing.pending.*")
        pending.write_bytes(b"foreign candidate\n")
        self.assert_refused_without_changes(self.recover)

    OTHER_BOOT = b"00000000-1111-2222-3333-444444444444"

    def stale_cron_candidate(self, reboot=False, restart=False, keep=None):
        """A complete candidate killed before publication, then the world moved on.

        `reboot` stands the candidate's boot line for a boot that is no longer
        current; `restart` replaces the fixture daemon's loaded table so its
        live identity differs; `keep` truncates the candidate to that prefix.
        """
        before, journal = self.interrupted_cron_reconciliation(
            "marker-cron-quiescing", installed=False, candidate=True)
        pending, = journal.glob("cron-quiescing.pending.*")
        lines = pending.read_bytes().split(b"\n")
        self.assertEqual(lines[0], b"CFCRON 2")
        self.assertEqual(lines[4], pending.name.rsplit(".", 1)[1].encode())
        if reboot:
            self.assertNotEqual(lines[1], self.OTHER_BOOT)
            lines[1] = self.OTHER_BOOT
        data = b"\n".join(lines)
        pending.write_bytes(data if keep is None else data[:keep])
        if restart:
            table = self.root / "crond-table"
            table.write_bytes(table.read_bytes() + b"# restarted daemon\n")
        return before, pending

    def test_unpublished_cron_candidate_after_reboot_recovers(self):
        before, _ = self.stale_cron_candidate(reboot=True)
        self.recover_and_uninstall(before)

    def test_unpublished_cron_candidate_after_daemon_restart_recovers(self):
        before, _ = self.stale_cron_candidate(restart=True)
        self.recover_and_uninstall(before)

    def test_unpublished_cron_candidate_after_reboot_and_restart_recovers(self):
        before, _ = self.stale_cron_candidate(reboot=True, restart=True)
        self.recover_and_uninstall(before)

    def test_truncated_cron_candidates_after_reboot_recover(self):
        # Inside the boot line, inside the daemon line, inside the mode line, inside the token.
        for keep in (12, 46, 50, 120, 150):
            with self.subTest(keep=keep):
                if keep != 12:
                    self.tearDown()
                    self.setUp()
                before, _ = self.stale_cron_candidate(reboot=True, restart=True, keep=keep)
                self.recover_and_uninstall(before)

    def test_cron_candidate_with_foreign_token_refuses_without_handover(self):
        _, pending = self.stale_cron_candidate(reboot=True)
        lines = pending.read_bytes().split(b"\n")
        lines[4] = b"f" * 64
        pending.write_bytes(b"\n".join(lines))
        result = self.assert_refused_without_changes(self.recover)
        self.assertIn("cron quiescence candidate", result.stderr)

    def test_cron_candidate_with_foreign_mode_refuses_without_handover(self):
        _, pending = self.stale_cron_candidate(reboot=True)
        pending.write_bytes(pending.read_bytes().replace(b"\nunpublished\n", b"\nreplace\n"))
        result = self.assert_refused_without_changes(self.recover)
        self.assertIn("cron quiescence candidate", result.stderr)

    def test_cron_candidate_with_malformed_boot_refuses_without_handover(self):
        _, pending = self.stale_cron_candidate()
        lines = pending.read_bytes().split(b"\n")
        lines[1] = b"not-a-boot-identity-zzzzzzzzzzzzzzzz"
        pending.write_bytes(b"\n".join(lines))
        result = self.assert_refused_without_changes(self.recover)
        self.assertIn("cron quiescence candidate", result.stderr)

    def test_malformed_cron_quiescence_mode_refuses_without_handover(self):
        _, journal = self.interrupted_cron_reconciliation("cron-table-restored")
        record = journal / "cron-quiescing"
        record.write_bytes(record.read_bytes().replace(b"\nreplace\n", b"\nforeign\n"))
        self.assert_refused_without_changes(self.recover)

    def test_cron_postpublication_verifier_failure_preserves_provenance(self):
        before = self.originals_and_directories()
        self.production_cron_tools()
        baseline = (self.root / "etc/crontabs/root").read_bytes()
        (self.root / "crond-table").write_bytes(baseline)
        real_stat = shutil.which("stat")
        wrapper = self.root / "bin/stat"
        wrapper.write_text("#!/bin/sh\n"
                           'if [ "$1" = -c ] && [ "$2" = "%Y %y" ] && '
                           '[ "$3" = "$CF_ROOT/etc/couvrefeu/backup/etc_crontabs_root.original" ] && '
                           '[ ! -e "$CF_ROOT/stat-fault-fired" ]; then\n'
                           '    : > "$CF_ROOT/stat-fault-fired"\n'
                           '    cp "$CF_ROOT/etc/crontabs/root" "$CF_ROOT/crond-table" || exit 97\n'
                           '    printf "0 1970-01-01 00:00:00.000000000 +0000\\n"; exit 0\n'
                           'fi\n' + 'exec ' + shlex.quote(real_stat) + ' "$@"\n')
        wrapper.chmod(0o700)
        failed = self.install("--activate")
        self.assertNotEqual(failed.returncode, 0, failed.stderr)
        self.assertTrue((self.root / "stat-fault-fired").exists(), failed.stderr)
        original = self.root / "etc/couvrefeu/backup/etc_crontabs_root.original"
        self.assertTrue(original.is_file(), "successful cron publication must preserve its original")
        self.assertEqual(original.read_bytes(), baseline)
        self.assertNotEqual((self.root / "etc/crontabs/root").read_bytes(), baseline)
        self.assertEqual((self.root / "crond-table").read_bytes(),
                         (self.root / "etc/crontabs/root").read_bytes())
        wrapper.unlink()
        self.recover_and_uninstall(before)

    def test_activation_intent_crash_recovers_then_single_uninstall_restores(self):
        self.recover_and_uninstall(self.killed_install("intent"))

    def test_service_forced_command_cannot_recover_administrator_lock(self):
        before = self.killed_install("linked")
        self.env["CF_SERVICE_FORCED_COMMAND"] = "status"
        try:
            self.assert_refused_without_changes(self.recover)
        finally:
            self.env.pop("CF_SERVICE_FORCED_COMMAND")
        self.recover_and_uninstall(before)

    def legacy_lock(self, pid=None):
        self.write_originals()
        # Preexisting valid permanent inode isolates legacy evidence checks from
        # harmless first-admission mutex creation.
        (self.root / ".couvrefeu-mutex").touch(mode=0o600)
        lock = self.root / ".couvrefeu-install.lock"
        lock.mkdir(mode=0o700)
        if pid is not None:
            (lock / "pid").write_text(f"{pid}\n")
            (lock / "pid").chmod(0o600)
        self.assert_refused_without_changes(self.recover)
        self.assert_refused_without_changes(lambda: self.install("--activate"))
        self.assert_refused_without_changes(lambda: self.run_script("uninstall.sh"))

    def test_legacy_ownerless_lock_preserves_all_evidence(self):
        self.legacy_lock()

    def test_legacy_pid_only_lock_preserves_all_evidence(self):
        self.legacy_lock(os.getpid())

    def orphan_metadata(self, name, operation):
        self.write_originals()
        # The shared fixture normally precreates permanent lock infrastructure.
        # This case deliberately starts with no infrastructure or owner; remove
        # only that empty fixture-created inode before taking the refusal oracle.
        mutex = self.root / ".couvrefeu-mutex"
        self.assertFalse(mutex.is_symlink())
        self.assertEqual(mutex.stat().st_nlink, 1)
        self.assertEqual(mutex.read_bytes(), b"")
        mutex.unlink()
        marker = self.root / name
        marker.write_text("a" * 64 + "\n" if name.endswith("required") else "foreign retirement receipt\n")
        marker.chmod(0o600)
        self.assertFalse((self.root / ".couvrefeu-transaction").exists())
        self.assertFalse((self.root / ".couvrefeu-mutex").exists())
        if operation == "install":
            action = lambda: self.install("--activate")
        elif operation == "uninstall":
            action = lambda: self.run_script("uninstall.sh")
        else:
            action = self.recover
        self.assert_refused_without_changes(action)

    def test_orphan_fence_refuses_install_without_adoption(self):
        self.orphan_metadata(".couvrefeu-recovery-required", "install")

    def test_orphan_fence_refuses_uninstall_without_adoption(self):
        self.orphan_metadata(".couvrefeu-recovery-required", "uninstall")

    def test_orphan_fence_refuses_recovery_without_adoption(self):
        self.orphan_metadata(".couvrefeu-recovery-required", "recover")

    def test_foreign_orphan_receipt_refuses_install_without_adoption(self):
        self.orphan_metadata(".couvrefeu-retirement", "install")

    def test_foreign_orphan_receipt_refuses_uninstall_without_adoption(self):
        self.orphan_metadata(".couvrefeu-retirement", "uninstall")

    def test_foreign_orphan_receipt_refuses_recovery_without_adoption(self):
        self.orphan_metadata(".couvrefeu-retirement", "recover")

    def test_foreign_new_owner_bytes_refuse_without_retiring_evidence(self):
        self.killed_install("linked")
        owner = self.root / ".couvrefeu-transaction"
        owner.write_text("foreign owner record\n")
        self.assert_refused_without_changes(self.recover)

    def test_valid_shape_foreign_token_cannot_retire_new_owner(self):
        self.killed_install("linked")
        token = (self.root / ".couvrefeu-install.lock/token").read_text().strip()
        replacement = ("0" if token[0] != "0" else "1") + token[1:]
        owner = self.root / ".couvrefeu-transaction"
        contents = owner.read_text()
        self.assertEqual(contents.count(token), 1)
        owner.write_text(contents.replace(token, replacement, 1))
        self.assert_refused_without_changes(self.recover)

    def foreign_runtime(self, directory=False):
        self.killed_install("ready")
        runtime = self.root / "etc/couvrefeu/runtime"
        runtime.mkdir(mode=0o700)
        foreign = runtime / "foreign"
        if directory:
            foreign.mkdir(mode=0o700)
        else:
            foreign.write_text("foreign evidence\n")
            foreign.chmod(0o600)
        self.assert_refused_without_changes(self.recover)

    def test_dangling_managed_symlink_refuses_before_handover(self):
        self.killed_install("prepared", present=False)
        target = self.root / "usr/sbin/cfctl"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.symlink_to(self.root / "nonexistent-foreign")
        self.assert_refused_without_changes(self.recover)

    def test_foreign_runtime_file_refuses_before_handover(self):
        self.foreign_runtime()

    def test_foreign_runtime_directory_refuses_before_handover(self):
        self.foreign_runtime(directory=True)

    def foreign_namespace_entry(self, area, name, point="linked"):
        self.killed_install(point)
        if area == "lock":
            directory = self.root / ".couvrefeu-install.lock"
        elif area == "stage":
            token = (self.root / ".couvrefeu-install.lock/token").read_text().strip()
            directory = self.root / f".couvrefeu-stage.{token}"
        else:
            directory = self.root / "etc/couvrefeu/backup"
        self.assertTrue(directory.is_dir())
        entry = directory / name
        entry.write_text("foreign evidence\n")
        entry.chmod(0o600)
        self.assert_refused_without_changes(self.recover)

    def test_hidden_lock_entry_refuses_without_changes(self):
        self.foreign_namespace_entry("lock", ".foreign")

    def test_newline_lock_entry_refuses_without_changes(self):
        self.foreign_namespace_entry("lock", "foreign\nentry")

    def test_hidden_stage_entry_refuses_without_changes(self):
        self.foreign_namespace_entry("stage", ".foreign")

    def test_newline_stage_entry_refuses_without_changes(self):
        self.foreign_namespace_entry("stage", "foreign\nentry")

    def test_hidden_ready_journal_entry_refuses_without_changes(self):
        self.foreign_namespace_entry("journal", ".foreign", point="ready")

    def test_newline_ready_journal_entry_refuses_without_changes(self):
        self.foreign_namespace_entry("journal", "foreign\nentry", point="ready")

    def test_foreign_partial_journal_entry_refuses_before_handover(self):
        self.foreign_namespace_entry("journal", ".foreign")

    def test_hardlinked_new_owner_refuses_without_retiring_evidence(self):
        self.killed_install("linked")
        owner = self.root / ".couvrefeu-transaction"
        os.link(owner, self.root / "foreign-owner-alias")
        self.assert_refused_without_changes(self.recover)

    def test_publicly_readable_owner_refuses_without_changing_evidence(self):
        self.killed_install("linked")
        (self.root / ".couvrefeu-transaction").chmod(0o644)
        self.assert_refused_without_changes(self.recover)

    def test_missing_install_token_recovers_only_under_intact_bound_owner(self):
        before = self.killed_install("linked")
        token = self.root / ".couvrefeu-install.lock/token"
        token.rename(self.root / "original-install-token")
        self.recover_and_uninstall(before)

    def killed_runtime_lock(self, files, point="intent"):
        """Stage the runtime lock a SIGKILL leaves inside cf_lock publication.

        Owned publication is mkdir, token, pid: every prefix of that sequence
        (and of each record's bytes) is a state a kill can leave behind.
        """
        before = self.killed_install(point)
        owner = (self.root / ".couvrefeu-transaction").read_text().splitlines()
        values = {"pid": owner[3] + "\n", "token": owner[5] + "\n"}
        runtime = self.root / "etc/couvrefeu/runtime"
        if not runtime.exists():
            runtime.mkdir(mode=0o700)
        lock = runtime / "lock"
        lock.mkdir(mode=0o700)
        for name, length in files:
            record = lock / name
            data = values.get(name, name)
            record.write_text(data if length is None else data[:length])
            record.chmod(0o600)
        self.assertEqual(sorted(p.name for p in lock.iterdir()), sorted(name for name, _ in files))
        return before

    def test_empty_runtime_lock_after_kill_recovers_then_uninstall_restores(self):
        self.recover_and_uninstall(self.killed_runtime_lock([]))

    def test_empty_token_runtime_lock_after_kill_recovers(self):
        self.recover_and_uninstall(self.killed_runtime_lock([("token", 0)]))

    def test_partial_token_runtime_lock_after_kill_recovers(self):
        self.recover_and_uninstall(self.killed_runtime_lock([("token", 31)]))

    def test_token_only_runtime_lock_after_kill_recovers(self):
        self.recover_and_uninstall(self.killed_runtime_lock([("token", None)]))

    def test_token_and_partial_pid_runtime_lock_after_kill_recovers(self):
        self.recover_and_uninstall(self.killed_runtime_lock([("token", None), ("pid", 0)]))

    def test_owner_pid_only_runtime_lock_after_kill_recovers(self):
        self.recover_and_uninstall(self.killed_runtime_lock([("pid", None)]))

    def test_empty_runtime_lock_after_killed_uninstall_recovers(self):
        before, _ = self.interrupted_cron_reconciliation("cron-quiescing")
        lock = self.root / "etc/couvrefeu/runtime/lock"
        self.assertFalse(lock.exists())
        if not lock.parent.exists():
            lock.parent.mkdir(mode=0o700)  # cf_runtime_prepare precedes the lock mkdir.
        lock.mkdir(mode=0o700)
        self.recover_and_uninstall(before)

    def test_foreign_pid_only_runtime_lock_refuses_without_changes(self):
        self.killed_runtime_lock([])
        pid = self.root / "etc/couvrefeu/runtime/lock/pid"
        pid.write_text(f"{os.getpid()}\n")
        pid.chmod(0o600)
        result = self.assert_refused_without_changes(self.recover)
        self.assertIn("recovery lock owner mismatch", result.stderr)

    def test_foreign_token_runtime_lock_refuses_without_changes(self):
        self.killed_runtime_lock([])
        token = self.root / "etc/couvrefeu/runtime/lock/token"
        token.write_text("f" * 64 + "\n")
        token.chmod(0o600)
        result = self.assert_refused_without_changes(self.recover)
        self.assertIn("recovery lock token mismatch", result.stderr)

    def test_foreign_runtime_lock_entry_refuses_without_changes(self):
        self.killed_runtime_lock([("foreign", None)])
        result = self.assert_refused_without_changes(self.recover)
        self.assertIn("foreign recovery lock entry", result.stderr)

    PROFILE_KEY = "etc_couvrefeu_platform-profile"

    def killed_journal(self, record, empty=None):
        """SIGKILL install right after the pre-ready journal wrote `record`.

        `empty` names the next record, created zero-length as a kill between
        its open/truncate and its first write leaves it.
        """
        before = self.killed_install("journal-" + record)
        backup = self.root / "etc/couvrefeu/backup"
        self.assertTrue(backup.is_dir())
        self.assertFalse((backup / "ready").exists())
        if record != "backup":
            self.assertTrue((backup / record).is_file(), record)
        if empty is not None:
            self.assertFalse((backup / empty).exists(), empty)
            (backup / empty).write_bytes(b"")
            (backup / empty).chmod(0o600)
        return before

    def test_profile_staged_without_after_recovers_then_uninstall_restores(self):
        before = self.killed_journal(self.PROFILE_KEY + ".staged")
        self.assertFalse((self.root / f"etc/couvrefeu/backup/{self.PROFILE_KEY}.after").exists())
        self.recover_and_uninstall(before)

    def test_profile_staged_with_empty_after_recovers(self):
        self.recover_and_uninstall(self.killed_journal(self.PROFILE_KEY + ".staged", self.PROFILE_KEY + ".after"))

    def test_empty_profile_staged_recovers(self):
        self.recover_and_uninstall(self.killed_journal(self.PROFILE_KEY + ".mtime", self.PROFILE_KEY + ".staged"))

    def test_foreign_profile_after_refuses_without_changes(self):
        self.killed_journal(self.PROFILE_KEY + ".after")
        after = self.root / f"etc/couvrefeu/backup/{self.PROFILE_KEY}.after"
        after.write_text("0" * 64 + f":600:{os.getuid()}:{os.getgid()}\n")
        self.assert_refused_without_changes(self.recover)

    def test_pre_ready_staged_profile_conflicting_with_owner_refuses(self):
        self.killed_journal(self.PROFILE_KEY + ".staged")
        owner = (self.root / ".couvrefeu-transaction").read_text().splitlines()
        other = ("gl-xe3000-4.8.3-logd-011-v1" if owner[7] == "strict" else "strict") + "\n"
        (self.root / f"etc/couvrefeu/backup/{self.PROFILE_KEY}.staged").write_text(other)
        self.assert_refused_without_changes(self.recover)

    def materialize_crash(self, point, empty=False):
        before = self.killed_install("prepared")
        self.assertEqual(self.recover().returncode, 0)
        self.env["CF_TEST_UNINSTALL_CRASH_AT"] = point
        try:
            killed = self.run_script("uninstall.sh")
        finally:
            self.env.pop("CF_TEST_UNINSTALL_CRASH_AT")
        self.assertEqual(killed.returncode, -signal.SIGKILL, killed.stdout + killed.stderr)
        backup = self.root / "etc/couvrefeu/backup"
        self.assertFalse((backup / "ready").exists())
        record = backup / (point.split("-", 1)[1].rsplit(".", 1)[0] + ".staged")
        self.assertEqual(record.exists(), point.endswith(".staged"))
        if empty:
            record.write_bytes(b"")
            record.chmod(0o600)
        self.recover_and_uninstall(before)

    def test_kill_after_materialize_clears_profile_staged_recovers(self):
        self.materialize_crash(f"materialize-{self.PROFILE_KEY}.cleared")

    def test_kill_with_empty_materialized_profile_staged_recovers(self):
        self.materialize_crash(f"materialize-{self.PROFILE_KEY}.cleared", empty=True)

    def test_kill_after_materialized_profile_staged_recovers(self):
        self.materialize_crash(f"materialize-{self.PROFILE_KEY}.staged")

    def test_kill_after_first_materialized_staged_recovers(self):
        self.materialize_crash("materialize-usr_lib_couvrefeu_core.sh.staged")

    def test_failed_uninstall_after_materialize_retries_and_restores(self):
        for present in (True, False):
            with self.subTest(present=present):
                if not present:
                    self.tearDown()
                    self.setUp()
                before = self.killed_install("prepared", present=present)
                self.assertEqual(self.recover().returncode, 0)
                self.env["CF_TEST_UNINSTALL_FAIL_AFTER"] = "1"
                try:
                    failed = self.run_script("uninstall.sh")
                finally:
                    self.env.pop("CF_TEST_UNINSTALL_FAIL_AFTER")
                self.assertIn("injected partial restoration", failed.stderr)
                self.assertTrue((self.root / ".couvrefeu-recovery/ready").is_file())
                removed = self.run_script("uninstall.sh")
                self.assertEqual(removed.returncode, 0, removed.stdout + removed.stderr)
                self.assert_restored(*before)

    def test_symlink_new_owner_refuses_without_touching_foreign_target(self):
        self.killed_install("linked")
        owner = self.root / ".couvrefeu-transaction"
        foreign = self.root / "foreign-owner-target"
        owner.rename(foreign)
        owner.symlink_to(foreign)
        self.assert_refused_without_changes(self.recover)

    def test_replaced_mutex_symlink_preserves_original_inode_and_evidence(self):
        self.killed_install("linked")
        mutex = self.root / ".couvrefeu-mutex"
        original = self.root / "original-mutex-inode"
        mutex.rename(original)
        mutex.symlink_to(original)
        self.assert_refused_without_changes(self.recover)

    def test_hardlinked_mutex_preserves_all_recovery_evidence(self):
        self.killed_install("linked")
        os.link(self.root / ".couvrefeu-mutex", self.root / "foreign-mutex-alias")
        self.assert_refused_without_changes(self.recover)

    def test_modified_external_recovery_module_is_never_executed(self):
        self.killed_install("linked")
        external = self.root / "external-recovery-source"
        shutil.copytree(support.emitted_router(), external)
        marker = self.root / "unauthenticated-module-executed"
        core = external / "lib/core.sh"
        core.write_text("printf 'executed\\n' > " + shlex.quote(str(marker)) + "\n" + core.read_text())
        self.assert_refused_without_changes(
            lambda: self.run_script(str(external / "cfctl"), "recover-install-lock"))
        self.assertFalse(marker.exists())

    def test_live_new_owner_refuses_recovery_before_prepared_publication(self):
        before = self.originals_and_directories()
        with self.barrier("ownership-published") as (entered, _):
            with self.running("install.sh", *self.install_arguments()) as (owner, _):
                self.assertEqual(int(entered.line()), owner.pid)
                self.assert_refused_without_changes(self.recover)
                self.assert_refused_without_changes(lambda: self.install("--activate"))
                owner.kill()
                self.assertEqual(owner.wait(timeout=5), -signal.SIGKILL)
        self.recover_and_uninstall(before)

    def test_second_recoverer_cannot_retire_first_recoverers_ownership(self):
        before = self.killed_install("linked")
        with self.barrier("recovery-validated") as (entered, release):
            with self.running("cfctl", "recover-install-lock") as (recoverer, _):
                self.assertEqual(int(entered.line()), recoverer.pid)
                self.assert_refused_without_changes(self.recover)
                release.write(b"continue\n")
                stdout, stderr = recoverer.communicate(timeout=30)
                self.assertEqual(recoverer.returncode, 0, stdout + stderr)
        self.uninstall_after_recovery(before)

    def test_killed_recoverer_before_handover_retries_without_manual_cleanup(self):
        before = self.killed_install("linked")
        with self.barrier("recovery-validated") as (entered, _):
            evidence = self.evidence_snapshot()
            with self.running("cfctl", "recover-install-lock") as (recoverer, _):
                self.assertEqual(int(entered.line()), recoverer.pid)
                recoverer.kill()
                self.assertEqual(recoverer.wait(timeout=5), -signal.SIGKILL)
            self.assertEqual(self.evidence_snapshot(), evidence)
        self.recover_and_uninstall(before)

    def test_replaced_mutex_does_not_admit_recovery_while_owner_survives(self):
        before = self.originals_and_directories()
        with self.barrier("ownership-published") as (entered, _):
            with self.running("install.sh", *self.install_arguments()) as (owner, _):
                self.assertEqual(int(entered.line()), owner.pid)
                mutex = self.root / ".couvrefeu-mutex"
                original = self.root / "original-live-mutex-inode"
                original_inode = mutex.stat().st_ino
                mutex.rename(original)
                mutex.touch(mode=0o600)
                self.assertNotEqual(mutex.stat().st_ino, original_inode)
                self.assert_refused_without_changes(self.recover)
                self.assertEqual(original.stat().st_ino, original_inode)
                owner.kill()
                self.assertEqual(owner.wait(timeout=5), -signal.SIGKILL)
        # The durable owner binds the original inode. Its replacement remains
        # ambiguous after process death; never repair it manually to pass.
        self.assertEqual(self.originals_state(), before[0])
        self.assert_refused_without_changes(self.recover)
        self.assert_refused_without_changes(lambda: self.run_script("uninstall.sh"))

    def test_killed_parent_with_live_copy_worker_refuses_until_worker_drains(self):
        before = self.originals_and_directories()
        entered_read, entered_write = os.pipe()
        release_read, release_write = os.pipe()
        for descriptor in (entered_read, entered_write, release_read, release_write):
            self.addCleanup(os.close, descriptor)
        original_copy = self.root / "bin/copy-original"
        (self.root / "bin/cp").rename(original_copy)
        worker_script = self.root / "held-copy.py"
        worker_script.write_text(
            "import json,os,sys\n"
            "event={'pid':os.getpid(),'session':os.getsid(0),'group':os.getpgrp(),"
            "'mutex_inode':os.fstat(9).st_ino,'destination':sys.argv[-1]}\n"
            "os.write(int(os.environ['CF_COPY_ENTERED']),json.dumps(event).encode()+b'\\n')\n"
            "assert os.read(int(os.environ['CF_COPY_RELEASE']),1)==b'R'\n"
            "os.execv(" + repr(str(original_copy)) + ",['copy-original',*sys.argv[1:]])\n")
        wrapper = self.root / "bin/cp"
        wrapper.write_text("#!/bin/sh\nexec " + shlex.quote(sys.executable) + " -B "
                           + shlex.quote(str(worker_script)) + ' "$@"\n')
        wrapper.chmod(0o700)
        self.env.update(CF_COPY_ENTERED=str(entered_write), CF_COPY_RELEASE=str(release_read))
        stream = os.fdopen(os.dup(entered_read), "rb", buffering=0)
        self.addCleanup(stream.close)
        with self.running("install.sh", *self.install_arguments(),
                          pass_fds=(entered_write, release_read)) as (owner, workers):
            event = json.loads(primitives.Barrier(stream).line())
            worker_pid = event["pid"]
            identity = primitives.proc_identity(worker_pid)
            workers[worker_pid] = identity
            self.assertEqual(event["session"], owner.pid)
            self.assertEqual(event["group"], owner.pid)
            self.assertEqual(event["mutex_inode"], (self.root / ".couvrefeu-mutex").stat().st_ino)
            descriptor = os.pidfd_open(worker_pid)
            try:
                owner.kill()
                self.assertEqual(owner.wait(timeout=5), -signal.SIGKILL)
                self.assertNotIn(primitives.proc_identity(worker_pid)["state"], ("Z", "X"))
                self.assert_refused_without_changes(self.recover)
                os.write(release_write, b"R")
                with selectors.DefaultSelector() as selector:
                    selector.register(descriptor, selectors.EVENT_READ)
                    self.assertTrue(selector.select(10), "copy worker did not drain")
                self.reap_worker(worker_pid)
            finally:
                os.close(descriptor)
        self.env.pop("CF_COPY_ENTERED")
        self.env.pop("CF_COPY_RELEASE")
        wrapper.write_bytes(original_copy.read_bytes())
        self.recover_and_uninstall(before)

    def assert_no_persistent_transaction_state(self, root):
        for pattern in (".couvrefeu-mutex*", ".couvrefeu-transaction*", ".couvrefeu-prepared*",
                        ".couvrefeu-recovery-required*", ".couvrefeu-fence.*", ".couvrefeu-retirement*"):
            self.assertEqual(list(root.glob(pattern)), [], pattern)

    def test_fresh_status_and_rpc_status_create_no_persistent_transaction_state(self):
        for command in (("status", "--json"), ("rpc-status", "--json")):
            with self.subTest(command=command):
                with contextlib.closing(RouterFixture()) as fixture:
                    result = subprocess.run(self.command("cfctl", *command), env=fixture.env,
                                            capture_output=True, text=True, timeout=30,
                                            start_new_session=True)
                    response = json.loads(result.stdout)
                    if command[0] == "status":
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertIsInstance(response["ok"], bool)
                    else:
                        # This fresh fixture has not enrolled an RPC scope.
                        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                        self.assertEqual(response["errors"], ["rpc_disabled"])
                    self.assert_no_persistent_transaction_state(fixture.root)

    def test_caller_transaction_authority_environment_is_refused_even_if_empty(self):
        privileged = (
            "CF_TRANSACTION_BASE", "CF_TRANSACTION_BOOT", "CF_TRANSACTION_DIGEST",
            "CF_TRANSACTION_FENCE", "CF_TRANSACTION_HELD", "CF_TRANSACTION_LAUNCH_PID",
            "CF_TRANSACTION_MUTEX", "CF_TRANSACTION_OWNED", "CF_TRANSACTION_OWNER",
            "CF_TRANSACTION_PARENT", "CF_TRANSACTION_PID", "CF_TRANSACTION_PREPARED",
            "CF_TRANSACTION_RECOVER", "CF_TRANSACTION_RETIREMENT", "CF_TRANSACTION_START", "CF_TRANSACTION_STATE",
            "CF_TRANSACTION_TOKEN",
        )
        with contextlib.closing(RouterFixture()) as fixture:
            baseline = subprocess.run(self.command("cfctl", "status", "--json"), env=fixture.env,
                                      capture_output=True, text=True, timeout=30,
                                      start_new_session=True)
            self.assertEqual(baseline.returncode, 0, baseline.stdout + baseline.stderr)
            self.assert_no_persistent_transaction_state(fixture.root)
            for variable in privileged:
                for value in ("", "1"):
                    with self.subTest(variable=variable, value=value):
                        environment = dict(fixture.env, **{variable: value})
                        result = subprocess.run(self.command("cfctl", "status", "--json"), env=environment,
                                                capture_output=True, text=True, timeout=30,
                                                start_new_session=True)
                        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertNotIn('"invalid_command"', result.stdout + result.stderr)
                        self.assert_no_persistent_transaction_state(fixture.root)

    def fixture_callback(self, fixture):
        entries = [line.split(None, 5)[5]
                   for line in (fixture.root / "etc/crontabs/root").read_text().splitlines()
                   if line.strip() and not line.startswith("#") and "--installation-generation" in line]
        self.assertEqual(len(entries), 1, "exactly one generation-bound cron callback is required")
        command = shlex.split(entries[0], comments=True)
        self.assertEqual(len(command), 4)
        self.assertRegex(command[0], r"^/etc/\.couvrefeu-release-[0-9a-f]{64}/cfctl$")
        self.assertEqual(command[1], "--installation-generation")
        self.assertRegex(command[2], r"^[0-9a-f]{64}$")
        self.assertEqual(command[3], "expire")
        # Never execute host paths from a fixture crontab. Only this explicitly
        # validated immutable callback path is mapped into the private root.
        command[0] = str(fixture.root / command[0].lstrip("/"))
        self.assertTrue(Path(command[0]).is_file())
        return command

    @contextlib.contextmanager
    def paused_job(self, command, environment):
        process = subprocess.Popen(
            [self.busybox, "ash", "-c", 'printf "ready\\n"; read -r go; exec "$@"',
             "fixture-cron-job", *command], env=environment,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            process_group=0)
        workers = {}
        try:
            self.assertEqual(primitives.Barrier(process.stdout).line(), "ready")
            self.assertEqual(os.getpgid(process.pid), process.pid)
            # BusyBox crond creates a process group, without requiring a new SID.
            self.assertEqual(os.getsid(process.pid), os.getsid(0))
            yield process
        finally:
            try:
                if process.poll() is None:
                    for entry in Path("/proc").iterdir():
                        if not entry.name.isdigit() or int(entry.name) == process.pid:
                            continue
                        try:
                            identity = primitives.proc_identity(int(entry.name))
                        except (FileNotFoundError, ProcessLookupError):
                            continue
                        if identity["group"] == process.pid and identity["session"] == os.getsid(0):
                            workers[int(entry.name)] = identity
                    for pid, identity in workers.items():
                        self.stop_worker(pid, identity)
                    process.kill()
                process.wait(timeout=5)
                for pid in workers:
                    self.reap_worker(pid)
            finally:
                for stream in (process.stdin, process.stdout, process.stderr):
                    stream.close()

    def test_late_cron_jobs_cannot_execute_restored_original_or_next_generation(self):
        with contextlib.closing(RouterFixture()) as fixture:
            fixture.env["CF_TEST_RELEASE_DIR"] = "1"
            original = fixture.root / "usr/sbin/cfctl"
            original.parent.mkdir(parents=True, exist_ok=True)
            original.write_text('#!/bin/sh\nprintf "forbidden\\n" > "$CF_ROOT/original-cfctl-executed"\n')
            original.chmod(0o750)
            os.utime(original, ns=(support.FRACTIONAL, support.FRACTIONAL))
            original_signature = support.exact_signature(original)
            marker = fixture.root / "original-cfctl-executed"

            def invoke(name, *args):
                return subprocess.run(self.command(name, *args), env=fixture.env,
                                      capture_output=True, text=True, timeout=90,
                                      start_new_session=True)

            def install_generation():
                result = invoke("install.sh", "--activate", "--protect", PROTECTED,
                                "--rpc-allow", KID)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                return self.fixture_callback(fixture)

            first = install_generation()
            with self.paused_job(first, fixture.env) as after_uninstall:
                with self.paused_job(first, fixture.env) as after_reinstall:
                    removed = invoke("uninstall.sh")
                    self.assertEqual(removed.returncode, 0, removed.stdout + removed.stderr)
                    self.assertEqual(support.exact_signature(original), original_signature)
                    after_uninstall.stdin.write(b"execute\n")
                    after_uninstall.stdin.flush()
                    stdout, stderr = after_uninstall.communicate(timeout=30)
                    self.assertNotEqual(after_uninstall.returncode, 0, stdout + stderr)
                    self.assertFalse(marker.exists(), "late job executed restored vendor binary")

                    second = install_generation()
                    self.assertEqual(second[0], first[0], "exercise same-release path reuse")
                    self.assertNotEqual(second[2], first[2], "installation generation must rotate")
                    # The successful callback performs the full backend proof;
                    # measured fixture cost exceeds 30s. Stale refusals retain 30s.
                    current = subprocess.run(second, env=fixture.env, capture_output=True,
                                             text=True, timeout=90, start_new_session=True)
                    self.assertEqual(current.returncode, 0, current.stdout + current.stderr)
                    durable = fixture.durable_snapshot()
                    mutations = fixture.mutation_calls()
                    owner = fixture.root / ".couvrefeu-transaction"
                    owner_before = (owner.read_bytes(), support.exact_signature(owner))
                    after_reinstall.stdin.write(b"execute\n")
                    after_reinstall.stdin.flush()
                    stdout, stderr = after_reinstall.communicate(timeout=30)
                    self.assertNotEqual(after_reinstall.returncode, 0, stdout + stderr)
                    self.assertNotIn(b'"invalid_command"', stdout + stderr)
                    self.assertFalse(marker.exists())
                    self.assertEqual(fixture.durable_snapshot(), durable)
                    self.assertEqual(fixture.mutation_calls(), mutations)
                    self.assertEqual((owner.read_bytes(), support.exact_signature(owner)), owner_before)
            removed = invoke("uninstall.sh")
            self.assertEqual(removed.returncode, 0, removed.stdout + removed.stderr)
            self.assertEqual(support.exact_signature(original), original_signature)


# Every pre-ready journal record boundary of the platform-profile file, plus the
# representative first/last of each other record class (copies, directories,
# first and last managed file), each killed for real between `mkdir BACKUP` and `linked`.
JOURNAL_KILL_POINTS = (
    "backup",
    "etc_config_firewall.copy", "etc_crontabs_root.copy",
    "dir_etc", "dir_etc_couvrefeu",
    "usr_lib_couvrefeu_core.sh.before", "usr_lib_couvrefeu_core.sh.after",
    InstallRecoveryTests.PROFILE_KEY + ".before", InstallRecoveryTests.PROFILE_KEY + ".mtime",
    InstallRecoveryTests.PROFILE_KEY + ".after",
    "usr_lib_couvrefeu_activity.sh.staged", "usr_lib_couvrefeu_activity.sh.after",
)


def _journal_kill_case(record):
    def test(self):
        self.recover_and_uninstall(self.killed_journal(record))
    return test


for _record in JOURNAL_KILL_POINTS:
    setattr(InstallRecoveryTests, "test_journal_kill_after_" + _record.replace(".", "_").replace("-", "_"),
            _journal_kill_case(_record))


if __name__ == "__main__":
    unittest.main(verbosity=2)
