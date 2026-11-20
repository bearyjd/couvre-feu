#!/usr/bin/env python3
# timeout-ok-file: measured: busybox/lock primitives finish in <0.01 s against 5 s waits (load 3-25)
"""Real BusyBox primitive proofs, using private files and pipe barriers only.

The M4b gate must record a run with BusyBox 1.33.1. These are local kernel and
applet observations, not proof of router, power-loss, or delegated-service drain.
"""
import contextlib
import ctypes
import os
from pathlib import Path
import selectors
import shlex
import shutil
import signal
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch


class Barrier:
    """Bounded, unbuffered reads so one event cannot hide the following event."""

    def __init__(self, stream):
        self.stream = stream
        self.pending = b""

    def line(self):
        deadline = time.monotonic() + 5
        with selectors.DefaultSelector() as selector:
            selector.register(self.stream, selectors.EVENT_READ)
            while b"\n" not in self.pending:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise AssertionError("primitive did not reach its pipe barrier")
                chunk = os.read(self.stream.fileno(), 4096)
                if not chunk:
                    raise AssertionError("primitive exited before its pipe barrier")
                self.pending += chunk
        line, self.pending = self.pending.split(b"\n", 1)
        return line.decode()

    def eof(self):
        if self.pending:
            raise AssertionError("unexpected primitive output before exit")
        with selectors.DefaultSelector() as selector:
            selector.register(self.stream, selectors.EVENT_READ)
            if not selector.select(5):
                raise AssertionError("primitive did not close its output on exit")
            if os.read(self.stream.fileno(), 4096):
                raise AssertionError("unexpected primitive output instead of EOF")


def proc_identity(pid):
    # comm may contain spaces/parentheses. Fields after its final ')' start at 3.
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return {"state": fields[0], "parent": int(fields[1]), "group": int(fields[2]),
            "session": int(fields[3]), "starttime": fields[19]}


class InstallRecoveryPrimitiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Parent-kill proofs deliberately orphan workers. Adopt and reap them
        # here instead of depending on the host/container's PID 1 to do so.
        libc = ctypes.CDLL(None, use_errno=True)
        previous = ctypes.c_int()
        if libc.prctl(37, ctypes.byref(previous), 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "PR_GET_CHILD_SUBREAPER")
        if libc.prctl(36, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "PR_SET_CHILD_SUBREAPER")
        cls.addClassCleanup(libc.prctl, 36, previous.value, 0, 0, 0)
        cls.busybox = os.environ.get("CF_TEST_BUSYBOX") or shutil.which("busybox")
        if not cls.busybox:
            raise AssertionError("real BusyBox is required; primitive proofs cannot skip")
        result = subprocess.run([cls.busybox], capture_output=True, text=True, timeout=5)
        cls.banner = result.stdout.splitlines()[0]
        if not cls.banner.startswith("BusyBox v"):
            raise AssertionError("CF_TEST_BUSYBOX must name a real BusyBox binary")
        print(f"Primitive runtime: {cls.busybox}: {cls.banner}", flush=True)
        cls.bb = shlex.quote(cls.busybox)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cf-primitive-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.mutex = self.root / "mutex"
        self.mutex.touch(mode=0o600)

    def run_bb(self, *args):
        return subprocess.run([self.busybox, *map(str, args)], capture_output=True,
                              text=True, timeout=5)

    def contender(self, path=None):
        return self.run_bb("flock", "-n", path or self.mutex, self.busybox, "true")

    def track_worker(self, owner, pid):
        identity = proc_identity(pid)
        self.assertEqual(identity["session"], owner.pid)
        self.assertEqual(identity["group"], owner.pid)
        owner.primitive_workers[pid] = identity

    def stop_worker(self, pid, identity):
        try:
            descriptor = os.pidfd_open(pid)
        except ProcessLookupError:
            return
        try:
            try:
                current = proc_identity(pid)
            except (FileNotFoundError, ProcessLookupError):
                return
            # Pin before validation, then signal the pinned process. An ash
            # parent may reap a worker between the stat read and this signal.
            for field in ("starttime", "session", "group"):
                self.assertEqual(current[field], identity[field], f"worker {field} changed")
            if current["state"] not in ("Z", "X"):
                try:
                    signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        finally:
            os.close(descriptor)

    def reap_worker(self, pid):
        try:
            result, _ = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return  # Its original ash parent already reaped it.
        if result:
            return
        descriptor = os.pidfd_open(pid)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(descriptor, selectors.EVENT_READ)
                self.assertTrue(selector.select(5), "owned worker did not stop")
            self.assertEqual(os.waitpid(pid, 0)[0], pid)
        finally:
            os.close(descriptor)

    @contextlib.contextmanager
    def owner(self, body, *, session=False, pass_fds=()):
        prefix = f"exec 9<> {shlex.quote(str(self.mutex))}\n{self.bb} flock -n 9 || exit 71\n"
        command = [self.busybox, "ash", "-c", prefix + body]
        if session:
            # Child of this Python process is not its inherited process-group
            # leader. BusyBox setsid must therefore exec without forking.
            command = [self.busybox, "setsid", *command]
        process = subprocess.Popen(command, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   pass_fds=pass_fds)
        process.primitive_workers = {}
        owner_starttime = proc_identity(process.pid)["starttime"]
        try:
            yield process, Barrier(process.stdout)
        finally:
            try:
                # On a failed readiness assertion, also discover children while
                # the unreaped, verified owner still anchors its session.
                if session and process.poll() is None:
                    owner_identity = proc_identity(process.pid)
                    self.assertEqual(owner_identity["starttime"], owner_starttime)
                    if owner_identity["session"] == process.pid:
                        for entry in Path("/proc").iterdir():
                            if entry.name.isdigit() and int(entry.name) != process.pid:
                                try:
                                    identity = proc_identity(int(entry.name))
                                except (FileNotFoundError, ProcessLookupError):
                                    continue
                                if identity["session"] == process.pid:
                                    process.primitive_workers[int(entry.name)] = identity
                for pid, identity in process.primitive_workers.items():
                    self.stop_worker(pid, identity)
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)
                for pid in process.primitive_workers:
                    self.reap_worker(pid)
            finally:
                for stream in (process.stdin, process.stdout, process.stderr):
                    stream.close()

    def test_parent_death_keeps_inherited_lock_until_final_worker_close(self):
        control_read, control_write = os.pipe()
        self.addCleanup(os.close, control_write)
        self.addCleanup(os.close, control_read)
        child = self.root / "worker.sh"
        child.write_text("printf 'worker %s\\n' \"$$\"\n"
                         "read -r action || exit 72\n"
                         "[ \"$action\" = close ] || exit 73\n"
                         "exec 9>&-\n"
                         "printf 'closed\\n'\n"
                         "read -r action || exit 74\n"
                         "[ \"$action\" = exit ]\n")
        body = (f"{self.bb} ash {shlex.quote(str(child))} "
                f"< /proc/self/fd/{control_read} &\n"
                "printf 'owner %s %s\\n' \"$$\" \"$!\"\nwait\n")
        with self.owner(body, session=True, pass_fds=(control_read,)) as (owner, barrier):
            events = [barrier.line().split(), barrier.line().split()]
            owner_event = next(event for event in events if event[0] == "owner")
            worker_event = next(event for event in events if event[0] == "worker")
            worker_pid = int(worker_event[1])
            self.track_worker(owner, worker_pid)
            self.assertEqual(int(owner_event[1]), owner.pid)
            self.assertEqual(int(owner_event[2]), worker_pid)
            for pid in (owner.pid, worker_pid):
                self.assertEqual(proc_identity(pid)["session"], owner.pid)
                self.assertEqual(proc_identity(pid)["group"], owner.pid)
            owner.kill()
            self.assertEqual(owner.wait(timeout=5), -signal.SIGKILL)
            self.assertNotIn(proc_identity(worker_pid)["state"], ("Z", "X"))
            self.assertEqual(self.contender().returncode, 1)
            os.write(control_write, b"close\n")
            self.assertEqual(barrier.line(), "closed")
            # This is a deliberate hazard demonstration. Production workers
            # must retain their inherited FD for their entire mutating lifetime.
            self.assertNotIn(proc_identity(worker_pid)["state"], ("Z", "X"))
            self.assertEqual(self.contender().returncode, 0)
            os.write(control_write, b"exit\n")
            barrier.eof()

    def test_worker_exit_releases_last_inherited_lock_after_parent_death(self):
        control_read, control_write = os.pipe()
        self.addCleanup(os.close, control_write)
        self.addCleanup(os.close, control_read)
        worker = "printf 'worker %s\\n' \"$$\"\nread -r finish\n"
        body = (f"{self.bb} ash -c {shlex.quote(worker)} "
                f"< /proc/self/fd/{control_read} &\nwait\n")
        with self.owner(body, session=True, pass_fds=(control_read,)) as (owner, barrier):
            worker_pid = int(barrier.line().split()[1])
            self.track_worker(owner, worker_pid)
            self.assertEqual(proc_identity(worker_pid)["session"], owner.pid)
            owner.kill()
            self.assertEqual(owner.wait(timeout=5), -signal.SIGKILL)
            self.assertEqual(self.contender().returncode, 1)
            os.write(control_write, b"finish\n")
            barrier.eof()
            self.assertEqual(self.contender().returncode, 0)

    def test_nested_inherited_description_succeeds_but_reopened_inode_conflicts(self):
        nested = (f"{self.bb} flock -n 9 || exit 75\n"
                  f"{self.bb} flock -n {shlex.quote(str(self.mutex))} {self.bb} true\n"
                  "[ \"$?\" = 1 ] || exit 76\nexec 9>&-\n")
        body = (f"{self.bb} ash -c {shlex.quote(nested)} || exit 77\n"
                "printf 'nested-closed\\n'\nread -r finish\n")
        with self.owner(body) as (owner, barrier):
            self.assertEqual(barrier.line(), "nested-closed")
            self.assertEqual(self.contender().returncode, 1)
            owner.stdin.write(b"finish\n")
            owner.stdin.flush()
            self.assertEqual(owner.wait(timeout=5), 0)
        self.assertEqual(self.contender().returncode, 0)

    def test_explicit_unlock_in_child_releases_parent_lock(self):
        unlock = f"{self.bb} flock -u 9"
        body = (f"{self.bb} ash -c {shlex.quote(unlock)} || exit 78\n"
                "printf 'unlocked\\n'\nread -r finish\n")
        with self.owner(body) as (owner, barrier):
            self.assertEqual(barrier.line(), "unlocked")
            self.assertIsNone(owner.poll())
            self.assertEqual(self.contender().returncode, 0)

    def test_env_clear_preserves_lock_fd_and_explicit_close_drops_it(self):
        # env -i only clears environment; it does not sanitize descriptors at a
        # service launch boundary. Exercise a real external applet in each case.
        nested = (f"{self.bb} env -i {self.bb} flock -n 9 || exit 79\n"
                  "exec 9>&-\n"
                  f"{self.bb} env -i {self.bb} flock -n 9 2>/dev/null\n"
                  "[ \"$?\" != 0 ] || exit 80\n")
        body = (f"{self.bb} ash -c {shlex.quote(nested)} || exit 81\n"
                "printf 'service-boundary\\n'\nread -r finish\n")
        with self.owner(body) as (_, barrier):
            self.assertEqual(barrier.line(), "service-boundary")
            self.assertEqual(self.contender().returncode, 1)

    def test_setsid_exec_retains_pid_and_workers_join_session(self):
        body = ("printf 'owner %s\\n' \"$$\"\n"
                f"{self.bb} ash -c 'printf \"worker %s\\n\" \"$$\"; read -r finish' &\n"
                "wait\n")
        # Background ash reads /dev/null unless explicitly redirected; use a
        # separate inherited pipe to keep it alive at the membership barrier.
        control_read, control_write = os.pipe()
        self.addCleanup(os.close, control_read)
        self.addCleanup(os.close, control_write)
        body = body.replace("' &\n", f"' < /proc/self/fd/{control_read} &\n")
        with self.owner(body, session=True, pass_fds=(control_read,)) as (owner, barrier):
            events = dict(barrier.line().split() for _ in range(2))
            self.assertEqual(int(events["owner"]), owner.pid)
            self.track_worker(owner, int(events["worker"]))
            for pid in (owner.pid, int(events["worker"])):
                self.assertEqual(proc_identity(pid)["session"], owner.pid)
                self.assertEqual(proc_identity(pid)["group"], owner.pid)
            os.write(control_write, b"finish\n")
            self.assertEqual(owner.wait(timeout=5), 0)

    def test_setsid_group_leader_forks_and_cannot_preserve_launcher_identity(self):
        # BusyBox 1.33.1 has no setsid -f. Its implicit fork when already a group
        # leader is observable: a launcher must rule this out before ownership.
        worker = "printf 'worker %s\\n' \"$$\"\nread -r finish\n"
        process = subprocess.Popen([self.busybox, "setsid", self.busybox, "ash",
                                    "-c", worker], start_new_session=True,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        worker_pid = None
        worker_identity = None
        try:
            barrier = Barrier(process.stdout)
            worker_pid = int(barrier.line().split()[1])
            worker_identity = proc_identity(worker_pid)
            self.assertNotEqual(worker_pid, process.pid)
            self.assertEqual(proc_identity(worker_pid)["session"], worker_pid)
            self.assertEqual(proc_identity(worker_pid)["group"], worker_pid)
            self.assertEqual(process.wait(timeout=5), 0)
            process.stdin.write(b"finish\n")
            process.stdin.flush()
            barrier.eof()
        finally:
            if worker_identity is not None:
                self.stop_worker(worker_pid, worker_identity)
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
            if worker_identity is not None:
                self.reap_worker(worker_pid)
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()

    def test_no_replace_ln_preserves_regular_symlink_and_directory_destinations(self):
        source = self.root / "candidate"
        source.write_text("new complete owner record\n")
        target = self.root / "published"
        self.assertEqual(self.run_bb("ln", "-T", "-n", source, target).returncode, 0)
        identity = target.stat()
        self.assertEqual(identity.st_ino, source.stat().st_ino)
        other = self.root / "other"
        other.write_text("foreign\n")
        self.assertNotEqual(self.run_bb("ln", "-T", "-n", other, target).returncode, 0)
        self.assertEqual(target.stat().st_ino, identity.st_ino)
        self.assertEqual(target.read_text(), source.read_text())
        for destination, referent in ((self.root / "file-link", other),
                                      (self.root / "directory-link", self.root)):
            destination.symlink_to(referent)
            before = destination.lstat()
            self.assertNotEqual(self.run_bb("ln", "-T", "-n", source, destination).returncode, 0)
            self.assertEqual(destination.lstat().st_ino, before.st_ino)
            self.assertEqual(destination.readlink(), referent)
        directory = self.root / "foreign-directory"
        directory.mkdir()
        self.assertNotEqual(self.run_bb("ln", "-T", "-n", source, directory).returncode, 0)
        self.assertEqual(list(directory.iterdir()), [])
        self.assertEqual(other.read_text(), "foreign\n")

    def test_simultaneous_no_replace_publication_has_one_winner(self):
        target = self.root / "winner"
        processes = []
        try:
            for index in range(2):
                source = self.root / f"candidate-{index}"
                source.write_text(f"complete-{index}\n")
                body = ("printf 'ready\\n'\nread -r start\n"
                        f"exec {self.bb} ln -T -n {shlex.quote(str(source))} {shlex.quote(str(target))}\n")
                process = subprocess.Popen([self.busybox, "ash", "-c", body],
                                           stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE)
                processes.append(process)
                self.assertEqual(Barrier(process.stdout).line(), "ready")
            for process in processes:
                process.stdin.write(b"start\n")
                process.stdin.flush()
            codes = [process.wait(timeout=5) for process in processes]
            self.assertEqual(sorted(codes), [0, 1])
            winner = codes.index(0)
            source = self.root / f"candidate-{winner}"
            self.assertEqual(target.stat().st_ino, source.stat().st_ino)
            self.assertEqual(target.read_bytes(), source.read_bytes())
            self.assertEqual((self.root / f"candidate-{1 - winner}").read_text(), f"complete-{1 - winner}\n")
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)
                for stream in (process.stdin, process.stdout, process.stderr):
                    stream.close()

    def directory_candidate(self, name):
        root = self.root / name
        source = root / "candidate-container" / (".couvrefeu-release-" + "a" * 64)
        (source / "lib").mkdir(parents=True, mode=0o700)
        (source / "cfctl").write_text("complete entry\n")
        (source / "lib/core.sh").write_text("complete library\n")
        (source / "release.sha256").write_text("complete manifest\n")
        destination = root / "etc"
        destination.mkdir(mode=0o700)
        self.assertEqual(source.stat().st_dev, destination.stat().st_dev)
        return root, source, destination

    def tree_image(self, root):
        result = {}
        for path in sorted(root.rglob("*")):
            info = path.lstat()
            metadata = (info.st_mode, info.st_uid, info.st_gid, info.st_ino, info.st_mtime_ns)
            if path.is_symlink():
                content = ("symlink", os.readlink(path))
            elif path.is_dir():
                content = ("directory",)
            else:
                content = ("file", path.read_bytes())
            result[str(path.relative_to(root))] = metadata + content
        return result

    def test_directory_mv_n_to_existing_parent_never_nests_or_changes_collision(self):
        for kind in ("empty-directory", "nonempty-directory", "symlink-file",
                     "symlink-directory", "dangling-symlink", "regular-file"):
            with self.subTest(kind=kind):
                root, source, parent = self.directory_candidate(kind)
                target = parent / source.name
                if kind.endswith("directory") and not kind.startswith("symlink"):
                    target.mkdir()
                    if kind.startswith("nonempty"):
                        (target / "foreign").write_text("preserve foreign directory\n")
                elif kind == "regular-file":
                    target.write_text("preserve foreign file\n")
                else:
                    referent = root / "foreign-referent"
                    if kind == "symlink-directory":
                        referent.mkdir()
                        (referent / "foreign").write_text("preserve symlink target\n")
                    elif kind == "symlink-file":
                        referent.write_text("preserve symlink target\n")
                    target.symlink_to(referent)
                before = self.tree_image(root)
                body = (f"{self.bb} mv -n {shlex.quote(str(source))} {shlex.quote(str(parent) + '/')}\n"
                        "printf 'result %s\\n' \"$?\"\nread -r finish\n")
                with self.owner(body) as (_, barrier):
                    # BusyBox -n may return success for a skipped collision. A
                    # publisher must verify source disappearance and identity.
                    self.assertIn(barrier.line(), ("result 0", "result 1"))
                    self.assertEqual(self.contender().returncode, 1)
                    self.assertEqual(self.tree_image(root), before)
                    self.assertTrue(source.is_dir())

    def test_directory_mv_n_crash_before_and_after_complete_publication(self):
        for point in ("before", "after"):
            with self.subTest(point=point):
                _, source, parent = self.directory_candidate("publish-" + point)
                target = parent / source.name
                source_inode = source.stat().st_ino
                expected = {str(path.relative_to(source)): path.read_bytes()
                            for path in source.rglob("*") if path.is_file()}
                body = ("printf 'before\\n'\nread -r publish\n"
                        f"{self.bb} mv -n {shlex.quote(str(source))} {shlex.quote(str(parent) + '/')} || exit 82\n"
                        "printf 'after\\n'\nread -r finish\n")
                with self.owner(body) as (owner, barrier):
                    self.assertEqual(barrier.line(), "before")
                    self.assertFalse(target.exists())
                    self.assertTrue(source.is_dir())
                    if point == "after":
                        owner.stdin.write(b"publish\n")
                        owner.stdin.flush()
                        self.assertEqual(barrier.line(), "after")
                        self.assertFalse(source.exists())
                        self.assertEqual(target.stat().st_ino, source_inode)
                    owner.kill()
                    self.assertEqual(owner.wait(timeout=5), -signal.SIGKILL)
                visible = source if point == "before" else target
                self.assertEqual({str(path.relative_to(visible)): path.read_bytes()
                                  for path in visible.rglob("*") if path.is_file()}, expected)
                self.assertEqual(visible.stat().st_ino, source_inode)
                self.assertEqual(target.exists(), point == "after")

    def test_replacing_mutex_inode_splits_exclusion_and_must_be_forbidden(self):
        with self.owner("printf 'locked\\n'\nread -r finish\n") as (_, barrier):
            self.assertEqual(barrier.line(), "locked")
            original = self.mutex.stat()
            retired = self.root / "original-inode"
            self.mutex.rename(retired)
            self.mutex.write_text("foreign replacement\n")
            self.assertNotEqual(self.mutex.stat().st_ino, original.st_ino)
            self.assertEqual(self.contender(retired).returncode, 1)
            self.assertEqual(self.contender().returncode, 0)
            self.assertEqual(self.mutex.read_text(), "foreign replacement\n")
            self.assertEqual(retired.stat().st_ino, original.st_ino)

    def test_worker_reaped_during_validation_never_signals_numeric_pid(self):
        process = subprocess.Popen([self.busybox, "ash", "-c",
                                    "printf 'ready\\n'; read -r finish"],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        descriptor = os.pidfd_open(process.pid)
        try:
            self.assertEqual(Barrier(process.stdout).line(), "ready")
            identity = proc_identity(process.pid)

            def reaped_after_identity_read(pid):
                self.assertEqual(pid, process.pid)
                signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                self.assertEqual(process.wait(timeout=5), -signal.SIGKILL)
                return identity

            # Force exit and reaping between identity validation and signaling.
            # Numeric signaling could now address a recycled, unrelated PID.
            with patch.dict(globals(), proc_identity=reaped_after_identity_read):
                with patch("os.kill", side_effect=AssertionError("unsafe numeric worker signal")):
                    self.stop_worker(process.pid, identity)
        finally:
            if process.poll() is None:
                signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            process.wait(timeout=5)
            os.close(descriptor)
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
