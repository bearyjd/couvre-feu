#!/usr/bin/env python3
"""Run independent private-root cases in four bounded subprocess lanes."""
from concurrent.futures import ThreadPoolExecutor, as_completed
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'tests/fixtures'))
from harness import run_owned_process


def cases(suite):
    for case in suite:
        if isinstance(case, unittest.TestSuite):
            yield from cases(case)
        else:
            yield case.id().split('.', 1)[1]


def run_lane(job, directory, timeout=1800, started=None):
    filename, index, group = job
    log = directory / f'{filename}-{index}.log'
    with log.open('w') as stream:
        log.chmod(0o600)
        try:
            result = run_owned_process([sys.executable, str(REPO / 'tests' / filename), *group],
                                       cwd=REPO, env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1', CF_TEST_LANE='1'),
                                       stdout=stream, stderr=subprocess.STDOUT, timeout=timeout,
                                       interrupt_on_timeout=True, started=started)
            return filename, index, len(group), result.returncode, log
        except subprocess.TimeoutExpired:
            return filename, index, len(group), 124, log


def worker_count():
    value = os.environ.get('CF_TEST_WORKERS', '4')
    if value not in ('1', '2', '3', '4'):
        raise ValueError('CF_TEST_WORKERS must be an integer from 1 through 4')
    return int(value)


def main():
    try:
        workers = worker_count()
    except ValueError as error:
        print(f'FAIL: {error}', file=sys.stderr, flush=True)
        return 2
    jobs = []
    for filename in ('test-transition.py', 'test-rpc.py', 'test-core.py', 'test-fixture-process.py'):
        name = 'fixture_' + filename.replace('-', '_').removesuffix('.py')
        spec = importlib.util.spec_from_file_location(name, REPO / 'tests' / filename)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        names = sorted(cases(unittest.defaultTestLoader.loadTestsFromModule(module)))
        for index in range(4):
            group = names[index::4]
            if group:
                jobs.append((filename, index, group))
    directory = Path(tempfile.mkdtemp(prefix='couvre-feu-suite-', dir='/tmp'))
    directory.chmod(0o700)

    failed = False
    # Partitions remain four per suite; this only bounds concurrent lane execution.
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for future in as_completed([pool.submit(run_lane, job, directory) for job in jobs]):
            filename, index, count, status, log = future.result()
            print(f'{"PASS" if status == 0 else "FAIL"}: {filename} lane {index + 1}, {count} cases', flush=True)
            if status:
                failed = True
                print(log.read_text(), flush=True)
    if failed:
        print(f'Private fixture failure logs retained: {directory}', flush=True)
        return 1
    for log in directory.iterdir():
        log.unlink()
    directory.rmdir()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
