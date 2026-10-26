#!/usr/bin/env python3
"""Run independent private-root cases in four bounded subprocess lanes."""
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'tests/fixtures'))
from harness import run_owned_process

SUITES = ('test-transition.py', 'test-rpc.py', 'test-core.py', 'test-fixture-process.py', 'test-penn-pilot.py', 'test-penn-pilot-leg2.py', 'test-penn-pilot-leg2-guards.py', 'test-scope-admin.py', 'test-inventory.py')
# Fixed public source paths bind the plan to fixtures and the entire release.
SOURCE_FILES = ('.github/workflows/ci.yml', 'tests/run.sh', 'tests/run-fixtures.py', 'tests/fixtures/harness.py', 'tests/fixtures/backend.py',
                'tests/test-live-rehearsal.py',
                'router/release.sha256', 'router/install.sh', 'router/uninstall.sh',
                'router/cfctl', 'router/cfctl-ssh', 'router/cfctl-scope', 'router/lib/platform-bootstrap.sh',
                'router/lib/vendor-platform.sh', 'router/lib/install-common.sh',
                'router/lib/core.sh', 'router/lib/rpc.sh', 'router/lib/firewall.sh',
                'router/lib/state.awk', 'router/lib/rules.awk', 'router/lib/json.awk',
                'router/lib/activity.sh')


# Measured seconds, per suite, for the cases that dominate its runtime; every
# other case weighs DEFAULT_WEIGHT. Used only to spread cases over the four
# partitions so no shard approaches the lane budget: a stale or missing entry
# makes the split less even but never changes which cases run (coverage is
# proven in discovery_plan). Refresh: take the 'TIMING: __main__.<Class>.<test>
# <n>s' lines from a CI run's shard logs (emitted per case by
# tests/fixtures/harness.py, relayed by main()) and keep entries of roughly
# 30 s or more as {'<Class>.<test>': seconds}.
DEFAULT_WEIGHT = 10
CASE_WEIGHTS = {
    'test-transition.py': {
        'FailClosedReconstructionTests.test_failure_at_each_staging_step_keeps_old_generation_dispatched': 145,
        'FailClosedReconstructionTests.test_interrupted_transition_address_change_repairs_with_iptables_delete_order': 130,
        'FailClosedReconstructionTests.test_child_address_change_repairs_stale_selector_with_iptables_delete_order': 125,
        'FailClosedReconstructionTests.test_router_sort_order_enrolled_transition_and_uninstall': 112,
        'FailClosedReconstructionTests.test_failure_after_complete_shadow_build_rolls_back_slot_and_intent': 106,
        'FailClosedReconstructionTests.test_status_after_refused_command_never_rewrites_shadow_intent': 102,
        'FailClosedReconstructionTests.test_crashed_staging_leftover_generation_is_removed_on_next_run': 90,
        'FailClosedReconstructionTests.test_schedule_and_resolver_change_blocks_child_in_every_observed_state': 84,
        'FailClosedReconstructionTests.test_rollback_failing_after_partial_deletes_keeps_journal_and_uninstall_recovers': 84,
        'FailClosedReconstructionTests.test_uninstall_refuses_referenced_staging_slot_without_mutation': 78,
        'FailClosedReconstructionTests.test_uninstall_from_drifted_staging_intent_restores_exactly': 74,
        'FailClosedReconstructionTests.test_uninstall_after_crashed_staging_refuses_until_stale_lock_recovery': 74,
        'FailClosedReconstructionTests.test_failed_set_read_never_drops_journal_and_uninstall_recovers': 74,
        'FailClosedReconstructionTests.test_first_dispatcher_switch_failure_keeps_old_generation_dispatched': 72,
        'FailClosedReconstructionTests.test_uninstall_removes_failed_shadow_generation': 65,
        'FailClosedReconstructionTests.test_router_order_stored_snapshot_is_accepted': 59,
        'FailClosedReconstructionTests.test_added_child_is_guarded_before_switch_and_drained': 59,
        'FailClosedReconstructionTests.test_drift_repair_blocks_child_in_every_observed_state': 58,
        'FailClosedReconstructionTests.test_removed_child_stays_blocked_until_switch_completes': 57,
        'FailClosedReconstructionTests.test_swapped_child_mac_keeps_union_blocked_through_switch': 53,
    },
}


def partition_cases(names, weights=None, count=4):
    """Greedy longest-first split; deterministic for a given name list and table."""
    weights = weights or {}
    loads, groups = [0] * count, [[] for _ in range(count)]
    for name in sorted(names, key=lambda item: (-weights.get(item, DEFAULT_WEIGHT), item)):
        target = min(range(count), key=lambda index: (loads[index], len(groups[index]), index))
        loads[target] += weights.get(name, DEFAULT_WEIGHT)
        groups[target].append(name)
    return [sorted(group) for group in groups]


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
            status = result.returncode
            if status == 0:
                text = log.read_text()
                summary = re.findall(r'^Ran ([0-9]+) tests? in ', text, re.M)
                if summary != [str(len(group))] or re.search(r'^OK \(skipped=', text, re.M):
                    status = 125
                    stream.write('\nFAIL: lane did not prove every requested case without skips\n')
            return filename, index, len(group), status, log
        except subprocess.TimeoutExpired:
            return filename, index, len(group), 124, log


def worker_count():
    value = os.environ.get('CF_TEST_WORKERS', '4')
    if value not in ('1', '2', '3', '4'):
        raise ValueError('CF_TEST_WORKERS must be an integer from 1 through 4')
    return int(value)


def source_revision():
    revision = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=REPO,
                              check=True, capture_output=True, text=True).stdout.strip()
    if not re.fullmatch(r'[0-9a-f]{40}', revision):
        raise ValueError('invalid source Git revision')
    if 'GITHUB_SHA' in os.environ and os.environ['GITHUB_SHA'] != revision:
        raise ValueError('checkout revision differs from workflow commit')
    return revision


def discovery_plan():
    shards = []
    sources = {name: hashlib.sha256((REPO / name).read_bytes()).hexdigest() for name in SOURCE_FILES}
    for filename in SUITES:
        name = 'fixture_' + filename.replace('-', '_').removesuffix('.py')
        path = REPO / 'tests' / filename
        sources['tests/' + filename] = hashlib.sha256(path.read_bytes()).hexdigest()
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        names = sorted(cases(unittest.defaultTestLoader.loadTestsFromModule(module)))
        if not names or len(names) != len(set(names)):
            raise ValueError(f'empty or duplicate discovery: {filename}')
        partitions = partition_cases(names, CASE_WEIGHTS.get(filename))
        union = [case for group in partitions for case in group]
        if not all(partitions) or sorted(union) != names or len(union) != len(set(union)):
            raise ValueError(f'incomplete or duplicate partition coverage: {filename}')
        for index, group in enumerate(partitions):
            shards.append({'suite': filename, 'partition': index, 'cases': group})
    return {'version': 1, 'revision': source_revision(), 'sources': sources, 'shards': shards}


def plan_digest(plan):
    return hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'duplicate JSON key: {key}')
        result[key] = value
    return result


def read_json(path):
    path = Path(path)
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 1048576:
        raise ValueError('unsafe or oversized coverage file')
    value = json.loads(path.read_text(), object_pairs_hook=unique_object)
    if not isinstance(value, dict):
        raise ValueError('coverage document must be an object')
    return value


def write_json(path, value):
    path = Path(path)
    with path.open('x') as stream:
        path.chmod(0o600)
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')


def validated_plan(path):
    plan = read_json(path)
    if plan_digest(plan) != plan_digest(discovery_plan()):
        raise ValueError('coverage plan differs from complete current source discovery')
    return plan


def receipt_for(plan, shard, status):
    return {'version': 1, 'planSHA256': plan_digest(plan), **shard,
            'count': len(shard['cases']), 'status': status}


def verify_receipts(plan, directory):
    directory = Path(directory)
    if not directory.is_dir() or directory.is_symlink():
        raise ValueError('receipt directory missing or unsafe')
    entries = list(directory.iterdir())
    if len(entries) != len(plan['shards']):
        raise ValueError(f"all {len(plan['shards'])} shard receipts are required")
    expected = {(shard['suite'], shard['partition']): receipt_for(plan, shard, 0)
                for shard in plan['shards']}
    seen = set()
    for entry in entries:
        if entry.suffix != '.json':
            raise ValueError('unexpected receipt entry')
        receipt = read_json(entry)
        if not isinstance(receipt.get('suite'), str) or type(receipt.get('partition')) is not int:
            raise ValueError('invalid receipt selector types')
        key = (receipt['suite'], receipt['partition'])
        if key not in expected or key in seen or plan_digest(receipt) != plan_digest(expected[key]):
            raise ValueError('unknown, duplicate, failed or incomplete shard receipt')
        seen.add(key)
    if seen != set(expected):
        raise ValueError('missing coverage partition')
    print(f"PASS: all {len(plan['shards'])} nonempty shards prove complete duplicate-free case coverage", flush=True)


def selection(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group()
    action.add_argument('--write-plan')
    action.add_argument('--shard', choices=SUITES)
    action.add_argument('--verify-receipts')
    parser.add_argument('--partition', choices=('0', '1', '2', '3'))
    parser.add_argument('--plan')
    parser.add_argument('--receipt')
    args = parser.parse_args(argv)
    for name in ('write_plan', 'shard', 'verify_receipts', 'plan', 'receipt'):
        if getattr(args, name) == '':
            parser.error(f'{name} cannot be empty')
    if args.shard:
        if args.partition is None or not args.plan or not args.receipt:
            parser.error('shard requires partition, plan and receipt')
    elif args.verify_receipts:
        if not args.plan or args.partition is not None or args.receipt:
            parser.error('receipt verification requires only a plan and receipt directory')
    elif args.partition is not None or args.plan or args.receipt:
        parser.error('selection fields require a shard or receipt verification')
    if args.partition is not None:
        args.partition = int(args.partition)
    return args


def main(argv=()):
    try:
        args = selection(argv)
        workers = worker_count()
        if args.write_plan:
            write_json(args.write_plan, discovery_plan())
            return 0
        if args.verify_receipts:
            verify_receipts(validated_plan(args.plan), args.verify_receipts)
            return 0
        plan = validated_plan(args.plan) if args.shard else discovery_plan()
        selected = [shard for shard in plan['shards']
                    if not args.shard or (shard['suite'] == args.shard and shard['partition'] == args.partition)]
        if not selected or (args.shard and len(selected) != 1):
            raise ValueError('selected shard missing or empty')
    except SystemExit as error:
        return error.code
    except (ValueError, OSError) as error:
        print(f'FAIL: {error}', file=sys.stderr, flush=True)
        return 2
    jobs = [(shard['suite'], shard['partition'], shard['cases']) for shard in selected]
    directory = Path(tempfile.mkdtemp(prefix='couvre-feu-suite-', dir='/tmp'))
    directory.chmod(0o700)

    failed = False
    # Partitions remain four per suite (see partition_cases); this only bounds concurrent lane execution.
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for future in as_completed([pool.submit(run_lane, job, directory) for job in jobs]):
            filename, index, count, status, log = future.result()
            print(f'{"PASS" if status == 0 else "FAIL"}: {filename} lane {index + 1}, {count} cases', flush=True)
            # Relay per-test durations that suites opt into; never other log text.
            # unittest's verbose '... ' prefix shares the line, so match anywhere.
            for timing in re.findall(r'TIMING: \S+ [0-9]+\.[0-9]s', log.read_text()):
                print(timing, flush=True)
            if args.shard:
                write_json(args.receipt, receipt_for(plan, selected[0], status))
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
    raise SystemExit(main(sys.argv[1:]))
