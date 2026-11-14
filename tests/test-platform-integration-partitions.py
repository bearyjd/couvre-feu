#!/usr/bin/env python3
"""Guard: the CI partitions of every sharded preflight suite cover each test exactly once."""
import os
from pathlib import Path
import subprocess
import sys
import unittest

sys.dont_write_bytecode = True
REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'tests/fixtures'))
import partition  # noqa: E402

# Partition cells per suite; must equal the cells for that suite in .github/workflows/ci.yml.
SUITES = {'test-platform-integration.py': 4, 'test-install.py': 3, 'test-os-trust.py': 3}


def run_script(suite, *args, partition_text=None):
    env = {key: value for key, value in os.environ.items() if key != 'CF_TEST_PARTITION'}
    env.setdefault('CF_TEST_SHELL', 'busybox ash')
    if partition_text:
        env['CF_TEST_PARTITION'] = partition_text
    return subprocess.run([sys.executable, '-B', str(REPO / 'tests' / suite), *args],
                          env=env, capture_output=True, text=True, timeout=300)


class PartitionHelperTests(unittest.TestCase):
    def test_round_robin_over_sorted_ids_is_disjoint_and_covering(self):
        ids = [f'm.C.t{n:02d}' for n in range(11)][::-1]
        groups = [partition.select_partition(ids, index, 3) for index in range(1, 4)]
        self.assertEqual(groups[0], ['m.C.t00', 'm.C.t03', 'm.C.t06', 'm.C.t09'])
        self.assertEqual(sorted(name for group in groups for name in group), sorted(ids))

    def test_malformed_partition_is_refused(self):
        for text in ('0/4', '5/4', '1/0', 'a/4', '1', '1/4/2', '-1/4', ''):
            with self.assertRaises(SystemExit, msg=text):
                partition.parse_partition(text)
        self.assertEqual(partition.parse_partition('2/4'), (2, 4))


class RealScriptPartitionTests(unittest.TestCase):
    def test_script_partitions_cover_full_list_exactly_once(self):
        for suite, count in SUITES.items():
            with self.subTest(suite=suite):
                full = run_script(suite, '--list')
                self.assertEqual(full.returncode, 0, full.stderr)
                full_ids = full.stdout.split()
                self.assertGreater(len(full_ids), 50)
                self.assertEqual(len(full_ids), len(set(full_ids)))
                union = []
                sizes = []
                for index in range(1, count + 1):
                    part = run_script(suite, '--list', partition_text=f'{index}/{count}')
                    self.assertEqual(part.returncode, 0, part.stderr)
                    ids = part.stdout.split()
                    self.assertIn(f'partition {index}/{count}: {len(ids)} of {len(full_ids)} tests', part.stderr)
                    union += ids
                    sizes.append(len(ids))
                self.assertEqual(len(union), len(set(union)), 'a test appears in two partitions')
                self.assertEqual(sorted(union), sorted(full_ids))
                self.assertEqual(sum(sizes), len(full_ids))
                self.assertLessEqual(max(sizes) - min(sizes), 1)

    def test_malformed_empty_and_ambiguous_selection_exits_1(self):
        for suite, count in SUITES.items():
            with self.subTest(suite=suite):
                for text in ('0/3', f'{count + 1}/{count}', 'x', '1/0', '1000/1000'):
                    self.assertEqual(run_script(suite, '--list', partition_text=text).returncode, 1, text)
                self.assertEqual(run_script(suite, '--list', '--partition').returncode, 1)
                conflict = run_script(suite, '--list', '--partition', '1/3', partition_text='2/3')
                self.assertEqual(conflict.returncode, 1)
                agree = run_script(suite, '--list', '--partition', '2/3', partition_text='2/3')
                self.assertEqual(agree.returncode, 0, agree.stderr)

    def test_positional_selection_is_not_overridden_by_partition(self):
        result = run_script('test-platform-integration.py', '-v', 'VendorCommParserTests', partition_text='1/4')
        ran = [line for line in result.stderr.splitlines() if ' ... ' in line]
        self.assertTrue(ran)
        self.assertTrue(all('VendorCommParserTests' in line for line in ran), ran)


if __name__ == '__main__':
    unittest.main()
