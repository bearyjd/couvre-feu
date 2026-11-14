#!/usr/bin/env python3
"""Guard: the CI partitions of test-platform-integration.py cover every test exactly once."""
import importlib.util
import os
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
REPO = Path(__file__).resolve().parents[1]
# Imported only to enumerate tests; nothing here runs a shell.
os.environ.setdefault('CF_TEST_SHELL', 'busybox ash')
PARTITIONS = 4  # must equal the partition cells for this suite in .github/workflows/ci.yml
spec = importlib.util.spec_from_file_location('platform_integration', REPO / 'tests/test-platform-integration.py')
module = importlib.util.module_from_spec(spec)
sys.modules['platform_integration'] = module
spec.loader.exec_module(module)


class PartitionCoverageTests(unittest.TestCase):
    def setUp(self):
        loaded = unittest.defaultTestLoader.loadTestsFromModule(module)
        self.ids = sorted(module.flatten_ids(loaded))

    def test_union_equals_full_sorted_list_with_no_duplicates(self):
        self.assertGreater(len(self.ids), 50)
        self.assertEqual(len(self.ids), len(set(self.ids)))
        groups = [module.select_partition(self.ids, index, PARTITIONS) for index in range(1, PARTITIONS + 1)]
        union = [name for group in groups for name in group]
        self.assertEqual(len(union), len(set(union)), 'a test appears in two partitions')
        self.assertEqual(sorted(union), self.ids, 'a test is dropped or invented by partitioning')
        self.assertTrue(all(groups), 'empty partition')

    def test_partitions_are_balanced_by_count(self):
        sizes = [len(module.select_partition(self.ids, index, PARTITIONS)) for index in range(1, PARTITIONS + 1)]
        self.assertLessEqual(max(sizes) - min(sizes), 1)

    def test_malformed_partition_is_refused(self):
        for text in ('0/4', '5/4', '1/0', 'a/4', '1', '1/4/2', '-1/4'):
            with self.assertRaises(SystemExit, msg=text):
                module.parse_partition(text)
        self.assertEqual(module.parse_partition('2/4'), (2, 4))


if __name__ == '__main__':
    unittest.main()
