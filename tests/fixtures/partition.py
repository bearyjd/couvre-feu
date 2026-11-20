"""Shared CI partition selection for the sharded preflight suites (--partition i/N or CF_TEST_PARTITION=i/N)."""
import os
import sys
import unittest


def flatten_ids(suite):
    for case in suite:
        if isinstance(case, unittest.TestSuite):
            yield from flatten_ids(case)
        else:
            yield case.id()


def parse_partition(text):
    """'i/N' (1-based) -> (i, N); anything else is refused so a typo cannot run a subset silently."""
    index, _, count = text.partition('/')
    if not (index.isdigit() and count.isdigit() and 1 <= int(index) <= int(count)):
        raise SystemExit(f'invalid partition {text!r}: expected i/N with 1 <= i <= N')
    return int(index), int(count)


def select_partition(ids, index, count):
    """Round-robin over the sorted ids: deterministic, disjoint, and covering.

    Sorted order groups tests by class, so striding mixes the heavy install and
    recovery cases evenly across partitions without a per-test timing table.
    """
    return sorted(ids)[index - 1::count]


def requested_partition(argv, environ):
    """Return (argv without --partition, 'i/N' or ''); a missing value or a conflict between flag and env is refused."""
    argv = list(argv)
    text = environ.get('CF_TEST_PARTITION', '')
    if '--partition' in argv:
        position = argv.index('--partition')
        if position + 1 >= len(argv):
            raise SystemExit('--partition requires a value i/N')
        flag = argv[position + 1]
        del argv[position:position + 2]
        if text and text != flag:
            raise SystemExit(f'--partition {flag} conflicts with CF_TEST_PARTITION={text}')
        text = flag
    return argv, text


def main(argv):
    """Run all tests, or one partition via --partition i/N or CF_TEST_PARTITION=i/N; --list only prints ids.

    Positional test names or flags such as -k given on the command line select tests themselves
    and are never overridden by a partition.
    """
    argv, text = requested_partition(argv, os.environ)
    listing = '--list' in argv
    if listing:
        argv.remove('--list')
    names = sorted(flatten_ids(unittest.defaultTestLoader.loadTestsFromModule(sys.modules['__main__'])))
    total = len(names)
    if text:
        names = select_partition(names, *parse_partition(text))
        if not names:
            raise SystemExit(f'partition {text} selected no tests')
        print(f'partition {text}: {len(names)} of {total} tests', file=sys.stderr)
    if listing:
        print('\n'.join(names))
        return
    targeted = any(not arg.startswith('-') for arg in argv[1:])
    unittest.main(argv=argv if targeted or not text else argv + names, module=None)
