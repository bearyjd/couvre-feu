#!/usr/bin/env python3
"""Write the production copy of a router forced-command wrapper without its CF_TEST_MODE block.

Usage: strip-test-mode.py OUTPUT [cfctl-ssh|cfctl-scope] (default cfctl-ssh). Offline and
deterministic: removes exactly the marked block (comment line through its closing fi),
refuses anything else, and prints the SHA-256 of the written file for disclosure in the
approval request. M4's production tree must carry both wrappers stripped.
"""
import hashlib
from pathlib import Path
import subprocess
import sys

START = '# The grammar fixture may invoke only a marked private-root executable.\n'
OPEN = 'if [ "${CF_TEST_MODE-}" = 1 ];then\n'
END = 'fi\n'
BLOCK_LINES = {'cfctl-ssh': 9, 'cfctl-scope': 14}


def strip(text, block_lines=BLOCK_LINES['cfctl-ssh']):
    lines = text.splitlines(keepends=True)
    if lines.count(START) != 1:
        raise ValueError('test-mode marker comment not found exactly once')
    begin = lines.index(START)
    if lines[begin + 1] != OPEN:
        raise ValueError('test-mode block does not follow its marker')
    end = next((i for i in range(begin + 2, len(lines)) if lines[i] == END), None)
    if end is None:
        raise ValueError('test-mode block has no closing fi')
    if end - begin + 1 != block_lines:
        raise ValueError('test-mode block is not the expected %d lines' % block_lines)
    result = lines[:begin] + lines[end + 1:]
    if 'CF_TEST_MODE' in ''.join(result):
        raise ValueError('CF_TEST_MODE remains after stripping')
    return ''.join(result)


if __name__ == '__main__':
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] not in BLOCK_LINES):
        sys.exit('usage: strip-test-mode.py OUTPUT [cfctl-ssh|cfctl-scope]')
    name = sys.argv[2] if len(sys.argv) == 3 else 'cfctl-ssh'
    source = Path(__file__).resolve().parent.parent / 'router' / name
    try:
        data = strip(source.read_text(), BLOCK_LINES[name]).encode()
        if subprocess.run(['sh', '-n'], input=data, capture_output=True).returncode:
            raise ValueError('stripped output fails sh -n')
    except ValueError as error:
        sys.exit('refused: ' + str(error))
    Path(sys.argv[1]).write_bytes(data)
    print(hashlib.sha256(data).hexdigest())
