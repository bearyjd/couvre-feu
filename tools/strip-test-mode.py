#!/usr/bin/env python3
"""Write the production copy of router/cfctl-ssh without its CF_TEST_MODE block.

Usage: strip-test-mode.py OUTPUT. Offline and deterministic: removes exactly the
marked block (comment line through its closing fi), refuses anything else, and
prints the SHA-256 of the written file for disclosure in the approval request.
"""
import hashlib
from pathlib import Path
import subprocess
import sys

START = '# The grammar fixture may invoke only a marked private-root executable.\n'
OPEN = 'if [ "${CF_TEST_MODE-}" = 1 ];then\n'
END = 'fi\n'
BLOCK_LINES = 9


def strip(text):
    lines = text.splitlines(keepends=True)
    if lines.count(START) != 1:
        raise ValueError('test-mode marker comment not found exactly once')
    begin = lines.index(START)
    if lines[begin + 1] != OPEN:
        raise ValueError('test-mode block does not follow its marker')
    end = next((i for i in range(begin + 2, len(lines)) if lines[i] == END), None)
    if end is None:
        raise ValueError('test-mode block has no closing fi')
    if end - begin + 1 != BLOCK_LINES:
        raise ValueError('test-mode block is not the expected %d lines' % BLOCK_LINES)
    result = lines[:begin] + lines[end + 1:]
    if 'CF_TEST_MODE' in ''.join(result):
        raise ValueError('CF_TEST_MODE remains after stripping')
    return ''.join(result)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit('usage: strip-test-mode.py OUTPUT')
    source = Path(__file__).resolve().parent.parent / 'router' / 'cfctl-ssh'
    try:
        data = strip(source.read_text()).encode()
        if subprocess.run(['sh', '-n'], input=data, capture_output=True).returncode:
            raise ValueError('stripped output fails sh -n')
    except ValueError as error:
        sys.exit('refused: ' + str(error))
    Path(sys.argv[1]).write_bytes(data)
    print(hashlib.sha256(data).hexdigest())
