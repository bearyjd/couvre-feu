#!/usr/bin/env python3
"""Fail on tight hard-coded subprocess/exec timeouts in test code.

CI runners are shared and routinely run 3-10x slower than a developer host. A literal timeout below
MIN_LITERAL_SECONDS that bounds a subprocess/exec call has flaked in CI before (client-probe 10 s,
core ipv6-alias 60 s, empty-witness 60 s). Raise it through a named constant, or justify the tight
bound on the same line, the line above, or any line of a multi-line call with:

    # timeout-ok: <reason>      (Python)
    // timeout-ok: <reason>     (TypeScript / JavaScript)

A file whose short limits were all measured with large headroom may instead carry one
`# timeout-ok-file: <reason with the measurement>` comment in its first FILE_MARKER_LINES lines.

Scope: Python subprocess.run/check_*/call, Popen.communicate/wait (keyword or first positional
literal) under tests/; TypeScript/JS `timeout:` options under shared/tests, service/tests, tests/.
Not covered (different failure mode, see docs): thread.join, socket timeouts, Playwright expectations.
"""
import ast
from pathlib import Path
import re
import sys
import unittest

sys.dont_write_bytecode = True
REPO = Path(__file__).resolve().parents[1]
MIN_LITERAL_SECONDS = 20
SUBPROCESS_CALLS = {'run', 'check_output', 'check_call', 'call', 'communicate', 'wait'}
# Files owned by an in-flight PR when this audit landed; burn the entries down once those merge.
PENDING_FILES = {
    'tests/test-core.py': 'edited by the CI fifth-partition PR (#108)',
    'tests/test-fixture-process.py': 'edited by the CI fifth-partition PR (#108); its short timeouts test the timeout path itself',
    'tests/run-fixtures.py': 'edited by the CI fifth-partition PR (#108)',
}
FILE_MARKER_LINES = 40
FILE_MARKER = re.compile(r'(?:#|//)\s*timeout-ok-file:\s*\S')
MARKER = re.compile(r'(?:#|//)\s*timeout-ok:\s*\S')
JS_TIMEOUT = re.compile(r'\btimeout\s*:\s*(\d[\d_]*)\b')


def literal_seconds(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
        return node.value
    return None


def justified(lines, first, last):
    """True when a timeout-ok marker sits on the line above or on any line of first..last (1-based)."""
    return any(MARKER.search(lines[i]) for i in range(max(first - 2, 0), min(last, len(lines))))


def file_justified(lines):
    return any(FILE_MARKER.search(line) for line in lines[:FILE_MARKER_LINES])


def python_findings(path):
    source = path.read_text()
    lines = source.splitlines()
    if file_justified(lines):
        return []
    found = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, 'id', None)
        if name not in SUBPROCESS_CALLS:
            continue
        values = [kw.value for kw in node.keywords if kw.arg == 'timeout']
        if name == 'wait' and node.args:
            values.append(node.args[0])
        for value in values:
            seconds = literal_seconds(value)
            if seconds is not None and seconds < MIN_LITERAL_SECONDS and not justified(lines, node.lineno, node.end_lineno):
                found.append((value.lineno, f'{name}(timeout={seconds})'))
    return found


def javascript_findings(path):
    lines = path.read_text().splitlines()
    if file_justified(lines):
        return []
    found = []
    for number, line in enumerate(lines, 1):
        for match in JS_TIMEOUT.finditer(line):
            milliseconds = int(match.group(1).replace('_', ''))
            if milliseconds < MIN_LITERAL_SECONDS * 1000 and not justified(lines, number, number):
                found.append((number, f'timeout: {milliseconds} ms'))
    return found


def audit():
    findings = []
    for path in sorted((REPO / 'tests').rglob('*.py')):
        relative = path.relative_to(REPO).as_posix()
        if path.name != Path(__file__).name and relative not in PENDING_FILES:
            findings += [(relative, number, text) for number, text in python_findings(path)]
    for root in ('shared/tests', 'service/tests', 'tests'):
        for path in sorted((REPO / root).rglob('*.ts')) + sorted((REPO / root).rglob('*.mjs')):
            relative = path.relative_to(REPO).as_posix()
            findings += [(relative, number, text) for number, text in javascript_findings(path)]
    return findings


class TimeoutAuditTests(unittest.TestCase):
    def test_no_unjustified_tight_literal_timeouts(self):
        findings = audit()
        report = '\n'.join(f'  {path}:{number}: {text}' for path, number, text in findings)
        self.assertEqual(findings, [], f'tight hard-coded timeouts (< {MIN_LITERAL_SECONDS} s) need a named constant '
                         f'or a "timeout-ok: <reason>" marker:\n{report}')

    def test_pending_files_exist(self):
        for relative in PENDING_FILES:
            self.assertTrue((REPO / relative).is_file(), f'{relative} no longer exists; drop it from PENDING_FILES')

    def test_detector_flags_and_honours_markers(self):
        scratch = Path(__import__('tempfile').mkdtemp())
        try:
            bad = scratch / 'bad.py'
            bad.write_text('import subprocess\nsubprocess.run(["x"], timeout=10)\np.wait(5)\np.communicate(timeout=19.5)\n'
                           'subprocess.run(["x"], timeout=20)\nsubprocess.run(["x"], timeout=T)\nt.join(timeout=1)\n')
            self.assertEqual([number for number, _ in python_findings(bad)], [2, 3, 4])
            ok = scratch / 'ok.py'
            ok.write_text('import subprocess\n# timeout-ok: asserts the timeout path\nsubprocess.run(["x"], timeout=3)\n'
                          'subprocess.run(["x"],\n    timeout=3)  # timeout-ok: same\nx = 1\nsubprocess.run(["x"], timeout=3)  # timeout-ok:\n')
            self.assertEqual([number for number, _ in python_findings(ok)], [7])
            js = scratch / 'a.ts'
            js.write_text('spawnSync(a, {timeout: 3000});\nspawnSync(a, {timeout: 20000});\n'
                          '// timeout-ok: expected\nspawnSync(a, {timeout: 3000});\n')
            self.assertEqual([number for number, _ in javascript_findings(js)], [1])
            whole = scratch / 'whole.py'
            whole.write_text('# timeout-ok-file: measured 0.1 s\nimport subprocess\nsubprocess.run(["x"], timeout=3)\n')
            self.assertEqual(python_findings(whole), [])
        finally:
            for child in scratch.iterdir():
                child.unlink()
            scratch.rmdir()


if __name__ == '__main__':
    unittest.main(verbosity=2)
