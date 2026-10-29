#!/usr/bin/env python3
"""Fail on tight hard-coded subprocess/exec timeouts in test code.

CI runners are shared and routinely run 3-10x slower than a developer host. A literal timeout below
MIN_LITERAL_SECONDS that bounds a subprocess/exec call has flaked in CI before (client-probe 10 s,
core ipv6-alias 60 s, empty-witness 60 s). Raise it through a named constant, or justify the tight
bound on the same line, the line above, or any line of a multi-line call with:

    # timeout-ok: <reason>      (Python)
    // timeout-ok: <reason>     (TypeScript / JavaScript)

A file whose short limits were all measured with large headroom may instead carry one
`# timeout-ok-file: <reason with the measurement>` comment in its first FILE_MARKER_LINES lines. The
text must say 'measured' or 'UNMEASURED'. An UNMEASURED file must also carry `expires: YYYY-MM-DD`;
once that date passes the audit fails until the file is measured and the marker is rewritten.

Scope: Python subprocess.run/check_*/call, Popen.communicate/wait (keyword or first positional
literal) under tests/; TypeScript/JS `timeout:` options under shared/tests, service/tests, tests/.
Not covered (different failure mode, see docs): thread.join, socket timeouts, Playwright expectations.
"""
import ast
import datetime
from pathlib import Path
import re
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
REPO = Path(__file__).resolve().parents[1]
MIN_LITERAL_SECONDS = 20
SUBPROCESS_CALLS = {'run', 'check_output', 'check_call', 'call', 'communicate', 'wait'}
FILE_MARKER_LINES = 40
FILE_MARKER = re.compile(r'(?:#|//)\s*timeout-ok-file:\s*(\S.*)')
MEASURED_WORD = re.compile(r'\b(?:un)?measured\b', re.IGNORECASE)
UNMEASURED_WORD = re.compile(r'\bunmeasured\b', re.IGNORECASE)
EXPIRES = re.compile(r'\bexpires:\s*(\d{4}-\d{2}-\d{2})\b')
MARKER = re.compile(r'(?:#|//)\s*timeout-ok:\s*\S')
JS_TIMEOUT = re.compile(r'\btimeout\s*:\s*(\d[\d_]*)\b')


def literal_seconds(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
        return node.value
    return None


def justified(lines, first, last):
    """True when a timeout-ok marker sits on the line above or on any line of first..last (1-based)."""
    return any(MARKER.search(lines[i]) for i in range(max(first - 2, 0), min(last, len(lines))))


def file_marker_problem(lines, today):
    """Return (has_marker, line_number, problem); problem is None when the file-level marker is valid."""
    for number, line in enumerate(lines[:FILE_MARKER_LINES], 1):
        match = FILE_MARKER.search(line)
        if not match:
            continue
        text = match.group(1)
        if not MEASURED_WORD.search(text):
            return True, number, 'timeout-ok-file text must say "measured" or "UNMEASURED"'
        if UNMEASURED_WORD.search(text):
            expiry = EXPIRES.search(text)
            if not expiry:
                return True, number, 'UNMEASURED timeout-ok-file needs "expires: YYYY-MM-DD"'
            try:
                deadline = datetime.date.fromisoformat(expiry.group(1))
            except ValueError:
                return True, number, f'invalid expires date {expiry.group(1)}'
            if today > deadline:
                return True, number, f'UNMEASURED timeout-ok-file expired {deadline}; measure it and rewrite the marker'
        return True, number, None
    return False, 0, None


def file_marker_findings(lines, today):
    """None when the file has no file-level marker; otherwise the list of marker problems (empty when valid)."""
    has_marker, number, problem = file_marker_problem(lines, today)
    if not has_marker:
        return None
    return [(number, problem)] if problem else []


def python_findings(path, today=None):
    source = path.read_text()
    lines = source.splitlines()
    marker = file_marker_findings(lines, today or datetime.date.today())
    if marker is not None:
        return marker
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


def javascript_findings(path, today=None):
    lines = path.read_text().splitlines()
    marker = file_marker_findings(lines, today or datetime.date.today())
    if marker is not None:
        return marker
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
        if path.name != Path(__file__).name:
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

    def test_detector_flags_and_honours_markers(self):
        scratch = Path(tempfile.mkdtemp())
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

    def test_file_marker_requires_keyword_and_expiry(self):
        scratch = Path(tempfile.mkdtemp())
        clock = datetime.date(2026, 10, 28)
        body = 'import subprocess\nsubprocess.run(["x"], timeout=3)\n'

        def check(marker, today=clock):
            path = scratch / 'f.py'
            path.write_text(marker + '\n' + body)
            return [text for _, text in python_findings(path, today)]
        try:
            self.assertEqual(check('# timeout-ok-file: because I said so'),
                             ['timeout-ok-file text must say "measured" or "UNMEASURED"'])
            self.assertEqual(check('# timeout-ok-file: UNMEASURED: follow-up'),
                             ['UNMEASURED timeout-ok-file needs "expires: YYYY-MM-DD"'])
            self.assertEqual(len(check('# timeout-ok-file: UNMEASURED: x expires: 2026-12-31', datetime.date(2027, 1, 1))), 1)
            self.assertEqual(check('# timeout-ok-file: UNMEASURED: x expires: 2026-12-31'), [])
            self.assertEqual(check('# timeout-ok-file: UNMEASURED: x expires: 2026-12-31', datetime.date(2026, 12, 31)), [])
            self.assertEqual(check('# timeout-ok-file: measured 0.1 s'), [])
            js = scratch / 'a.ts'
            js.write_text('// timeout-ok-file: nope\nspawnSync(a, {timeout: 3000});\n')
            self.assertEqual(len(javascript_findings(js, clock)), 1)
        finally:
            for child in scratch.iterdir():
                child.unlink()
            scratch.rmdir()


if __name__ == '__main__':
    unittest.main(verbosity=2)
