#!/usr/bin/env python3
"""Check bounded, saved admission observations offline; never grant admission."""
import argparse
import json
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
REPO = Path(__file__).resolve().parents[2]
DEFAULT_TABLE = REPO / "docs/runbooks/router-admission-facts.md"
MAX_INPUT = 1048576
MAX_LINES = 4096
MAX_LINE = 1024


def load_expectations(path=DEFAULT_TABLE):
    """The audit table's inline JSON is the checker source of truth."""
    rules = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.startswith("|"):
            continue
        cells = line.split("|")
        fact_id = cells[1].strip().strip("`")
        if not fact_id.startswith(("path:", "runtime:", "probe:", "tool:", "system:")):
            continue
        matches = re.findall(r"`(\[[^`]*\]|\{[^`]*\})`", line)
        if len(matches) != 1 or fact_id in rules:
            raise ValueError("invalid or duplicate audit-table row")
        rule = json.loads(matches[0])
        if isinstance(rule, list):
            if not rule or not all(isinstance(value, str) for value in rule):
                raise ValueError("invalid audit-table allowlist")
        elif isinstance(rule, dict):
            if rule.get("observable") is False:
                if not isinstance(rule.get("reason"), str) or not rule["reason"]:
                    raise ValueError("unknown gate needs a reason")
            elif set(rule) == {"min", "max"}:
                if type(rule["min"]) is not int or type(rule["max"]) is not int or not 0 <= rule["min"] <= rule["max"]:
                    raise ValueError("invalid audit-table bounds")
            elif set(rule) == {"owner", "safe_mode", "exceptions"}:
                if not re.fullmatch(r"[0-9]+:[0-9]+", rule["owner"]) or rule["safe_mode"] is not True:
                    raise ValueError("invalid metadata predicate")
                if not isinstance(rule["exceptions"], list) or not all(re.fullmatch(r"[0-7]{3,4}", mode) for mode in rule["exceptions"]):
                    raise ValueError("invalid metadata exceptions")
            else:
                raise ValueError("unsupported audit-table predicate")
        else:
            raise ValueError("invalid audit-table predicate")
        rules[fact_id] = rule
    if rules.get("probe:format") != ["1"] or "path:/usr/share:metadata" not in rules:
        raise ValueError("incomplete audit table")
    return rules


def valid_value(fact_id, value):
    if value == "UNOBSERVABLE":
        return True
    if fact_id.startswith("runtime:"):
        return False
    if fact_id == "probe:format":
        return value == "1"
    if fact_id.startswith("tool:") or fact_id in {
        "system:root-credentials", "system:mountinfo-readable", "system:boot-id-shape",
        "system:stat-mtime-format", "system:stat-mount-format"
    }:
        return value in {"yes", "no"}
    if fact_id == "system:architecture":
        return value in {"aarch64", "OTHER"}
    if fact_id in {"system:epoch", "system:uptime-centiseconds"}:
        return bool(re.fullmatch(r"0|[1-9][0-9]{0,12}", value))
    suffix = fact_id.rsplit(":", 1)[-1]
    if suffix == "metadata":
        return bool(re.fullmatch(r"[0-9]{1,10}:[0-9]{1,10}:[0-7]{3,4}", value))
    if suffix in {"size", "links"}:
        return bool(re.fullmatch(r"0|[1-9][0-9]{0,9}", value))
    if suffix == "sha256":
        return bool(re.fullmatch(r"[0-9a-f]{64}", value))
    if suffix == "type":
        return value in {"dir", "file", "link", "other", "missing"}
    if suffix == "canonical":
        return value in {"yes", "no"}
    if suffix == "link":
        return value in {"libc.so", "/usr/libexec/stat-coreutils", "tmp", "OTHER"}
    return False


def parse_facts(data, rules):
    if len(data) > MAX_INPUT:
        raise ValueError("input exceeds byte limit")
    if any((byte < 32 and byte != 10) or byte == 127 for byte in data):
        raise ValueError("control byte in FACT input")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("non-ASCII input") from error
    lines = text.splitlines()
    if len(lines) > MAX_LINES:
        raise ValueError("input exceeds line limit")
    facts = {}
    for line in lines:
        if len(line) > MAX_LINE or not re.fullmatch(r"FACT [A-Za-z0-9_./:+-]+ [A-Za-z0-9_./:+-]+", line):
            raise ValueError("malformed FACT record")
        _, fact_id, value = line.split(" ")
        if fact_id not in rules:
            raise ValueError("unknown fact ID")
        if fact_id in facts:
            raise ValueError("duplicate fact ID")
        if not valid_value(fact_id, value):
            raise ValueError("invalid fact value")
        facts[fact_id] = value
    return facts


def matches(value, rule):
    if isinstance(rule, list):
        return value in rule
    if "min" in rule:
        return bool(re.fullmatch(r"0|[1-9][0-9]*", value)) and rule["min"] <= int(value) <= rule["max"]
    if rule.get("safe_mode"):
        if not re.fullmatch(r"[0-9]{1,10}:[0-9]{1,10}:[0-7]{3,4}", value):
            return False
        uid, gid, mode = value.split(":")
        return f"{uid}:{gid}" == rule["owner"] and (
            int(mode, 8) & 0o7022 == 0 or mode in rule["exceptions"]
        )
    return False


def assess(facts, rules):
    rows = []
    for fact_id, rule in rules.items():
        value = facts.get(fact_id)
        if isinstance(rule, dict) and rule.get("observable") is False:
            rows.append(("SKIP", fact_id, rule["reason"]))
            continue
        base = fact_id.rsplit(":", 1)[0]
        optional_type = rules.get(base + ":type", [])
        optional_absent = (
            fact_id.startswith("path:") and facts.get(base + ":type") == "missing"
            and isinstance(optional_type, list) and "missing" in optional_type
        )
        if value is None or value == "UNOBSERVABLE":
            if optional_absent:
                rows.append(("SKIP", fact_id, "optional path absent"))
            else:
                rows.append(("MISSING", fact_id, "not observed" if value is None else "read unavailable"))
        elif matches(value, rule):
            rows.append(("PASS", fact_id, ""))
        else:
            rows.append(("FAIL", fact_id, "observed value violates audit table"))
    return rows


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("facts", nargs="?", default="-", help="saved probe output, or - for stdin")
    parser.add_argument("--table", type=Path, default=DEFAULT_TABLE, help="reviewed audit table")
    args = parser.parse_args(argv)
    try:
        rules = load_expectations(args.table)
        if args.facts == "-":
            data = sys.stdin.buffer.read(MAX_INPUT + 1)
        else:
            with open(args.facts, "rb") as stream:
                data = stream.read(MAX_INPUT + 1)
        facts = parse_facts(data, rules)
        rows = assess(facts, rules)
    except (OSError, ValueError, TypeError, KeyError) as error:
        # No untrusted file contents or filenames enter diagnostics.
        print("FAIL input invalid or unavailable: " + (
            str(error) if isinstance(error, ValueError) else type(error).__name__
        ))
        return 2
    for status, fact_id, reason in rows:
        rule = json.dumps(rules.get(fact_id, {"observable": False, "reason": "no admission predicate"}), separators=(",", ":"), ensure_ascii=True)
        observed = facts.get(fact_id, "NOT_CAPTURED")
        print(f"{status} {fact_id} observed={observed} rule={rule}" + (f" {reason}" if reason else ""))
    counts = {status: sum(row[0] == status for row in rows) for status in ("PASS", "FAIL", "MISSING", "SKIP")}
    incomplete = counts["MISSING"] or counts["SKIP"]
    print("RESULT " + ("INCOMPLETE" if incomplete else "COMPLETE") + " " + " ".join(f"{key.lower()}={value}" for key, value in counts.items()))
    print("Observation only: no installer execution, writes, credential attestation or live admission proved.")
    return 1 if counts["FAIL"] or counts["MISSING"] else 0


if __name__ == "__main__":
    raise SystemExit(main())

