#!/usr/bin/python3
"""Deterministic command doubles: these never exercise packet enforcement.

All subprocess arguments are recorded as arrays, never evaluated as shell code.
State and failure injection live entirely below CF_BACKEND_STATE.
"""
import fcntl
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time


def main():
    command, args = sys.argv[1], sys.argv[2:]
    state_path = Path(os.environ["CF_BACKEND_STATE"])
    with open(str(state_path) + ".lock", "a", encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = json.loads(state_path.read_text())
        with open(os.environ["CF_BACKEND_LOG"], "a", encoding="utf-8") as log:
            log.write(json.dumps({"command": command, "argv": args}) + "\n")
        for failure in state.get("failures", []):
            if (failure["command"] == command
                    and all(part in args for part in failure.get("contains", []))
                    and failure.get("remaining", 1)):
                failure["remaining"] = failure.get("remaining", 1) - 1
                state_path.write_text(json.dumps(state))
                print(failure.get("message", "injected backend failure"), file=sys.stderr)
                return failure.get("exit", 2)
        for delay in state.get("delays", []):
            if delay["command"] == command and all(p in args for p in delay.get("contains", [])):
                time.sleep(delay["seconds"])
        try:
            result, output = dispatch(command, args, state)
        except (KeyError, ValueError, IndexError) as error:
            print(f"unsupported fixture call {command} {args!r}: {error}", file=sys.stderr)
            return 97
        state_path.write_text(json.dumps(state))
        if output:
            print(output)
        return result


def dispatch(command, args, state):
    if command == "ipset":
        return ipset(args, state)
    if command in ("iptables", "ip6tables"):
        return iptables(command, args, state)
    if command in ("iptables-save", "ip6tables-save"):
        table = command.removesuffix("-save")
        return 0, "\n".join(f"-A {chain} {' '.join(rule)}" for chain, rules in state["tables"][table].get("filter", {}).items() for rule in rules)
    if command == "uci":
        return uci(args, state)
    if command == "conntrack":
        if "-D" not in args:
            raise ValueError("only conntrack deletion is modeled")
        state.setdefault("conntrack_deletions", []).append(args)
        return 0, ""
    if command == "ip":
        family = 6 if "-6" in args else 4
        if "neigh" in args or "neighbor" in args:
            selected = "dev" in args and args[args.index("dev") + 1] == "br-lan"
            def neighbor_line(row):
                device = row.get("dev", "br-lan")
                interface = "" if selected and device == "br-lan" and not state.get("neighbor_explicit_dev") else " dev " + device
                return f"{row['ip']}{interface} lladdr {row['mac']} {row.get('state', 'REACHABLE')}"
            return 0, "\n".join(neighbor_line(row) for row in state.get("neighbors", []) if (":" in row["ip"]) == (family == 6))
        if "addr" in args or "address" in args:
            return 0, "\n".join(state.get(f"addresses{family}", []))
        if "route" in args:
            return 0, "\n".join(state.get(f"routes{family}", []))
        raise ValueError("unsupported ip operation")
    if command == "jsonfilter":
        return jsonfilter(args)
    if command in ("fw3", "firewall"):
        state.setdefault("firewall_calls", []).append(args)
        if args == ["-q", "zone", "wan"]:
            return 0, "\n".join(state.get("wan_devices", ["eth0"]))
        if "reload" in args:
            reload_firewall(state)
            include_installed = state["uci"].get("firewall.couvrefeu.path") == "/etc/firewall.couvrefeu"
            if state.get("reload_include") and (command == "fw3" or include_installed):
                core = Path(__file__).resolve().parents[2] / "router/cfctl"
                shell = shlex.split(os.environ.get("CF_TEST_SHELL", "sh"))
                result = subprocess.run(shell + [str(core), "apply-fw"], env=os.environ,
                                        text=True, capture_output=True, timeout=5)
                state.setdefault("reload_includes", []).append({
                    "returncode": result.returncode, "stdout": result.stdout,
                    "stderr": result.stderr})
                if result.returncode:
                    return result.returncode, result.stdout
        return 0, ""
    raise ValueError("unknown backend")


def reload_firewall(state):
    """Model native witnesses and include callback, never compile real fw3 rules."""
    uci(["show", "firewall"], state)
    values = state["uci"]
    native = []
    for key, value in values.items():
        if key.count(".") != 1 or not key.startswith("firewall.cf_sched_") or value != "rule":
            continue
        if values.get(key + ".couvrefeu_owner") != "v1":
            continue
        native.append(["-m", "mac", "--mac-source", values[key + ".src_mac"],
                       "-m", "time", "--timestart", values[key + ".start_time"],
                       "--timestop", values[key + ".stop_time"],
                       "--weekdays", values[key + ".weekdays"].replace(" ", ","),
                       "--kerneltz", "-m", "comment", "--comment",
                       "!fw3: " + key.split(".")[1], "-j", "zone_wan_dest_REJECT"])
    for family in state["tables"].values():
        for table in family.values():
            for chain in list(table):
                if chain.startswith(("CF_", "cf_")):
                    del table[chain]
                else:
                    table[chain] = [rule for rule in table[chain]
                                    if not ("-j" in rule and rule[rule.index("-j") + 1].startswith(("CF_", "cf_")))]
        family["filter"]["zone_lan_forward"] = [list(row) for row in native] if state.get("native_witness") else []
        family["filter"]["zone_wan_dest_REJECT"] = [["-o", device, "-j", "reject"]
                                                    for device in state.get("wan_devices", ["eth0"])]
        family["filter"]["reject"] = [["-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"],
                                        ["-j", "REJECT"]]


def ipset(args, state):
    tolerate_exists = "-exist" in args or "-!" in args
    args = [arg for arg in args if arg not in ("-exist", "-!", "-quiet")]
    op = args[0]
    sets = state.setdefault("sets", {})
    if op == "restore":
        for line in sys.stdin:
            result, _ = ipset(shlex.split(line), state)
            if result:
                return result, ""
        return 0, ""
    name = args[1] if len(args) > 1 else None
    if op in ("create", "-N"):
        if name in sets and not tolerate_exists:
            return 1, ""
        metadata = {"type": args[2], "members": []}
        if args[2] == "hash:ip":
            metadata["family"] = args[args.index("family") + 1] if "family" in args else "inet"
        sets.setdefault(name, metadata)
    elif op in ("add", "-A"):
        if name not in sets:
            return 1, ""
        if args[2].lower() in sets[name]["members"] and not tolerate_exists:
            return 1, ""
        if args[2].lower() not in sets[name]["members"]:
            sets[name]["members"].append(args[2].lower())
    elif op in ("del", "-D"):
        if name not in sets or args[2].lower() not in sets[name]["members"]:
            return (0 if tolerate_exists else 1), ""
        if args[2].lower() in sets[name]["members"]:
            sets[name]["members"].remove(args[2].lower())
    elif op == "test":
        if name not in sets:
            return 1, ""
        return int(args[2].lower() not in sets[name]["members"]), ""
    elif op in ("flush", "-F"):
        if name not in sets:
            return 1, ""
        sets[name]["members"] = []
    elif op in ("destroy", "-X"):
        if name not in sets:
            return (0 if tolerate_exists else 1), ""
        sets.pop(name, None)
    elif op == "swap":
        sets[name], sets[args[2]] = sets[args[2]], sets[name]
    elif op in ("list", "save", "-L"):
        if name and name not in sets:
            return 1, ""
        selected = {name: sets[name]} if name else sets
        if op == "save":
            return 0, "\n".join(line for key, value in selected.items() for line in [f"create {key} {value['type']}" + (" family " + value["family"] if "family" in value else ""), *[f"add {key} {mac}" for mac in value["members"]]])
        return 0, "\n".join(f"Name: {key}\nType: {value['type']}\nHeader: family inet\nReferences: 0\nNumber of entries: {len(value['members'])}\nMembers:\n" + "\n".join(value["members"]) for key, value in selected.items())
    else:
        raise ValueError("unknown ipset operation")
    return 0, ""


def iptables(command, args, state):
    args = list(args)
    table = "filter"
    if "-t" in args:
        index = args.index("-t")
        table = args[index + 1]
        del args[index:index + 2]
    if "-w" in args:
        index = args.index("-w")
        del args[index]
        if index < len(args) and args[index].isdigit():
            del args[index]
    chains = state.setdefault("tables", {}).setdefault(command, {}).setdefault(table, {})
    operation = args[0]
    chain = args[1] if len(args) > 1 else None
    rule = args[2:]
    if operation == "-N":
        if chain in chains:
            return 1, ""
        chains[chain] = []
    elif operation == "-F":
        if chain not in chains:
            return 1, ""
        chains[chain] = []
    elif operation == "-X":
        if chain not in chains or chains[chain] or any(
                "-j" in row and row[row.index("-j") + 1] == chain
                for rows in chains.values() for row in rows):
            return 1, ""
        del chains[chain]
    elif operation in ("-A", "-I"):
        if chain not in chains:
            return 1, ""
        index = len(chains[chain]) if operation == "-A" else 0
        if operation == "-I" and rule and rule[0].isdigit():
            index, rule = int(rule[0]) - 1, rule[1:]
        chains[chain].insert(index, rule)
    elif operation in ("-C", "-D"):
        if chain not in chains or rule not in chains[chain]:
            return 1, ""
        if operation == "-D":
            chains[chain].remove(rule)
    elif operation in ("-S", "-L"):
        if chain and chain not in chains:
            return 1, ""
        selected = {chain: chains[chain]} if chain else chains
        builtin = {"INPUT", "OUTPUT", "FORWARD", "PREROUTING", "POSTROUTING"}
        lines = []
        for key, rows in selected.items():
            if operation == "-S" and key not in builtin:
                lines.append("-N " + key)
            lines.extend(f"-A {key} {serialize_rule(row, state.get('canonical_rules', False), command)}" for row in rows)
        return 0, "\n".join(lines)
    else:
        raise ValueError("unknown iptables operation")
    return 0, ""


def serialize_rule(row, canonical, command):
    row = list(row)
    if not canonical:
        return " ".join(json.dumps(value) if any(char.isspace() for char in value) else value for value in row)
    if "--mac-source" in row:
        index = row.index("--mac-source") + 1
        row[index] = row[index].upper()
    if "-p" in row:
        protocol = row[row.index("-p") + 1]
        if protocol in ("tcp", "udp") and not any(row[index:index + 2] == ["-m", protocol] for index in range(len(row))):
            row[row.index("-p") + 2:row.index("-p") + 2] = ["-m", protocol]
    if "REJECT" in row and "--reject-with" not in row:
        row += ["--reject-with", "icmp6-port-unreachable" if command == "ip6tables" else "icmp-port-unreachable"]
    if "--weekdays" in row:
        index = row.index("--weekdays") + 1
        order = {day: i for i, day in enumerate(("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"))}
        row[index] = ",".join(sorted(row[index].split(","), key=lambda day: order[day]))
    if "-i" in row:
        index = row.index("-i")
        selector = row[index:index + 2]
        del row[index:index + 2]
        row = selector + row
    return " ".join(json.dumps(value) if any(char.isspace() for char in value) else value for value in row)


def uci(args, state):
    args = list(args)
    directory = Path(os.environ["CF_ROOT"]) / "etc/config"
    if "-c" in args:
        index = args.index("-c")
        directory = Path(args[index + 1])
        del args[index:index + 2]
    if "-t" in args:
        index = args.index("-t")
        del args[index:index + 2]
    args = [arg for arg in args if arg not in ("-q", "-X")]
    op = args[0]
    if op == "changes":
        return 0, state.get("uci_deltas", "")
    values = state.setdefault("uci", {})
    # Keep staged namespaces separate; commit changes only the fake staged file.
    # Direct reads observe an atomically moved staged file, never optimistic state.
    namespaces = state.setdefault("uci_namespaces", {})
    namespace = str(directory)
    if namespace not in namespaces:
        namespaces[namespace] = dict(values)
    selected = namespaces[namespace]
    config = directory / "firewall"
    if config.exists():
        section = None
        parsed = {}
        for line in config.read_text().splitlines():
            tokens = shlex.split(line, comments=True)
            if not tokens:
                continue
            if tokens[0] == "config" and len(tokens) == 3:
                section = tokens[2]
                parsed["firewall." + section] = tokens[1]
            elif tokens[0] in ("option", "list") and len(tokens) == 3 and section:
                key = "firewall." + section + "." + tokens[1]
                parsed[key] = (parsed.get(key, "") + " " + tokens[2]).strip() if tokens[0] == "list" else tokens[2]
        # Dirty staged changes are kept until commit, as real UCI deltas are.
        if not state.setdefault("uci_dirty", {}).get(namespace):
            selected = {key: value for key, value in selected.items() if not key.startswith("firewall.")}
            selected.update(parsed)
            namespaces[namespace] = selected
    values = selected
    if op == "batch":
        for line in sys.stdin:
            result, _ = uci(["-c", namespace] + shlex.split(line), state)
            if result:
                return result, ""
        return 0, ""
    if op == "commit":
        if len(args) > 1 and args[1] == "firewall":
            config.parent.mkdir(parents=True, exist_ok=True)
            lines = []
            for name, value in sorted(values.items()):
                parts = name.split(".")
                if len(parts) == 2 and parts[0] == "firewall":
                    lines.append("config " + shlex.quote(value) + " " + shlex.quote(parts[1]))
                    lines.extend("\toption " + shlex.quote(key[len(name) + 1:]) + " " + shlex.quote(option)
                                 for key, option in sorted(values.items()) if key.startswith(name + "."))
            config.write_text("\n".join(lines) + "\n")
            state["uci_dirty"][namespace] = False
        if directory == Path(os.environ["CF_ROOT"]) / "etc/config":
            state["uci"] = dict(values)
        return 0, ""
    if op == "revert":
        state["uci_dirty"][namespace] = False
        return 0, ""
    key = args[1]
    if op == "set":
        key, value = key.split("=", 1)
        values[key] = value
        state["uci_dirty"][namespace] = True
    elif op == "add_list":
        key, value = key.split("=", 1)
        values[key] = (values.get(key, "") + " " + value).strip()
        state["uci_dirty"][namespace] = True
    elif op == "delete":
        if key not in values and not any(k.startswith(key + ".") for k in values):
            return 1, ""
        for existing in list(values):
            if existing == key or existing.startswith(key + "."):
                del values[existing]
        state["uci_dirty"][namespace] = True
    elif op == "get":
        return (0, values[key]) if key in values else (1, "")
    elif op in ("show", "export"):
        if directory == Path(os.environ["CF_ROOT"]) / "etc/config":
            state["uci"] = dict(values)
        return 0, "\n".join(f"{name}={shlex.quote(value)}" for name, value in sorted(values.items()) if name == key or name.startswith(key + "."))
    else:
        raise ValueError("unknown uci operation")
    return 0, ""


def jsonfilter(args):
    """Subset double, explicitly not evidence for the target OpenWrt parser."""
    if "-i" in args:
        raw = Path(args[args.index("-i") + 1]).read_text()
    elif "-s" in args:
        raw = args[args.index("-s") + 1]
    else:
        raw = sys.stdin.read()
    document = json.loads(raw)
    expression = args[args.index("-e") + 1]
    if expression == "@":
        return 0, json.dumps(document, separators=(",", ":"))
    import re
    parts = re.findall(r"\.([A-Za-z_][A-Za-z_0-9]*)|\[([0-9]+|\*)\]", expression.removeprefix("@"))
    nodes = [document]
    for key, index in parts:
        nodes = [child for node in nodes for child in ((list(node.values()) if isinstance(node, dict) else node) if index == "*" else [node[key] if key else node[int(index)]])]
    def encode(node):
        if isinstance(node, bool):
            return "true" if node else "false"
        if isinstance(node, (dict, list)):
            return json.dumps(node, separators=(",", ":"))
        if node is None:
            return "null"
        return str(node)
    return 0, "\n".join(map(encode, nodes))


if __name__ == "__main__":
    sys.exit(main())
