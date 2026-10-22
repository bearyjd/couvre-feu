#!/usr/bin/env python3
"""M1e: read-only `cfctl rpc-inventory --json` (docs/contracts/tier1-rpc.md section 2, LOCKED v1).

Isolated fixtures only (no SSH, Dropbear, router or packets). All MACs are fictional.

Mutation checks (each applied to a COPY of the repository, re-frozen, and required to turn this suite red):
  include protected devices; count FAILED neighbours; sort IPv4 numerically; strip instead of reject
  hostnames; take the lock; write a file; drop the guest-subnet filter; drop the size guard; emit the keys
  in a different order; drop cf_protected_valid from admission; validate lease rows before the subnet and
  expiry filters; ignore a protected-list read error; default the prefix to 0 when the br-lan mask is
  missing; lose the collect error code in the subshell; drop the neighbour subnet filter; remove the
  distinct-MAC intake cap.

Golden replies (tests/fixtures/inventory-golden) are produced by this router fixture and parsed by the REAL
service parser in shared/tests/router-inventory-golden.test.ts. Regenerate with CF_INVENTORY_GOLDEN_WRITE=1.
"""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent / 'fixtures'))
from harness import KID, OTHER_KID, PROTECTED, REPO, RouterFixture, policy  # noqa: E402

KEYS = ['inventory_version', 'generation', 'routerTime', 'devices', 'truncated', 'errors']
DEVICE_KEYS = ['mac', 'ipv4', 'hostname', 'source']
NOW = 1736204400
GOLDEN = REPO / 'tests/fixtures/inventory-golden'
GOLDEN_GENERATION = '5a' * 32
BUSYBOX = shutil.which('busybox') or str(Path.home() / '.local/bin/busybox')  # CI installs it on PATH
# Raw-reply shape the service enforces before JSON.parse (shared/src/router-inventory.ts assertPlainInventoryText).
PLAIN = re.compile(r'^[\x20-\x7e]*\n$')


def mac(n):
    return '02:00:00:00:{:02x}:{:02x}'.format(n // 256, n % 256)


def c_sorted(values):
    """C-locale order, computed independently of the router: byte order."""
    return sorted(values, key=lambda value: value.encode())


class InventoryCommon:
    def setUp(self):
        self.f = RouterFixture()
        self.runtime = self.f.root / 'etc/couvrefeu/runtime'
        self.install()

    def tearDown(self):
        self.f.close()

    def script(self, name, *args, env=None):
        return subprocess.run(self.f.shell + [str(REPO / 'router' / name), *args],
                              env=env or self.f.env, capture_output=True, text=True, timeout=120)

    def install(self, *floor):
        args = ['--activate', '--protect', PROTECTED]
        for address in floor or (KID,):
            args += ['--rpc-allow', address]
        result = self.script('install.sh', *args)
        self.assertEqual(result.returncode, 0, result.stderr)

    def generation(self):
        result = self.f.run('rpc-status', '--json')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return json.loads(result.stdout)['generation']

    def neighbours(self, rows):
        self.f.update_backend(neighbors=rows)

    def leases(self, text):
        path = self.f.root / 'tmp/dhcp.leases'
        path.write_bytes(text.encode() if isinstance(text, str) else text)

    def raw(self, env=None, code=0):
        result = self.f.run('rpc-inventory', '--json', env=env)
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        return result.stdout

    def inventory(self, env=None, code=0):
        text = self.raw(env, code)
        self.assertRegex(text, PLAIN)
        self.assertLess(len(text.encode()), 131072)
        # Integers only outside strings (no 1.0, 5e0 or -0), as the service's raw-text gate checks.
        for token in re.findall(r'-?[0-9][0-9.eE+-]*', re.sub(r'"[^"]*"', '""', text)):
            self.assertRegex(token, r'^(0|[1-9][0-9]*)$')
        document = json.loads(text)
        self.assertEqual(list(document), KEYS)
        for device in document['devices']:
            self.assertEqual(list(device), DEVICE_KEYS)
        macs = [device['mac'] for device in document['devices']]
        self.assertEqual(macs, c_sorted(set(macs)))
        self.assertNotIn(PROTECTED, text)
        return document

    def by_mac(self, document):
        return {device['mac']: device for device in document['devices']}

    def core_shell(self, body):
        prelude = ('set -f;PATH=/usr/sbin:/usr/bin:/sbin:/bin;LC_ALL=C;umask 077;CF_LOCAL_TEST=1;CF_BASE=$CF_ROOT\n'
                   'CF_LIB=' + str(REPO / 'router/lib') + '\n. "$CF_LIB/platform-bootstrap.sh"\n'
                   'platform_entry_root_validate;platform_choose runtime "$CF_BASE"\n. "$CF_LIB/core.sh"\n'
                   'platform_admit runtime "$CF_BASE" "$CF_LIB"\n. "$CF_LIB/rpc.sh";. "$CF_LIB/firewall.sh";. "$CF_LIB/activity.sh"\n')
        return subprocess.run(self.f.shell + ['-c', prelude + body], env=self.f.env, stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=120)

    def busybox_inventory(self):
        """The real collection under BusyBox awk (the router's awk): cfctl itself needs busybox on the system PATH."""
        if not os.access(BUSYBOX, os.X_OK):
            self.skipTest('busybox unavailable')
        result = self.core_shell('awk(){ %s awk "$@"; }\ncf_rpc_inventory' % BUSYBOX)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertRegex(result.stdout, PLAIN)
        return json.loads(result.stdout)

    def refused(self, document, code):
        self.assertEqual(document['devices'], [])
        self.assertIs(document['truncated'], False)
        self.assertEqual(document['routerTime'], 0)
        self.assertEqual(document['errors'], [code])

    def tree(self):
        """Every file and directory of the private root except the fake backend's own bookkeeping."""
        skip = ('backend.json', 'backend.jsonl', 'backend-bin')
        result = {}
        for path in sorted(self.f.root.rglob('*')):
            relative = path.relative_to(self.f.root)
            if relative.parts[0] in skip:
                continue
            stat = path.lstat()
            result[str(relative)] = (path.read_bytes() if path.is_file() else None, stat.st_mode)
        return result


class InventoryTests(InventoryCommon, unittest.TestCase):
    def test_baseline_shape_generation_time_and_protected_exclusion(self):
        # The protected device is present as a neighbour AND (upper-case) as a lease: it is never listed, never counted.
        self.leases('0 {} 192.168.1.20 fixture *\n0 {} 192.168.1.22 fixture2 *\n0 {} 192.168.1.10 admin-pc *\n'
                    .format(KID, OTHER_KID, PROTECTED.upper()))
        document = self.inventory()
        self.assertEqual(document['inventory_version'], 1)
        self.assertEqual(document['generation'], self.generation())
        self.assertEqual(document['routerTime'], NOW)
        self.assertIs(document['truncated'], False)
        self.assertEqual(document['errors'], [])
        self.assertEqual(document['devices'], [
            {'mac': KID, 'ipv4': ['192.168.1.20', '192.168.1.21'], 'hostname': 'fixture', 'source': 'both'},
            {'mac': OTHER_KID, 'ipv4': ['192.168.1.22'], 'hostname': 'fixture2', 'source': 'both'}])
        self.assertNotIn('protected', json.dumps(document).lower())

    def test_sources_and_neighbour_states(self):
        rows = [
            {'ip': '192.168.1.31', 'mac': mac(2), 'state': 'REACHABLE'},     # neigh only
            {'ip': '192.168.1.32', 'mac': mac(3), 'state': 'STALE'},         # both
            {'ip': '192.168.1.33', 'mac': mac(4), 'state': 'FAILED'},        # not counted
            {'ip': '192.168.1.34', 'mac': mac(5), 'state': 'INCOMPLETE'},    # not counted; lease keeps it
            {'ip': '192.168.1.44', 'mac': mac(5), 'state': 'FAILED'},
            {'ip': '192.168.1.35', 'mac': mac(6), 'state': 'DELAY'},
            {'ip': '192.168.1.36', 'mac': mac(7), 'state': 'PROBE'},
            {'ip': '192.168.1.37', 'mac': mac(8), 'state': 'PERMANENT'},
            {'ip': '192.168.1.38', 'mac': mac(9), 'state': 'NOARP'},
            {'ip': '192.168.1.39', 'mac': mac(10), 'state': 'REACHABLE', 'dev': 'wlan-guest'},  # not br-lan
            {'ip': '192.168.1.10', 'mac': PROTECTED, 'state': 'REACHABLE'},
        ]
        self.neighbours(rows)
        self.leases('0 {} 192.168.1.30 lease-only *\n0 {} 192.168.1.32 both-a *\n0 {} 192.168.1.54 inc *\n'
                    .format(mac(1), mac(3), mac(5)))
        document = self.inventory()
        self.assertEqual(document['errors'], [])
        found = {d['mac']: (d['ipv4'], d['source']) for d in document['devices']}
        self.assertEqual(found, {
            mac(1): (['192.168.1.30'], 'lease'),
            mac(2): (['192.168.1.31'], 'neigh'),
            mac(3): (['192.168.1.32'], 'both'),
            mac(5): (['192.168.1.54'], 'lease'),
            mac(6): (['192.168.1.35'], 'neigh'),
            mac(7): (['192.168.1.36'], 'neigh'),
            mac(8): (['192.168.1.37'], 'neigh'),
        })

    def test_ipv4_c_locale_string_order_unique_and_capped_at_four(self):
        self.neighbours([{'ip': ip, 'mac': mac(1)} for ip in ('192.168.1.9', '192.168.1.100', '192.168.1.2')])
        self.leases(''.join('0 {} {} multi *\n'.format(mac(1), ip) for ip in ('192.168.1.10', '192.168.1.9', '192.168.1.30')))
        device = self.by_mac(self.inventory())[mac(1)]
        # Five distinct addresses; the four smallest in C order (192.168.1.10 BEFORE 192.168.1.9).
        self.assertEqual(device['ipv4'], ['192.168.1.10', '192.168.1.100', '192.168.1.2', '192.168.1.30'])
        self.assertEqual(device['ipv4'], c_sorted(device['ipv4']))
        self.assertEqual(device['source'], 'both')

    def test_ipv4_dot_sorts_before_digits_on_a_wide_subnet(self):
        # 10.0.1.5 < 10.0.10.5 in C order ('.' 0x2e < '0' 0x30); ranking '.' after the digits reverses them.
        backend = self.f.backend()
        backend['uci']['network.lan.ipaddr'] = '10.0.0.1'
        self.f.update_backend(uci=backend['uci'], addresses4=['2: br-lan    inet 10.0.0.1/16 scope global br-lan'],
                              neighbors=[{'ip': '10.0.10.5', 'mac': mac(1)}, {'ip': '10.0.1.5', 'mac': mac(1)}])
        self.leases('0 {} 10.0.20.7 wide *\n0 {} 10.0.2.7 wide *\n0 {} 10.1.0.9 outside *\n'.format(mac(2), mac(2), mac(3)))
        found = self.by_mac(self.inventory())
        self.assertEqual(found[mac(1)]['ipv4'], ['10.0.1.5', '10.0.10.5'])
        self.assertEqual(found[mac(2)]['ipv4'], ['10.0.2.7', '10.0.20.7'])
        self.assertNotIn(mac(3), found)

    def test_hostnames_rejected_never_stripped(self):
        names = {1: ('host-a.lan_1', 'host-a.lan_1'), 2: ('*', None), 3: ('', None), 4: ('bad!name', None),
                 5: ('a' * 63, 'a' * 63), 6: ('a' * 64, None), 7: ('-lead', None), 8: ('.lead', None),
                 9: ('tab\tname', None), 10: ('ctl\x01name', None), 11: ('<script>', None), 12: ('quo"te', None),
                 13: ('back\\slash', None), 14: ('caf\xe9', None), 15: ('9Lives', '9Lives'), 16: ('_under', None)}
        text = ''.join('0 {} 192.168.1.{} {} *\n'.format(mac(100 + n), 100 + n, name) for n, (name, _) in names.items())
        # Field count other than dnsmasq's five: the hostname is ambiguous, so null (the row itself is sound).
        text += '0 {} 192.168.1.130 two words *\n'.format(mac(30))
        self.leases(text.encode('latin-1'))
        document = self.inventory()
        found = self.by_mac(document)
        for n, (name, expected) in names.items():
            with self.subTest(name=name):
                self.assertEqual(found[mac(100 + n)]['hostname'], expected)
                self.assertEqual(found[mac(100 + n)]['source'], 'lease')
        self.assertIsNone(found[mac(30)]['hostname'])
        self.assertEqual(document['errors'], [])

    def test_guest_subnet_and_expired_leases_excluded_without_errors(self):
        self.neighbours([{'ip': '192.168.1.40', 'mac': mac(2)}])
        self.leases('0 {} 192.168.8.50 guest *\n0 {} 192.168.8.51 guest2 *\n{} {} 192.168.1.60 old *\n{} {} 192.168.1.61 fresh *\n'
                    .format(mac(1), mac(2), NOW - 1, mac(3), NOW + 600, mac(4)))
        document = self.inventory()
        found = self.by_mac(document)
        self.assertNotIn(mac(1), found)
        self.assertEqual(found[mac(2)], {'mac': mac(2), 'ipv4': ['192.168.1.40'], 'hostname': None, 'source': 'neigh'})
        self.assertNotIn(mac(3), found)
        self.assertEqual(found[mac(4)]['ipv4'], ['192.168.1.61'])
        self.assertNotIn('192.168.8.', json.dumps(document))
        self.assertEqual(document['errors'], [])

    def test_malformed_rows_dropped_and_reported_once(self):
        self.neighbours([{'ip': '192.168.1.20', 'mac': KID}, {'ip': '192.168.1.70', 'mac': 'zz:00:00:00:00:01'},
                         {'ip': '192.168.1.071', 'mac': mac(9)}])
        self.leases('duid 00:01:00:01:2c:00:00:00:02:00:00:00:00:01\n'
                    '1736300000 1234 2001:db8::5 v6host *\n'
                    '0 01:00:5e:00:00:01 192.168.1.80 multicast *\n'
                    '0 00:00:00:00:00:00 192.168.1.81 zero *\n'
                    '0 02:00:00:00:00 192.168.1.82 short *\n'
                    '0 {} 192.168.1.256 badip *\n'
                    '0 {} 192.168.1.083 leadingzero *\n'
                    'never {} 192.168.1.84 badexpiry *\n'
                    '0 {}\n'
                    '0 {} 192.168.1.85 good *\n'.format(mac(1), mac(2), mac(3), mac(4), mac(5)))
        document = self.inventory()
        self.assertEqual(document['errors'], ['inventory_row_dropped'])
        self.assertEqual(sorted(self.by_mac(document)), [KID, mac(5)])

    def test_invalid_clock_reports_zero_time_and_keeps_devices(self):
        self.leases('0 {} 192.168.1.20 fixture *\n{} {} 192.168.1.90 stale-clock *\n'.format(KID, NOW - 10, mac(300)))
        document = self.inventory(env=dict(self.f.env, CF_NOW='0'))
        self.assertEqual(document['routerTime'], 0)
        self.assertEqual(document['errors'], ['invalid_clock'])
        self.assertIn(KID, self.by_mac(document))
        self.assertIn(mac(300), self.by_mac(document))

    def test_read_only_lockless_and_creates_nothing(self):
        before = self.tree()
        calls = len(self.f.mutation_calls())
        holder = subprocess.Popen(['sleep', '120'])
        self.addCleanup(holder.wait)
        self.addCleanup(holder.kill)
        lock = self.runtime / 'lock'
        lock.mkdir(mode=0o700)
        (lock / 'pid').write_text('{}\n'.format(holder.pid))
        (lock / 'pid').chmod(0o600)
        held = self.tree()
        document = self.inventory()
        self.assertEqual([d['mac'] for d in document['devices']], [KID, OTHER_KID])
        self.assertEqual(self.tree(), held)
        (lock / 'pid').unlink()
        lock.rmdir()
        self.inventory()
        self.assertEqual(self.tree(), before)
        self.assertEqual(len(self.f.mutation_calls()), calls)
        self.assertEqual(sorted(p.name for p in self.runtime.glob('.scope.*')), [])

    def test_refusals_carry_the_same_keys_and_no_devices(self):
        self.assertEqual(json.loads(self.f.run('rpc-inventory').stdout), {'ok': False, 'errors': ['invalid_command']})
        self.assertEqual(self.f.run('rpc-inventory').returncode, 2)
        self.assertEqual(self.f.run('rpc-inventory', '--json', 'extra').returncode, 2)
        generation = self.generation()
        ready = self.f.root / 'etc/couvrefeu/backup/ready'
        content = ready.read_bytes()
        ready.unlink()
        document = self.inventory(code=1)
        self.assertEqual(document['devices'], [])
        self.assertIs(document['truncated'], False)
        self.assertEqual(document['routerTime'], 0)
        self.assertEqual(document['errors'], ['inactive_generation'])
        self.assertEqual(document['generation'], generation)
        ready.write_bytes(content)
        ready.chmod(0o600)
        lock = self.f.root / '.couvrefeu-install.lock'
        lock.mkdir(mode=0o700)
        document = self.inventory(code=1)
        self.assertEqual((document['devices'], document['errors']), ([], ['installation_in_progress']))
        lock.rmdir()
        self.assertEqual(self.inventory()['errors'], [])


class FilterOrderTests(InventoryCommon, unittest.TestCase):
    """S1/S4: rows a LAN or guest client can induce are skipped silently; only in-scope corruption is reported."""

    def test_client_induced_lease_rows_are_skipped_silently(self):
        # dnsmasq writes hwtype-prefixed MACs for htype != 1 and keeps multicast/zero chaddr as given.
        self.leases('0 06-02:00:00:00:00:01 192.168.8.50 guest-hw *\n'
                    '0 01:00:5e:00:00:02 192.168.8.51 guest-mcast *\n'
                    'never 01:00:5e:00:00:03 192.168.8.52 guest-badexpiry *\n'
                    '{} 01:00:5e:00:00:04 192.168.1.80 expired-mcast *\n'
                    '{} 06-02:00:00:00:00:05 192.168.1.81 expired-hw *\n'
                    '0 06-02:00:00:00:00:06 192.168.1.82 lan-hw *\n'
                    '0 01:00:5e:00:00:07 192.168.1.83 lan-mcast *\n'
                    '0 00:00:00:00:00:00 192.168.1.84 lan-zero *\n'
                    '0 02:00:00:00:00 192.168.1.85 lan-short *\n'
                    '0 {} 192.168.1.86 good *\n'.format(NOW - 1, NOW - 5, mac(5)))
        document = self.inventory()
        self.assertEqual(document['errors'], [])
        self.assertEqual(sorted(self.by_mac(document)), [KID, OTHER_KID, mac(5)])

    def test_client_induced_neighbour_rows_are_skipped_silently(self):
        self.neighbours([{'ip': '192.168.1.20', 'mac': KID}, {'ip': '192.168.1.70', 'mac': '01:00:5e:00:00:01'},
                         {'ip': '192.168.1.71', 'mac': '00:00:00:00:00:00'}, {'ip': '192.168.1.72', 'mac': mac(7)}])
        document = self.inventory()
        self.assertEqual(document['errors'], [])
        self.assertEqual(sorted(self.by_mac(document)), [KID, OTHER_KID, mac(7)])  # OTHER_KID: lease only

    def test_in_scope_malformed_lease_row_is_reported_once(self):
        self.leases('never {} 192.168.1.84 badexpiry *\n12345678901 {} 192.168.1.85 longexpiry *\n'
                    '0 {} 192.168.1.86 good *\n'.format(mac(3), mac(4), mac(5)))
        document = self.inventory()
        self.assertEqual(document['errors'], ['inventory_row_dropped'])
        self.assertEqual(sorted(self.by_mac(document)), [KID, OTHER_KID, mac(5)])

    def test_single_in_scope_malformed_row_reports_exactly_one_error(self):
        self.leases('never {} 192.168.1.84 badexpiry *\n'.format(mac(3)))
        self.assertEqual(self.inventory()['errors'], ['inventory_row_dropped'])

    def test_neighbours_outside_the_br_lan_subnet_are_not_listed(self):
        # ARP can place any address on br-lan; only the br-lan subnet is reported, like leases.
        self.neighbours([{'ip': '192.168.1.20', 'mac': KID}, {'ip': '192.168.8.40', 'mac': mac(8)},
                         {'ip': '10.9.9.9', 'mac': mac(9), 'state': 'STALE'}, {'ip': '192.168.8.41', 'mac': KID}])
        document = self.inventory()
        self.assertEqual(document['errors'], [])
        self.assertEqual(document['devices'], [
            {'mac': KID, 'ipv4': ['192.168.1.20'], 'hostname': 'fixture', 'source': 'both'},
            {'mac': OTHER_KID, 'ipv4': ['192.168.1.22'], 'hostname': 'fixture2', 'source': 'lease'}])

    def setUp(self):
        super().setUp()
        self.leases('0 {} 192.168.1.20 fixture *\n0 {} 192.168.1.22 fixture2 *\n'.format(KID, OTHER_KID))

    def test_double_space_and_nul_rows_never_forge_a_lease(self):
        # BusyBox awk ends a record at NUL: the bytes after it would otherwise parse as a lease row of their own.
        # The row holding the NUL is dnsmasq's own: it stays, with its now ambiguous hostname null.
        self.leases(b'0 ' + mac(401).encode() + b' 192.168.1.5 ok\x000 ' + mac(402).encode() + b' 192.168.1.6 forged *\n'
                    b'0  ' + mac(403).encode() + b' 192.168.1.7 spaced *\n'
                    # A shell command substitution drops NUL silently: 'ok\0evil' would become the valid 'okevil'.
                    b'0 ' + mac(404).encode() + b' 192.168.1.8 ok\x00evil *\n')
        for runtime, document in (('awk', self.inventory()), ('busybox', self.busybox_inventory())):
            with self.subTest(runtime=runtime):
                self.nul_checks(document)

    def nul_checks(self, document):
        found = self.by_mac(document)
        self.assertNotIn(mac(402), found)
        self.assertNotIn(mac(403), found)
        self.assertNotIn('forged', json.dumps(document))
        self.assertEqual(found[mac(401)], {'mac': mac(401), 'ipv4': ['192.168.1.5'], 'hostname': None, 'source': 'lease'})
        self.assertIsNone(found[mac(404)]['hostname'])
        self.assertNotIn('okevil', json.dumps(document))
        self.assertEqual(sorted(found), [KID, OTHER_KID, mac(401), mac(404)])


class ProtectedListTests(InventoryCommon, unittest.TestCase):
    """S2: the protected list fails closed at admission AND when it changes before collection."""

    def setUp(self):
        super().setUp()
        self.protected = self.f.root / 'etc/couvrefeu/protected'
        self.content = self.protected.read_bytes()

    def restore(self):
        self.protected.unlink(missing_ok=True)
        self.protected.write_bytes(self.content)
        self.protected.chmod(0o600)

    def test_admission_refuses_every_unsafe_protected_file(self):
        target = self.f.root / 'protected-copy'
        cases = [('missing', lambda: self.protected.unlink(), 'unsafe_protected_file'),
                 ('symlink', lambda: (target.write_bytes(self.content), target.chmod(0o600), self.protected.unlink(),
                                      self.protected.symlink_to(target)), 'unsafe_protected_file'),
                 ('invalid', lambda: self.protected.write_text('garbage\n'), 'invalid_protected_mac'),
                 ('empty', lambda: self.protected.write_bytes(b''), 'unsafe_protected_file')]
        if os.geteuid() != 0:
            cases.append(('unreadable', lambda: self.protected.chmod(0), 'unsafe_protected_file'))
        for name, damage, code in cases:
            with self.subTest(name=name):
                damage()
                try:
                    self.refused(self.inventory(code=1), code)
                finally:
                    self.restore()
                self.assertEqual(self.inventory()['errors'], [])

    def test_protected_list_changed_after_admission_fails_closed(self):
        # cf_network runs after admission, inside collection: damage the list there (the race).
        stub = ('cf_network(){ %s;CF_LAN_IP=192.168.1.1;cf_addr4="2: br-lan    inet 192.168.1.1/24 scope global br-lan"; }\n'
                'cf_rpc_inventory')
        cases = [('missing', 'rm -f "$CF_PROTECTED"', 'inventory_protected_unreadable'),
                 ('invalid', 'printf "garbage\\n" >"$CF_PROTECTED"', 'inventory_protected_unreadable'),
                 ('empty', ': >"$CF_PROTECTED"', 'inventory_protected_empty')]
        if os.geteuid() != 0:
            cases.append(('unreadable', 'chmod 000 "$CF_PROTECTED"', 'inventory_protected_unreadable'))
        for name, damage, code in cases:
            with self.subTest(name=name):
                result = self.core_shell(stub % damage)
                self.restore()
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertRegex(result.stdout, PLAIN)
                document = json.loads(result.stdout)
                self.assertEqual(list(document), KEYS)
                self.refused(document, code)
                self.assertNotIn(PROTECTED, result.stdout)


class NetworkRefusalTests(InventoryCommon, unittest.TestCase):
    """S3/C1: br-lan subnet and source failures name their code and never yield an unfiltered listing."""

    def setUp(self):
        super().setUp()
        self.generation()
        self.leases('0 {} 192.168.1.20 fixture *\n0 {} 192.168.8.50 guest *\n0 {} 10.0.0.9 other *\n'
                    .format(KID, mac(301), mac(302)))

    def addresses(self, *rows):
        self.f.update_backend(addresses4=list(rows))

    def test_br_lan_address_shapes_that_are_refused(self):
        cases = [('no mask', ['2: br-lan    inet 192.168.1.1 scope global br-lan'], 'lan_address_mismatch'),
                 ('ipv6 only', [], 'lan_address_mismatch'),
                 ('below /8', ['2: br-lan    inet 192.168.1.1/7 scope global br-lan'], 'lan_address_mismatch'),
                 ('other address only', ['2: br-lan    inet 10.0.0.1/8 scope global br-lan'], 'lan_address_mismatch')]
        for name, rows, code in cases:
            with self.subTest(name=name):
                self.addresses(*rows)
                self.refused(self.inventory(code=1), code)

    def test_host_prefix_lists_nothing_outside_the_router_address(self):
        self.addresses('2: br-lan    inet 192.168.1.1/32 scope global br-lan')
        document = self.inventory()
        self.assertEqual((document['devices'], document['errors'], document['truncated']), ([], [], False))

    def test_two_br_lan_addresses_use_the_lan_entry_in_either_order(self):
        lan, other = '2: br-lan    inet 192.168.1.1/24 scope global br-lan', '2: br-lan    inet 10.0.0.1/8 scope global br-lan'
        for rows in ((lan, other), (other, lan)):
            with self.subTest(rows=rows):
                self.addresses(*rows)
                document = self.inventory()
                self.assertEqual(sorted(self.by_mac(document)), [KID, OTHER_KID])
                self.assertEqual(document['errors'], [])

    def test_address_inspection_failure_names_its_code(self):
        self.f.update_backend(failures=[{'command': 'ip', 'contains': ['-4', 'addr'], 'remaining': 100}])
        self.refused(self.inventory(code=1), 'lan_inspection_failed')

    def test_neighbour_inspection_failure_keeps_filtered_leases(self):
        self.f.update_backend(failures=[{'command': 'ip', 'contains': ['-4', 'neigh'], 'remaining': 100}])
        document = self.inventory()
        self.assertEqual(document['errors'], ['neighbor_inspection_failed'])
        self.assertEqual(document['devices'], [{'mac': KID, 'ipv4': ['192.168.1.20'], 'hostname': 'fixture', 'source': 'lease'}])

    def test_lease_file_symlink_or_unreadable_keeps_filtered_neighbours(self):
        path = self.f.root / 'tmp/dhcp.leases'
        target = self.f.root / 'tmp/leases-target'
        path.rename(target)
        path.symlink_to(target)
        cases = [('symlink', None)]
        if os.geteuid() != 0:
            cases.append(('unreadable', lambda: (path.unlink(), target.rename(path), path.chmod(0))))
        self.neighbours([{'ip': '192.168.1.20', 'mac': KID}, {'ip': '192.168.8.40', 'mac': mac(8)}])
        for name, damage in cases:
            with self.subTest(name=name):
                if damage:
                    damage()
                result = self.f.run('rpc-inventory', '--json')
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                for leak in ('Permission', 'denied', 'awk', 'tr:', 'dhcp.leases', 'No such'):
                    self.assertNotIn(leak, result.stdout)
                document = json.loads(result.stdout)
                self.assertEqual(document['errors'], ['lease_inspection_failed'])
                self.assertEqual(document['devices'], [{'mac': KID, 'ipv4': ['192.168.1.20'], 'hostname': None, 'source': 'neigh'}])

class NotInstalledTests(unittest.TestCase):
    def test_not_installed_refusal(self):
        fixture = RouterFixture()
        self.addCleanup(fixture.close)
        result = fixture.run('rpc-inventory', '--json')
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertRegex(result.stdout, PLAIN)
        document = json.loads(result.stdout)
        self.assertEqual(list(document), KEYS)
        self.assertEqual(document, {'inventory_version': 1, 'generation': '0' * 64, 'routerTime': 0, 'devices': [],
                                    'truncated': False, 'errors': ['rpc_disabled']})


HIGH_KID = '02:00:00:00:ff:fe'


class TruncationTests(InventoryCommon, unittest.TestCase):
    def install(self, *floor):
        super().install(KID, HIGH_KID)

    def enrol_high_kid(self):
        # Enrolment needs the kid attached; it is lease-only afterwards.
        self.neighbours(self.f.backend()['neighbors'] + [{'ip': '192.168.1.250', 'mac': HIGH_KID}])
        status = json.loads(self.f.run('rpc-status', '--json').stdout)
        document = policy(status['acceptedPolicy']['revision'] + 1)
        document['people'][0]['macs'] = [HIGH_KID]
        request = dict(rpc_version=1, generation=status['generation'], operation_id='op_kid',
                       expected_revision=status['acceptedPolicy']['revision'], expected_digest=status['policyDigest'],
                       policy=document)
        result = self.f.run('rpc-sync', document=request)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_cap_keeps_kids_then_neighbours_then_lowest_macs_as_whole_devices(self):
        self.enrol_high_kid()
        # 300 lease-only devices, 10 neighbour-only devices with the HIGHEST MACs, and the kid (lease-only, high MAC).
        lease_macs = [mac(256 + n) for n in range(300)]
        neigh_macs = [mac(60000 + n) for n in range(10)]
        self.neighbours([{'ip': '192.168.1.{}'.format(200 + n), 'mac': m} for n, m in enumerate(neigh_macs)])
        self.leases(''.join('0 {} 192.168.1.{} h{} *\n'.format(m, 2 + n % 200, n) for n, m in enumerate(lease_macs))
                    + '0 {} 192.168.1.250 kid *\n'.format(HIGH_KID))
        inventory = self.inventory()
        self.assertIs(inventory['truncated'], True)
        self.assertEqual(inventory['errors'], [])
        macs = [d['mac'] for d in inventory['devices']]
        self.assertEqual(len(macs), 256)
        expected = c_sorted([HIGH_KID] + neigh_macs + c_sorted(lease_macs)[:245])
        self.assertEqual(macs, expected)
        found = self.by_mac(inventory)
        self.assertEqual(found[HIGH_KID]['source'], 'lease')
        self.assertTrue(all(len(found[m]['ipv4']) == 1 for m in macs))


    def test_distinct_mac_intake_is_capped_and_kids_still_kept(self):
        # A lease flood: 4096 distinct high MACs first, then 1904 LOWER MACs, then the lease-only kid. Intake stops
        # at 4096 distinct MACs (kids exempt), so the lower late MACs are never seen and the kid is still kept.
        self.enrol_high_kid()
        self.neighbours([])
        first = [mac(10000 + n) for n in range(4096)]
        late = [mac(256 + n) for n in range(1904)]
        self.leases(''.join('0 {} 192.168.1.{} f{} *\n'.format(m, 2 + n % 200, n) for n, m in enumerate(first + late))
                    + '0 {} 192.168.1.250 kid *\n'.format(HIGH_KID))
        for runtime, run in (('awk', self.inventory), ('busybox', self.busybox_inventory)):
            with self.subTest(runtime=runtime):
                started = time.monotonic()
                inventory = run()
                print('\n[flood] {} 6001 lease rows: {:.2f}s'.format(runtime, time.monotonic() - started), file=sys.stderr)
                self.assertIs(inventory['truncated'], True)
                self.assertEqual(inventory['errors'], [])
                self.assertEqual([d['mac'] for d in inventory['devices']], c_sorted([HIGH_KID] + first[:255]))

class SizeGuardTests(InventoryCommon, unittest.TestCase):
    def test_byte_guard_drops_whole_trailing_devices_and_sets_truncated(self):
        self.leases(''.join('0 {} 192.168.1.{} host-{} *\n'.format(mac(256 + n), 2 + n, n) for n in range(40)))
        full = self.inventory()
        self.assertIs(full['truncated'], False)
        self.assertEqual(len(full['devices']), 42)
        limit = 1200
        result = self.core_shell('CF_INVENTORY_MAX_BYTES={};cf_rpc_inventory'.format(limit))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertLess(len(result.stdout.encode()), limit)
        self.assertRegex(result.stdout, PLAIN)
        document = json.loads(result.stdout)
        self.assertEqual(list(document), KEYS)
        self.assertIs(document['truncated'], True)
        kept = document['devices']
        self.assertGreater(len(kept), 3)
        # Neighbour devices first, then the lowest lease-only MACs; every kept device is exactly the full reply's entry.
        expected = [d for d in full['devices'] if d['source'] != 'lease'] + [d for d in full['devices'] if d['source'] == 'lease']
        self.assertEqual(kept, sorted(expected[:len(kept)], key=lambda d: d['mac'].encode()))
        # The next device would not have fitted.
        self.assertGreaterEqual(len(result.stdout.encode()) + len(json.dumps(expected[len(kept)], separators=(',', ':'))) + 1, limit)


class AwkParityTests(unittest.TestCase):
    def test_inventory_awk_mac_copy_agrees_with_cf_mac_valid(self):
        source = (REPO / 'router/lib/activity.sh').read_text()
        copies = [line.strip() for line in source.splitlines() if line.strip().startswith('function mac(')]
        self.assertEqual(len(copies), 1)
        samples = [KID, '0a:00:00:00:00:01', '03:00:00:00:00:03', '01:00:5e:00:00:01', '33:33:00:00:00:01',
                   'ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00', '02:00:00:00:00:0A', '02:00:00:00:00:003', '2:00:00:00:00:03',
                   '02-00-00-00-00-03', '02:00:00:00:00', '02:00:00:00:00:03:', '', 'zz:00:00:00:00:00']
        valid = subprocess.run(['sh', '-c', 'CF_BASE=;. "$0";for s;do if cf_mac_valid "$s";then echo 1;else echo 0;fi;done',
                                str(REPO / 'router/lib/core.sh'), *samples], capture_output=True, text=True, timeout=60)
        expected = valid.stdout.split()
        self.assertEqual(len(expected), len(samples), valid.stderr)
        for runtime in (['awk'], [str(BUSYBOX), 'awk']):
            with self.subTest(runtime=runtime[0]):
                result = subprocess.run(runtime + [copies[0] + ' {print mac($0)?1:0}'], input=''.join(s + '\n' for s in samples),
                                        capture_output=True, text=True, timeout=30)
                self.assertEqual(result.stdout.split(), expected, result.stderr)

    def test_inventory_hostname_rule_matches_the_shared_sanitiser(self):
        samples = ['host-a', 'a' * 63, 'a' * 64, '-x', '.x', '_x', 'x y', 'x!', '9', '*', '', 'A.b_c-d']
        sanitised = subprocess.run(['sh', '-c', 'CF_BASE=;. "$0";for s;do printf "%s\\n" "$s" | cf_hostname_sanitise;done',
                                    str(REPO / 'router/lib/core.sh'), *samples], capture_output=True, text=True, timeout=60)
        expected = ['' if line == '(unnamed)' else line for line in sanitised.stdout.split('\n')[:len(samples)]]
        source = (REPO / 'router/lib/activity.sh').read_text()
        copies = [line.strip() for line in source.splitlines() if line.strip().startswith('function hname(')]
        self.assertEqual(len(copies), 1)
        for runtime in (['awk'], [str(BUSYBOX), 'awk']):
            with self.subTest(runtime=runtime[0]):
                result = subprocess.run(runtime + [copies[0] + ' {print hname($0)}'], input=''.join(s + '\n' for s in samples),
                                        capture_output=True, text=True, timeout=30)
                self.assertEqual(result.stdout.split('\n')[:len(samples)], expected, result.stderr)


class GrammarTests(unittest.TestCase):
    def setUp(self):
        self.f = RouterFixture()
        self.addCleanup(self.f.close)
        # env -i leaves the double only its argv and the forced-command marker; admission is its exit status.
        target = self.f.bin / 'cfctl'
        target.write_text('#!/bin/sh\n[ "$#" = 2 ] && [ "$1" = rpc-inventory ] && [ "$2" = --json ] '
                          '&& [ "$CF_SERVICE_FORCED_COMMAND" = 1 ]\n')
        target.chmod(0o700)

    def wrapper(self, command, *flags):
        env = dict(self.f.env, SSH_ORIGINAL_COMMAND=command)
        return subprocess.run(self.f.shell + [str(REPO / 'router/cfctl-ssh'), *flags], env=env, capture_output=True, text=True, timeout=30)

    def test_rpc_inventory_admitted_exactly(self):
        for flags in ((), ('--rpc-only',)):
            with self.subTest(flags=flags):
                result = self.wrapper('cfctl rpc-inventory --json', *flags)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for command in ('cfctl rpc-inventory', 'cfctl rpc-inventory --json extra', 'cfctl rpc-inventory --json; id',
                        'cfctl rpc-inventory --json --json', 'cfctl rpc-inventory json', 'cfctl rpc-inventory --JSON',
                        'cfctl rpc-inventory --json op_1', 'rpc-inventory --json', 'cfctl inventory --json',
                        'cfctl rpc-inventory --json\n', 'cfctl rpc-inventory $(id)'):
            for flags in ((), ('--rpc-only',)):
                with self.subTest(command=command, flags=flags):
                    self.assertEqual(self.wrapper(command, *flags).returncode, 2)


class GoldenTests(InventoryCommon, unittest.TestCase):
    """Router replies checked in for the service parser test; generation normalised to a fixed value."""

    def scenario(self, name):
        if name == 'mixed':
            self.neighbours([{'ip': '192.168.1.9', 'mac': mac(1)}, {'ip': '192.168.1.10', 'mac': mac(1), 'state': 'STALE'},
                             {'ip': '192.168.1.50', 'mac': mac(2), 'state': 'FAILED'}, {'ip': '192.168.1.10', 'mac': PROTECTED}])
            self.leases('0 {} 192.168.1.9 host-a *\n0 {} 192.168.1.51 * *\n0 {} 192.168.1.52 bad!name *\n0 {} 192.168.8.9 guest *\n'
                        '0 {} 192.168.1.53 printer.lan *\n'.format(mac(1), mac(2), '0a:00:00:00:00:03', mac(4), 'f2:00:00:00:00:05'))
        elif name == 'invalid-clock':
            return dict(self.f.env, CF_NOW='0'), 0
        elif name == 'dropped-row':
            self.leases('never {} 192.168.1.80 badexpiry *\n0 {} 192.168.1.20 fixture *\n'.format(mac(3), KID))
        elif name == 'truncated':
            self.leases(''.join('0 {} 192.168.1.{} h{} *\n'.format(mac(256 + n), 2 + n % 200, n) for n in range(300)))
        elif name == 'refusal':
            (self.f.root / 'etc/couvrefeu/backup/ready').unlink()
            return None, 1
        return None, 0

    def test_golden_replies_match_the_router(self):
        manifest = {}
        for name in ('baseline', 'mixed', 'invalid-clock', 'dropped-row', 'truncated', 'refusal'):
            with self.subTest(name=name):
                self.f.close()
                self.f = RouterFixture()
                self.install()
                generation = self.generation()
                env, code = self.scenario(name)
                text = self.raw(env, code)
                self.assertEqual(text.count(generation), 1)
                text = text.replace(generation, GOLDEN_GENERATION)
                manifest[name] = {'file': name + '.json', 'exit': code}
                path = GOLDEN / (name + '.json')
                if os.environ.get('CF_INVENTORY_GOLDEN_WRITE') == '1':
                    GOLDEN.mkdir(exist_ok=True)
                    path.write_text(text)
                self.assertEqual(path.read_text(), text)
        context = {'generation': GOLDEN_GENERATION, 'protectedMacs': [PROTECTED], 'replies': manifest}
        manifest_path = GOLDEN / 'manifest.json'
        if os.environ.get('CF_INVENTORY_GOLDEN_WRITE') == '1':
            manifest_path.write_text(json.dumps(context, indent=2, sort_keys=True) + '\n')
        self.assertEqual(json.loads(manifest_path.read_text()), context)


if __name__ == '__main__':
    unittest.main()
