#!/usr/bin/env python3
"""Native OS-trust fixtures, not firmware trust or target latency evidence.

The static helper runs its actual bounded account/provider/PID1 parsers against
private filesystem paths. Only root-owner metadata and the hardware pin census
are fixture adapters. Recovery tests use the existing inert vendor adapter.
"""
import hashlib
import json
import importlib.util
import os
import re
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

REPO=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('platform_fixtures',REPO/'tests/test-platform-integration.py')
platform=importlib.util.module_from_spec(spec);spec.loader.exec_module(platform)
SHELL=platform.SHELL
PROFILE='gl-xe3000-4.8.3-os-trust-v1'
# Bound for one shell snippet or reap. Measured at 0.00-0.23 s (one case sleeps ~4 s on purpose) with load average 3-25;
# 30 s keeps >100x headroom for a CI runner yet a real hang still fails in 30 s.
SHELL_TIMEOUT=30

class StaticWitnessTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='couvre-feu-os-trust-static-')
        self.root=Path(self.temp.name)
        for p in ['etc','tmp','run','proc/1/task/1','sbin']:(self.root/p).mkdir(parents=True,exist_ok=True)
        (self.root/'var').symlink_to('tmp')
        (self.root/'etc/passwd').write_text('root:x:0:0:root:/root:/bin/ash\nlogd:x:514:514:log:/var/log:/bin/false\n')
        (self.root/'etc/group').write_text('root:x:0:root\nlogd:x:514:\n')
        (self.root/'etc/nsswitch.conf').write_text('passwd: files\ngroup: files\n')
        (self.root/'etc/glversion').write_text('4.8.3\n')
        (self.root/'sbin/procd').write_text('inert pinned-image fixture\n')
        task=self.root/'proc/1/task/1'
        (task/'stat').write_text('1 (procd) S '+'0 '*18+'123\n')
        (task/'status').write_text('Tgid:\t1\nPid:\t1\nPPid:\t0\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nGroups:\n')
        (task/'comm').write_text('procd\n');(task/'exe').symlink_to(self.root/'sbin/procd')
        source=(REPO/'router/lib/vendor-platform.sh').read_text()
        # One substitution pass avoids rewriting the /tmp fixture prefix.
        # These literal source-path changes exist only in this private fixture.
        source=re.sub(r'/(etc|tmp|run|var|proc|sbin)(?=/|$|[^A-Za-z0-9_-])',
                      lambda match:str(self.root/match.group(1)),source)
        self.helper=self.root/'helper.sh';self.helper.write_text(source)
        self.setup=f'''set -eu
. "{self.helper}"
awk() {{ "{SHELL[0]}" awk "$@"; }}
timeout() {{ "{SHELL[0]}" timeout "$@"; }}
fail() {{ printf 'REFUSED=%s\\n' "$1" >&2;exit 2; }}
regular() {{ [ -f "$1" ] && [ ! -L "$1" ] || fail regular; }}
hash_is() {{ regular "$1"; value=$(sha256sum "$1") || fail hash_read; [ "${{value%% *}}" = "$2" ] || fail hash_mismatch; }}
stat_private() {{
    case "$*" in
        *%u:%g:*) result=$(command stat "$@") || return;printf '%s\\n' "$result" | awk -F: 'BEGIN{{OFS=":"}}{{$1=0;$2=0;print}}';;
        *) command stat "$@";;
    esac
}}
vp_pins() {{ printf 'fixture-hardware-pin-closure\\n'; }}
vp_census() {{ fail forbidden_population_scan; }}
vp_profile={PROFILE}
'''

    def tearDown(self):self.temp.cleanup()
    def run_helper(self,extra=''):
        return subprocess.run(SHELL+['-c',self.setup+extra+'\nvp_transaction_check'],capture_output=True,text=True,timeout=SHELL_TIMEOUT)
    def test_static_success_has_distinct_result_without_population_scan(self):
        r=self.run_helper();self.assertEqual(r.returncode,0,r.stderr)
        self.assertIn('OS_TRUST_PROFILE_ATTESTED:',r.stdout);self.assertNotIn('VENDOR_PROFILE_ATTESTED:',r.stdout)
    def test_configured_accounts_refuse_ambiguous_and_nonroot_gid_zero(self):
        for data in ['guest:x:7:0:g:/tmp:/bin/false\n','logd2:x:514:514:g:/tmp:/bin/false\n']:
            with self.subTest(data=data):
                p=self.root/'etc/passwd';old=p.read_text();p.write_text(old+data)
                self.assertNotEqual(self.run_helper().returncode,0);p.write_text(old)
        (self.root/'etc/group').write_text('root:x:0:logd\nlogd:x:514:\n')
        self.assertNotEqual(self.run_helper().returncode,0)
    def test_providers_and_provider_sockets_refuse(self):
        p=self.root/'etc/nsswitch.conf';p.write_text('passwd: files ldap\ngroup: files\n')
        self.assertIn('configured_credential_provider',self.run_helper().stderr)
        p.write_text('passwd: files\ngroup: files\n');socket=self.root/'run/nscd/socket';socket.parent.mkdir();socket.touch()
        self.assertIn('credential_provider_socket',self.run_helper().stderr)
    def test_firmware_and_initial_pin_failure_refuse(self):
        (self.root/'etc/glversion').write_text('4.8.4\n')
        self.assertIn('hash_mismatch',self.run_helper().stderr)
        (self.root/'etc/glversion').write_text('4.8.3\n')
        self.assertIn('profile_pins',self.run_helper('vp_pins() { return 7; }').stderr)
    def test_complete_pid1_witness_refuses_comm_credentials_and_missing_task(self):
        task=self.root/'proc/1/task/1';p=task/'comm';p.write_text('unexpected\n')
        self.assertIn('supervisor_comm',self.run_helper().stderr);p.write_text('procd\n')
        status=task/'status';old=status.read_text();status.write_text(old.replace('Uid:\t0\t0\t0\t0','Uid:\t7\t7\t7\t7'))
        self.assertIn('supervisor_credentials',self.run_helper().stderr);status.write_text(old)
        p.unlink();self.assertNotEqual(self.run_helper().returncode,0)
    def test_final_pin_and_pid1_drift_refuse(self):
        counter=self.root/'counter'
        extra=f'''vp_pins() {{ if [ -e "{counter}" ];then printf drift;else : > "{counter}";printf stable;fi; }}'''
        self.assertIn('profile_drift',self.run_helper(extra).stderr)
        counter.unlink()
        extra=f'''vp_pins() {{ if [ -e "{counter}" ];then printf rogue > "{self.root}/proc/1/task/1/comm";else : > "{counter}";fi;printf stable; }}'''
        self.assertIn('supervisor_',self.run_helper(extra).stderr)
    def test_firmware_correct_bytes_nonzero_stat_status_refuses(self):
        self.setup=self.setup.replace('stat_private() {','fixture_stat_private() {',1)
        extra='stat_private() { case "$*" in *%u:%g:%s*) printf "0:0:6\\n";return 7;;*)fixture_stat_private "$@";;esac; }'
        self.assertIn('firmware_identity_metadata',self.run_helper(extra).stderr)
    def test_firmware_world_write_refuses_before_identity(self):
        (self.root/'etc/glversion').chmod(0o666)
        self.assertIn('metadata_special_or_world_write',self.run_helper().stderr)
    def test_exact_group_writable_firmware_is_os_profile_only(self):
        firmware=self.root/'etc/glversion';firmware.chmod(0o664)
        # Actual metadata admission and firmware size/hash checks run; only the
        # fixture's existing root-owner adapter substitutes the local UID/GID.
        direct=f'\nvp_metadata "{firmware}";vp_os_firmware'
        for profile in [PROFILE,'strict',platform.PROFILE,None]:
            with self.subTest(profile=profile):
                selector='unset vp_profile' if profile is None else 'vp_profile='+profile
                result=subprocess.run(SHELL+['-c',self.setup+'\n'+selector+direct],capture_output=True,text=True,timeout=SHELL_TIMEOUT)
                self.assertEqual(result.returncode==0,profile==PROFILE,result.stderr)
                if profile!=PROFILE:self.assertIn('unobserved_group_writable_path' if profile==platform.PROFILE else 'unsupported_vendor_profile',result.stderr)
        result=self.run_helper();self.assertEqual(result.returncode,0,result.stderr)
        firmware.write_text('4.8.4\n')
        self.assertIn('firmware_identity_pin',self.run_helper().stderr)
        firmware.write_text('4.8.3\n');firmware.chmod(0o666)
        self.assertIn('metadata_special_or_world_write',self.run_helper().stderr)
        firmware.chmod(0o664)
        self.assertIn('metadata_owner',self.run_helper('stat_private() { printf "7:0:664\\n"; }').stderr)
        other=self.root/'etc/unknown-firmware';other.write_text('4.8.3\n');other.chmod(0o664)
        result=subprocess.run(SHELL+['-c',self.setup+f'\nvp_metadata "{other}"'],capture_output=True,text=True,timeout=SHELL_TIMEOUT)
        self.assertIn('unobserved_group_writable_path',result.stderr)
    def test_account_drift_and_provider_appearance_after_first_witness_refuse(self):
        # Rename only the fixture wrapper so the actual complete PID1 witness
        # runs before these controlled local changes.
        original=self.helper.read_text().replace('vp_supervisor() (','fixture_supervisor() (',1)
        self.helper.write_text(original)
        p=self.root/'etc/passwd';old=p.read_text()
        extra=f'vp_supervisor() {{ fixture_supervisor;printf "guest:x:7:7:g:/tmp:/bin/false\\n" >> "{p}"; }}'
        self.assertIn('account_metadata_drift',self.run_helper(extra).stderr)
        p.write_text(old);nss=self.root/'etc/nsswitch.conf';nss.unlink()
        extra=f'vp_supervisor() {{ fixture_supervisor;printf "passwd: files\\ngroup: files\\n" > "{nss}"; }}'
        self.assertIn('provider_config_appeared',self.run_helper(extra).stderr)
    def test_distinct_selector_never_falls_back_or_weakens_old_census(self):
        self.assertIn('unsupported_vendor_profile',self.run_helper('vp_profile=unknown').stderr)
        self.assertIn('forbidden_population_scan',self.run_helper('vp_profile='+platform.PROFILE).stderr)

class DeadlineTests(unittest.TestCase):
    def setUp(self):
        self.bootstrap=REPO/'router/lib/platform-bootstrap.sh'
        self.setup=f'. "{self.bootstrap}"; CF_PLATFORM_PROFILE={PROFILE}; CF_PLATFORM_ENTRY_TICK=100; '
    def run_shell(self,body):
        return subprocess.run(SHELL+['-c',self.setup+body],capture_output=True,text=True,timeout=SHELL_TIMEOUT)
    def test_exclusive_centisecond_boundary_and_anchor_reuse(self):
        for tick,ok in [(100,True),(1399,True),(1400,False),(99,False)]:
            r=self.run_shell(f'platform_clock_tick() {{ printf {tick}; }}; platform_deadline_check; platform_deadline_check;printf complete')
            self.assertEqual(r.returncode==0,ok,r.stderr)
        r=self.run_shell('CF_PLATFORM_ENTRY_TICK=;platform_deadline_check;printf unsafe')
        self.assertNotEqual(r.returncode,0);self.assertNotIn('unsafe',r.stdout)
    def test_profile_isolation_and_post_initial_write_recovery(self):
        for profile in ['strict',platform.PROFILE]:
            r=self.run_shell(f'CF_PLATFORM_PROFILE={profile};CF_PLATFORM_ENTRY_TICK=;platform_deadline_check;printf complete')
            self.assertEqual(r.returncode,0,r.stderr)
        r=self.run_shell('platform_clock_tick() { printf 100; };platform_initial_write;platform_clock_tick() { printf 9000; };platform_deadline_check;printf recovery')
        self.assertEqual(r.returncode,0,r.stderr);self.assertIn('recovery',r.stdout)
    def test_late_blocking_phase_cannot_resume_into_first_write(self):
        r=self.run_shell('CF_PLATFORM_ENTRY_TICK=$(platform_clock_tick);CF_PLATFORM_ENTRY_TICK=$((CF_PLATFORM_ENTRY_TICK-1295));sleep 0.12;platform_initial_write;printf unsafe')
        self.assertNotEqual(r.returncode,0);self.assertIn('admission_deadline',r.stderr);self.assertNotIn('unsafe',r.stdout)
    def test_readonly_backend_is_allowed_but_late_mutation_refuses(self):
        core=REPO/'router/lib/core.sh'
        body=f'''. "{core}";cf_backend_available() {{ cf_executable=/bin/true; }};platform_clock_tick() {{ printf 1400; }};cf_backend iptables -S;printf observed;cf_backend iptables -A dummy;printf unsafe'''
        r=self.run_shell(body);self.assertIn('observed',r.stdout);self.assertNotIn('unsafe',r.stdout);self.assertNotEqual(r.returncode,0)
    def test_actual_write_barriers_and_entry_anchor_environment_fences(self):
        for name in ['cfctl','install.sh','uninstall.sh']:
            text=(REPO/'router'/name).read_text()
            self.assertLess(text.index('CF_PLATFORM_ENTRY_TICK=$('),text.index('platform_bootstrap_digest='))
            self.assertIn('${CF_PLATFORM_ENTRY_TICK+x}',text);self.assertIn('${CF_PLATFORM_INITIAL_WRITE+x}',text)
        for name,fragment in [('core.sh','platform_initial_write\n    printf'),('firewall.sh','platform_initial_write\n    printf'),('install-common.sh','phase() {\n    platform_initial_write')]:
            self.assertIn(fragment,(REPO/'router/lib'/name).read_text())
    def test_expiry_and_signal_release_only_the_owned_admission_lock(self):
        with tempfile.TemporaryDirectory(prefix='couvre-feu-os-trust-lock-') as folder:
            lock=Path(folder)/'lock';foreign=Path(folder)/'foreign';foreign.write_text('preserve')
            for ending in ['platform_deadline_check','kill -TERM $$']:
                body=f'''umask 077;CF_PLATFORM_OWNER=$(id -u):$(id -g);CF_PLATFORM_LOCK={lock};mkdir -m 700 "$CF_PLATFORM_LOCK";printf '%s\\n' "$$" > "$CF_PLATFORM_LOCK/pid";CF_PLATFORM_LOCKED=1;trap 'platform_lock_release' 0;trap 'exit 143' TERM;platform_clock_tick() {{ printf 1400; }};{ending};printf unsafe'''
                r=self.run_shell(body);self.assertNotEqual(r.returncode,0)
                self.assertNotIn('unsafe',r.stdout);self.assertFalse(lock.exists());self.assertEqual(foreign.read_text(),'preserve')
    def test_slow_input_within_ten_seconds_still_checks_cumulative_deadline(self):
        # Entry anchored 8s back (500-tick margin to the 1300-tick budget). The stage's input
        # file appearing proves every pre-read deadline check passed; stdin then arrives
        # after the margin but well inside dd's 10s bound, so only the post-read
        # admission_deadline check can refuse (not an early one, not the dd deadline).
        with tempfile.TemporaryDirectory(prefix='couvre-feu-os-trust-input-') as folder:
            root=Path(folder);(root/'tmp').mkdir();(root/'tmp').chmod(0o1777)
            body=f'''CF_BASE={root};CF_LIB={REPO}/router/lib;CF_LOCAL_TEST=1;CF_TEST_TIMEOUT='{SHELL[0]} timeout';. "{REPO}/router/lib/core.sh";CF_PLATFORM_ENTRY_TICK=$(platform_clock_tick);CF_PLATFORM_ENTRY_TICK=$((CF_PLATFORM_ENTRY_TICK-800));cf_sync_stage 0;printf unsafe'''
            child=subprocess.Popen(SHELL+['-c',self.setup+body],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            try:
                deadline=time.monotonic()+4
                while not list((root/'tmp').glob('couvrefeu-input.*/input')):
                    self.assertIsNone(child.poll(),'stage refused before its read began (early deadline check)')
                    self.assertLess(time.monotonic(),deadline,'stage read never began within the margin')
                    time.sleep(.01)
                time.sleep(5.5);out,err=child.communicate('{}',timeout=30)
                self.assertNotEqual(child.returncode,0);self.assertIn('admission_deadline',err);self.assertNotIn('unsafe',out)
                self.assertNotIn('input_deadline_or_read_failure',out+err)
                self.assertEqual(list((root/'tmp').iterdir()),[])
            finally:
                if child.poll() is None:child.kill()
                child.communicate(timeout=SHELL_TIMEOUT)
    def test_native_blocked_stat_producer_cannot_grant_initial_write(self):
        text=self.bootstrap.read_text();start=text.index('    platform_stat() {')
        stop=text.index('    [ "$(platform_stat -c',start);fragment=text[start:stop]
        with tempfile.TemporaryDirectory(prefix='couvre-feu-os-trust-producer-') as folder:
            producer=Path(folder)/'stat';producer.write_text('#!/bin/sh\nsleep 6\nprintf "0:0:755\\n"\n');producer.chmod(0o700)
            fragment=fragment.replace('/usr/libexec/stat-coreutils',str(producer))
            body=f'''CF_PLATFORM_ENTRY_TICK=$(platform_clock_tick);timeout() {{ "{SHELL[0]}" timeout "$@"; }};
{fragment}
platform_stat -c '%u:%g:%a' /unused;platform_initial_write;printf unsafe'''
            r=self.run_shell(body)
            self.assertNotEqual(r.returncode,0);self.assertIn('stat_read',r.stderr);self.assertNotIn('unsafe',r.stdout)

class OsTrustRecoveryTests(platform.VendorRecoveryTests):
    def setUp(self):
        super().setUp();self.expected_profile=PROFILE
    def install(self):
        r=self.run_entry(args=['--platform-profile',PROFILE,'--protect','02:00:00:00:00:01','--activate'])
        self.assertEqual(r.returncode,0,r.stderr)
    def test_old_profile_is_not_migrated_or_selected_implicitly(self):
        self.install()
        r=self.run_entry(args=['--platform-profile',platform.PROFILE,'--protect','02:00:00:00:00:01'])
        self.assertNotEqual(r.returncode,0)
        self.assertEqual((self.root/'etc/couvrefeu/platform-profile').read_text(),PROFILE+'\n')

class FirstWriteRegressionTests(unittest.TestCase):
    setUp=DeadlineTests.setUp
    run_shell=DeadlineTests.run_shell
    def test_zero_owned_cleanup_checks_after_kernel_proof_and_empty_proof_does_not_disarm(self):
        with tempfile.TemporaryDirectory(prefix='couvre-feu-os-trust-zero-') as folder:
            root=Path(folder);record=root/'error';record.write_text('owned')
            body=f'''. "{REPO}/router/lib/core.sh";. "{REPO}/router/lib/rpc.sh";. "{REPO}/router/lib/firewall.sh";. "{REPO}/router/lib/activity.sh";
CF_RUNTIME={root};fixture_tick=100;platform_clock_tick() {{ printf '%s' "$fixture_tick"; }};
cf_ownership_valid() {{ return 1; }};cf_zero_owned_runtime() {{ printf '%s\\n' "{record}"; }};
cf_zero_owned_kernel() {{ fixture_tick=1400; }};cf_backend() {{ :; }};cf_remove_fw;printf unsafe'''
            r=self.run_shell(body);self.assertNotEqual(r.returncode,0);self.assertIn('admission_deadline',r.stderr)
            self.assertTrue(record.exists());self.assertNotIn('unsafe',r.stdout)
            body=body.replace(f'printf \'%s\\n\' "{record}"',':').replace('cf_remove_fw;printf unsafe','cf_remove_fw;[ "$CF_PLATFORM_INITIAL_WRITE" = 0 ];platform_initial_write;printf unsafe')
            r=self.run_shell(body);self.assertNotEqual(r.returncode,0);self.assertIn('admission_deadline',r.stderr)
            self.assertTrue(record.exists());self.assertNotIn('unsafe',r.stdout)
    def test_lock_expiry_installs_owned_cleanup_before_guard(self):
        with tempfile.TemporaryDirectory(prefix='couvre-feu-os-trust-runtime-lock-') as folder:
            root=Path(folder);runtime=root/'runtime';runtime.mkdir()
            body=f'''. "{REPO}/router/lib/core.sh";CF_RUNTIME={runtime};CF_RPC_REQUIRE_RUNTIME=1;
cf_private_dir() {{ :; }};fixture_tick=100;platform_clock_tick() {{ printf '%s' "$fixture_tick"; }};
mkdir() {{ command mkdir "$@";fixture_tick=1400; }};cf_lock;printf unsafe'''
            r=self.run_shell(body);self.assertNotEqual(r.returncode,0);self.assertNotIn('unsafe',r.stdout)
            self.assertFalse((runtime/'lock').exists())
    def test_recovery_guard_after_slow_owner_validation_preserves_dead_lock(self):
        with tempfile.TemporaryDirectory(prefix='couvre-feu-os-trust-dead-lock-') as folder:
            root=Path(folder);lock=root/'lock';lock.mkdir();(lock/'pid').write_text('999999999\n')
            text=self.bootstrap.read_text();start=text.index('platform_lock_recover() (');stop=text.index('platform_profile_validate()',start)
            fn=text[start:stop]
            body=f'''set -eu
platform_lock_path={lock}
{fn}
fixture_tick=100;platform_clock_tick() {{ printf '%s' "$fixture_tick"; }};
platform_stat() {{ printf '0:0:1777'; }};platform_private() {{ fixture_tick=1400; }};
platform_lock_recover;printf unsafe'''
            r=self.run_shell(body);self.assertNotEqual(r.returncode,0);self.assertIn('admission_deadline',r.stderr);self.assertNotIn('unsafe',r.stdout)
            self.assertEqual((lock/'pid').read_text(),'999999999\n')
    def test_platform_lock_path_is_the_single_source(self):
        # Explicit recovery (install-common.sh) reads platform_lock_path; acquire, release, recover and the
        # compatibility fence must name the same lock, never a second hard-coded copy.
        text=self.bootstrap.read_text()
        self.assertEqual([line for line in text.splitlines() if '/tmp/couvrefeu-platform.lock' in line],
                         ['platform_lock_path=/tmp/couvrefeu-platform.lock'])
        with tempfile.TemporaryDirectory(prefix='couvre-feu-os-trust-lock-path-') as folder:
            lock=Path(folder)/'platform.lock'
            body=f'''set -eu
. "{self.bootstrap}"
platform_lock_path={lock}
platform_stat() {{ printf '0:0:1777'; }};platform_private() {{ :; }};platform_deadline_check() {{ :; }}
platform_lock_acquire;[ "$(cat "{lock}/pid")" = "$$" ];printf acquired;platform_lock_release;[ ! -e "{lock}" ];printf released
mkdir "{lock}";printf '999999999\\n' > "{lock}/pid";platform_lock_recover;[ ! -e "{lock}" ];printf recovered
platform_transaction_paths() {{ :; }};mkdir "{lock}";(platform_transaction_compat_clear) 2>/dev/null || printf fenced'''
            r=self.run_shell(body)
            self.assertEqual(r.stdout,'acquiredreleasedrecoveredfenced',r.stderr)
    def test_internal_receipt_separates_kernel_proof_and_protected_attempt(self):
        for zero,started,ok in [(True,False,True),(True,True,True),(False,True,True),(False,False,False)]:
            receipt=json.dumps({'ok':True,'removed':True,'zeroOwnedMutations':zero,'initialProtectedWrite':started,'errors':[]},separators=(',',':'))
            r=self.run_shell('platform_cleanup_receipt '+shlex.quote(receipt)+';printf "%s:%s" "$platform_cleanup_zero" "$CF_PLATFORM_INITIAL_WRITE"')
            self.assertEqual(r.returncode==0,ok,r.stderr)
            if ok:self.assertEqual(r.stdout,str(int(zero))+':'+str(int(started)))
        for receipt in ['{"ok":true,"removed":true,"zeroOwnedMutations":true,"errors":[]}',
                        '{"ok":true,"removed":true,"zeroOwnedMutations":true,"initialProtectedWrite":1,"errors":[]}',
                        '{"ok":true,"removed":true,"zeroOwnedMutations":true,"initialProtectedWrite":false,"errors":[],"extra":true}']:
            self.assertNotEqual(self.run_shell('platform_cleanup_receipt '+shlex.quote(receipt)).returncode,0)
        receipt='{"ok":true,"removed":true,"zeroOwnedMutations":true,"initialProtectedWrite":false,"errors":[]}'
        self.assertNotEqual(self.run_shell('CF_PLATFORM_INITIAL_WRITE=1;platform_cleanup_receipt '+shlex.quote(receipt)).returncode,0)
    def test_resume_barriers_and_atomic_copy_follow_blocking_proofs(self):
        install=(REPO/'router/install.sh').read_text();uninstall=(REPO/'router/uninstall.sh').read_text()
        self.assertIn('install_parent=$(dirname "$ROOT/$rel")\n    platform_initial_write\n    mkdir',install)
        self.assertIn('else platform_initial_write; rm -f "$p"',uninstall)
        self.assertIn('else platform_initial_write; chmod "$mode"',uninstall)
        common=(REPO/'router/lib/install-common.sh').read_text();start=common.index('atomic_copy() (');stop=common.index('\n)\n',start)+3
        fn=common[start:stop]
        # atomic_copy publishes through publish_temp; both carry the write barrier.
        start=common.index('publish_temp() {');stop=common.index('\n}\n',start)+3
        fn=common[start:stop]+fn
        with tempfile.TemporaryDirectory(prefix='couvre-feu-os-trust-copy-') as folder:
            root=Path(folder);src=root/'src';dst=root/'dst';tmp=root/'dst.couvrefeu-tmp'
            src.write_text('expected');dst.write_text('original');tmp.write_text('expected')
            body=f'''set -eu
{fn}
printf 100 > {root}/tick;platform_clock_tick() {{ cat {root}/tick; }};
fail() {{ exit 2; }};owned_temp() {{ :; }};signature() {{ printf 1400 > {root}/tick;printf expected; }};
atomic_copy {src} {dst};printf unsafe'''
            # The signature proof runs in command substitution; a clock file
            # carries the injected time past the proof into the write barrier.
            r=self.run_shell(body);self.assertNotEqual(r.returncode,0);self.assertNotIn('unsafe',r.stdout)
            self.assertEqual(dst.read_text(),'original');self.assertTrue(tmp.exists())

    def test_resumed_done_publication_checks_after_final_validation(self):
        text=self.bootstrap.read_text();start=text.index('platform_publish_done() {');stop=text.index('\n}',start)+2
        fn=text[start:stop]
        with tempfile.TemporaryDirectory(prefix='couvre-feu-os-trust-done-') as folder:
            done=Path(folder)/'done';pending=Path(str(done)+'.next')
            for existing in [False,True]:
                for profile,started,ok in [(PROFILE,0,False),('strict',0,True),(platform.PROFILE,0,True),(PROFILE,1,True)]:
                    done.unlink(missing_ok=True);pending.unlink(missing_ok=True)
                    if existing:pending.write_text('validated receipt');pending.chmod(0o600)
                    body=f"""set -eu
{fn}
DONE={done};HERE=/unused;CF_RELEASE_ID=fixed;CF_PLATFORM_PROFILE={profile};CF_PLATFORM_INITIAL_WRITE={started};CF_PLATFORM_OWNER="$(id -u):$(id -g)";
fixture_tick=100;platform_clock_tick() {{ printf '%s' "$fixture_tick"; }};
platform_external_closure() {{ fixture_tick=1400; }};platform_valid_done() {{ fixture_tick=1400; }};
sync() {{ :; }};platform_publish_done;printf complete"""
                    r=self.run_shell(body);self.assertEqual(r.returncode==0,ok,r.stderr)
                    self.assertEqual(done.exists(),ok)
                    if not ok:
                        self.assertIn('admission_deadline',r.stderr);self.assertEqual(pending.exists(),existing)
                        if existing:self.assertEqual(pending.read_text(),'validated receipt')

    def test_resumed_reload_checks_after_fixture_tool_validation(self):
        text=(REPO/'router/lib/install-common.sh').read_text();start=text.index('reload_firewall() {');stop=text.index('\n}',start)+2
        fn=text[start:stop]
        with tempfile.TemporaryDirectory(prefix='couvre-feu-os-trust-reload-') as folder:
            root=Path(folder);marker=root/'reloaded';backend=root/'firewall'
            backend.write_text('#!/bin/sh\nprintf reloaded > '+shlex.quote(str(marker))+'\n');backend.chmod(0o700)
            for profile,started,ok in [(PROFILE,0,False),('strict',0,True),(platform.PROFILE,0,True),(PROFILE,1,True)]:
                marker.unlink(missing_ok=True)
                body=f"""set -eu
{fn}
CF_TEST_MODE=1;CF_BACKEND_DIR={root};CF_PLATFORM_PROFILE={profile};CF_PLATFORM_INITIAL_WRITE={started};
fixture_tick=100;platform_clock_tick() {{ printf '%s' "$fixture_tick"; }};
fixture_tools() {{ fixture_tick=1400; }};reload_firewall;printf complete"""
                r=self.run_shell(body);self.assertEqual(r.returncode==0,ok,r.stderr)
                self.assertEqual(marker.exists(),ok)
                if not ok:self.assertIn('admission_deadline',r.stderr)
            # Production dispatch has the same immediate primitive boundary.
            self.assertIn('else platform_initial_write; env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C /etc/init.d/firewall reload; fi',fn)

class OperationalFlowTests(unittest.TestCase):
    def os_trust_release(self,f,stat_payload=None):
        # The genuine ash/router code uses the isolated JSON backend. Hardware
        # admission is the same explicit inert adapter as recovery fixtures.
        # stat_payload keeps the genuine vendor platform_stat (env -i + timeout -s KILL)
        # with only its payload path replaced, so its children can be observed.
        (f.root/'tmp').chmod(0o1777)
        release=f.root/'release';shutil.copytree(REPO/'router',release)
        bootstrap=release/'lib/platform-bootstrap.sh';text=bootstrap.read_text()
        start=text.index('platform_bootstrap_vendor() {');stop=text.index('platform_verify_modules()',start)
        adapter='platform_bootstrap_vendor() { :; }\n'
        if stat_payload is not None:
            body=text[start:stop];stat_start=body.index('    platform_stat() {');stat_stop=body.index('\n    }\n',stat_start)+7
            adapter=('platform_bootstrap_vendor() {\n'+body[stat_start:stat_stop].replace('/usr/libexec/stat-coreutils',str(stat_payload))
                     +'    stat() { platform_stat "$@"; }\n}\n')
        text=text[:start]+adapter+text[stop:]
        text=text.replace('/tmp/couvrefeu-platform.lock',str(f.root/'tmp/couvrefeu-platform.lock'))
        text=text.replace("'%u:%g:%a' /tmp)","'%u:%g:%a' "+str(f.root/'tmp')+')').replace('0:0:1777',f'{os.getuid()}:{os.getgid()}:1777')
        text=text.replace('        vp_transaction_check >/dev/null','        vp_transaction_check() { return 0; }; vp_transaction_check >/dev/null')
        bootstrap.write_text(text)
        compiler=(REPO/'tools/freeze-router-release.py').read_text().replace("Path(__file__).resolve().parent / 'strip-test-mode.py'", 'Path(' + repr(str(REPO / 'tools/strip-test-mode.py')) + ')').replace("router = Path(__file__).resolve().parents[1] / 'router'",'router = Path('+repr(str(release))+')')
        subprocess.run(['python3','-c',compiler],capture_output=True,check=True)
        return release

    def test_native_complete_flows_record_latency_without_target_claim(self):
        sys.path.insert(0,str(REPO/'tests/fixtures'))
        from harness import RouterFixture,PROTECTED,KID,policy
        f=RouterFixture()
        try:
            release=self.os_trust_release(f)
            env=dict(f.env,CF_TEST_INSTALL_KERNEL='1');rows=[]
            def run(label,argv,raw=None):
                started=time.monotonic()
                result=subprocess.run(f.shell+argv,env=env,input=raw,capture_output=True,text=True,timeout=60)
                elapsed=time.monotonic()-started;rows.append({'flow':label,'seconds':round(elapsed,6),'exit':result.returncode})
                self.assertEqual(result.returncode,0,result.stderr+result.stdout)
                # Fixture backend latency only. Actual production margin remains
                # a separately measured release gate, never inferred from this.
                rows[-1]['withinHost15Seconds']=elapsed<15
                return result
            run('activation',[str(release/'install.sh'),'--platform-profile',PROFILE,'--activate','--protect',PROTECTED,'--rpc-allow',KID])
            entry=str(f.root/'usr/sbin/cfctl')
            run('status',[entry,'status','--json'])
            data=policy();data['people'][0]['macs']=[KID]
            run('sync',[entry,'sync'],json.dumps(data))
            run('expire',[entry,'expire'])
            run('nested-journal-reload',[entry,'apply-fw'])
            run('restoration',[str(release/'uninstall.sh')])
            print('OS_TRUST_FIXTURE_LATENCY '+json.dumps(rows),file=__import__('sys').stderr)
        finally:f.close()

    def test_blocked_output_holds_no_lock(self):
        # Vendor entry holds the platform lock (and mutating verbs the transaction mutex) from
        # admission; a client that stops reading stdout must keep neither. Even `status`, which
        # takes no runtime lock, holds the platform lock under this profile.
        sys.path.insert(0,str(REPO/'tests/fixtures'))
        from harness import RouterFixture,PROTECTED,KID,policy,start_with_full_stdout,drain_full_stdout
        f=RouterFixture()
        try:
            release=self.os_trust_release(f)
            env=dict(f.env,CF_TEST_INSTALL_KERNEL='1')
            installed=subprocess.run(f.shell+[str(release/'install.sh'),'--platform-profile',PROFILE,'--activate','--protect',PROTECTED,'--rpc-allow',KID],
                                     env=env,capture_output=True,text=True,timeout=120)
            self.assertEqual(installed.returncode,0,installed.stderr+installed.stdout)
            entry=str(f.root/'usr/sbin/cfctl')
            def cfctl(*args,raw=None):
                return subprocess.run(f.shell+[entry,*args],env=env,input=raw,capture_output=True,text=True,timeout=120)
            def document():
                current=json.loads(cfctl('rpc-status','--json').stdout)
                data=policy(current['acceptedPolicy']['revision']+1);data['people'][0]['macs']=[KID]
                return current,data
            def rpc_request():
                current,data=document()
                return json.dumps(dict(rpc_version=1,generation=current['generation'],operation_id='op_blocked',
                                       expected_revision=current['acceptedPolicy']['revision'],expected_digest=current['policyDigest'],policy=data))
            cases=(('status',('status','--json'),None),('sync',('sync',),lambda:json.dumps(document()[1])),
                   ('rpc-sync',('rpc-sync',),rpc_request),('pause',('pause','alice'),None),('resume',('resume','alice'),None),
                   ('expire',('expire',),None),('rpc-status',('rpc-status','--json'),None),
                   ('apply-fw',('apply-fw',),None),('rpc-activity',('rpc-activity','--json'),None),
                   ('rpc-inventory',('rpc-inventory','--json'),None),
                   # A refusal raised under the platform lock and cf_lock (stale CAS revision).
                   ('refusal',('rpc-sync',),lambda:json.dumps(dict(json.loads(rpc_request()),expected_revision=999))),
                   ('remove-fw',('remove-fw',),None))  # last: it changes the firewall state
            for label,args,stdin in cases:
                with self.subTest(command=label):
                    child,read_end=start_with_full_stdout(f.shell+[entry,*args],env,stdin() if stdin else None)
                    try:
                        probe=cfctl('expire')
                        self.assertEqual(probe.returncode,0,(label,probe.stdout,probe.stderr))
                        self.assertIsNone(child.poll(),'the blocked command must still be writing')
                    finally:
                        status,stdout=drain_full_stdout(child,read_end)
                    self.assertEqual(status,1 if label=='refusal' else 0,stdout)
                    self.assertTrue(stdout.rstrip().endswith('}'),stdout)
        finally:f.close()

    def installed_entry(self,f,**release_options):
        sys.path.insert(0,str(REPO/'tests/fixtures'))
        from harness import PROTECTED,KID
        release=self.os_trust_release(f,**release_options)
        env=dict(f.env,CF_TEST_INSTALL_KERNEL='1')
        installed=subprocess.run(f.shell+[str(release/'install.sh'),'--platform-profile',PROFILE,'--activate','--protect',PROTECTED,'--rpc-allow',KID],
                                 env=env,capture_output=True,text=True,timeout=120)
        self.assertEqual(installed.returncode,0,installed.stderr+installed.stdout)
        return str(f.root/'usr/sbin/cfctl'),env

    def test_signal_while_output_blocked_keeps_a_foreign_platform_lock(self):
        # The blocked command released every lock before writing. Another command then holds the
        # platform lock, the mutex and cf_lock (stopped at before_write). HUP/TERM to the blocked one
        # must release nothing it no longer owns.
        sys.path.insert(0,str(REPO/'tests/fixtures'))
        from harness import RouterFixture,KID,policy,start_with_full_stdout,drain_full_stdout
        f=RouterFixture()
        try:
            entry,env=self.installed_entry(f)
            data=policy(2);data['people'][0]['macs']=[KID]
            synced=subprocess.run(f.shell+[entry,'sync'],env=env,input=json.dumps(data),capture_output=True,text=True,timeout=120)
            self.assertEqual(synced.returncode,0,synced.stderr+synced.stdout)
            platform_lock=f.root/'tmp/couvrefeu-platform.lock';marker=f.root/'rpc-stopped'
            for signum,code in ((signal.SIGHUP,129),(signal.SIGTERM,143)):
                with self.subTest(signal=signum):
                    child,read_end=start_with_full_stdout(f.shell+[entry,'expire'],env)
                    marker.unlink(missing_ok=True)
                    parked=subprocess.Popen(f.shell+[entry,'pause','alice'],env=dict(env,CF_TEST_RPC_STOP='before_write'),stdin=subprocess.DEVNULL,
                                            stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
                    try:
                        deadline=time.monotonic()+90
                        while not (marker.exists() and open('/proc/%d/stat'%parked.pid).read().rsplit(') ',1)[1][0]=='T'):
                            self.assertLess(time.monotonic(),deadline,'checkpoint not reached');time.sleep(.1)
                        held=(platform_lock/'pid').read_text();self.assertEqual(held.strip(),str(parked.pid))
                        os.kill(child.pid,signum)
                        status,stdout=drain_full_stdout(child,read_end)
                        self.assertIn(status,(code,0),stdout)
                        self.assertEqual((platform_lock/'pid').read_text(),held,'a foreign platform lock was released')
                        self.assertTrue((f.root/'etc/couvrefeu/runtime/lock').exists(),'a foreign cf_lock was released')
                        os.kill(parked.pid,signal.SIGCONT)
                        out,err=parked.communicate(timeout=120)
                        self.assertEqual(parked.returncode,0,out+err)
                    finally:
                        for process in (child,parked):
                            if process.poll() is None:os.killpg(process.pid,signal.SIGKILL);process.wait()
                    resumed=subprocess.run(f.shell+[entry,'resume','alice'],env=env,capture_output=True,text=True,timeout=120)
                    self.assertEqual(resumed.returncode,0,resumed.stderr+resumed.stdout)
        finally:f.close()

    def test_mutex_children_do_not_inherit_fd9(self):
        # The vendor platform_stat runs `timeout -s KILL` children, many of them under the transaction
        # mutex. BusyBox timeout is reported to leave a detached watcher that inherits fds above 2; the
        # payload below records fd 9 and emulates that watcher with a 2 s background sleep. A child that
        # inherits fd 9 keeps the flock after cfctl exits, so the next `expire` gets transaction_contention.
        sys.path.insert(0,str(REPO/'tests/fixtures'))
        from harness import RouterFixture
        f=RouterFixture()
        try:
            log=f.root/'stat-fd9.log';payload=f.root/'stat-payload'
            payload.write_text('#!/bin/sh\nprintf "%s\\n" "$(readlink /proc/$$/fd/9 2>/dev/null || echo closed)" >> '+str(log)+'\n'
                               'sleep 2 </dev/null >/dev/null 2>&1 &\nexec stat "$@"\n')
            payload.chmod(0o700)
            entry,env=self.installed_entry(f,stat_payload=payload)
            log.write_text('')
            for args in (('expire',),('apply-fw',),('expire',),('pause','nobody')):
                result=subprocess.run(f.shell+[entry,*args],env=env,capture_output=True,text=True,timeout=120)
                self.assertNotIn('transaction_contention',result.stderr,args)
                if args!=('pause','nobody'):self.assertEqual(result.returncode,0,(args,result.stdout,result.stderr))
            seen=log.read_text().splitlines()
            self.assertGreater(len(seen),10,'the genuine platform_stat was not exercised')
            self.assertEqual([line for line in seen if line.endswith('.couvrefeu-mutex')],[],'a timeout child inherited the mutex fd 9')
        finally:
            time.sleep(2.2);f.close()

if __name__=='__main__':unittest.main()
