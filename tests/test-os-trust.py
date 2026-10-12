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
        return subprocess.run(SHELL+['-c',self.setup+extra+'\nvp_transaction_check'],capture_output=True,text=True,timeout=10)
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
        return subprocess.run(SHELL+['-c',self.setup+body],capture_output=True,text=True,timeout=10)
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
        with tempfile.TemporaryDirectory(prefix='couvre-feu-os-trust-input-') as folder:
            root=Path(folder);(root/'tmp').mkdir()
            body=f'''CF_BASE={root};CF_LOCAL_TEST=1;CF_TEST_TIMEOUT='{SHELL[0]} timeout';. "{REPO}/router/lib/core.sh";CF_PLATFORM_ENTRY_TICK=$(platform_clock_tick);CF_PLATFORM_ENTRY_TICK=$((CF_PLATFORM_ENTRY_TICK-1290));cf_sync_stage 0;printf unsafe'''
            child=subprocess.Popen(SHELL+['-c',self.setup+body],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            try:
                time.sleep(.2);out,err=child.communicate('{}',timeout=5)
                self.assertNotEqual(child.returncode,0);self.assertIn('admission_deadline',err);self.assertNotIn('unsafe',out)
                self.assertEqual(list((root/'tmp').iterdir()),[])
            finally:
                if child.poll() is None:child.kill()
                child.communicate(timeout=5)
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

class OperationalFlowTests(unittest.TestCase):
    def test_native_complete_flows_record_latency_without_target_claim(self):
        # The genuine ash/router code uses the isolated JSON backend. Hardware
        # admission is the same explicit inert adapter as recovery fixtures.
        sys.path.insert(0,str(REPO/'tests/fixtures'))
        from harness import RouterFixture,PROTECTED,KID,policy
        f=RouterFixture()
        try:
            (f.root/'tmp').chmod(0o1777)
            release=f.root/'release';shutil.copytree(REPO/'router',release)
            bootstrap=release/'lib/platform-bootstrap.sh';text=bootstrap.read_text()
            start=text.index('platform_bootstrap_vendor() {');stop=text.index('platform_verify_modules()',start)
            text=text[:start]+'platform_bootstrap_vendor() { :; }\n'+text[stop:]
            text=text.replace('/tmp/couvrefeu-platform.lock',str(f.root/'tmp/couvrefeu-platform.lock'))
            text=text.replace("'%u:%g:%a' /tmp)","'%u:%g:%a' "+str(f.root/'tmp')+')').replace('0:0:1777',f'{os.getuid()}:{os.getgid()}:1777')
            text=text.replace('        vp_transaction_check >/dev/null','        vp_transaction_check() { return 0; }; vp_transaction_check >/dev/null')
            bootstrap.write_text(text)
            compiler=(REPO/'tools/freeze-router-release.py').read_text().replace("router = Path(__file__).resolve().parents[1] / 'router'",'router = Path('+repr(str(release))+')')
            subprocess.run(['python3','-c',compiler],capture_output=True,check=True)
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

if __name__=='__main__':unittest.main()
