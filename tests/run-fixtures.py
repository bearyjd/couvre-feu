#!/usr/bin/env python3
"""Run independent private-root cases in bounded subprocess lanes."""
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'tests/fixtures'))
from harness import run_owned_process

SUITES = ('test-transition.py', 'test-rpc.py', 'test-core.py', 'test-fixture-process.py', 'test-penn-pilot.py', 'test-penn-pilot-leg2.py', 'test-penn-pilot-leg2-guards.py', 'test-scope-admin.py', 'test-inventory.py')
# Fixed public source paths bind the plan to fixtures and the entire release.
SOURCE_FILES = ('.github/workflows/ci.yml', 'tests/run.sh', 'tests/run-fixtures.py', 'tests/fixtures/harness.py', 'tests/fixtures/backend.py',
                'tests/test-live-rehearsal.py',
                'router/release.sha256', 'router/install.sh', 'router/uninstall.sh',
                'router/cfctl', 'router/cfctl-ssh', 'router/cfctl-scope', 'router/lib/platform-bootstrap.sh',
                'router/lib/vendor-platform.sh', 'router/lib/install-common.sh',
                'router/lib/core.sh', 'router/lib/rpc.sh', 'router/lib/firewall.sh',
                'router/lib/state.awk', 'router/lib/rules.awk', 'router/lib/json.awk',
                'router/lib/activity.sh')


# Measured seconds, per suite, for the cases that dominate its runtime; every
# other case weighs DEFAULT_WEIGHT. Used only to spread cases over each suite's
# partitions so no shard approaches the lane budget: a stale or missing entry
# makes the split less even but never changes which cases run (coverage is
# proven in discovery_plan). Refresh: take the 'TIMING: __main__.<Class>.<test>
# <n>s' lines from a CI run's shard logs (emitted per case by
# tests/fixtures/harness.py, relayed by main()) and keep entries of roughly
# 30 s or more as {'<Class>.<test>': seconds}. Seeded from CI run 40377200351; test-core refreshed from run 40667834404.
DEFAULT_WEIGHT = 5
# Partitions per suite (default 4). test-core.py is ~3900 s of serial cases: four
# shards ran 630-1290 s against the 1800 s lane budget; five predict about 770 s each.
# test-penn-pilot.py was ~1047 s with four; five predict about 837 s each. The longest
# predicted shard is now test-transition.py at about 904 s (50%).
DEFAULT_PARTITIONS = 4
PARTITION_COUNTS = {'test-core.py': 5, 'test-penn-pilot.py': 5}
LANE_TIMEOUT = 1800
CASE_WEIGHTS = {
    'test-core.py': {
        'CoreTests.test_allowance_unblocks_schedule_and_local_expiry_reblocks_without_service': 169,
        'InstalledPackageTests.test_actual_installed_core_lifecycle_and_exact_recovery': 158,
        'ActivityTests.test_counter_epoch_changes_whenever_counters_reset': 109,
        'CoreTests.test_nan_and_inf_person_ids_pause_only_themselves': 104,
        'CoreTests.test_pause_resume_all_person_devices_increment_revision': 104,
        'CoreTests.test_healthy_unchanged_expire_and_apply_verify_without_kernel_mutations': 101,
        'CoreTests.test_cached_ipv6_aliases_cover_schedule_pause_guards_and_conntrack': 89,
        'CoreTests.test_observation_accepts_equivalent_iptables_serialization': 86,
        'CoreTests.test_ipv6_valid_state_changes_preserve_confirmation_and_noop_sync': 84,
        'CoreTests.test_pause_flushes_every_known_ipv4_ipv6_source_and_destination': 82,
        'CoreTests.test_cross_midnight_schedule_rotates_weekdays_and_excludes_stop': 79,
        'CoreTests.test_allowance_overrides_manual_pause_and_expiry_restores_it': 78,
        'CoreTests.test_latent_native_selector_cannot_be_blessed_by_healthy_kernel_witness': 74,
        'CoreTests.test_changed_child_address_rebuilds_inbound_guards': 73,
        'CoreTests.test_reload_reconstructs_owned_rules_and_sets': 73,
        'CoreTests.test_allowance_horizon_boundary_and_expired_allowance_is_inert': 72,
        'CoreTests.test_cli_pause_is_an_emergency_block_that_clears_the_allowance': 71,
        'CoreTests.test_expired_kid_lease_cannot_flush_current_protected_adult': 69,
        'CoreTests.test_backward_clock_jump_does_not_resurrect_expired_allowance': 62,
        'CoreTests.test_backward_clock_jump_does_not_resurrect_already_expired_pause': 61,
        'CoreTests.test_pending_apply_records_and_missing_confirmation_require_recovery_work': 61,
        'CoreTests.test_native_metadata_without_dual_family_witness_cannot_confirm': 59,
        'CoreTests.test_repeat_sync_and_apply_fw_are_idempotent': 57,
        'CoreTests.test_expiry_removes_mac_pause_when_ipv6_neighbor_is_not_fresh': 56,
        'CoreTests.test_early_schedule_covers_inbound_ipv4_ipv6_without_blocking_adults': 55,
        'CoreTests.test_native_schedule_hidden_by_earlier_accept_cannot_confirm': 54,
        'InstalledPackageTests.test_uninstall_removes_activity_accounting_in_both_families': 50,
        'CoreTests.test_expiry_is_local_and_same_revision_replay_cannot_resurrect': 48,
        'CoreTests.test_unknown_person_cli_and_shell_payload_never_mutate': 48,
        'InstalledPackageTests.test_actual_uninstall_partial_kernel_cleanup_then_retry': 47,
        'CoreTests.test_lock_record_write_error_is_unsafe_lock_and_leaves_no_record': 46,
        'CoreTests.test_preexisting_failed_or_missing_alias_remains_an_inventory_gap': 46,
        'CoreTests.test_expire_killed_before_pid_publication_does_not_wedge_later_expiry': 43,
        'CoreTests.test_sync_open_stdin_cannot_lock_out_local_expiry': 43,
        'CoreTests.test_set_drift_rebuilds_instead_of_skipping_actual_verification': 42,
        'CoreTests.test_surplus_owned_native_section_cannot_survive_healthy_empty_schedule': 42,
        'CoreTests.test_failed_empty_owned_chain_read_cannot_confirm_a_new_revision': 41,
        'CoreTests.test_wholly_absent_interrupted_initial_staging_recovers_old_policy': 41,
        'CoreTests.test_parent_hook_narrowed_to_tcp_cannot_confirm': 40,
        'CoreTests.test_failed_observation_never_reports_healthy_confirmation': 38,
        'CoreTests.test_host_prefix_equivalence_is_family_specific': 38,
        'CoreTests.test_status_rejects_missing_hook_and_extra_owned_accept': 38,
        'CoreTests.test_alive_lock_refuses_concurrent_mutation_then_interruption_recovers': 37,
        'CoreTests.test_invalid_allowances_rejected_without_mutation': 37,
        'ActivityTests.test_counters_parse_sum_and_sort_by_person_then_mac': 36,
        'CoreTests.test_higher_revision_with_same_effective_rules_updates_confirmation': 36,
        'CoreTests.test_invalid_clock_never_honors_allowance': 36,
        'CoreTests.test_native_schedule_extra_source_narrowing_cannot_confirm': 36,
        'CoreTests.test_known_protected_ipv6_ssh_client_can_sync': 35,
        'CoreTests.test_known_protected_ssh_client_can_sync': 35,
        'CoreTests.test_persisted_recovery_phase_blocks_enforcement_recreation': 35,
        'CoreTests.test_stale_and_conflicting_equal_revision_refuse_without_mutation': 35,
        'CoreTests.test_status_observes_actual_drift_without_mutating': 35,
        'CoreTests.test_sync_stage_injected_environment_refused': 35,
        'InstalledPackageTests.test_preflight_only_uninstall_retains_proof_across_sync_failure_and_process_kill': 35,
        'ActivityTests.test_blocked_hits_are_attributed_and_counters_never_change_verdicts': 34,
        'CoreTests.test_native_reject_requires_real_wan_device_and_complete_multiwan_coverage': 34,
        'CoreTests.test_unpublished_lock_with_a_record_is_never_stolen_by_expire': 34,
        'CoreTests.test_allowance_without_allowances_key_keeps_legacy_shape': 33,
        'CoreTests.test_known_target_input_prefixes_are_safe_disjoint_from_kid_dns': 31,
    },
    'test-fixture-process.py': {
        'FixtureProcessTests.test_router_success_preserves_result_and_confirmation': 36,
    },
    'test-inventory.py': {
        'GoldenTests.test_golden_replies_match_the_router': 38,
        'TruncationTests.test_cap_keeps_kids_then_neighbours_then_lowest_macs_as_whole_devices': 38,
    },
    'test-penn-pilot.py': {
        'PilotV2FixtureTests.test_v2_happy_path_passes_in_order_and_restores_exactly': 634,
        'PilotFixtureTests.test_single_child_exact_adult_alias_passes_and_preserves_protection': 301,
        'PilotFixtureTests.test_transient_drift_after_expiry_settles_at_the_accounted_revision': 299,
        'PilotFixtureTests.test_two_children_exact_adult_alias_passes_and_preserves_protection': 281,
        'PilotFixtureTests.test_transient_drift_after_rpc_sync_settles_with_one_rpc_sync': 276,
        'PilotFixtureTests.test_happy_path_passes_measures_and_restores_exactly': 275,
        'PilotFixtureTests.test_two_devices_with_scope_negative_test_pass_and_restore_exactly': 217,
        'PilotV2FixtureTests.test_v2_leg_that_never_runs_stops_and_tears_down_once_with_exact_restore': 210,
        'PilotV2FixtureTests.test_v2_wrong_confirmation_is_a_refused_leg_and_leg_one_does_not_believe_anything': 160,
        'PilotFixtureTests.test_adult_disruption_stops_and_always_tears_down': 124,
        'PilotFixtureTests.test_scope_firewall_change_stops_and_tears_down_once': 104,
        'PilotFixtureTests.test_scope_safe_band_never_opening_stops_and_tears_down_once': 92,
        'PilotV2FixtureTests.test_v2_self_abort_at_seventy_percent_ends_stopped_and_restored': 91,
        'PilotFixtureTests.test_status_errors_stop_enroll_on_first_read': 90,
        'PilotFixtureTests.test_persistent_drift_stops_enroll_after_settle_and_restores': 79,
        'PilotFixtureTests.test_enroll_coverage_failure_captures_scoped_snapshot_once_and_restores': 64,
    },
    'test-rpc.py': {
        'SshGuardTests.test_uninstall_with_ambiguous_client': 150,  # lane watchdog hit it; true time unknown
        'RpcTests.test_interruptions_keep_old_or_new_complete_policy_and_receipt': 494,
        'NumericLookingIdTests.test_each_id_accepts_replays_and_never_duplicates': 313,
        'MultiScopeRpcTests.test_maximum_scope_of_256_installs_and_binds': 211,
        'RpcTests.test_allowance_does_not_affect_exact_uninstall': 153,
        'ReceiptEvictionTests.test_consecutive_syncs_at_capacity_evict_in_insertion_order': 114,
        'SshGuardTests.test_fifty_preflight_refused_syncs_never_change_protected': 91,
        'RpcTests.test_rpc_allowance_is_reported_and_expires_locally_with_idempotent_replay': 84,
        'RpcTests.test_scoped_kernel_activation_rpc_and_exact_uninstall': 84,
        'RpcTests.test_local_edit_preserves_history_clears_current': 79,
        'RpcTests.test_sync_failure_after_rename_retains_receipt_without_apply': 68,
        'RpcTests.test_expired_replay_preserves_original_until_and_never_reapplies': 64,
        'NumericLookingIdTests.test_100_and_1e2_are_distinct_operations': 60,
        'SshGuardTests.test_apply_fw_and_expire_from_unprotected_client_are_not_guarded': 59,
        'ReceiptEvictionTests.test_sync_at_capacity_evicts_oldest_in_the_same_write': 56,
        'RpcTests.test_normalized_whitespace_key_array_and_ipv6_replay': 56,
        'RpcTests.test_open_stdin_does_not_lock_expiry_and_crosses_uninstall': 52,
        'RpcTests.test_identical_legacy_sync_invalidates_current_receipt': 51,
        'MultiScopeRpcTests.test_scope_change_is_uninstall_then_fresh_generation': 49,
        'RpcTests.test_historical_rpc_replay_after_new_rpc_does_not_restore': 49,
        'MultiScopeRpcTests.test_policy_across_people_within_scope_accepted_and_activity_reports_both': 47,
        'LiveScopeTests.test_resume_keeps_grown_scope_and_checks_policy_against_live_scope': 45,
        'MultiScopeRpcTests.test_consistently_resigned_noncanonical_scope_fails_closed': 45,
        'RpcTests.test_cas_stale_base_and_generation': 45,
        'SshGuardTests.test_unresolvable_client_mac_is_refused': 45,
        'LiveScopeTests.test_grown_scope_is_listed_with_digest_and_usable': 44,
        'RpcTests.test_exact_acceptance_and_readonly_replay': 44,
        'SshGuardTests.test_sync_pause_resume_from_unprotected_client_are_refused': 44,
        'LiveScopeTests.test_scope_swapped_after_the_safety_check_never_reaches_the_reply': 43,
        'RpcTests.test_apply_failure_retains_receipt_and_replay_never_recovers': 43,
        'LiveScopeTests.test_runtime_and_installer_validators_accept_and_reject_the_same_scopes': 39,
        'ReceiptEvictionTests.test_eviction_and_policy_change_persist_in_one_rename': 39,
        'RpcTests.test_same_id_changed_request_conflicts_before_writes': 39,
        'SshGuardTests.test_non_rpc_sync_from_in_scope_client_is_refused': 39,
        'SshGuardTests.test_protected_client_still_syncs_and_leaves_protected_unchanged': 39,
        'LiveScopeTests.test_unlocked_activity_reads_scope_once_consistently': 38,
        'RpcTests.test_rpc_activity_is_scoped_lockless_and_readonly': 37,
        'RpcTests.test_runtime_owner_blocks_uninstall_and_competing_rpc': 35,
        'RpcTests.test_receipt_metadata_corruption_fails_closed': 33,
        'SshGuardTests.test_sync_with_unset_scope_skips_the_scope_check': 33,
        'LiveScopeTests.test_uninstall_restores_exact_bytes_with_grown_scope_and_stray_snapshot': 32,
    },
    'test-scope-admin.py': {
        'ScopeReviewFixTests.test_commit_output_blocked_on_a_full_pipe_holds_no_lock': 92,
        'OutputBackpressureTests.test_pause_and_resume': 89,
        'OutputBackpressureTests.test_sync': 53,
        'ScopeConcurrencyTests.test_scope_add_waits_for_rpc_sync_lock': 53,
        'ScopeConcurrencyTests.test_stop_and_crash_at_each_write_step_keeps_rpc_and_uninstall_working': 52,
        'OutputBackpressureTests.test_expire': 51,
        'OutputBackpressureTests.test_rpc_sync': 51,
        'OutputBackpressureTests.test_unusable_buffer_parent_never_refuses_enforcement': 48,
        'ScopeAddRemoveTests.test_enrolled_scope_added_mac_can_be_used_by_policy': 43,
        'OutputBackpressureTests.test_scope_preview': 41,
        'ScopeConcurrencyTests.test_rpc_sync_waits_for_scope_add_lock': 41,
        'OutputBackpressureTests.test_rpc_status': 38,
        'ScopeRefusalTests.test_no_current_evidence': 32,
        'ScopeRefusalTests.test_mac_in_use_by_a_person_cannot_be_removed': 31,
    },
    'test-transition.py': {
        'TransitionTests.test_all_switch_and_unguard_failures_remain_safe_and_retry': 306,
        'FailClosedReconstructionTests.test_failure_at_each_staging_step_keeps_old_generation_dispatched': 195,
        'FailClosedReconstructionTests.test_child_address_change_repairs_stale_selector_with_iptables_delete_order': 172,
        'FailClosedReconstructionTests.test_router_sort_order_enrolled_transition_and_uninstall': 140,
        'TransitionTests.test_reload_guard_loss_fences_all_switches_and_confirmation': 139,
        'FailClosedReconstructionTests.test_interrupted_transition_address_change_repairs_with_iptables_delete_order': 137,
        'TransitionTests.test_interrupted_expiry_repair_never_restores_a_protected_reverse_selector': 131,
        'FailClosedReconstructionTests.test_failure_after_complete_shadow_build_rolls_back_slot_and_intent': 127,
        'FailClosedReconstructionTests.test_status_after_refused_command_never_rewrites_shadow_intent': 122,
        'TransitionTests.test_interrupted_transition_never_revives_allowance_expired_in_between': 118,
        'TransitionTests.test_accepted_interrupted_pause_expiry_rebases_without_resurrection': 108,
        'FailClosedReconstructionTests.test_rollback_failing_after_partial_deletes_keeps_journal_and_uninstall_recovers': 107,
        'FailClosedReconstructionTests.test_uninstall_after_crashed_staging_refuses_until_stale_lock_recovery': 105,
        'FailClosedReconstructionTests.test_first_dispatcher_switch_failure_keeps_old_generation_dispatched': 101,
        'FailClosedReconstructionTests.test_schedule_and_resolver_change_blocks_child_in_every_observed_state': 101,
        'FailClosedReconstructionTests.test_failed_set_read_never_drops_journal_and_uninstall_recovers': 99,
        'TransitionTests.test_full_reload_during_native_update_is_degraded_and_reconstructs': 88,
        'FailClosedReconstructionTests.test_router_order_stored_snapshot_is_accepted': 85,
        'FailClosedReconstructionTests.test_crashed_staging_leftover_generation_is_removed_on_next_run': 83,
        'FailClosedReconstructionTests.test_uninstall_from_drifted_staging_intent_restores_exactly': 80,
        'FailClosedReconstructionTests.test_added_child_is_guarded_before_switch_and_drained': 79,
        'TransitionTests.test_crash_after_first_switch_recovers_observed_effect_before_phase': 79,
        'FailClosedReconstructionTests.test_swapped_child_mac_keeps_union_blocked_through_switch': 77,
        'FailClosedReconstructionTests.test_uninstall_removes_failed_shadow_generation': 77,
        'FailClosedReconstructionTests.test_uninstall_refuses_referenced_staging_slot_without_mutation': 72,
        'TransitionTests.test_expiry_clears_offline_child_and_does_not_evict_reassigned_adult': 72,
        'FailClosedReconstructionTests.test_drift_repair_blocks_child_in_every_observed_state': 70,
        'TransitionTests.test_corrupt_marker_blocks_uninstall_and_exact_retry_cleans_kernel': 67,
        'TransitionTests.test_every_effect_preserves_paused_child_and_adult_reachability': 67,
        'FailClosedReconstructionTests.test_removed_child_stays_blocked_until_switch_completes': 60,
        'TransitionTests.test_failed_second_family_switch_retains_guard_and_recovers': 60,
        'TransitionTests.test_unchanged_active_schedule_drains_both_directions_without_rebuilding': 60,
        'TransitionTests.test_boot_identity_invalidates_confirmation_until_fresh_observation': 50,
        'TransitionTests.test_foreign_reference_refuses_before_flushing_generation': 37,
        'TransitionTests.test_no_marker_rejects_hidden_runtime_and_existing_kernel_objects': 36,
        'TransitionTests.test_old_enrolled_child_cannot_become_protected_during_removal': 34,
    },
}


def partition_cases(names, weights=None, count=4):
    """Greedy longest-first split; deterministic for a given name list and table."""
    weights = weights or {}
    loads, groups = [0] * count, [[] for _ in range(count)]
    for name in sorted(names, key=lambda item: (-weights.get(item, DEFAULT_WEIGHT), item)):
        target = min(range(count), key=lambda index: (loads[index], len(groups[index]), index))
        loads[target] += weights.get(name, DEFAULT_WEIGHT)
        groups[target].append(name)
    return [sorted(group) for group in groups]


def cases(suite):
    for case in suite:
        if isinstance(case, unittest.TestSuite):
            yield from cases(case)
        else:
            yield case.id().split('.', 1)[1]


def run_lane(job, directory, timeout=LANE_TIMEOUT, started=None):
    filename, index, group = job
    log = directory / f'{filename}-{index}.log'
    with log.open('w') as stream:
        log.chmod(0o600)
        try:
            result = run_owned_process([sys.executable, str(REPO / 'tests' / filename), *group],
                                       cwd=REPO, env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1', CF_TEST_LANE='1'),
                                       stdout=stream, stderr=subprocess.STDOUT, timeout=timeout,
                                       interrupt_on_timeout=True, started=started)
            status = result.returncode
            if status == 0:
                text = log.read_text()
                summary = re.findall(r'^Ran ([0-9]+) tests? in ', text, re.M)
                if summary != [str(len(group))] or re.search(r'^OK \(skipped=', text, re.M):
                    status = 125
                    stream.write('\nFAIL: lane did not prove every requested case without skips\n')
            return filename, index, len(group), status, log
        except subprocess.TimeoutExpired:
            return filename, index, len(group), 124, log


def worker_count():
    value = os.environ.get('CF_TEST_WORKERS', '4')
    if value not in ('1', '2', '3', '4'):
        raise ValueError('CF_TEST_WORKERS must be an integer from 1 through 4')
    return int(value)


def source_revision():
    revision = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=REPO,
                              check=True, capture_output=True, text=True).stdout.strip()
    if not re.fullmatch(r'[0-9a-f]{40}', revision):
        raise ValueError('invalid source Git revision')
    if 'GITHUB_SHA' in os.environ and os.environ['GITHUB_SHA'] != revision:
        raise ValueError('checkout revision differs from workflow commit')
    return revision


def discovery_plan():
    shards = []
    sources = {name: hashlib.sha256((REPO / name).read_bytes()).hexdigest() for name in SOURCE_FILES}
    for filename in SUITES:
        name = 'fixture_' + filename.replace('-', '_').removesuffix('.py')
        path = REPO / 'tests' / filename
        sources['tests/' + filename] = hashlib.sha256(path.read_bytes()).hexdigest()
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        names = sorted(cases(unittest.defaultTestLoader.loadTestsFromModule(module)))
        if not names or len(names) != len(set(names)):
            raise ValueError(f'empty or duplicate discovery: {filename}')
        partitions = partition_cases(names, CASE_WEIGHTS.get(filename), PARTITION_COUNTS.get(filename, DEFAULT_PARTITIONS))
        union = [case for group in partitions for case in group]
        if not all(partitions) or sorted(union) != names or len(union) != len(set(union)):
            raise ValueError(f'incomplete or duplicate partition coverage: {filename}')
        for index, group in enumerate(partitions):
            shards.append({'suite': filename, 'partition': index, 'cases': group})
    return {'version': 1, 'revision': source_revision(), 'sources': sources, 'shards': shards}


def plan_digest(plan):
    return hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'duplicate JSON key: {key}')
        result[key] = value
    return result


def read_json(path):
    path = Path(path)
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 1048576:
        raise ValueError('unsafe or oversized coverage file')
    value = json.loads(path.read_text(), object_pairs_hook=unique_object)
    if not isinstance(value, dict):
        raise ValueError('coverage document must be an object')
    return value


def write_json(path, value):
    path = Path(path)
    with path.open('x') as stream:
        path.chmod(0o600)
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')


def validated_plan(path):
    plan = read_json(path)
    if plan_digest(plan) != plan_digest(discovery_plan()):
        raise ValueError('coverage plan differs from complete current source discovery')
    return plan


def receipt_for(plan, shard, status):
    return {'version': 1, 'planSHA256': plan_digest(plan), **shard,
            'count': len(shard['cases']), 'status': status}


def verify_receipts(plan, directory):
    directory = Path(directory)
    if not directory.is_dir() or directory.is_symlink():
        raise ValueError('receipt directory missing or unsafe')
    entries = list(directory.iterdir())
    if len(entries) != len(plan['shards']):
        raise ValueError(f"all {len(plan['shards'])} shard receipts are required")
    expected = {(shard['suite'], shard['partition']): receipt_for(plan, shard, 0)
                for shard in plan['shards']}
    seen = set()
    for entry in entries:
        if entry.suffix != '.json':
            raise ValueError('unexpected receipt entry')
        receipt = read_json(entry)
        if not isinstance(receipt.get('suite'), str) or type(receipt.get('partition')) is not int:
            raise ValueError('invalid receipt selector types')
        key = (receipt['suite'], receipt['partition'])
        if key not in expected or key in seen or plan_digest(receipt) != plan_digest(expected[key]):
            raise ValueError('unknown, duplicate, failed or incomplete shard receipt')
        seen.add(key)
    if seen != set(expected):
        raise ValueError('missing coverage partition')
    print(f"PASS: all {len(plan['shards'])} nonempty shards prove complete duplicate-free case coverage", flush=True)


def selection(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group()
    action.add_argument('--write-plan')
    action.add_argument('--shard', choices=SUITES)
    action.add_argument('--verify-receipts')
    parser.add_argument('--partition', choices=tuple(str(index) for index in range(max(PARTITION_COUNTS.values(), default=DEFAULT_PARTITIONS))))
    parser.add_argument('--plan')
    parser.add_argument('--receipt')
    args = parser.parse_args(argv)
    for name in ('write_plan', 'shard', 'verify_receipts', 'plan', 'receipt'):
        if getattr(args, name) == '':
            parser.error(f'{name} cannot be empty')
    if args.shard:
        if args.partition is None or not args.plan or not args.receipt:
            parser.error('shard requires partition, plan and receipt')
    elif args.verify_receipts:
        if not args.plan or args.partition is not None or args.receipt:
            parser.error('receipt verification requires only a plan and receipt directory')
    elif args.partition is not None or args.plan or args.receipt:
        parser.error('selection fields require a shard or receipt verification')
    if args.partition is not None:
        args.partition = int(args.partition)
    return args


def main(argv=()):
    try:
        args = selection(argv)
        workers = worker_count()
        if args.write_plan:
            write_json(args.write_plan, discovery_plan())
            return 0
        if args.verify_receipts:
            verify_receipts(validated_plan(args.plan), args.verify_receipts)
            return 0
        plan = validated_plan(args.plan) if args.shard else discovery_plan()
        selected = [shard for shard in plan['shards']
                    if not args.shard or (shard['suite'] == args.shard and shard['partition'] == args.partition)]
        if not selected or (args.shard and len(selected) != 1):
            raise ValueError('selected shard missing or empty')
    except SystemExit as error:
        return error.code
    except (ValueError, OSError) as error:
        print(f'FAIL: {error}', file=sys.stderr, flush=True)
        return 2
    jobs = [(shard['suite'], shard['partition'], shard['cases']) for shard in selected]
    directory = Path(tempfile.mkdtemp(prefix='couvre-feu-suite-', dir='/tmp'))
    directory.chmod(0o700)

    failed = False
    # Partition counts come from PARTITION_COUNTS; this only bounds concurrent lane execution.
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for future in as_completed([pool.submit(run_lane, job, directory) for job in jobs]):
            filename, index, count, status, log = future.result()
            print(f'{"PASS" if status == 0 else "FAIL"}: {filename} lane {index + 1}, {count} cases', flush=True)
            # Relay per-test durations that suites opt into; never other log text.
            # unittest's verbose '... ' prefix shares the line, so match anywhere.
            for timing in re.findall(r'TIMING: \S+ [0-9]+\.[0-9]s', log.read_text()):
                print(timing, flush=True)
            if args.shard:
                write_json(args.receipt, receipt_for(plan, selected[0], status))
            if status:
                failed = True
                print(log.read_text(), flush=True)
    if failed:
        print(f'Private fixture failure logs retained: {directory}', flush=True)
        return 1
    for log in directory.iterdir():
        log.unlink()
    directory.rmdir()
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
