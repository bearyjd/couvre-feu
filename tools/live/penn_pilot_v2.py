"""Config schema v2 pieces of the Penn pilot, split out of penn-pilot.py (file size cap).

Loaded by penn-pilot.py with `FR` (the first-rehearsal module) already set on this module, so `Refusal` is the
same class the pilot catches. Not a script: it has no entry point and is never run directly. Standard library only.

Everything here is pure: configuration validation, the v2 policy validator and its independent per-stage
expectation, the Leg-2 commit command table, the v2 phase worst cases and the digest/disclosure rules."""
import json
import re

Refusal = FR.Refusal  # noqa: F821  (FR is injected by penn-pilot.py before this module body runs)

PERSON = 'penn'
# Tool-synthesised second person for the MOVE phase; never read from the config.
PILOT_B = 'pilot_b'
SECOND_ROLE = 'penn_child_2'
SCOPE_TARGET_ROLE = 'scope_target'
CT107_ROLE = 'ct107'
PILOT_ROLES = (SECOND_ROLE, CT107_ROLE, SCOPE_TARGET_ROLE)
# Synthetic, unicast, locally administered and never a household device.
SCOPE_TEST_MAC = '02:00:00:00:00:99'
MAC_TOKEN = re.compile(r'[0-9a-f]{2}(?::[0-9a-f]{2}){5}')
# DEC-4 order; the optional SCOPE negative test is inserted before SCOPE-ADD-1.
PHASES_V2 = ('PAYLOAD', 'IDENTITY', 'PREREQ', 'SNAPSHOT', 'BASELINE', 'INSTALL', 'ENROLL', 'SCOPE-ADD-1', 'SCOPE-ADD-2',
             'PAUSE', 'RESUME', 'MOVE', 'BULK', 'EXPIRY', 'DNS', 'INVENTORY', 'SCOPE-REMOVE', 'UNINSTALL', 'RESTORE',
             'CONNECTIVITY')
NEW_PHASES = ('SCOPE-ADD-1', 'SCOPE-ADD-2', 'MOVE', 'BULK', 'INVENTORY', 'SCOPE-REMOVE')
STAGES = ('enroll', 'enroll_phone', 'move', 'move_back')
# Q6, decided by the user: a failed block-all is reported as `unchanged` (provable by the firewall
# fingerprint compare), never `not_blocking` (a packet claim the tool cannot measure).
FAILED_BLOCK_ALL_WORDING = 'unchanged'
FAILED_BLOCK_ALL_DECIDED_BY = 'user'
# Hard max for v2 only; the effective cap is min(this, minimumRemoteTimeoutSeconds + slack).
V2_MAX_REMOTE_TIMEOUT_SECONDS = 10800
V2_TIMEOUT_SLACK_SECONDS = 900
# Leg 2 (local pty driver): hard timeout of each commit leg, no retry.
SCOPE_LEG_SECONDS = 60
SCOPE_LEGS = (('2a', 'cfctl', 'scope-add'), ('2b', 'cfctl', 'scope-remove'),
              ('2c', 'cfctl-scope', 'scope-add'), ('2d', 'cfctl-scope', 'scope-remove'))
POLICY_KEYS = {'version', 'revision', 'people', 'pauses', 'schedules', 'doh'}
# Bound into the plan digest of every v2 plan; a missing one is a refusal, never a silent drop.
V2_ONLY_DIGEST_FIELDS = ('configSchemaVersion', 'legs', 'pilotPolicies', 'failedBlockAllWording',
                         'failedBlockAllWordingDecidedBy')
V2_DIGEST_FIELDS = V2_ONLY_DIGEST_FIELDS + ('roles', 'protectedHistoricalMacs', 'platformProfile', 'sourceCommit')


def v2_timeout(document):
    timeout = document.get('remoteTimeoutSeconds', 1800)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 600 <= timeout <= V2_MAX_REMOTE_TIMEOUT_SECONDS:
        raise Refusal(f'remoteTimeoutSeconds must be an integer from 600 to {V2_MAX_REMOTE_TIMEOUT_SECONDS}')
    return timeout


def remote_timeout_limit(minimum):
    """The v2 cap on remoteTimeoutSeconds: the disclosed worst case plus a fixed slack, never above the hard max."""
    return min(V2_MAX_REMOTE_TIMEOUT_SECONDS, minimum + V2_TIMEOUT_SLACK_SECONDS)


def pilot_roles(roles, version):
    """The pilot-only role entries present in the raw `roles`, refused unless the set fits `version`."""
    extra = {role: roles[role] for role in PILOT_ROLES if role in roles} if isinstance(roles, dict) else {}
    if version == 1:
        for role in (CT107_ROLE, SCOPE_TARGET_ROLE):
            if role in extra:
                raise Refusal(f'roles.{role} requires schemaVersion 2')
        return extra
    if SECOND_ROLE in extra:
        raise Refusal(f'roles.{SECOND_ROLE} is replaced by roles.{SCOPE_TARGET_ROLE} in schemaVersion 2')
    for role in (SCOPE_TARGET_ROLE, CT107_ROLE):
        if role not in extra:
            raise Refusal(f'roles.{role} is required in schemaVersion 2')
    return extra


def _device(entry, role):
    if not isinstance(entry, dict) or set(entry) != {'ip', 'mac'}:
        raise Refusal(f'roles.{role} must contain exactly ip and mac')
    return {'ip': FR.canonical_ipv4(entry['ip'], f'roles.{role}.ip'), 'mac': FR.canonical_mac(entry['mac'], f'roles.{role}.mac')}


def checked_device(entry, role, config):
    """A pilot-only device role: exact {ip, mac}, distinct from every role, the host and protected MACs."""
    device = _device(entry, role)
    macs = {known['mac'] for known in config['roles'].values()} | set(config['protectedHistoricalMacs'])
    ips = {known['ip'] for known in config['roles'].values()} | {config['host']}
    if device['mac'] in macs | {SCOPE_TEST_MAC} or device['ip'] in ips:
        raise Refusal(f'roles.{role} must have a MAC and IP distinct from every role, the host, '
                      'protected MACs and the scope test MAC')
    return device


def checked_ct107(entry, config):
    """CT107 (infrastructure): distinct from every role and the host, and its MAC must be in the protected list."""
    device = _device(entry, CT107_ROLE)
    macs = {known['mac'] for known in config['roles'].values()} | {SCOPE_TEST_MAC}
    ips = {known['ip'] for known in config['roles'].values()} | {config['host']}
    if device['mac'] in macs or device['ip'] in ips:
        raise Refusal('roles.ct107 must have a MAC and IP distinct from every role, the host and the scope test MAC')
    if device['mac'] not in config['protectedHistoricalMacs']:
        raise Refusal('roles.ct107 MAC must be listed in protectedHistoricalMacs (CT107 must stay protected)')
    return device


def add_pilot_roles(config, extra):
    """`config` plus the validated pilot-only roles (ct107 before scope_target, which must differ from it)."""
    for role in PILOT_ROLES:
        if role in extra:
            entry = checked_ct107(extra[role], config) if role == CT107_ROLE else checked_device(extra[role], role, config)
            config = dict(config, roles=dict(config['roles'], **{role: entry}))
    return config


def protected_macs(config):
    """Every MAC no pilot policy may ever name: management, adult, CT107 (v2) and the historical list."""
    roles = config['roles']
    ct107 = [roles[CT107_ROLE]['mac']] if CT107_ROLE in roles else []
    return {roles['management']['mac'], roles['jd_adult']['mac'], *ct107, *config['protectedHistoricalMacs']}


def penn_device_macs(config):
    """Every MAC a v2 policy may name: the Chromebook floor device and the scope target."""
    return {config['roles']['penn_child']['mac'], config['roles'][SCOPE_TARGET_ROLE]['mac']}


def expected_stage_policy(stage, config):
    """The exact policy of one v2 stage, built from the config alone (never from the policy being validated)."""
    chromebook, phone = config['roles']['penn_child']['mac'], config['roles'][SCOPE_TARGET_ROLE]['mac']
    both = sorted([chromebook, phone])
    spec = {'enroll': (1, [(PERSON, [chromebook])]), 'enroll_phone': (2, [(PERSON, both)]),
            'move': (3, [(PERSON, [phone]), (PILOT_B, [chromebook])]), 'move_back': (4, [(PERSON, both)])}
    if stage not in spec:
        raise Refusal(f'unknown pilot policy stage {stage!r}')
    revision, people = spec[stage]
    return {'version': 1, 'revision': revision, 'people': [{'id': who, 'macs': macs} for who, macs in people],
            'pauses': [], 'schedules': [], 'doh': {'ipv4': [], 'ipv6': []}}


def assert_policy_pilot(policy, config, expected):
    """Fail closed (before ssh) unless `policy` is exactly `expected` and only names Penn's devices.

    `expected` must come from `expected_stage_policy` (the config), never from a copy of `policy`. Independently
    of it: people are a subset of {penn, pilot_b} with string ids; every MAC is a Penn device MAC, none protected,
    none repeated within or across people; version and revision are ints; pauses and schedules are exactly `[]`
    and doh exactly the empty address lists (type-strict: 0, '', {} and None are refused). The final comparison
    is of canonical JSON, so 1, 1.0 and True never match each other."""
    allowed = penn_device_macs(config)
    if protected_macs(config) & allowed:
        raise Refusal('a Penn device MAC is protected')
    if not isinstance(policy, dict) or set(policy) != POLICY_KEYS:
        raise Refusal('pilot policy has unexpected fields')
    if any(type(policy[key]) is not int for key in ('version', 'revision')):
        raise Refusal('pilot policy version and revision must be integers')
    people = policy['people']
    if type(people) is not list or not 1 <= len(people) <= 2:
        raise Refusal('pilot policy must contain one or two people')
    ids, macs = [], []
    for person in people:
        if not isinstance(person, dict) or set(person) != {'id', 'macs'} or type(person['macs']) is not list:
            raise Refusal('pilot policy person must contain exactly id and macs')
        ids.append(person['id'])
        macs.extend(person['macs'])
    if not all(type(who) is str for who in ids) or len(set(ids)) != len(ids) or not set(ids) <= {PERSON, PILOT_B}:
        raise Refusal('pilot policy people must be penn and pilot_b only')
    if not all(type(mac) is str for mac in macs) or len(set(macs)) != len(macs):
        raise Refusal('pilot policy MACs must be unique across people')
    if not set(macs) <= allowed:
        raise Refusal('pilot policy names a MAC that is not a Penn device')
    if policy['pauses'] != [] or policy['schedules'] != [] or policy['doh'] != {'ipv4': [], 'ipv6': []}:
        raise Refusal('pilot policy must not carry pauses, schedules or DoH addresses')
    if sorted(MAC_TOKEN.findall(json.dumps(policy).lower())) != sorted(macs):
        raise Refusal('pilot policy contains a MAC token outside the people lists')
    try:
        same = json.dumps(policy, sort_keys=True) == json.dumps(expected, sort_keys=True)
    except (TypeError, ValueError):
        same = False
    if not same:
        raise Refusal('pilot policy differs from the expected policy')
    return policy


def pilot_policies(config, base):
    """The v2 policy sequence (stage, policy): enrol Chromebook, add phone, MOVE A, MOVE back; each validated
    against its independently built expectation. `base` is the enrollment policy shape to derive them from."""
    chromebook, phone = config['roles']['penn_child']['mac'], config['roles'][SCOPE_TARGET_ROLE]['mac']

    def stage(revision, people):
        return dict(base, revision=revision, people=people)
    both = sorted([chromebook, phone])
    policies = (stage(1, [{'id': PERSON, 'macs': [chromebook]}]), stage(2, [{'id': PERSON, 'macs': both}]),
                stage(3, [{'id': PERSON, 'macs': [phone]}, {'id': PILOT_B, 'macs': [chromebook]}]),
                stage(4, [{'id': PERSON, 'macs': both}]))
    return [(name, assert_policy_pilot(policy, config, expected_stage_policy(name, config)))
            for name, policy in zip(STAGES, policies)]


def scope_legs(config):
    """Leg-2 commit commands, fixed text; {MAC} and {BASE} are substituted only by validated values."""
    legs = []
    for leg, form, op in SCOPE_LEGS:
        inner = f'{op} {{MAC}} --base {{BASE}}'
        template = (f'/usr/sbin/cfctl {inner}' if form == 'cfctl'
                    else f"env SSH_ORIGINAL_COMMAND='cfctl {inner}' /usr/sbin/cfctl-scope pilot")
        legs.append({'leg': leg, 'form': form, 'op': op, 'commandTemplate': template, 'pty': True,
                     'timeoutSeconds': SCOPE_LEG_SECONDS, 'retry': False, 'confirmation': 'last6hex',
                     'scopeTargetMac': config['roles'][SCOPE_TARGET_ROLE]['mac']})
    return legs


def new_phase_worst_seconds(call, snap, read, settle):
    """Worst case of the v2 phases. `call` is one cfctl call (safe-band wait + allowance), `snap` one counters
    snapshot, `read` one read-only firewall read, `settle` one status settle; each leg is its hard timeout."""
    return {
        # preview, no-TTY refusal, status, status, status, one slack call; legs 2a and 2b
        'SCOPE-ADD-1': 6 * call + 2 * SCOPE_LEG_SECONDS,
        # preview, two argv negatives, status, rpc-sync enrolling the phone, one slack call; leg 2c; settle
        'SCOPE-ADD-2': 6 * call + SCOPE_LEG_SECONDS + settle,
        # sync A, pause, resume, sync B, status, one slack call; kernel reads; settle
        'MOVE': 6 * call + 2 * read + settle,
        # two syncs, two status reads; per-family chain counts before and after; settle
        'BULK': 4 * call + 2 * snap + settle,
        # three rpc-inventory reads and one wrapper read
        'INVENTORY': 4 * call,
        # unenrol sync, status, status; leg 2d; settle
        'SCOPE-REMOVE': 3 * call + SCOPE_LEG_SECONDS + settle,
    }


def digest_fields(details):
    """The extra digest-bound fields of a v2 plan ({} for v1). A v2 plan missing any of them is refused."""
    roles = details.get('roles')
    is_v2 = (isinstance(roles, dict) and SCOPE_TARGET_ROLE in roles) or any(f in details for f in V2_ONLY_DIGEST_FIELDS)
    if not is_v2:
        return {}
    missing = [field for field in V2_DIGEST_FIELDS if field not in details]
    if missing:
        raise Refusal('v2 plan lacks mandatory digest fields: ' + ', '.join(missing))
    return {field: details[field] for field in V2_DIGEST_FIELDS}


def disclosure_lines(details):
    """Operator-facing lines printed after a v2 plan: owner confirmation, timeout bounds, break-glass recovery."""
    target = details['roles'][SCOPE_TARGET_ROLE]
    return [
        f'OWNER CONFIRMATION: scope_target {target["ip"]} {target["mac"]} is the only device added to and removed from '
        "Penn's scope. Confirm Penn owns it; it must not be an adult, management, CT107 or admin device.",
        f'minimumRemoteTimeoutSeconds {details["minimumRemoteTimeoutSeconds"]}; '
        f'maximumRemoteTimeoutSeconds {details["maximumRemoteTimeoutSeconds"]} '
        f'(minimum + {V2_TIMEOUT_SLACK_SECONDS} s, hard max {V2_MAX_REMOTE_TIMEOUT_SECONDS} s); '
        f'configured remoteTimeoutSeconds {details["remoteTimeoutSeconds"]}.',
        'break-glass cleanup: if the session dies or teardown fails, recovery is a manual password login on the router '
        '(password/admin login to the router and CT107 is never disabled or confined by this pilot), then follow the '
        'README guidance for an absent or refusing uninstall. Do not retry the pilot.']
