"""Reuse pinned province readers for current ROOT reward-limit inputs."""
from copy import deepcopy
import hashlib

from . import foreign_technology_capture as owner
from . import province_interest_capture as interests
from . import province_interest_memory
from . import mission_trigger_provinces as provinces
from .mission_trigger_memory import _subject_holds
from .mission_trigger_profile import load_profile as load_trigger_profile, PROFILE_SHA256 as TRIGGER_SHA


SCHEMA = 'information.mission_reward_inputs.v1'
PROFILE_SHA256 = hashlib.sha256(
    (interests.PROFILE_SHA256 + ':' + TRIGGER_SHA).encode('ascii')).hexdigest()
SUBJECT_GUARDS = {'country_or_non_sovereign_subject_holds', 'subject_type_getter'}


def _load_profile():
    profile = deepcopy(interests._load_profile())
    trigger = load_trigger_profile()
    guards = [row for row in trigger['code_guards'] if row['name'] in SUBJECT_GUARDS]
    if {row['name'] for row in guards} != SUBJECT_GUARDS:
        raise ValueError('REWARD_SUBJECT_GUARDS_MISSING')
    for row in guards:
        profile['code_guards'].append({
            'name': row['name'], 'rva': hex(row['rva']),
            'end_rva_exclusive': hex(row['rva'] + len(bytes.fromhex(row['raw_hex']))),
            'bytes': row['raw_hex'], 'sha256': row['sha256'],
        })
    return profile


def _known(value):
    return {'status': 'known', 'value': value}


def _unknown(reason):
    return {'status': 'unknown', 'reason': reason}


class _SubjectReader:
    def __init__(self, reader):
        self.reader = reader
        self.rows = []

    def read(self, address, size, label):
        raw = owner._read(self.reader, address, size, label)
        self.rows.append([address, raw.hex()])
        return raw

    def qword(self, address, label):
        raw = self.read(address, 8, label)
        return int.from_bytes(raw, 'little'), raw


def _snapshot(reader, base, province_id, observer):
    core = province_interest_memory.read_two_pass(
        reader, base, province_id, observer=observer, fields=('G01.cores',), observer_scoped=True)
    state = provinces.read_province_state(reader, base, province_id, observer=observer)
    checks = {name: _unknown('REWARD_INPUT_UNAVAILABLE') for name in
              ('is_core', 'owned_by', 'country_or_non_sovereign_subject_holds')}
    targets = core.get('targets', [])
    if (core.get('status') != 'observed' or core.get('consistency', {}).get('status') != 'stable'
            or len(targets) != 1):
        return {'core': core, 'state': state, 'checks': checks, 'subject_reads': []}
    target = targets[0]
    for phase in ('pass1', 'pass2'):
        gate = target.get('admission_by_pass', {}).get(phase, {})
        discovery = target.get('discovery_by_pass', {}).get(phase, {})
        if (gate.get('admitted') is not True or gate.get('status') != 'known'
                or discovery.get('status') != 'known' or discovery.get('value') is not True):
            return {'core': core, 'state': state, 'checks': checks, 'subject_reads': []}
    bindings = target.get('bindings_by_pass', {})
    identity = provinces._observer_identity(
        {phase: bindings.get(phase, {}).get('observer') for phase in ('pass1', 'pass2')}, observer)
    members = target.get('fields', {}).get('G01.cores', {})
    if (members.get('status') == 'known'
            and target.get('field_consistency', {}).get('G01.cores', {}).get('status') == 'stable'):
        checks['is_core'] = _known(observer in members['value'])
    subject = _SubjectReader(reader)
    actual = state.get('owner', {})
    if (identity is not None and state.get('status') == 'known'
            and (state.get('observer_pointer'), state.get('observer_reference')) == identity
            and actual.get('status') == 'known' and type(actual.get('reference')) is int):
        same = actual['reference'] == identity[1]
        checks['owned_by'] = _known(same)
        if same:
            checks['country_or_non_sovereign_subject_holds'] = _known(True)
        elif type(actual.get('country_pointer')) is int:
            value, reason = _subject_holds(subject, actual['country_pointer'], identity[1], 'reward_limit')
            checks['country_or_non_sovereign_subject_holds'] = (
                _known(value) if type(value) is bool else _unknown(reason or 'REWARD_SUBJECT_UNKNOWN'))
    return {'core': core, 'state': state, 'checks': checks, 'subject_reads': subject.rows}


def _observe_for(province_id, observer='FRA'):
    def observe(reader, base, country, profile):
        if country != observer:
            raise ValueError('REWARD_OBSERVER_SCOPE')
        def backend(read, module_base, observer_country):
            if observer_country != observer:
                raise ValueError('REWARD_OBSERVER_SCOPE')
            before = _snapshot(read, module_base, province_id, observer)
            after = _snapshot(read, module_base, province_id, observer)
            stable = owner._same(before, after)
            return {'status': 'observed', 'targets': after['core'].get('targets', []),
                    'consistency': {'status': 'stable' if stable else 'changed'},
                    'before': before, 'after': after}
        return owner._observe(reader, base, country, profile, backend_reader=backend)
    return observe


def capture(installation, province_id, *, observer='FRA'):
    if type(province_id) is not int or not 1 <= province_id <= 65535:
        raise ValueError('REWARD_PROVINCE_SCOPE')
    return owner._capture_common(
        installation, observer, observer=observer, schema=SCHEMA, profile_sha256=PROFILE_SHA256,
        load_profile=_load_profile, observe=_observe_for(province_id, observer),
        allow_observer_target=True, observer_scoped=True)


def validate_capture(report, context, creation, province_id):
    observer = context.get('observer') if isinstance(context, dict) else None
    return owner._validate_capture_common(
        report, context, creation, observer, schema=SCHEMA, profile_sha256=PROFILE_SHA256,
        load_profile=_load_profile, observe=_observe_for(province_id, observer),
        allow_observer_target=True, require_access=True, observer_scoped=True)


class NativeMissionRewardInputs:
    def __init__(self, source, *, capture_reader=None):
        self.source = source
        self.capture_reader = capture_reader

    def __call__(self, province_ids, context):
        observer = context.get('observer')
        result = {'observer': observer, 'session_id': context.get('session_id'),
                  'game_date': context.get('game_date'), 'provinces': {}}
        session = getattr(self.source, 'session', None)
        if (session is None or context.get('status') != 'ready'
                or not isinstance(observer, str) or not owner._TAG.fullmatch(observer)
                or not isinstance(province_ids, list) or len(province_ids) > 64
                or any(type(value) is not int or not 1 <= value <= 65535 for value in province_ids)):
            return result
        for province_id in dict.fromkeys(province_ids):
            row = _unknown('REWARD_INPUT_CAPTURE_FAILED')
            try:
                installation = session.directory / 'installation.json'
                report = (self.capture_reader(installation, province_id) if self.capture_reader is not None
                          else capture(installation, province_id, observer=observer))
                if validate_capture(report, context, session.record['creation_filetime'], province_id):
                    row = {'status': 'known',
                           'checks': deepcopy(report['observation']['backend']['after']['checks']),
                           'basis': 'pinned_province_core_owner_and_native_subject_criterion',
                           'profile_sha256': PROFILE_SHA256}
            except Exception:
                pass
            result['provinces'][str(province_id)] = row
        return result
