"""Live observer identity for a battle-only information server."""
from copy import deepcopy
from pathlib import Path
import re

from . import country_reference_memory as references
from . import foreign_technology_capture as native
from .catalog import get_topic, validate_query
from .model import InformationError
from .sources import _context_from_health, _field_result, _result, _source_info
from .observation_time import active, dates_match, sampled_read, without_clock

TOPICS = ('C01', 'B01', 'B02', 'B03', 'B04', 'H01', 'W03')


def read_binding(reader, base, observer, expected_date):
    """Compare two canonical identity/controller reads without country fields."""
    passes = []
    last_date = expected_date
    for _ in range(2):
        before = native._context(reader, base)
        physical_ref = int.from_bytes(bytes.fromhex(before['physical_client_reference_raw_hex']), 'little')
        physical = references._tag_from_fullref(physical_ref)
        if physical is None:
            raise ValueError('BATTLE_PHYSICAL_REFERENCE_INVALID')
        requested = [observer] if observer == physical else [observer, physical]
        bindings = references.resolve_countries(reader.read, base, requested,
                                               expected_refs={physical: physical_ref})
        # The controller-array layout is shared with native._bound_admission.
        # A battle reader only needs the observer's role and canonical identity.
        world = int(before['world_pointer'], 16)
        slot = bindings['requested'][observer]['slot']
        count = int.from_bytes(native._read(reader, world + 0xa60, 4,
                                           'battle_observer.human_count'), 'little', signed=True)
        controllers = native._pointer(native._u64(reader, world + 0x1d48,
                                                   'battle_observer.controllers'))
        kind = int.from_bytes(native._read(reader, controllers + slot * 4, 4,
                                          'battle_observer.controller_type'), 'little', signed=True)
        role = {'observer': observer, 'slot': slot, 'human_count': count,
                'controller_type': kind, 'verified': True}
        after = native._context(reader, base)
        if (without_clock(before) != without_clock(after)
                or (active() and not dates_match(last_date, before['game_date'], after['game_date']))
                or (not active() and before['game_date'] != expected_date)):
            raise ValueError('BATTLE_OBSERVER_WORLD_CHANGED')
        last_date = after['game_date']
        passes.append({'context': before, 'observer': bindings['requested'][observer],
                       'physical': bindings['requested'][physical],
                       'role': role})
    if without_clock(passes[0]) != without_clock(passes[1]):
        raise ValueError('BATTLE_OBSERVER_BINDING_CHANGED')
    return passes


def validate_binding(report, observer, expected_date):
    """Rebuild the identity reads from the ordered trace after closing the process."""
    try:
        profile = native._load_profile()
        reader = native._Replay(report['raw_reads'])
        base = int(report['module_base'], 16)
        before = native._guards(reader, base, profile)
        passes = read_binding(reader, base, observer, expected_date)
        after = native._guards(reader, base, profile)
        return (reader.index == len(reader.rows) and before == report['code_before']
                and passes == report['passes'] and after == report['code_after'])
    except Exception:
        return False


def capture_binding(installation, observer, expected_date):
    """Reuse fixed-build identity, ROM guards and bounded RPM, closing every handle."""
    report = {'status': 'unknown', 'identity': {}}
    kernel = handle = reader = None
    try:
        profile = native._load_profile()
        document = native._identity._load_installation(Path(installation))
        kernel = native._identity._configure_kernel()
        handle = kernel.OpenProcess(native._mm.PROCESS_ACCESS, False, int(document['pid']))
        if not handle:
            raise OSError('BATTLE_OBSERVER_OPEN_PROCESS')
        base = native._identity._capture_identity(report, document, kernel, handle)
        report['module_base'] = hex(base)
        process_path = Path(report['identity']['process_path'])
        for guard in profile['code_guards']:
            expected = bytes.fromhex(guard['bytes'])
            if native._mm._read_pe_rva_bytes(process_path, int(guard['rva'], 0), len(expected)) != expected:
                raise ValueError('BATTLE_OBSERVER_FILE_CODE_MISMATCH')
        reader = native._parent.AddressBoundedRPM(kernel, handle, base)
        report['code_before'] = native._guards(reader, base, profile)
        report['passes'] = read_binding(reader, base, observer, expected_date)
        report['code_after'] = native._guards(reader, base, profile)
        after = {'identity': {}}
        if (native._identity._capture_identity(after, document, kernel, handle) != base
                or report['identity'] != after['identity']):
            raise ValueError('BATTLE_OBSERVER_PROCESS_CHANGED')
        report['identity_after'] = after['identity']
        report['status'] = 'observed'
    except Exception as error:
        report['reason'] = str(error)
    finally:
        if reader is not None:
            report['raw_reads'] = deepcopy(reader.read_log)
        report['cleanup'] = native._identity._close_process_handle(kernel, handle)
        if report['cleanup'].get('status') != 'closed':
            report['status'] = 'unknown'
    if report['status'] == 'observed':
        report['trace_replay_verified'] = validate_binding(report, observer, expected_date)
        if not report['trace_replay_verified']:
            report.update(status='unknown', reason='BATTLE_OBSERVER_TRACE_REPLAY_FAILED')
    return report


class BattleObserverContextSource:
    """Expose session context and battle records independently of execution authority."""

    event_types = ()

    def __init__(self, session, installation, observer):
        if not isinstance(observer, str) or re.fullmatch(r'[A-Z0-9]{3}', observer) is None:
            raise ValueError('Battle observer must be a country tag')
        self.session = session
        self.installation = Path(installation)
        self.observer = observer
        self.last_role_capture = None

    def catalog(self):
        return [get_topic(topic) for topic in TOPICS]

    def context(self):
        try:
            health_reader = getattr(self.session, 'information_health', None)
            if not callable(health_reader):
                health_reader = self.session.health
            health = health_reader()
        except Exception:
            health = {'status': 'unready', 'complete': False,
                      'reasons': [{'code': 'SESSION_HEALTH_FAILED'}]}
        context = _context_from_health(self.session, dict(health, observer=self.observer),
                                       mode='live', observer=self.observer)
        context['observer_binding'] = 'native_information_scope'
        context['information_scope'] = 'battle_records'
        self.last_role_capture = None
        if context['status'] != 'ready':
            return context
        # Role identity is part of the live C01 information context.  Keep its
        # date window local to this collection; direct capture_binding callers
        # retain the strict same-date behavior when no sampling scope is active.
        with sampled_read({'topic': 'C01'}, context,
                          enabled=context.get('mode') == 'live'):
            capture = capture_binding(self.installation, self.observer, context['game_date'])
        self.last_role_capture = capture
        if capture['status'] != 'observed':
            context.update(status='unready', complete=False)
            context.setdefault('reasons', []).append({'code': 'BATTLE_OBSERVER_ROLE_UNVERIFIED'})
            return context
        identity = capture['identity']
        expected = self.session.record
        if (identity.get('installation_session_id') != context['session_id']
                or identity.get('installation_pid') != int(expected['pid'])
                or identity.get('installation_creation_filetime') != int(expected['creation_filetime'])):
            context.update(status='unready', complete=False)
            context.setdefault('reasons', []).append({'code': 'BATTLE_OBSERVER_SESSION_CHANGED'})
            return context
        passes = capture.get('passes')
        if isinstance(passes, list) and passes and isinstance(passes[-1], dict):
            latest_native_date = (passes[-1].get('context', {}).get('game_date')
                                  if isinstance(passes[-1].get('context'), dict) else None)
            if type(latest_native_date) is int:
                context['game_date'] = latest_native_date
                context['game_date_raw'] = latest_native_date
                context['game_day'] = latest_native_date // 24
        context['observer_ref'] = f"{int(capture['passes'][0]['observer']['fullref'], 16):016x}"
        return context

    def validate_query(self, query, context=None):
        if not isinstance(query, dict) or query.get('topic') not in TOPICS:
            raise InformationError('unknown_topic', 'This source provides session context and battle records')
        return validate_query(query, context)

    def read(self, query, context):
        normalized = self.validate_query(query, context)
        fields, complete = _field_result(normalized['fields'], context, get_topic(normalized['topic']),
                                         unsupported=normalized['topic'] != 'C01')
        return _result(normalized, context, fields, complete,
                       _source_info('ObserverSession.health_and_native_observer_binding', context))

    def poll_events(self, context, cursor):
        return {'events': [], 'cursor': cursor, 'complete': True, 'gaps': []}
