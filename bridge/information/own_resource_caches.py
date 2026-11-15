"""Own treasury, manpower, and maximum manpower/sailor caches."""
from pathlib import Path
from copy import deepcopy
import hashlib
import json

from . import foreign_country_memory as _countries
from . import foreign_technology_capture as _owner
from . import observation_time as _time
from .country_state import NativeCountryStateSource
from .sources import _result, _source_info

ROOT = Path(__file__).resolve().parents[2]
PROFILE_FILE = Path(__file__).with_name('profiles') / 'own-resource-caches-memory-1374-v3.json'
PROFILE_SHA256 = '8e99c7b209c829574c7f6afd954c79d6206c8bb0bf3601ad617bd16054a5ad8d'
SCHEMA = 'information.own_resource_caches.v1'

_CACHE_FIELDS = {'N01.treasury', 'N02.manpower', 'N02.max_manpower', 'N02.max_sailors'}
_MAX_CACHE_FIELDS = {'N02.max_manpower', 'N02.max_sailors'}


def _max_field_reason(field, reason):
    if field == 'N02.max_sailors' and reason.startswith('MAX_MANPOWER_'):
        return 'MAX_SAILORS_' + reason.removeprefix('MAX_MANPOWER_')
    if field == 'N02.max_manpower' and reason.startswith('MAX_SAILORS_'):
        return 'MAX_MANPOWER_' + reason.removeprefix('MAX_SAILORS_')
    return reason


def _max_field_basis(fields):
    selected = set(fields) & _MAX_CACHE_FIELDS
    if selected == {'N02.max_manpower'}:
        return 'native_country_max_manpower_cache'
    if selected == {'N02.max_sailors'}:
        return 'native_country_max_sailors_cache'
    return 'native_country_max_resource_caches'


def _load_profile():
    raw = PROFILE_FILE.read_bytes()
    if len(raw) > 16384 or hashlib.sha256(raw).hexdigest() != PROFILE_SHA256:
        raise ValueError('OWN_RESOURCE_CACHE_PROFILE_PIN')
    profile = json.loads(raw)
    parent = _owner._load_profile()
    if profile['code_guards'] != parent['code_guards']:
        raise ValueError('OWN_RESOURCE_CACHE_PARENT_GUARDS')
    for item in profile['native_cache_source_dependencies']:
        path = ROOT / item['path']
        if path.stat().st_size != item['bytes'] or hashlib.sha256(path.read_bytes()).hexdigest() != item['sha256']:
            raise ValueError('OWN_RESOURCE_CACHE_SOURCE_PIN')
    return profile


def _observe_for(fields):
    def observe(reader, base, country, profile):
        def read_fields(read, module_base, binding, selected):
            pointer = int(binding['country_pointer'], 0)
            result = {}
            for field in selected:
                spec = profile['cache_fields'][field]
                raw = read.read(pointer + spec['offset'], 4, 'own_resource_cache.' + field)
                value = int.from_bytes(raw, 'little', signed=True)
                if field in ('N02.manpower', 'N02.max_manpower', 'N02.max_sailors') and value < 0:
                    reason = {
                        'N02.max_manpower': 'MAX_MANPOWER_CACHE_NEGATIVE',
                        'N02.max_sailors': 'MAX_SAILORS_CACHE_NEGATIVE',
                        'N02.manpower': 'MANPOWER_CACHE_NEGATIVE',
                    }[field]
                    result[field] = {'status': 'unknown', 'reason': reason}
                else:
                    result[field] = {'status': 'known', 'value': value, 'raw': value,
                                     'raw_hex': raw.hex(), 'unit': spec['unit'], 'scale': spec['scale']}
            return result

        def backend(read, module_base, observer):
            return _countries.read_two_pass(read, module_base, observer, [observer], fields=fields,
                admission_reader=_owner._bound_admission, read_fields=read_fields)

        return _owner._observe(reader, base, country, profile, backend_reader=backend)
    return observe


def capture(installation, fields):
    return _owner._capture_common(installation, 'FRA', observer='FRA', schema=SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile, observe=_observe_for(fields),
        allow_observer_target=True)


def read(source, query, context):
    fields = tuple(query['topic'] + '.' + field for field in query['fields'])
    max_requested = bool(set(fields) & _MAX_CACHE_FIELDS)
    basis = _max_field_basis(fields)

    def unavailable(reason):
        if not max_requested:
            return None
        selected = {}
        first_max_reason = _max_field_reason(next(field for field in fields if field in _MAX_CACHE_FIELDS), reason)
        for field in query['fields']:
            full_field = query['topic'] + '.' + field
            field_reason = (_max_field_reason(full_field, reason)
                            if full_field in _MAX_CACHE_FIELDS else first_max_reason)
            selected[field] = {'status': 'unknown', 'reason': field_reason}
        return _result(query, context, selected, False, _source_info(
            'OwnResourceCaches', context, complete=False,
            provenance={'basis': basis,
                        'profile_sha256': PROFILE_SHA256,
                        'native_function_invoked': False,
                        'observer_nonplayer_role_verified': False}))

    session = getattr(source, 'session', None)
    if session is None or query['object'].get('country') != 'FRA':
        return unavailable('MAX_MANPOWER_CACHE_SCOPE_UNAVAILABLE')
    directory = getattr(session, 'directory', None)
    if directory is None:
        return unavailable('MAX_MANPOWER_CACHE_SESSION_UNAVAILABLE')
    if not fields or set(fields) - _CACHE_FIELDS:
        return unavailable('MAX_MANPOWER_CACHE_FIELDS_UNAVAILABLE')
    try:
        report = capture(Path(directory) / 'installation.json', fields)
        valid = _owner._validate_capture_common(report, context, session.record['creation_filetime'], 'FRA',
            schema=SCHEMA, profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
            observe=_observe_for(fields), allow_observer_target=True, require_access=True)
        if not valid:
            return unavailable('MAX_MANPOWER_CACHE_CAPTURE_INVALID')
        after = source.context()
        if (after.get('status') != 'ready' or NativeCountryStateSource._monarch_points_context_identity(after)
                != NativeCountryStateSource._monarch_points_context_identity(context)
                or not _time.dates_match(context.get('game_date'), after.get('game_date'))):
            return unavailable('MAX_MANPOWER_CACHE_CONTEXT_CHANGED')
        target = report['observation']['backend']['targets'][0]
        selected = {field: deepcopy(target['fields'][query['topic'] + '.' + field]) for field in query['fields']}
        complete = all(value.get('status') == 'known' for value in selected.values())
        if not complete and not max_requested:
            return None
        if not complete:
            # Preserve per-field unknowns (including a negative max cache) so
            # the caller cannot mistake current manpower for its maximum.
            selected = {
                name: (value if value.get('status') == 'known' else
                       {'status': 'unknown', 'reason': value.get('reason', 'OWN_RESOURCE_CACHE_FIELD_UNKNOWN')})
                for name, value in selected.items()
            }
        return _result(query, context, selected, complete, _source_info(
            'OwnResourceCaches', context, complete=complete,
            provenance={'basis': basis if max_requested else 'existing_native_country_resource_caches',
                        'profile_sha256': PROFILE_SHA256,
                        'native_function_invoked': False, 'observer_nonplayer_role_verified': True}))
    except Exception:
        return unavailable('MAX_MANPOWER_CACHE_CAPTURE_FAILED')
