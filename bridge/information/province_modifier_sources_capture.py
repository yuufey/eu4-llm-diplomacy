"""Own a v2 province source observation with one shared leaf per parent pass."""
import hashlib
import json
from pathlib import Path

from . import foreign_technology_capture as _owner
from . import province_state_memory as _province
from . import province_modifier_sources_memory as _leaf
from .province_goods_sources_capture import _valid_observer
from .province_state_capture import _validate_reviewed_layout_dependencies

PROFILE_FILE = Path(__file__).with_name('profiles')/'province-modifier-sources-memory-1374-v2-r2-sampling-r1.json'
PROFILE_SHA256 = '49f3e915d0cbbad2cf8f2bb6155be1e0916211ea17b69a93493d4988994831b2'
SCHEMA = 'information.province_modifier_sources_capture.v2'
INNER_SCHEMA = 'information.province_modifier_sources_observer_snapshot.v2'
LAYOUT = {
    'cache_offset': '0x988', 'ready_state': 2, 'aggregate_offset': '0x998',
    'component_offsets': [hex(offset) for offset in _leaf.CACHE_COMPONENT_OFFSETS],
    'definition_key_offset': '0x158', 'modifier_index': 21,
    'modifier_key': 'trade_goods_size_modifier', 'descriptor_global_rva': '0x2358060',
    'static_manager_global_rva': '0x242bce8',
    'direct_definitions': {key: hex(offset) for key, offset, _ in _leaf.DIRECT_SOURCES},
    'province_siege_pointer_offset': '0x388', 'province_flags_offset': '0x958',
    'blockade_mask': '0x40', 'province_state_pointer_offset': '0x2e0',
    'prosperity_necessary_state_value_offset': '0x18', 'prosperity_necessary_threshold': 100000,
    'full_source_coverage': False, 'last_refresh_execution_observed': False,
}

def _valid_id(value):
    return type(value) is int and 1 <= value <= 0xffff

def _load_profile():
    if not 0 < PROFILE_FILE.stat().st_size <= 256*1024:
        raise ValueError('PROVINCE_SOURCE_PROFILE_SIZE')
    raw = PROFILE_FILE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROFILE_SHA256:
        raise ValueError('PROVINCE_SOURCE_PROFILE_PIN')
    profile = json.loads(raw)
    if (profile['profile_id'] != 'province-modifier-sources-memory-1374'
            or profile['profile_version'] != 2 or profile.get('observer') != 'FRA'
            or profile.get('game_version') != '1.37.4'
            or profile['executable']['sha256'] != _owner.EXE_SHA256
            or profile['semantics']['supported_fields'] != [_leaf.FIELD]
            or not _owner._same(profile['layout']['province_modifier_sources'], LAYOUT)):
        raise ValueError('PROVINCE_SOURCE_PROFILE_LAYOUT')
    _validate_reviewed_layout_dependencies(profile, 'PROVINCE_SOURCE_DEPENDENCY_PIN')
    return profile

def _observe_for(province_id, observer='FRA'):
    def observe(reader, base, country, profile):
        if country != observer or not _valid_id(province_id):
            raise ValueError('PROVINCE_SOURCE_SCOPE')
        table = profile['layout']['province_goods_sources']['callback_table']
        address = base + int(table['rva'], 0)
        expected = b''.join((base+int(rva,0)).to_bytes(8,'little') for rva in table['target_rvas'])
        if len(expected) != 288:
            raise ValueError('PROVINCE_SOURCE_CALLBACK_COUNT')
        def backend(read, module_base, observer_country):
            if observer_country != observer:
                raise ValueError('PROVINCE_SOURCE_SCOPE')
            before = _owner._read(read,address,len(expected),'province_sources.callbacks.before')
            if before != expected:
                raise ValueError('PROVINCE_SOURCE_CALLBACK_MISMATCH')
            result = _province.read_two_pass(read, module_base, province_id, observer=observer,
                observer_scoped=True, fields=(_leaf.FIELD,), read_fields=_leaf.read_fields)
            after = _owner._read(read,address,len(expected),'province_sources.callbacks.after')
            if after != before:
                raise ValueError('PROVINCE_SOURCE_CALLBACK_CHANGED')
            result['callback_table'] = {'address':hex(address),'raw_hex':before.hex(),
                'target_rvas':table['target_rvas'],'stable':True}
            return result
        return _owner._observe(reader,base,country,profile,backend_reader=backend)
    return observe

def capture(installation: Path, province_id: int, *, observer: str = 'FRA'):
    if not _valid_id(province_id) or not _valid_observer(observer):
        raise ValueError('PROVINCE_SOURCE_REQUEST_SCOPE')
    inner = _owner._capture_common(installation, observer, observer=observer, schema=INNER_SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=_observe_for(province_id, observer), allow_observer_target=True, observer_scoped=True)
    return {'schema':SCHEMA,'observer':observer,'object':{'type':'province','province_id':province_id},'capture':inner}

def validate_capture(report, context, creation, province_id):
    observer = context.get('observer') if isinstance(context, dict) else None
    if (not _valid_id(province_id) or not _valid_observer(observer) or not isinstance(report,dict)
            or set(report) != {'schema','observer','object','capture'}
            or report['schema'] != SCHEMA or report['observer'] != observer
            or not _owner._same(report['object'],{'type':'province','province_id':province_id})):
        return False
    return _owner._validate_capture_common(report['capture'], context, creation, observer,
        schema=INNER_SCHEMA, profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=_observe_for(province_id, observer), allow_observer_target=True,
        observer_scoped=True, require_access=True)
