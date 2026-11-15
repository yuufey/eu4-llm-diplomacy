"""Capture province inputs and passive native cache-writer calculation gates."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from . import foreign_technology_capture as _owner
from . import province_trade_power_calculation_memory as _backend

ROOT = Path(__file__).resolve().parents[2]
PROFILE_FILE = Path(__file__).with_name('profiles') / 'province-trade-power-calculation-memory-1374-v1-sampling-r1.json'
PROFILE_SHA256 = '6a6db6b73b56a0dcfa0f48fc506cf60b63f3045e576bbc3b95ec62eba3c5aa7e'
SCHEMA = 'information.province_trade_power_capture.v1'
INNER_SCHEMA = 'information.province_trade_power_observer_snapshot.v1'
FIELDS = _backend.FIELDS
LAYOUT = {
    'mode': 'cache_writer_zero_additional_inputs',
    'province_node_offset': '0xe8', 'node_virtual_predicate_offset': '0x40',
    'constant_predicate_prefixes': ['b001c3', 'b000c3'],
    'controller_type_pointer_offset': '0x2440', 'controller_type_flag_offset': '0x79',
    'province_flags_offset': '0x958', 'owner_linked_container_offset': '0x8a8',
    'owner_entries_begin_offset': '0x28', 'owner_entries_end_offset': '0x30',
    'entry_country_fullref_offset': '0x1c0', 'entry_bonus_flag_offset': '0x40',
    'bonus_global_rva': '0x233f418', 'entry_limit': 4096,
    'owner_country_admission_required_when_referenced': True,
    'native_function_invoked': False}


def _load_profile():
    if not 0 < PROFILE_FILE.stat().st_size <= 256 * 1024:
        raise ValueError('PROVINCE_TRADE_CALCULATION_PROFILE_SIZE')
    raw = PROFILE_FILE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROFILE_SHA256:
        raise ValueError('PROVINCE_TRADE_CALCULATION_PROFILE_PIN')
    profile = json.loads(raw)
    if (profile.get('profile_id') != 'province-trade-power-calculation-memory-1374'
            or profile.get('profile_version') != 1 or profile.get('game_version') != '1.37.4'
            or profile.get('observer') != 'FRA'
            or profile.get('executable', {}).get('sha256') != _owner.EXE_SHA256
            or profile.get('layout', {}).get('province_trade_power_calculation') != LAYOUT
            or profile.get('semantics', {}).get('supported_fields') != list(FIELDS)):
        raise ValueError('PROVINCE_TRADE_CALCULATION_PROFILE_BUILD')
    for item in profile['source_evidence'] + profile['layout_dependencies']:
        path = (ROOT / item['path']).resolve()
        path.relative_to(ROOT)
        if path.stat().st_size != item['bytes'] or _owner._sha(path) != item['sha256']:
            raise ValueError('PROVINCE_TRADE_CALCULATION_PROFILE_DEPENDENCY')
    return profile


def _valid_id(value):
    return type(value) is int and 1 <= value <= 65535


def _observe_for(province_id):
    def observe(reader, module_base, country, profile):
        if country != 'FRA' or not _valid_id(province_id):
            raise ValueError('PROVINCE_TRADE_CALCULATION_SCOPE')

        def backend(read, base, observer):
            if observer != 'FRA':
                raise ValueError('PROVINCE_TRADE_CALCULATION_SCOPE')
            return _backend.read_two_pass(read, base, province_id, observer='FRA')

        return _owner._observe(reader, module_base, country, profile, backend_reader=backend)
    return observe


def capture(installation, province_id, *, observer='FRA'):
    if not _valid_id(province_id) or observer != 'FRA':
        raise ValueError('PROVINCE_TRADE_CALCULATION_SCOPE')
    inner = _owner._capture_common(installation, 'FRA', observer='FRA', schema=INNER_SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=_observe_for(province_id), allow_observer_target=True)
    return {'schema': SCHEMA, 'observer': 'FRA',
            'object': {'type': 'province', 'province_id': province_id}, 'capture': inner}


def validate_capture(report, context, creation, province_id):
    if (not _valid_id(province_id) or not isinstance(report, dict)
            or set(report) != {'schema', 'observer', 'object', 'capture'}
            or report.get('schema') != SCHEMA or report.get('observer') != 'FRA'
            or not _owner._same(report.get('object'), {'type': 'province', 'province_id': province_id})):
        return False
    return _owner._validate_capture_common(report['capture'], context, creation, 'FRA',
        schema=INNER_SCHEMA, profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=_observe_for(province_id), allow_observer_target=True, require_access=True)
