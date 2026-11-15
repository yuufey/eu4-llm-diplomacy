"""Capture current province trade power and qualified numeric modifier inputs."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from . import foreign_technology_capture as _owner
from . import province_state_memory as _province
from . import province_trade_power_inputs_memory as _leaf

ROOT = Path(__file__).resolve().parents[2]
PROFILE_FILE = Path(__file__).with_name('profiles') / 'province-trade-power-inputs-memory-1374-v1-sampling-r1.json'
PROFILE_SHA256 = '0939c950679d60854d82762b3bba9ee4268ac28480f0853163919a7fd3274ddc'
SCHEMA = 'information.province_trade_power_capture.v1'
INNER_SCHEMA = 'information.province_trade_power_observer_snapshot.v1'
FIELDS = ('G02.province_trade_power', 'G02.province_trade_power_value',
          'G02.province_trade_power_modifier', 'G02.province_trade_power_further_modifier')
LAYOUT = {'manager_global_rva': '0x2358060', 'descriptor_stride': '0x60',
    'processor_offset': '0x40', 'descriptor_key_offset': '0x0',
    'descriptor_key_length_offset': '0x10', 'descriptor_key_capacity_offset': '0x18',
    'province_modifier_object_offset': '0x998', 'province_further_modifier_object_offset': '0x2438',
    'dense_flag_offset': '0x10', 'values_pointer_offset': '0x58', 'sparse_count_offset': '0x64',
    'index_value_stride': 8, 'flat_index': 15, 'ratio_index': 16,
    'expected_keys': {'15': 'province_trade_power_value', '16': 'province_trade_power_modifier'},
    'require_processor_absent': True}


def _load_profile():
    if not 0 < PROFILE_FILE.stat().st_size <= 256 * 1024:
        raise ValueError('PROVINCE_TRADE_INPUTS_PROFILE_SIZE')
    raw = PROFILE_FILE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROFILE_SHA256:
        raise ValueError('PROVINCE_TRADE_INPUTS_PROFILE_PIN')
    profile = json.loads(raw)
    if (profile.get('profile_id') != 'province-trade-power-inputs-memory-1374'
            or profile.get('profile_version') != 1 or profile.get('game_version') != '1.37.4'
            or profile.get('observer') != 'FRA'
            or profile.get('executable', {}).get('sha256') != _owner.EXE_SHA256
            or profile.get('layout', {}).get('province_trade_power_inputs') != LAYOUT
            or profile.get('semantics', {}).get('supported_fields') != list(FIELDS)):
        raise ValueError('PROVINCE_TRADE_INPUTS_PROFILE_BUILD')
    for item in profile['source_evidence'] + profile['layout_dependencies']:
        path = (ROOT / item['path']).resolve()
        path.relative_to(ROOT)
        if path.stat().st_size != item['bytes'] or _owner._sha(path) != item['sha256']:
            raise ValueError('PROVINCE_TRADE_INPUTS_PROFILE_DEPENDENCY')
    return profile


def _valid_id(value):
    return type(value) is int and 1 <= value <= 65535


def _observe_for(province_id):
    def observe(reader, module_base, country, profile):
        if country != 'FRA' or not _valid_id(province_id):
            raise ValueError('PROVINCE_TRADE_INPUTS_SCOPE')

        def backend(read, base, observer):
            if observer != 'FRA':
                raise ValueError('PROVINCE_TRADE_INPUTS_SCOPE')
            return _province.read_two_pass(read, base, province_id, observer='FRA',
                fields=FIELDS, read_fields=_leaf.read_fields)

        return _owner._observe(reader, module_base, country, profile, backend_reader=backend)
    return observe


def capture(installation, province_id, *, observer='FRA'):
    if not _valid_id(province_id) or observer != 'FRA':
        raise ValueError('PROVINCE_TRADE_INPUTS_SCOPE')
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
