"""Capture province power with qualified controller and observer country inputs."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from . import foreign_technology_capture as _owner
from . import province_trade_power_country_memory as _backend

ROOT = Path(__file__).resolve().parents[2]
PROFILE_FILE = Path(__file__).with_name('profiles') / 'province-trade-power-country-memory-1374-v1-sampling-r1.json'
PROFILE_SHA256 = '028eb786828e11c4325f64163539b7057d97bad6b0e4d0118f871ed31019ce8e'
SCHEMA = 'information.province_trade_power_capture.v1'
INNER_SCHEMA = 'information.province_trade_power_observer_snapshot.v1'
FIELDS = _backend.FIELDS
LAYOUT = {'cache_state_offset': '0x28c8', 'modifier_object_offset': '0x28d0',
          'accepted_cache_states': [0, 2], 'accepted_cache_states_complete_enum': False,
          'index': 17, 'expected_key': 'global_prov_trade_power_modifier',
          'manager_global_rva': '0x2358060', 'descriptor_stride': '0x60',
          'processor_offset': '0x40', 'require_processor_absent': True,
          'controller_fullref_offset': '0x470',
          'country_view_admission_required_for_controller_and_observer': True}


def _load_profile():
    if not 0 < PROFILE_FILE.stat().st_size <= 256 * 1024:
        raise ValueError('PROVINCE_TRADE_COUNTRY_PROFILE_SIZE')
    raw = PROFILE_FILE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROFILE_SHA256:
        raise ValueError('PROVINCE_TRADE_COUNTRY_PROFILE_PIN')
    profile = json.loads(raw)
    if (profile.get('profile_id') != 'province-trade-power-country-memory-1374'
            or profile.get('profile_version') != 1 or profile.get('game_version') != '1.37.4'
            or profile.get('observer') != 'FRA'
            or profile.get('executable', {}).get('sha256') != _owner.EXE_SHA256
            or profile.get('layout', {}).get('province_trade_power_country') != LAYOUT
            or profile.get('semantics', {}).get('supported_fields') != list(FIELDS)):
        raise ValueError('PROVINCE_TRADE_COUNTRY_PROFILE_BUILD')
    for item in profile['source_evidence'] + profile['layout_dependencies']:
        path = (ROOT / item['path']).resolve()
        path.relative_to(ROOT)
        if path.stat().st_size != item['bytes'] or _owner._sha(path) != item['sha256']:
            raise ValueError('PROVINCE_TRADE_COUNTRY_PROFILE_DEPENDENCY')
    return profile


def _valid_id(value):
    return type(value) is int and 1 <= value <= 65535


def _observe_for(province_id):
    def observe(reader, module_base, country, profile):
        if country != 'FRA' or not _valid_id(province_id):
            raise ValueError('PROVINCE_TRADE_COUNTRY_SCOPE')

        def backend(read, base, observer):
            if observer != 'FRA':
                raise ValueError('PROVINCE_TRADE_COUNTRY_SCOPE')
            return _backend.read_two_pass(read, base, province_id, observer='FRA')

        return _owner._observe(reader, module_base, country, profile, backend_reader=backend)
    return observe


def capture(installation, province_id, *, observer='FRA'):
    if not _valid_id(province_id) or observer != 'FRA':
        raise ValueError('PROVINCE_TRADE_COUNTRY_SCOPE')
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
