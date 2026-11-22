"""Capture admitted province-to-node contribution and observer subtotal."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from . import foreign_technology_capture as _owner
from . import province_state_capture as _base
from . import province_trade_power_calculation_memory as _parent
from . import province_extension_memory as _extension
from . import province_node_allocation_memory as _leaf

PROFILE_FILE = Path(__file__).with_name('profiles') / 'province-node-allocation-memory-1374-v3-sampling-r1.json'
PROFILE_SHA256 = 'c9795ba9211a2ce8afa54b67b8ce4db80633e262bb134edd4a3669437eb89936'
SCHEMA = 'information.province_trade_power_capture.v1'
INNER_SCHEMA = 'information.province_trade_power_observer_snapshot.v1'
FIELDS = (*_parent.FIELDS, 'G02.province_node_allocation')
LAYOUT = {'province_node_offset': '0xe8', 'runtime_definition_offset': '0xa8',
          'definition_members_begin_offset': '0x68', 'definition_members_end_offset': '0x70',
          'province_controller_fullref_offset': '0x470', 'owner_presence_byte_offset': '0x46f',
          'province_power_offset': '0x890', 'node_country_table_offset': '0x18',
          'node_country_entry_count_offset': '0x24',
          'country_entry_stride': '0xc0', 'province_component_offset': '0x28',
          'component_key': 'TP_PROVINCE_POWER', 'observer': 'FRA', 'max_members': 512,
          'undiscovered_members_skipped_before_ownership_read': True,
          'country_aggregate_is_observer_only': True, 'native_function_invoked': False,
          'owner_absent_excludes_undefined_controller': True}


def _load_profile():
    if not 0 < PROFILE_FILE.stat().st_size <= 256 * 1024:
        raise ValueError('PROVINCE_NODE_ALLOCATION_PROFILE_SIZE')
    raw = PROFILE_FILE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROFILE_SHA256:
        raise ValueError('PROVINCE_NODE_ALLOCATION_PROFILE_PIN')
    profile = json.loads(raw)
    if (profile.get('profile_id') != 'province-node-allocation-memory-1374'
            or profile.get('profile_version') != 3 or profile.get('game_version') != '1.37.4'
            or profile.get('observer') != 'FRA'
            or profile.get('executable', {}).get('sha256') != _owner.EXE_SHA256
            or profile.get('layout', {}).get('province_node_allocation') != LAYOUT
            or profile.get('semantics', {}).get('supported_fields') != list(FIELDS)):
        raise ValueError('PROVINCE_NODE_ALLOCATION_PROFILE_BUILD')
    _base._validate_reviewed_layout_dependencies(profile, 'PROVINCE_NODE_ALLOCATION_PROFILE_DEPENDENCY')
    return profile


def _valid_id(value):
    return type(value) is int and 1 <= value <= 65535


def _observe_for(province_id, observer='FRA'):
    def observe(reader, module_base, country, profile):
        if country != observer or not _valid_id(province_id):
            raise ValueError('PROVINCE_NODE_ALLOCATION_SCOPE')

        def backend(read, base, observer_country):
            if observer_country != observer:
                raise ValueError('PROVINCE_NODE_ALLOCATION_SCOPE')
            return _extension.extend(read, base, province_id, observer=observer,
                parent_reader=_parent.read_two_pass, fields=('G02.province_node_allocation',),
                read_fields=_leaf.read_fields)

        return _owner._observe(reader, module_base, country, profile, backend_reader=backend)
    return observe


def capture(installation, province_id, *, observer='FRA'):
    if not _valid_id(province_id) or not isinstance(observer, str) or not _owner._TAG.fullmatch(observer):
        raise ValueError('PROVINCE_NODE_ALLOCATION_SCOPE')
    inner = _owner._capture_common(installation, observer, observer=observer, schema=INNER_SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=_observe_for(province_id, observer), allow_observer_target=True, observer_scoped=True)
    return {'schema': SCHEMA, 'observer': observer,
            'object': {'type': 'province', 'province_id': province_id}, 'capture': inner}


def validate_capture(report, context, creation, province_id):
    observer = context.get('observer') if isinstance(context, dict) else None
    if (not _valid_id(province_id) or not isinstance(report, dict)
            or not isinstance(observer, str) or not _owner._TAG.fullmatch(observer)
            or set(report) != {'schema', 'observer', 'object', 'capture'}
            or report.get('schema') != SCHEMA or report.get('observer') != observer
            or not _owner._same(report.get('object'), {'type': 'province', 'province_id': province_id})):
        return False
    return _owner._validate_capture_common(report['capture'], context, creation, observer,
        schema=INNER_SCHEMA, profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=_observe_for(province_id, observer), allow_observer_target=True,
        observer_scoped=True, require_access=True)
