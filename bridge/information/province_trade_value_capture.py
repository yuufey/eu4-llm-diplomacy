"""Capture admitted province value inputs with the existing power observation."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from . import foreign_technology_capture as _owner
from . import province_state_capture as _base
from . import province_node_allocation_capture as _allocation_capture
from . import province_node_allocation_memory as _allocation
from . import province_trade_power_calculation_memory as _power_parent
from . import province_extension_memory as _extension
from . import province_trade_value_parent_memory as _parent
from . import province_trade_value_memory as _leaf

PROFILE_FILE = Path(__file__).with_name('profiles') / 'province-trade-value-memory-1374-v1-sampling-r1.json'
PROFILE_SHA256 = '4769ca3dcaade3b3b8d9862318ab8bf093ba5c8f949927c79e03027f4bd45f85'
SCHEMA = 'information.province_trade_power_capture.v1'
INNER_SCHEMA = 'information.province_trade_power_observer_snapshot.v1'
FIELDS = (*_allocation_capture.FIELDS, _leaf.FIELD)
LAYOUT = {'province_modifier_object': '0x998', 'owner_reference': '0x468',
    'owner_cache_state': '0x28c8', 'owner_modifier_object': '0x28d0',
    'goods_definition': '0x458', 'goods_key': '0x18', 'goods_index': '0x78',
    'world_global_rva': '0x233fe58', 'goods_prices_container': '0x25d0',
    'goods_prices_array': '0x8', 'goods_price_stride': '0x38', 'goods_price_value': '0x4',
    'max_supported_goods_index_exclusive': 1024, 'goods_array_count_claimed': False,
    'modifier_descriptors': {str(k): v for k, v in _leaf.DESCRIPTORS.items()},
    'description_absent': True, 'extra_arguments_zero': True,
    'individual_monthly_contribution_claimed': False}


def _load_profile():
    raw = PROFILE_FILE.read_bytes()
    if not 0 < len(raw) <= 256*1024 or hashlib.sha256(raw).hexdigest() != PROFILE_SHA256:
        raise ValueError('PROVINCE_VALUE_PROFILE_PIN')
    profile = json.loads(raw)
    if (profile.get('profile_id') != 'province-trade-value-memory-1374'
            or profile.get('profile_version') != 1 or profile.get('game_version') != '1.37.4'
            or profile.get('observer') != 'FRA'
            or profile.get('executable', {}).get('sha256') != _owner.EXE_SHA256
            or profile.get('layout', {}).get('province_trade_value') != LAYOUT
            or profile.get('semantics', {}).get('supported_fields') != list(FIELDS)):
        raise ValueError('PROVINCE_VALUE_PROFILE_IDENTITY')
    _base._validate_reviewed_layout_dependencies(profile, 'PROVINCE_VALUE_DEPENDENCY_PIN')
    return profile


def _valid_id(value):
    return type(value) is int and 1 <= value <= 65535


def _observe_for(province_id, observer='FRA'):
    def observe(reader, module_base, country, profile):
        if country != observer or not _valid_id(province_id):
            raise ValueError('PROVINCE_VALUE_SCOPE')

        def power_parent(read, base, pid, *, observer):
            return _extension.extend(read, base, pid, observer=observer,
                parent_reader=_power_parent.read_two_pass,
                fields=('G02.province_node_allocation',), read_fields=_allocation.read_fields)

        def backend(read, base, observer_country):
            if observer_country != observer:
                raise ValueError('PROVINCE_VALUE_SCOPE')
            return _parent.extend(read, base, province_id, observer=observer,
                parent_reader=power_parent, read_fields=_leaf.read_fields)

        return _owner._observe(reader, module_base, country, profile, backend_reader=backend)
    return observe


def capture(installation, province_id, *, observer='FRA'):
    if not _valid_id(province_id) or not isinstance(observer, str) or not _owner._TAG.fullmatch(observer):
        raise ValueError('PROVINCE_VALUE_SCOPE')
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
