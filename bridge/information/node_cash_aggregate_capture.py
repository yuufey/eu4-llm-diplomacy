"""Capture node member values with the admitted province power observation."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from . import foreign_technology_capture as _owner
from . import province_trade_value_capture as _previous
from . import node_cash_aggregate_memory as _leaf
from . import node_cash_aggregate_parent_memory as _parent

ROOT = Path(__file__).resolve().parents[2]
PROFILE_FILE = Path(__file__).with_name('profiles') / 'node-cash-aggregate-memory-1374-v1-sampling-r1.json'
PROFILE_SHA256 = '291a567666a71395b1f3d5f450354bd01989358df4d8fd71b0d572e2c4a98068'
SCHEMA = _previous.SCHEMA
INNER_SCHEMA = _previous.INNER_SCHEMA
FIELDS = (*_previous.FIELDS, _leaf.FIELD)
LAYOUT = {'node_cash': '0xb0', 'runtime_definition': '0xa8', 'definition_key': '0x10',
    'definition_center': '0xdc', 'definition_members_begin_end': ['0x68', '0x70'],
    'province_stride': '0x2e10', 'province_runtime': '0xe8', 'owner_fullref': '0x468',
    'member_limit': 512, 'shared_descriptors_owners_prices_per_pass': True,
    'all_used_input_bytes_reread': True, 'sum_i32_wrap_then_trunc0_div12': True,
    'cache_refresh_verified': False, 'future_income_claimed': False}


def _load_profile():
    raw = PROFILE_FILE.read_bytes()
    if not 0 < len(raw) <= 256*1024 or hashlib.sha256(raw).hexdigest() != PROFILE_SHA256:
        raise ValueError('NODE_CASH_PROFILE_PIN')
    profile = json.loads(raw)
    if (profile.get('profile_id') != 'node-cash-aggregate-memory-1374'
            or profile.get('profile_version') != 1 or profile.get('game_version') != '1.37.4'
            or profile.get('observer') != 'FRA'
            or profile.get('executable', {}).get('sha256') != _owner.EXE_SHA256
            or profile.get('layout', {}).get('node_cash_aggregate') != LAYOUT
            or profile.get('semantics', {}).get('supported_fields') != list(FIELDS)):
        raise ValueError('NODE_CASH_PROFILE_IDENTITY')
    for entry in profile['source_evidence'] + profile['layout_dependencies']:
        path = (ROOT / entry['path']).resolve()
        path.relative_to(ROOT)
        if path.stat().st_size != entry['bytes'] or _owner._sha(path) != entry['sha256']:
            raise ValueError('NODE_CASH_DEPENDENCY_PIN')
    return profile


def _observe_for(province_id):
    def observe(reader, module_base, country, profile):
        if country != 'FRA' or not _previous._valid_id(province_id):
            raise ValueError('NODE_CASH_SCOPE')

        def power_parent(read, base, pid, *, observer):
            return _previous._extension.extend(read, base, pid, observer=observer,
                parent_reader=_previous._power_parent.read_two_pass,
                fields=('G02.province_node_allocation',), read_fields=_previous._allocation.read_fields)

        def value_parent(read, base, pid, *, observer):
            return _previous._parent.extend(read, base, pid, observer=observer,
                parent_reader=power_parent, read_fields=_previous._leaf.read_fields)

        def backend(read, base, observer):
            if observer != 'FRA':
                raise ValueError('NODE_CASH_SCOPE')
            return _parent.extend(read, base, province_id, observer='FRA', parent_reader=value_parent)

        return _owner._observe(reader, module_base, country, profile, backend_reader=backend)
    return observe


def capture(installation, province_id, *, observer='FRA'):
    if not _previous._valid_id(province_id) or observer != 'FRA':
        raise ValueError('NODE_CASH_SCOPE')
    inner = _owner._capture_common(installation, 'FRA', observer='FRA', schema=INNER_SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=_observe_for(province_id), allow_observer_target=True)
    return {'schema': SCHEMA, 'observer': 'FRA',
            'object': {'type': 'province', 'province_id': province_id}, 'capture': inner}


def validate_capture(report, context, creation, province_id):
    if (not _previous._valid_id(province_id) or not isinstance(report, dict)
            or set(report) != {'schema', 'observer', 'object', 'capture'}
            or report.get('schema') != SCHEMA or report.get('observer') != 'FRA'
            or not _owner._same(report.get('object'), {'type': 'province', 'province_id': province_id})):
        return False
    return _owner._validate_capture_common(report['capture'], context, creation, 'FRA',
        schema=INNER_SCHEMA, profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=_observe_for(province_id), allow_observer_target=True, require_access=True)
