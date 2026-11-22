"""Guard and strictly replay the selected current-income arithmetic child."""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from .model import canonical
from . import trade_income_calculation_memory as _memory
from . import trade_power_sum_capture as _shared
from . import trade_income_memory as _trade

ROOT = Path(__file__).resolve().parents[2]
PROFILE_FILE = Path(__file__).with_name('profiles') / 'trade-income-calculation-memory-1374-v1.json'
PROFILE_SHA256 = '335116cf4e225e860c993ed7b11a826e222416c10e246b3d4bafd4bd5175cf07'
SCHEMA = 'information.trade_income_calculation_capture.v1'
PREFIX = 'trade_income_calculation.'
_REVIEWED_DEPENDENCIES = {
    **_shared._REVIEWED_DEPENDENCIES,
    'bridge/information/trade_power_sum_capture.py': (
        9427, 'b0ccba3d05072dfab0e4952d93703a6e98f6a4f5ced7a72b1a90d20dd8d880e0'),
}


def _digest(value):
    return hashlib.sha256(canonical(value).encode('utf-8')).hexdigest()


def _load_profile():
    raw = PROFILE_FILE.read_bytes()
    if not 0 < len(raw) <= 256 * 1024 or hashlib.sha256(raw).hexdigest() != PROFILE_SHA256:
        raise ValueError('INCOME_PROFILE_PIN')
    profile = json.loads(raw)
    if (profile.get('profile_id') != 'trade-income-calculation-memory-1374'
            or profile.get('game_version') != '1.37.4'
            or profile.get('executable', {}).get('sha256') != _trade.EXPECTED_EXE_SHA256):
        raise ValueError('INCOME_PROFILE_IDENTITY')
    for entry in profile['source_evidence'] + profile['layout_dependencies']:
        _shared._check_dependency(ROOT, entry, 'INCOME', reviewed=_REVIEWED_DEPENDENCIES)
    if profile['layout'] != {'node_cash': '0xb0', 'node_writer_gate': '0xd0',
            'row_share': '0x2c', 'row_income': '0x34', 'row_pre_income': '0x38',
            'country_base_pointer': '0x2440', 'base_value': '0x20',
            'cache_state': '0x28c8', 'modifier_object': '0x28d0',
            'modifier_id': 14, 'modifier_key': 'trade_efficiency',
            'descriptor_manager_rva': '0x2358060', 'special_slot_rva': '0x233d8b8',
            'bonus_rva': '0x233e53c'}:
        raise ValueError('INCOME_LAYOUT_PIN')
    guards = profile['code_guards']
    if not isinstance(guards, list) or not 1 <= len(guards) <= 16:
        raise ValueError('INCOME_GUARDS')
    total = 0
    for entry in guards:
        data = bytes.fromhex(entry['bytes'])
        if (not 0 < len(data) <= 4096 or int(entry['end_rva_exclusive'], 0)
                - int(entry['rva'], 0) != len(data)
                or hashlib.sha256(data).hexdigest() != entry['sha256']):
            raise ValueError('INCOME_GUARD_SHAPE')
        total += len(data)
    if total > 8192:
        raise ValueError('INCOME_GUARD_BUDGET')
    return profile


def read_fields(reader, module_base, trade_income_record, country_scan,
                trade_power_sum_record, *, node_id):
    result = {'schema': SCHEMA, 'status': 'unknown', 'profile_sha256': PROFILE_SHA256,
        'module_base': hex(module_base) if type(module_base) is int else None, 'node_id': node_id,
        'trade_income_canonical_sha256': _digest(trade_income_record),
        'country_scan_canonical_sha256': _digest(country_scan),
        'trade_power_sum_canonical_sha256': _digest(trade_power_sum_record),
        'static_contract_guard': {'status': 'unknown'}, 'runtime_code_guard': {'status': 'unknown'},
        'observation': None, 'raw_reads': [], 'complete': False}
    tap = _shared._Tap(reader)
    try:
        if type(module_base) is not int or not _trade._valid_address(module_base):
            raise ValueError('INCOME_MODULE_INVALID')
        if not isinstance(node_id, str) or not _memory.NODE_PATTERN.fullmatch(node_id) or node_id == 'Null':
            raise ValueError('INCOME_SELECTOR_INVALID')
        profile = _load_profile()
        result['static_contract_guard'] = {'status': 'observed', 'profile_sha256': PROFILE_SHA256}
        checks = {}
        for entry in profile['code_guards']:
            expected = bytes.fromhex(entry['bytes'])
            actual = tap.read(module_base + int(entry['rva'], 0), len(expected), PREFIX + 'code.' + entry['name'])
            checks[entry['name']] = actual == expected
        result['runtime_code_guard'] = {'status': 'observed' if all(checks.values()) else 'mismatch', 'checks': checks}
        if not all(checks.values()):
            raise ValueError('INCOME_RUNTIME_GUARD')
        value = _memory.read_fields(tap, module_base, trade_income_record, country_scan,
                                    trade_power_sum_record, node_id=node_id)
        result['observation'] = value
        if value.get('status') == 'observed':
            result['status'] = 'observed'
        else:
            result['reason'] = 'TRADE_INCOME_CALCULATION_UNVERIFIED'
    except Exception as exc:
        result['reason'] = 'TRADE_INCOME_CALCULATION_CAPTURE_UNVERIFIED'
        result['error_type'] = type(exc).__name__
    result['raw_reads'] = tap.rows
    return result


def retract_record(record, reason):
    result = deepcopy(record) if isinstance(record, Mapping) else {'schema': SCHEMA}
    result.update(status='unknown', reason=reason, observation=None, complete=False)
    return result


def validate_record(record, trade_income_record, country_scan, trade_power_sum_record, *,
                    node_id, parent_read_log=None):
    try:
        if (not isinstance(record, Mapping) or record.get('status') != 'observed'
                or record.get('schema') != SCHEMA or record.get('profile_sha256') != PROFILE_SHA256
                or record.get('node_id') != node_id
                or record.get('trade_income_canonical_sha256') != _digest(trade_income_record)
                or record.get('country_scan_canonical_sha256') != _digest(country_scan)
                or record.get('trade_power_sum_canonical_sha256') != _digest(trade_power_sum_record)):
            return False
        rows = record['raw_reads']
        if parent_read_log is not None:
            if not isinstance(parent_read_log, list):
                return False
            selected = [r for r in parent_read_log if isinstance(r, Mapping)
                        and str(r.get('label', '')).startswith(PREFIX)]
            if len(selected) != len(rows):
                return False
            for actual, item in zip(selected, rows):
                if (actual.get('status') != 'observed'
                        or actual.get('address') != item['address'] or type(actual.get('size')) is not int
                        or actual['size'] != item['size'] or actual.get('label') != item['label']
                        or actual.get('raw_hex') != item['raw_hex']):
                    return False
        replay = _shared._Replay(rows)
        rebuilt = read_fields(replay, int(record['module_base'], 0), trade_income_record,
                              country_scan, trade_power_sum_record, node_id=node_id)
        return replay.at == len(rows) and canonical(rebuilt) == canonical(record)
    except Exception:
        return False
