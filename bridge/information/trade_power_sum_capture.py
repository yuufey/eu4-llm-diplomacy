"""Guard and replay an optional structural child of the joint T04 capture.

The parent owns the sole process handle, installation identity, date and two
passes. This module does not open a process or scan another country table.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from .model import canonical
from . import trade_income_memory as _trade
from . import trade_power_sum_memory as _memory

ROOT = Path(__file__).resolve().parents[2]
PROFILE_FILE = Path(__file__).with_name('profiles') / 'trade-power-sum-memory-1374-v2.json'
PROFILE_SHA256 = 'acc12445e59290b2335fb5d093811f7d467b08ceef6d9401aef53b32bb5b1b47'
SCHEMA = 'information.trade_power_sum_capture.v1'
EXE_SHA256 = _trade.EXPECTED_EXE_SHA256


def _digest(value):
    return hashlib.sha256(canonical(value).encode('utf-8')).hexdigest()


def _load_profile():
    if not 0 < PROFILE_FILE.stat().st_size <= 256 * 1024:
        raise ValueError('SUM_PROFILE_SIZE')
    raw = PROFILE_FILE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROFILE_SHA256:
        raise ValueError('SUM_PROFILE_PIN')
    profile = json.loads(raw)
    if (profile.get('profile_id') != 'trade-power-sum-memory-1374'
            or profile.get('game_version') != '1.37.4'
            or profile.get('executable', {}).get('sha256') != EXE_SHA256):
        raise ValueError('SUM_PROFILE_IDENTITY')
    for entry in profile['source_evidence'] + profile['layout_dependencies']:
        path = (ROOT / entry['path']).resolve()
        path.relative_to(ROOT)
        if not 0 < path.stat().st_size <= 10 * 1024 * 1024:
            raise ValueError('SUM_DEPENDENCY_SIZE')
        with path.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        if digest != entry['sha256'] or path.stat().st_size != entry['bytes']:
            raise ValueError('SUM_DEPENDENCY_PIN')
    if profile['layout'] != {
            'world_global_rva': '0x233fe58', 'members_pointer_offset': '0x1d08',
            'member_count_offset': '0x1d14', 'country_fullref_offset': '0x20',
            'canonical_database_rva': '0x233d8b0', 'canonical_table_offset': '0x118',
            'human_count_offset': '0xa60', 'controllers_pointer_offset': '0x1d48',
            'max_members': 4096}:
        raise ValueError('SUM_LAYOUT_PIN')
    guards = profile.get('code_guards')
    if not isinstance(guards, list) or not guards or len(guards) > 16:
        raise ValueError('SUM_GUARDS')
    total = 0
    for entry in guards:
        data = bytes.fromhex(entry['bytes'])
        if (not data or len(data) > 4096 or int(entry['end_rva_exclusive'], 0)
                - int(entry['rva'], 0) != len(data)
                or hashlib.sha256(data).hexdigest() != entry['sha256']):
            raise ValueError('SUM_GUARD_SHAPE')
        total += len(data)
    if total > 8192:
        raise ValueError('SUM_GUARD_BUDGET')
    return profile


class _Tap:
    def __init__(self, reader):
        self.reader = reader
        self.rows = []

    def read(self, address, size, label):
        row = {'address': hex(address), 'size': size, 'label': label, 'status': 'requested'}
        self.rows.append(row)
        try:
            value = self.reader.read(address, size, label)
            if not isinstance(value, bytes) or len(value) != size:
                raise ValueError('SUM_SHORT_READ')
            row.update(status='observed', raw_hex=value.hex())
            return value
        except Exception:
            row['status'] = 'failed'
            raise


def read_fields(reader, module_base, trade_income_record, country_scan):
    result = {'schema': SCHEMA, 'status': 'unknown', 'profile_sha256': PROFILE_SHA256,
        'module_base': hex(module_base) if type(module_base) is int else None,
        'trade_income_canonical_sha256': _digest(trade_income_record),
        'country_scan_canonical_sha256': _digest(country_scan),
        'static_contract_guard': {'status': 'unknown'}, 'runtime_code_guard': {'status': 'unknown'},
        'observation': None, 'raw_reads': [], 'complete': False}
    tap = _Tap(reader)
    try:
        if type(module_base) is not int or not _trade._valid_address(module_base):
            raise ValueError('SUM_MODULE_INVALID')
        profile = _load_profile()
        result['static_contract_guard'] = {'status': 'observed', 'profile_sha256': PROFILE_SHA256}
        checks = {}
        for entry in profile['code_guards']:
            expected = bytes.fromhex(entry['bytes'])
            actual = tap.read(module_base + int(entry['rva'], 0), len(expected),
                              'trade_power_sum.code.' + entry['name'])
            checks[entry['name']] = actual == expected
        result['runtime_code_guard'] = {'status': 'observed' if all(checks.values()) else 'mismatch',
                                        'checks': checks}
        if not all(checks.values()):
            raise ValueError('SUM_RUNTIME_GUARD')
        value = _memory.read_fields(tap, module_base, trade_income_record, country_scan)
        result['observation'] = value
        if value.get('status') == 'observed':
            result['status'] = 'observed'
        else:
            result['reason'] = 'TRADE_POWER_SUM_MEMBERSHIP_UNVERIFIED'
    except Exception as exc:
        result['reason'] = 'TRADE_POWER_SUM_CAPTURE_UNVERIFIED'
        result['error_type'] = type(exc).__name__
    result['raw_reads'] = tap.rows
    return result


def retract_record(record, reason):
    result = deepcopy(record) if isinstance(record, Mapping) else {'schema': SCHEMA}
    result.update(status='unknown', reason=reason, observation=None, complete=False)
    return result


class _Replay:
    def __init__(self, rows):
        if not isinstance(rows, list) or not rows or len(rows) > 8192:
            raise ValueError('SUM_REPLAY_ROWS')
        self.rows = rows
        self.at = 0

    def read(self, address, size, label):
        if self.at >= len(self.rows):
            raise ValueError('SUM_REPLAY_EXHAUSTED')
        row = self.rows[self.at]
        self.at += 1
        if (not isinstance(row, Mapping) or row.get('status') != 'observed'
                or row.get('address') != hex(address) or type(row.get('size')) is not int
                or row['size'] != size or row.get('label') != label):
            raise ValueError('SUM_REPLAY_IDENTITY')
        raw = bytes.fromhex(row['raw_hex'])
        if len(raw) != size:
            raise ValueError('SUM_REPLAY_WIDTH')
        return raw


def validate_record(record, trade_income_record, country_scan, parent_read_log=None):
    try:
        if (not isinstance(record, Mapping) or record.get('status') != 'observed'
                or record.get('schema') != SCHEMA or record.get('profile_sha256') != PROFILE_SHA256
                or record.get('trade_income_canonical_sha256') != _digest(trade_income_record)
                or record.get('country_scan_canonical_sha256') != _digest(country_scan)):
            return False
        rows = record['raw_reads']
        if parent_read_log is not None:
            # Bind the child trace to the parent's real handle reads, rather
            # than accepting a separately invented internally coherent trace.
            if not isinstance(parent_read_log, list):
                return False
            selected = [row for row in parent_read_log if isinstance(row, Mapping)
                        and str(row.get('label', '')).startswith('trade_power_sum.')]
            if len(selected) != len(rows):
                return False
            for actual, item in zip(selected, rows):
                if (actual.get('address') != item['address'] or type(actual.get('size')) is not int
                        or actual['size'] != item['size'] or actual.get('label') != item['label']
                        or actual.get('raw_hex') != item['raw_hex']):
                    return False
        replay = _Replay(rows)
        rebuilt = read_fields(replay, int(record['module_base'], 0), trade_income_record, country_scan)
        return replay.at == len(rows) and canonical(rebuilt) == canonical(record)
    except Exception:
        return False


__all__ = ['read_fields', 'retract_record', 'validate_record']
