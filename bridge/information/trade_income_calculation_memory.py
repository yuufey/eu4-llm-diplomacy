"""Passive reconstruction of one selected country's current income cache.

The parent owns the handle, role admission, snapshot and session guards. The
already replayed sum child supplies the canonical country binding. This leaf does
not forecast new shares, run processors, or call the native cache writer.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import re

from . import foreign_quality_memory as _quality
from . import province_trade_power_inputs_memory as _descriptor
from . import trade_power_sum_memory as _identity
from . import trade_power_sum_capture as _sum
from .modifier_storage import read_raw_modifier
from .trade_income_calculation import calculate_current

BASIS = 'native_current_trade_income_cache_arithmetic'
MAX_BYTES = 64 * 1024
MAX_CALLS = 4096
NODE_PATTERN = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$')
MODIFIER_KEY = 'trade_efficiency'


class _Unknown(Exception):
    pass


class _BoundedPrefix:
    def __init__(self, reader):
        self.reader = reader
        self.calls = 0
        self.bytes = 0

    def read(self, address, size, label):
        if self.calls >= MAX_CALLS or self.bytes + size > MAX_BYTES:
            raise _Unknown('INCOME_CALCULATION_READ_BUDGET')
        self.calls += 1
        self.bytes += size
        return self.reader.read(address, size, 'trade_income_calculation.' + label)


def read_fields(reader, module_base, trade_income_record, country_scan,
                trade_power_sum_record, *, node_id):
    bounded = _BoundedPrefix(reader)
    trace = _quality._TraceReader(bounded)
    private = {}
    result = {'status': 'unknown', 'basis': BASIS, 'period': 'current',
              'node_id': node_id, 'complete': False}
    try:
        if (not isinstance(node_id, str) or not NODE_PATTERN.fullmatch(node_id)
                or node_id == 'Null'):
            raise _Unknown('INCOME_CALCULATION_SELECTOR_INVALID')
        if not _sum.validate_record(trade_power_sum_record, trade_income_record, country_scan):
            raise _Unknown('INCOME_CALCULATION_SUM_UNVERIFIED')
        own = trade_power_sum_record['observation']
        if own.get('stable') is not True or own.get('canonical_observer_verified') is not True:
            raise _Unknown('INCOME_CALCULATION_OBSERVER_UNVERIFIED')
        identity = _identity._source_identity(trade_income_record, country_scan)
        base = _quality._valid_pointer(module_base, 'MODULE')
        country = identity['country_pointer']
        slot = identity['country_slot']
        private['country_slot'] = slot
        nodes = [n for n in trade_income_record['nodes'] if n.get('node_id') == node_id]
        if len(nodes) != 1:
            raise _Unknown('INCOME_CALCULATION_NODE_NOT_UNIQUE')
        node = nodes[0]
        runtime = _quality._valid_pointer(int(node['runtime_pointer'], 0), 'NODE')
        table = _quality._valid_pointer(int(node['table_pointer'], 0), 'NODE_TABLE')
        definition = _quality._valid_pointer(int(node['definition_pointer'], 0), 'DEFINITION')
        entry = _quality._valid_pointer(int(node['entry_pointer'], 0), 'ENTRY')
        if entry != table + slot * 0xC0:
            raise _Unknown('INCOME_CALCULATION_ENTRY_IDENTITY')

        # Recheck the canonical cell, without another country-table scan.
        database = trace.u64(_quality._add(base, 0x233D8B0, 8), 'database')
        _quality._valid_pointer(database, 'DATABASE')
        if database + 0x118 != identity['source_table_cell']:
            raise _Unknown('INCOME_CALCULATION_DATABASE_IDENTITY')
        canonical_table = trace.u64(database + 0x118, 'canonical_table')
        if canonical_table != identity['source_table_pointer']:
            raise _Unknown('INCOME_CALCULATION_CANONICAL_TABLE')
        if trace.u64(canonical_table + slot * 8, 'canonical_cell') != country:
            raise _Unknown('INCOME_CALCULATION_COUNTRY_IDENTITY')
        if trace.exact(country + 0x20, 8, 'canonical_fullref') != identity['country_fullref_raw']:
            raise _Unknown('INCOME_CALCULATION_FULLREF')
        if (trace.u64(runtime + 0xA8, 'node_definition') != definition
                or trace.u64(runtime + 0x18, 'node_table') != table):
            raise _Unknown('INCOME_CALCULATION_NODE_IDENTITY')
        count = trace.i32(runtime + 0x24, 'node_row_count')
        if not 0 <= slot < count <= 4096:
            raise _Unknown('INCOME_CALCULATION_ROW_RANGE')
        row = trace.exact(entry, 0xC0, 'selected_row')
        if row.hex() != node['entry_raw_hex'] or row[0x10:0x18] != identity['country_fullref_raw']:
            raise _Unknown('INCOME_CALCULATION_ROW_IDENTITY')
        if row[0x17] == 0:
            raise _Unknown('INCOME_CALCULATION_NATIVE_ROW_SKIPPED')
        # Exact nonempty branch in b58360; do not invent a sentinel default.
        fields = (0x48, 0x4C, 0x28, 0x2C, 0x30, 0x34, 0x38, 0x54,
                  0x1C, 0x18, 0x20, 0x24, 0x3C, 0x40, 0x44, 0x50,
                  0x58, 0x5C, 0x70, 0x88, 0xA0, 0xA8)
        nonempty = (any(row[o:o+4] != bytes(4) for o in fields)
                    or any(row[o] for o in (0xAD, 0xAF, 0xAE, 0xAC))
                    or row[0xB0:0xB8] != bytes(8))
        if not nonempty and int.from_bytes(row[0xB8:0xBC], 'little') == 0x029C77F8:
            raise _Unknown('INCOME_CALCULATION_NATIVE_ROW_SKIPPED')
        denominator = trace.i32(runtime + 0xD0, 'node_writer_gate')
        if denominator == 0:
            raise _Unknown('INCOME_CALCULATION_NATIVE_NODE_SKIPPED')
        cash = trace.i32(runtime + 0xB0, 'node_cash')
        cache_state = trace.i32(country + 0x28C8, 'country_cache_state')
        if cache_state not in (0, 2):
            raise _Unknown('INCOME_CALCULATION_CACHE_STATE_UNSUPPORTED')
        base_object = _quality._valid_pointer(trace.u64(country + 0x2440, 'country_base_object'), 'BASE_OBJECT')
        base_raw = trace.i32(base_object + 0x20, 'country_base')
        manager_cell = _quality._add(base, 0x2358060, 8)
        manager = _quality._valid_pointer(trace.u64(manager_cell, 'modifier_manager'), 'MODIFIER_MANAGER')
        descriptor_address = _quality._add(manager, 14 * 0x60, 0x60)
        descriptor_raw = trace.exact(descriptor_address, 0x60, 'descriptor14')
        forbidden = (country, country + 0x28D0, manager_cell, manager, descriptor_address,
                     descriptor_address + 0x40)
        private['descriptor'] = _descriptor._parse_descriptor_name(
            trace, descriptor_address, descriptor_raw, MODIFIER_KEY, forbidden, 'income14')
        if descriptor_raw[0x40:0x48] != bytes(8):
            raise _Unknown('INCOME_CALCULATION_PROCESSOR_PRESENT')
        component = read_raw_modifier(trace, country, 14, 'ratio',
                                      name=MODIFIER_KEY, forbidden_pointers=forbidden)
        private['modifier_storage'] = component
        if not isinstance(component, Mapping) or component.get('status') != 'known':
            raise _Unknown('INCOME_CALCULATION_STORAGE_UNVERIFIED')
        special = trace.i32(base + 0x233D8B8, 'special_slot')
        if special != trade_income_record['special_slot']:
            raise _Unknown('INCOME_CALCULATION_SPECIAL_SLOT_CHANGED')
        applies = slot == special or row[0xAE] != 0
        bonus = trace.i32(base + 0x233E53C, 'conditional_bonus') if applies else 0
        inputs = {'share_raw': int.from_bytes(row[0x2C:0x30], 'little', signed=True),
                  'node_cash_raw': cash, 'country_base_raw': base_raw,
                  'modifier_raw': component['raw'], 'bonus_raw': bonus, 'bonus_applies': applies}
        outputs = calculate_current(**inputs)
        cache = {'income_before_multiplier_raw': int.from_bytes(row[0x38:0x3C], 'little', signed=True),
                 'income_raw': int.from_bytes(row[0x34:0x38], 'little', signed=True)}
        # Every successfully used byte is checked again, including heap keys
        # and sparse entries. Parent doublepass is an additional outer check.
        used = deepcopy(trace.reads)
        for index, read in enumerate(used):
            if trace.exact(int(read['address'], 0), read['size'], f'stability.{index}') .hex() != read['raw_hex']:
                raise _Unknown('INCOME_CALCULATION_INPUT_CHANGED')
        result.update(status='observed', stable=True, value={
            'inputs': inputs, 'outputs': outputs, 'cache': cache,
            'matches_cache': all(outputs[k] == v for k, v in cache.items())})
    except Exception as exc:
        result['reason'] = str(exc) if isinstance(exc, _Unknown) else 'INCOME_CALCULATION_UNVERIFIED'
        result['error_type'] = type(exc).__name__
    private.update(reads=trace.reads, budget={'calls': bounded.calls,
                   'bytes_requested': bounded.bytes, 'max_calls': MAX_CALLS, 'max_bytes': MAX_BYTES})
    result['raw_inputs'] = private
    return result
