"""Read the supported province input to the native node-value accumulator.

The parent owns discovery, observer role, owner admission and two passes. This
leaf models the node caller's zero extra arguments and absent description;
it never executes a processor or assigns a monthly period to a single input.
"""
from __future__ import annotations

from copy import deepcopy

from . import province_identity_memory as _province
from . import province_resource_memory as _resource
from . import country_scale_development_memory as _country
from . import foreign_quality_memory as _quality
from . import province_trade_power_inputs_memory as _descriptor
from . import foreign_country_memory as _shared
from .modifier_storage import read_raw_modifier_object, read_raw_modifier
from .province_trade_value_calculation import calculate_current

FIELD = 'G02.province_trade_value_calculation'
BASIS = 'native_province_trade_value_processor_absent'
MAX_BYTES = 64 * 1024
MAX_CALLS = 4096
DESCRIPTORS = {
    20: 'trade_goods_size', 21: 'trade_goods_size_modifier',
    101: 'trade_value', 112: 'trade_value_modifier',
    184: 'global_trade_goods_size_modifier', 491: 'global_trade_goods_size',
}


class _Unknown(Exception):
    pass


class _BoundedPrefix:
    def __init__(self, reader):
        self.reader = reader
        self.calls = 0
        self.bytes = 0

    def read(self, address, size, label):
        if self.calls >= MAX_CALLS or self.bytes + size > MAX_BYTES:
            raise _Unknown('PROVINCE_VALUE_READ_BUDGET')
        self.calls += 1
        self.bytes += size
        return self.reader.read(address, size, 'province_trade_value.' + label)


def read_fields(reader, base, province_binding, province_scan, observer_binding, owner_binding):
    bounded = _BoundedPrefix(reader)
    trace = _quality._TraceReader(bounded)
    private = {}
    result = {'status': 'unknown', 'basis': BASIS, 'period': 'current', 'complete': False}
    try:
        base, record, binding = _province._validate_binding(base, province_binding)
        _, owner, retained = _country._parse_target(base, owner_binding)
        _, observer, observer_retained = _country._parse_target(base, observer_binding)
        if observer_retained['tag'] != 'FRA':
            raise _Unknown('PROVINCE_VALUE_OBSERVER_INVALID')
        if province_scan.get('status') != 'observed':
            raise _Unknown('PROVINCE_VALUE_PROVINCE_SCAN_UNVERIFIED')
        world_expected = int(province_scan['world']['pointer'], 0)
        limiter = _shared._BoundedReader(trace)
        private['owner_binding'] = _country._validate_target_binding(limiter, base, owner, retained)
        if trace.exact(record+0x468, 8, 'owner_fullref') != bytes.fromhex(retained['fullref_raw_hex']):
            raise _Unknown('PROVINCE_VALUE_OWNER_REFERENCE_MISMATCH')
        if trace.i32(owner+0x28C8, 'owner_cache_state') not in (0, 2):
            raise _Unknown('PROVINCE_VALUE_OWNER_CACHE_UNSUPPORTED')
        resource = _resource._read_resource(trace, base, province_binding)
        private['resource'] = resource
        if resource.get('status') != 'known':
            raise _Unknown('PROVINCE_VALUE_RESOURCE_UNVERIFIED')
        goods_index = resource['value']['icon_index']
        if type(goods_index) is not int or not 0 <= goods_index < 1024:
            raise _Unknown('PROVINCE_VALUE_GOODS_INDEX_UNSUPPORTED')
        world = trace.u64(base+0x233FE58, 'world')
        if world != world_expected:
            raise _Unknown('PROVINCE_VALUE_WORLD_MISMATCH')
        market = _quality._valid_pointer(trace.u64(world+0x25D0, 'goods_price_container'), 'GOODS_PRICE_CONTAINER')
        prices = _quality._valid_pointer(trace.u64(market+8, 'goods_prices'), 'GOODS_PRICES')
        if market in (record, owner, observer, world) or prices in (record, owner, observer, world, market):
            raise _Unknown('PROVINCE_VALUE_PRICE_POINTER_ALIAS')
        price_address = _quality._add(prices, goods_index*0x38+4, 4)
        price = trace.i32(price_address, 'selected_goods_price')
        private['price_identity'] = {'goods_index': goods_index, 'container': hex(market),
            'prices': hex(prices), 'selected_price_address': hex(price_address),
            'array_count_claimed': False}
        manager_cell = base+0x2358060
        manager = _quality._valid_pointer(trace.u64(manager_cell, 'modifier_manager'), 'MODIFIER_MANAGER')
        forbidden = (record, owner, observer, manager_cell, manager, market, prices)
        descriptors = {}
        for index, key in DESCRIPTORS.items():
            address = _quality._add(manager, index*0x60, 0x60)
            raw = trace.exact(address, 0x60, f'descriptor{index}')
            parsed = _descriptor._parse_descriptor_name(trace, address, raw, key,
                (*forbidden, address, address+0x40), f'province_value{index}')
            descriptors[str(index)] = {'key': parsed, 'raw_hex': raw.hex(), 'address': hex(address)}
            if raw[0x40:0x48] != bytes(8):
                raise _Unknown('PROVINCE_VALUE_PROCESSOR_PRESENT')
        private['descriptors'] = descriptors
        components = {}
        for index in (20, 21, 101, 112):
            components[str(index)] = read_raw_modifier_object(trace, record+0x998,
                index, 'raw', name=DESCRIPTORS[index], forbidden_pointers=forbidden)
        for index in (184, 491):
            components[str(index)] = read_raw_modifier(trace, owner, index, 'raw',
                name=DESCRIPTORS[index], forbidden_pointers=forbidden)
        private['components'] = components
        if any(c.get('status') != 'known' for c in components.values()):
            raise _Unknown('PROVINCE_VALUE_MODIFIER_STORAGE_UNVERIFIED')
        inputs = {'province_goods_base_raw': components['20']['raw'],
            'owner_goods_base_raw': components['491']['raw'],
            'province_goods_modifier_raw': components['21']['raw'],
            'owner_goods_modifier_raw': components['184']['raw'], 'goods_price_raw': price,
            'province_value_add_raw': components['101']['raw'],
            'province_value_modifier_raw': components['112']['raw']}
        calculated = calculate_current(**inputs)
        used = deepcopy(trace.reads)
        for index, row in enumerate(used):
            raw = trace.exact(int(row['address'], 0), row['size'], f'stability.{index}')
            if raw.hex() != row['raw_hex']:
                raise _Unknown('PROVINCE_VALUE_INPUT_CHANGED')
        result.update(status='known', value={'province_id': binding['province_id'],
            'owner': retained['tag'], 'resource': resource['value'], 'inputs': inputs,
            'calculation': calculated, 'scale': 1000, 'unit': 'native_trade_value_input',
            'extra_arguments_zero': True, 'description_absent': True,
            'current_only': True, 'individual_monthly_contribution_claimed': False})
    except Exception as exc:
        result['reason'] = str(exc) if isinstance(exc, _Unknown) else 'PROVINCE_VALUE_UNVERIFIED'
        result['error_type'] = type(exc).__name__
    private.update(reads=trace.reads, budget={'calls': bounded.calls, 'bytes_requested': bounded.bytes,
                   'max_calls': MAX_CALLS, 'max_bytes': MAX_BYTES})
    result['raw_inputs'] = private
    return {FIELD: result}
