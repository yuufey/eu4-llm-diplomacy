"""Reconstruct the current node B0 input from admitted loaded members.

The parent supplies the proven node/member anchors and complete country scan.
Shared descriptor, owner and price inputs are acquired once per call, never
across requests. All bytes actually used are reread; no native code is called.
"""
from __future__ import annotations

from copy import deepcopy

from . import foreign_country_memory as _shared
from . import foreign_quality_memory as _quality
from . import province_resource_memory as _resource
from . import province_trade_power_country_memory as _country
from . import province_trade_power_inputs_memory as _descriptor
from . import province_trade_value_memory as _value
from . import province_trade_value_parent_memory as _value_parent
from .modifier_storage import read_raw_modifier, read_raw_modifier_object
from .province_trade_value_calculation import calculate_current, aggregate_node_inputs
from .trade_value_memory import NODE_ID_RE

FIELD = 'G02.node_cash_aggregate'
BASIS = 'native_node_province_value_input_reconstruction'
MAX_BYTES = 128 * 1024
MAX_CALLS = 4096
MAX_MEMBERS = 512
_ALLOCATION = 'G02.province_node_allocation'


class _Unknown(ValueError):
    pass


class _SharedFailure(_Unknown):
    pass


class _Prefix:
    def __init__(self, reader):
        self.reader, self.calls, self.bytes = reader, 0, 0

    def read(self, address, size, label):
        if self.calls >= MAX_CALLS or self.bytes + size > MAX_BYTES:
            raise _Unknown('NODE_CASH_READ_BUDGET')
        self.calls += 1
        self.bytes += size
        return self.reader.read(address, size, 'node_cash.' + label)


def _require(condition, reason):
    if not condition:
        raise _SharedFailure(reason)


def _pointer(value):
    return _quality._valid_pointer(int(value, 0) if type(value) is str else value, 'NODE_CASH')


def _anchor(allocation):
    _require(isinstance(allocation, dict) and allocation.get('status') == 'known'
             and allocation.get('basis') == 'native_trade_node_province_component_reconstruction',
             'NODE_CASH_ALLOCATION_UNVERIFIED')
    passes = allocation['raw_inputs']['pass_summaries']
    _require(len(passes) == 2 and _shared._same_raw(passes[0], passes[1]),
             'NODE_CASH_MEMBERS_UNSTABLE')
    row, value = passes[0], allocation['value']
    node = value['node_id']
    _require(type(node) is str and NODE_ID_RE.fullmatch(node) is not None,
             'NODE_CASH_NODE_KEY_INVALID')
    members = row['members']
    _require(isinstance(members, list) and 0 < len(members) <= MAX_MEMBERS
             and len(members) == value['member_count'], 'NODE_CASH_MEMBER_COUNT_INVALID')
    header = bytes.fromhex(row['stable']['definition_province_vector_header_raw_hex'])
    vector = bytes.fromhex(row['stable']['definition_province_vector_raw_hex'])
    _require(len(header) == 16 and len(vector) == len(members)*8,
             'NODE_CASH_MEMBER_VECTOR_INVALID')
    begin, end = int.from_bytes(header[:8], 'little'), int.from_bytes(header[8:], 'little')
    _require(_pointer(begin) == begin and end - begin == len(vector),
             'NODE_CASH_MEMBER_VECTOR_INVALID')
    return {'node_id': node, 'runtime': _pointer(row['candidate_runtime_pointer']),
            'definition': _pointer(row['candidate_definition_pointer']),
            'center': value['center_province_id'], 'members': members,
            'header': header, 'vector': vector, 'begin': begin}


def _node_inputs(trace, base, province_scan, observer, allocation, private):
    anchor = _anchor(allocation)
    _require(province_scan.get('status') == 'observed', 'NODE_CASH_PROVINCE_SCAN_UNVERIFIED')
    world = trace.u64(base+0x233FE58, 'world')
    _require(world == _pointer(province_scan['world']['pointer']), 'NODE_CASH_WORLD_CHANGED')
    header = province_scan['header']
    for offset, name in ((0x1C90, 'begin'), (0x1C98, 'end'), (0x1CA8, 'records_pointer')):
        _require(trace.u64(world+offset, 'province_header.'+name) == _pointer(header[name]),
                 'NODE_CASH_PROVINCE_HEADER_CHANGED')
    records, count = _pointer(header['records_pointer']), header['count']
    _require(type(count) is int and 0 < count <= 65536
             and _pointer(header['end'])-_pointer(header['begin']) == count*8,
             'NODE_CASH_PROVINCE_HEADER_INVALID')
    runtime, definition = anchor['runtime'], anchor['definition']
    _require(runtime != definition and trace.u64(runtime+0xA8, 'node.definition') == definition,
             'NODE_CASH_NODE_DEFINITION_CHANGED')
    raw_key = trace.exact(definition+0x10, 32, 'node.key')
    _descriptor._parse_descriptor_name(trace, definition+0x10, raw_key, anchor['node_id'],
        (runtime, definition, records, world), 'node_key')
    center = anchor['center']
    _require(type(center) is int and 0 < center < count
             and trace.i32(definition+0xDC, 'node.center') == center,
             'NODE_CASH_CENTER_CHANGED')
    _require(trace.exact(definition+0x68, 16, 'node.member_header') == anchor['header']
             and trace.exact(anchor['begin'], len(anchor['vector']), 'node.member_vector') == anchor['vector'],
             'NODE_CASH_MEMBER_VECTOR_CHANGED')
    center_record = records+center*0x2E10
    _require(trace.i32(center_record+0x20, 'center.id') == center
             and trace.u64(center_record+0xE8, 'center.runtime') == runtime,
             'NODE_CASH_CENTER_RECORD_CHANGED')
    discovery = _country._province._read_discovery(_shared._BoundedReader(trace), center_record, observer['slot'])
    private['center_discovery'] = discovery
    if discovery.get('status') != 'known' or discovery.get('value') is not True:
        raise _Unknown('NODE_CASH_CENTER_NOT_DISCOVERED')
    private['node_binding'] = {k: hex(v) if k in ('runtime', 'definition', 'begin') else v
                               for k, v in anchor.items() if k not in ('header', 'vector', 'members')}
    private['cache_raw'] = trace.i32(runtime+0xB0, 'node.current_cash')
    members, seen = [], set()
    for index, retained in enumerate(anchor['members']):
        record = int.from_bytes(anchor['vector'][index*8:index*8+8], 'little')
        pid = retained['province_id']
        _require(type(pid) is int and 0 < pid < count and pid not in seen
                 and record == records+pid*0x2E10 and record == _pointer(retained['record_pointer']),
                 'NODE_CASH_MEMBER_IDENTITY_INVALID')
        seen.add(pid)
        _require(trace.i32(record+0x20, f'member{pid}.id') == pid
                 and trace.u64(record+0xE8, f'member{pid}.runtime') == runtime,
                 'NODE_CASH_MEMBER_IDENTITY_CHANGED')
        members.append({'province_id': pid, 'record_id': pid, 'record_pointer': hex(record),
                        'id_address': hex(record+0x20), 'id_raw_hex': pid.to_bytes(4, 'little').hex()})
    _require(center in seen and allocation['value']['province_id'] in seen,
             'NODE_CASH_SELECTED_MEMBER_MISSING')
    return anchor, world, members


def _descriptors(trace, base, forbidden):
    manager = _quality._valid_pointer(trace.u64(base+0x2358060, 'modifier_manager'), 'MODIFIER_MANAGER')
    _require(manager not in forbidden, 'NODE_CASH_MANAGER_ALIAS')
    result = {}
    for index, key in _value.DESCRIPTORS.items():
        address = _quality._add(manager, index*0x60, 0x60)
        raw = trace.exact(address, 0x60, f'descriptor{index}')
        parsed = _descriptor._parse_descriptor_name(trace, address, raw, key,
            (*forbidden, manager, address, address+0x40), f'descriptor{index}')
        result[str(index)] = {'address': hex(address), 'key': parsed, 'raw_hex': raw.hex()}
        if raw[0x40:0x48] != bytes(8):
            raise _Unknown('NODE_CASH_PROCESSOR_PRESENT')
    return result


def _owner_inputs(trace, limiter, base, scan, raw_ref, forbidden):
    # A malformed/absent owner stays unresolved. A valid retained canonical
    # row that no longer binds invalidates the shared observation.
    try:
        binding = _country._rebind(limiter, base, scan, raw_ref, 'node_cash.owner')
    except _country._ObserverFailure:
        raise _SharedFailure('NODE_CASH_OBSERVER_ROLE_CHANGED') from None
    except Exception as exc:
        if (_value_parent._owner_has_unique_retained_row(scan, raw_ref)
                or str(exc).split(':', 1)[0] in _value_parent._OWNER_SHARED_REBIND_ERRORS):
            raise _SharedFailure('NODE_CASH_OWNER_CANONICAL_CHANGED') from None
        return {'status': 'unknown', 'reason': 'NODE_CASH_OWNER_UNVERIFIED'}
    gate = _country._admit(limiter, base, scan, binding)
    result = {'status': 'unknown', 'binding': binding, 'admission': gate,
              'reason': 'NODE_CASH_OWNER_NOT_ADMITTED'}
    if not _country._allowed(gate):
        return result
    owner = _pointer(binding['country_pointer'])
    _require(owner not in forbidden, 'NODE_CASH_OWNER_ALIAS')
    state = trace.i32(owner+0x28C8, 'owner.cache_state')
    result['cache_state'] = state
    if state not in (0, 2):
        result['reason'] = 'NODE_CASH_OWNER_CACHE_UNSUPPORTED'
        return result
    components = {str(index): read_raw_modifier(trace, owner, index, 'raw',
        name=_value.DESCRIPTORS[index], forbidden_pointers=(*forbidden, owner)) for index in (184, 491)}
    result['components'] = components
    if any(c.get('status') != 'known' for c in components.values()):
        result['reason'] = 'NODE_CASH_OWNER_MODIFIERS_UNVERIFIED'
    else:
        result.update(status='known', reason=None)
    return result


def read_fields(reader, base, province_scan, observer_binding, country_scan, allocation):
    """Read one node group using validated upstream anchors, within one pass."""
    bounded = _Prefix(reader)
    trace = _quality._TraceReader(bounded)
    limiter = _shared._BoundedReader(trace)
    private = {'shared_valid': False, 'owners': {}, 'prices': {}, 'members': []}
    result = {'status': 'unknown', 'basis': BASIS, 'period': 'current', 'partial': True, 'complete': False}
    try:
        _quality._valid_pointer(base, 'BASE')
        _require(allocation.get('value', {}).get('observer_country') == observer_binding.get('tag'),
                 'NODE_CASH_OBSERVER_INVALID')
        observer = _country._rebind(limiter, base, country_scan,
            bytes.fromhex(observer_binding['fullref_raw_hex']), 'node_cash.observer')
        gate = _country._admit(limiter, base, country_scan, observer)
        _require(_shared._same_raw(observer, observer_binding) and _country._allowed(gate)
                 and gate.get('observer_nonplayer_role', {}).get('verified') is True,
                 'NODE_CASH_OBSERVER_UNVERIFIED')
        private['observer_admission'] = gate
        anchor, world, members = _node_inputs(trace, base, province_scan, observer, allocation, private)
        forbidden = (world, anchor['runtime'], anchor['definition'], _pointer(province_scan['header']['records_pointer']))
        private['descriptors'] = _descriptors(trace, base, forbidden)
        market = _quality._valid_pointer(trace.u64(world+0x25D0, 'price_container'), 'PRICE_CONTAINER')
        prices = _quality._valid_pointer(trace.u64(market+8, 'price_array'), 'PRICE_ARRAY')
        _require(market not in forbidden and prices not in (*forbidden, market), 'NODE_CASH_PRICE_ALIAS')
        private['price_identity'] = {'container': hex(market), 'prices': hex(prices), 'array_count_claimed': False}
        values, unresolved = [], []
        for binding in members:
            pid, record = binding['province_id'], _pointer(binding['record_pointer'])
            discovery = _country._province._read_discovery(limiter, record, observer['slot'])
            row = {'province_id': pid, 'discovery': discovery, 'status': 'unknown'}
            private['members'].append(row)
            try:
                if discovery.get('status') != 'known' or discovery.get('value') is not True:
                    raise _Unknown('NODE_CASH_MEMBER_NOT_DISCOVERED')
                ref = trace.exact(record+0x468, 8, f'member{pid}.owner')
                row['owner_reference_raw_hex'] = ref.hex()
                if ref.hex() not in private['owners']:
                    private['owners'][ref.hex()] = _owner_inputs(trace, limiter, base, country_scan, ref,
                                                               (*forbidden, record, market, prices))
                owner = private['owners'][ref.hex()]
                if owner['status'] != 'known':
                    raise _Unknown(owner['reason'])
                resource = _resource._read_resource(trace, base, binding)
                row['resource'] = resource
                if resource.get('status') != 'known':
                    raise _Unknown('NODE_CASH_RESOURCE_UNVERIFIED')
                goods = resource['value']['icon_index']
                if type(goods) is not int or not 0 <= goods < 1024:
                    raise _Unknown('NODE_CASH_GOODS_INDEX_UNSUPPORTED')
                if str(goods) not in private['prices']:
                    address = _quality._add(prices, goods*0x38+4, 4)
                    private['prices'][str(goods)] = {'address': hex(address), 'raw': trace.i32(address, f'price{goods}')}
                components = {str(index): read_raw_modifier_object(trace, record+0x998, index, 'raw',
                    name=_value.DESCRIPTORS[index], forbidden_pointers=(*forbidden, record, market, prices))
                    for index in (20, 21, 101, 112)}
                row['components'] = components
                if any(c.get('status') != 'known' for c in components.values()):
                    raise _Unknown('NODE_CASH_PROVINCE_MODIFIERS_UNVERIFIED')
                inputs = {'province_goods_base_raw': components['20']['raw'],
                    'owner_goods_base_raw': owner['components']['491']['raw'],
                    'province_goods_modifier_raw': components['21']['raw'],
                    'owner_goods_modifier_raw': owner['components']['184']['raw'],
                    'goods_price_raw': private['prices'][str(goods)]['raw'],
                    'province_value_add_raw': components['101']['raw'],
                    'province_value_modifier_raw': components['112']['raw']}
                calculated = calculate_current(**inputs)
                row.update(status='known', inputs=inputs, calculation=calculated, owner=owner['binding']['tag'])
                values.append(calculated['value_raw'])
            except _SharedFailure:
                raise
            except _Unknown as exc:
                row['reason'] = str(exc)
                unresolved.append(pid)
        # Failed reads cannot be promoted into a stable partial reconstruction.
        _require(all(r['status'] == 'ok' for r in trace.reads), 'NODE_CASH_READ_FAILED')
        aggregate = aggregate_node_inputs(values) if not unresolved else None
        result.update(status='known', value={'node_id': anchor['node_id'], 'center_province_id': anchor['center'],
            'member_count': len(members), 'valued_member_count': len(values), 'unresolved_province_ids': unresolved,
            'all_member_values_known': not unresolved, 'province_input_sum_raw': aggregate['sum_raw'] if aggregate else None,
            'calculated_node_cash_raw': aggregate['node_input_raw'] if aggregate else None,
            'cached_node_cash_raw': private['cache_raw'],
            'matches_cache': aggregate['node_input_raw'] == private['cache_raw'] if aggregate else None,
            'scale': 1000, 'unit': 'node_cash', 'current_only': True,
            'cache_refresh_verified': False, 'future_income_claimed': False})
        private['shared_valid'] = True
    except _country._ObserverFailure:
        result['reason'] = 'NODE_CASH_OBSERVER_ROLE_CHANGED'
    except Exception as exc:
        result['reason'] = str(exc) if isinstance(exc, _Unknown) else 'NODE_CASH_UNVERIFIED'
        result['error_type'] = type(exc).__name__
        # Unsupported numeric paths are local; shared identity/read drift is not.
        private['shared_valid'] = isinstance(exc, _Unknown) and not isinstance(exc, _SharedFailure)
    # Also recheck inputs that led to stable unsupported/denied outcomes. A
    # failed or incomplete reread cannot leave a known aggregate behind.
    try:
        _require(all(r['status'] == 'ok' for r in trace.reads), 'NODE_CASH_READ_FAILED')
        used = deepcopy(trace.reads)
        for index, row in enumerate(used):
            if trace.exact(int(row['address'], 0), row['size'], f'stability.{index}').hex() != row['raw_hex']:
                raise _SharedFailure('NODE_CASH_INPUT_CHANGED')
    except Exception:
        result.pop('value', None)
        result.update(status='unknown', reason='NODE_CASH_INPUT_STABILITY_UNVERIFIED')
        private['shared_valid'] = False
    private.update(reads=trace.reads, budget={'calls': bounded.calls, 'bytes_requested': bounded.bytes,
                   'max_calls': MAX_CALLS, 'max_bytes': MAX_BYTES})
    result['raw_inputs'] = private
    return {FIELD: result}
