"""Read one cached province modifier component with native layout guards.

Admission and discovery for the configured observer precede the leaf. The
output describes a cached component and arithmetic residual.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from . import foreign_technology_capture as _owner
from . import province_state_memory as _province
from .province_state_capture import _validate_reviewed_layout_dependencies
from . import province_goods_sources_memory as _leaf
from . import foreign_quality_memory as _quality
from . import province_trade_power_inputs_memory as _descriptor

PROFILE_FILE = Path(__file__).with_name('profiles')/'province-goods-sources-memory-1374-v1-sampling-r1.json'
PROFILE_SHA256 = '1b83ed3bc207fcdaea1fd94bf1ba20b52f120a04a742715cd0d0ed1066c36a05'
SCHEMA = 'information.province_goods_sources_capture.v1'
INNER_SCHEMA = 'information.province_goods_sources_observer_snapshot.v1'

def _valid_id(value):
    return type(value) is int and 1 <= value <= 0xffff

def _valid_observer(value):
    return isinstance(value, str) and _owner._TAG.fullmatch(value) is not None


def _load_profile():
    if not 0 < PROFILE_FILE.stat().st_size <= 256*1024:
        raise ValueError('PROVINCE_GOODS_SOURCES_PROFILE_SIZE')
    raw = PROFILE_FILE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROFILE_SHA256:
        raise ValueError('PROVINCE_GOODS_SOURCES_PROFILE_PIN')
    profile = json.loads(raw)
    if (profile['profile_id'] != 'province-goods-sources-memory-1374'
            or profile['profile_version'] != 1 or profile.get('observer') != 'FRA'
            or profile.get('game_version') != '1.37.4'
            or profile['executable']['sha256'] != _owner.EXE_SHA256
            or profile['semantics']['supported_fields'] != [_leaf.FIELD_GOODS_SOURCE]):
        raise ValueError('PROVINCE_GOODS_SOURCES_PROFILE_BUILD')
    layout = profile['layout']['province_goods_sources']
    if (layout['cache_offset'] != '0x988' or layout['ready_state'] != 2
            or layout['aggregate_offset'] != '0x998' or layout['component_offset'] != '0x1120'
            or layout['source_key_offset'] != '0x158' or layout['scale_input_offset'] != '0x42c'
            or layout['modifier_index'] != 21 or layout['modifier_key'] != 'trade_goods_size_modifier'
            or layout['full_source_coverage'] is not False):
        raise ValueError('PROVINCE_GOODS_SOURCES_LAYOUT')
    _validate_reviewed_layout_dependencies(profile, 'PROVINCE_GOODS_SOURCES_DEPENDENCY_PIN')
    return profile

def _qualified_fields(reader, base, binding, fields):
    result = _leaf.read_fields(reader, base, binding, fields)
    field = result.get(_leaf.FIELD_GOODS_SOURCE)
    if not isinstance(field, dict) or field.get('status') != 'known':
        return result
    trace = _quality._TraceReader(reader)
    try:
        record = int(binding['record_pointer'], 0)
        cell = base+0x2358060
        manager = _quality._valid_pointer(trace.u64(cell, 'province_goods_sources.manager'), 'MANAGER')
        address = _quality._add(manager, 21*0x60, 0x60)
        raw = trace.exact(address, 0x60, 'province_goods_sources.descriptor21')
        key = _descriptor._parse_descriptor_name(trace, address, raw, 'trade_goods_size_modifier',
            (record, cell, manager, address, address+0x40), 'goods_source21')
        if raw[0x40:0x48] != bytes(8):
            raise ValueError('PROCESSOR_PRESENT')
        used = deepcopy(trace.reads)
        for index, row in enumerate(used):
            current = trace.exact(int(row['address'],0), row['size'],
                f'province_goods_sources.descriptor_stability.{index}')
            if current.hex() != row['raw_hex']:
                raise ValueError('DESCRIPTOR_CHANGED')
        field['raw_inputs']['descriptor_qualification'] = {'key': key,
            'descriptor_address': hex(address), 'processor_null': True, 'reads': trace.reads}
        field['value']['descriptor_qualified'] = True
    except Exception as exc:
        result[_leaf.FIELD_GOODS_SOURCE] = {'status': 'unknown',
            'reason': 'PROVINCE_GOODS_SOURCE_DESCRIPTOR_UNVERIFIED', 'complete': False,
            'basis': _leaf.BASIS, 'period': 'current', 'raw_inputs': {'candidate': field,
                'descriptor_reads': trace.reads, 'error_type': type(exc).__name__}}
    return result

def _observe_for(province_id, observer='FRA'):
    def observe(reader, base, country, profile):
        if country != observer or not _valid_id(province_id):
            raise ValueError('PROVINCE_GOODS_SOURCES_SCOPE')
        table = profile['layout']['province_goods_sources']['callback_table']
        start = base+int(table['rva'],0)
        expected = b''.join((base+int(rva,0)).to_bytes(8,'little') for rva in table['target_rvas'])
        if len(expected) != 288:
            raise ValueError('PROVINCE_GOODS_SOURCE_CALLBACK_COUNT')
        def backend(read, module_base, observer_country):
            if observer_country != observer:
                raise ValueError('PROVINCE_GOODS_SOURCES_SCOPE')
            before = _owner._read(read, start, len(expected), 'province_goods_sources.callbacks.before')
            if before != expected:
                raise ValueError('PROVINCE_GOODS_SOURCE_CALLBACK_MISMATCH')
            result = _province.read_two_pass(read, module_base, province_id, observer=observer,
                observer_scoped=True, fields=(_leaf.FIELD_GOODS_SOURCE,), read_fields=_qualified_fields)
            after = _owner._read(read, start, len(expected), 'province_goods_sources.callbacks.after')
            if after != before:
                raise ValueError('PROVINCE_GOODS_SOURCE_CALLBACK_CHANGED')
            result['callback_table'] = {'address': hex(start), 'raw_hex': before.hex(),
                'target_rvas': table['target_rvas'], 'stable': True}
            return result
        return _owner._observe(reader,base,country,profile,backend_reader=backend)
    return observe

def capture(installation: Path, province_id: int, *, observer: str = 'FRA'):
    if not _valid_id(province_id) or not _valid_observer(observer):
        raise ValueError('PROVINCE_GOODS_SOURCES_REQUEST_SCOPE')
    inner = _owner._capture_common(installation, observer, observer=observer, schema=INNER_SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=_observe_for(province_id, observer), allow_observer_target=True, observer_scoped=True)
    return {'schema':SCHEMA,'observer':observer,
        'object':{'type':'province','province_id':province_id},'capture':inner}

def validate_capture(report, context, creation, province_id):
    observer = context.get('observer') if isinstance(context, dict) else None
    if (not _valid_id(province_id) or not _valid_observer(observer) or not isinstance(report,dict)
            or set(report) != {'schema','observer','object','capture'}
            or report['schema'] != SCHEMA or report['observer'] != observer
            or not _owner._same(report['object'],{'type':'province','province_id':province_id})):
        return False
    return _owner._validate_capture_common(report['capture'], context, creation, observer,
        schema=INNER_SCHEMA, profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=_observe_for(province_id, observer), allow_observer_target=True,
        observer_scoped=True, require_access=True)

__all__ = ['capture','validate_capture']
