"""FRA's native diplomat-capacity aggregate through the existing bounded cache reader."""
from collections.abc import Mapping
from copy import deepcopy

from . import country_scale_development_memory as _binding
from . import foreign_quality_memory as _quality
from . import relations_capacity_memory as _shared_cache
from .modifier_storage import read_raw_modifier

SCHEMA = 'information.diplomats_total_memory.v1'
FIELD = 'N05.diplomats_total'
FIELDS = (FIELD,)
MODIFIER_ID = 34
UNIT = 'diplomats'
SCALE = 1000
BASIS = 'native_diplomats_total_aggregate_cache'
VALUE_ORIGIN = 'copied_native_aggregate_modifier'


PROCESSOR_VTABLE_RVA = 0x1CC9238
PROCESSOR_METHOD_RVA = 0x8F9D20
PROCESSOR_GLOBAL_FLAG_RVA = 0x233FF0C
PROCESSOR_OVERRIDE_FLAG_RVA = 0x233FEB6


def _qualified_processor(trace, module, country, manager, component):
    """Support the proven global bypass; other TLS paths remain unknown."""
    inputs = component['raw_inputs']
    try:
        processor = int(inputs['processor_pointer'], 0)
        cell = int(inputs['processor_cell_address'], 0)
        vtable = trace.u64(_quality._add(processor, 0, 8), 'diplomats_total.processor.vtable')
        if vtable != module + PROCESSOR_VTABLE_RVA:
            return component
        method = trace.u64(_quality._add(vtable, 8, 8), 'diplomats_total.processor.method')
        if method != module + PROCESSOR_METHOD_RVA:
            return component
        flags = {
            'specific': trace.u8(_quality._add(module, PROCESSOR_GLOBAL_FLAG_RVA, 1),
                                 'diplomats_total.processor.specific_flag'),
            'override': trace.u8(_quality._add(module, PROCESSOR_OVERRIDE_FLAG_RVA, 1),
                                 'diplomats_total.processor.override_flag'),
        }
        inputs['typed_processor'] = {'vtable_rva': hex(PROCESSOR_VTABLE_RVA),
            'method_rva': hex(PROCESSOR_METHOD_RVA), 'flags': flags,
            'thread_state_read': False, 'native_called': False}
        if not (flags['specific'] != 0 and flags['override'] == 0):
            return _quality._empty_component('DIPLOMATS_TOTAL_THREAD_CONTEXT_UNAVAILABLE', inputs)
        value = read_raw_modifier(trace, country, MODIFIER_ID, UNIT,
                                  name='diplomats_total', forbidden_pointers=(manager, cell, processor))
        inputs['raw_storage'] = value
        if value.get('status') != 'known':
            return _quality._empty_component(value.get('reason', 'DIPLOMATS_TOTAL_STORAGE_UNKNOWN'), inputs)
        # Recheck the exact slot/vtable/method and globals after reading storage.
        stable = (
            trace.u64(cell, 'diplomats_total.processor.cell_after') == processor
            and trace.u64(processor, 'diplomats_total.processor.vtable_after') == vtable
            and trace.u64(vtable + 8, 'diplomats_total.processor.method_after') == method
            and trace.u8(module + PROCESSOR_GLOBAL_FLAG_RVA, 'diplomats_total.processor.specific_after') == flags['specific']
            and trace.u8(module + PROCESSOR_OVERRIDE_FLAG_RVA, 'diplomats_total.processor.override_after') == flags['override'])
        if not stable:
            return _quality._empty_component('DIPLOMATS_TOTAL_PROCESSOR_CHANGED', inputs)
        inputs['typed_processor']['branch'] = 'global_bypass_returns_input_unchanged'
        return _quality._known_component(value['raw'], value['raw'], UNIT, SCALE, inputs)
    except Exception:
        return component


def read_fields(reader, base, target_binding, fields=FIELDS, *, observer='FRA', **_unused):
    result = {}
    if not isinstance(fields, (tuple, list)) or len(fields) > 16:
        return {FIELD: {'status': 'unknown', 'reason': 'FIELD_REQUEST_INVALID'}}
    for field in fields:
        if not isinstance(field, str):
            return {FIELD: {'status': 'unknown', 'reason': 'FIELD_REQUEST_INVALID'}}
        if field != FIELD:
            result[field] = {'status': 'unknown', 'reason': 'FIELD_NOT_SUPPORTED'}
    if FIELD not in fields:
        return result
    trace = _quality._TraceReader(reader)
    raw = {'modifier_id': MODIFIER_ID, 'reads': [], 'budget': trace.budget()}
    status, reason, value = 'unknown', 'DIPLOMATS_TOTAL_INPUT_UNKNOWN', None
    try:
        module, country, retained = _binding._parse_target(base, target_binding)
        if retained.get('tag') != observer:
            raise ValueError('TARGET_COUNTRY_SCOPE')
        limiter = _binding._shared._BoundedReader(trace)
        raw['target_binding_revalidation'] = _binding._validate_target_binding(limiter, module, country, retained)
        raw['target_binding'] = deepcopy(retained)
        state = trace.i32(_quality._add(country, _quality.COUNTRY_CACHE_STATE_OFFSET, 4),
                          'diplomats_total.cache_state_i32')
        raw['cache_state'] = state
        if state == 1:
            reason = 'MILITARY_CACHE_CALCULATING'
        else:
            manager, manager_inputs, error = _shared_cache._manager_record(trace, module)
            raw['modifier_processor_manager'] = manager_inputs
            if error or manager is None:
                reason = 'DIPLOMATS_TOTAL_MANAGER_UNAVAILABLE'
            else:
                component = _quality._read_modifier(trace, country, manager, state,
                                                     'diplomats_total', MODIFIER_ID, UNIT)
                if component.get('reason') == 'MODIFIER_PROCESSOR_PRESENT':
                    component = _qualified_processor(trace, module, country, manager, component)
                raw['modifier_component'] = component
                if component.get('status') == 'known' and type(component.get('raw')) is int:
                    status, reason, value = 'known', None, component['raw']
                elif component.get('reason') in ('MODIFIER_PROCESSOR_PRESENT', 'MILITARY_CACHE_CALCULATING',
                        'DIPLOMATS_TOTAL_THREAD_CONTEXT_UNAVAILABLE', 'DIPLOMATS_TOTAL_PROCESSOR_CHANGED'):
                    reason = component['reason']
    except Exception as error:
        raw['failure'] = str(getattr(error, 'reason', None) or error)[:160]
        if raw['failure'] == 'TARGET_COUNTRY_SCOPE':
            reason = 'TARGET_COUNTRY_SCOPE'
        elif 'BINDING' in raw['failure'].upper() or 'TARGET' in raw['failure'].upper():
            reason = 'TARGET_BINDING_UNVERIFIED'
    raw.update(reads=deepcopy(trace.reads), budget=trace.budget())
    if trace.budget_failed:
        status, reason = 'unknown', 'DIPLOMATS_TOTAL_READ_BUDGET_EXCEEDED'
    field = {'status': status, 'raw_inputs': raw}
    if status == 'known':
        field.update(value=value, raw=value, raw_hex=value.to_bytes(4, 'little', signed=True).hex(),
                     unit=UNIT, scale=SCALE, period='current', partial=True, complete=False,
                     basis=BASIS, value_origin=VALUE_ORIGIN)
    else:
        field['reason'] = reason
    result[FIELD] = field
    return result
