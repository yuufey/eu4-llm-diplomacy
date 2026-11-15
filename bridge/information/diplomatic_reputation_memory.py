"""FRA's native reputation aggregate through the existing bounded cache reader."""
from collections.abc import Mapping
from copy import deepcopy

from . import country_scale_development_memory as _binding
from . import foreign_quality_memory as _quality
from . import relations_capacity_memory as _shared_cache

SCHEMA = 'information.diplomatic_reputation_memory.v1'
FIELD = 'N06.diplomatic_reputation'
FIELDS = (FIELD,)
MODIFIER_ID = 133
UNIT = 'diplomatic_reputation'
SCALE = 1000
BASIS = 'native_diplomatic_reputation_aggregate_cache'
VALUE_ORIGIN = 'copied_native_aggregate_modifier'


def read_fields(reader, base, target_binding, fields=FIELDS, **_unused):
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
    status, reason, value = 'unknown', 'DIPLOMATIC_REPUTATION_INPUT_UNKNOWN', None
    try:
        module, country, retained = _binding._parse_target(base, target_binding)
        if retained.get('tag') != 'FRA':
            raise ValueError('TARGET_COUNTRY_SCOPE')
        limiter = _binding._shared._BoundedReader(trace)
        raw['target_binding_revalidation'] = _binding._validate_target_binding(limiter, module, country, retained)
        raw['target_binding'] = deepcopy(retained)
        state = trace.i32(_quality._add(country, _quality.COUNTRY_CACHE_STATE_OFFSET, 4),
                          'diplomatic_reputation.cache_state_i32')
        raw['cache_state'] = state
        if state == 1:
            reason = 'MILITARY_CACHE_CALCULATING'
        else:
            manager, manager_inputs, error = _shared_cache._manager_record(trace, module)
            raw['modifier_processor_manager'] = manager_inputs
            if error or manager is None:
                reason = 'DIPLOMATIC_REPUTATION_MANAGER_UNAVAILABLE'
            else:
                component = _quality._read_modifier(trace, country, manager, state,
                                                     'diplomatic_reputation', MODIFIER_ID, UNIT)
                raw['modifier_component'] = component
                if component.get('status') == 'known' and type(component.get('raw')) is int:
                    status, reason, value = 'known', None, component['raw']
                elif component.get('reason') in ('MODIFIER_PROCESSOR_PRESENT', 'MILITARY_CACHE_CALCULATING'):
                    reason = component['reason']
    except Exception as error:
        raw['failure'] = str(getattr(error, 'reason', None) or error)[:160]
        if raw['failure'] == 'TARGET_COUNTRY_SCOPE':
            reason = 'TARGET_COUNTRY_SCOPE'
        elif 'BINDING' in raw['failure'].upper() or 'TARGET' in raw['failure'].upper():
            reason = 'TARGET_BINDING_UNVERIFIED'
    raw.update(reads=deepcopy(trace.reads), budget=trace.budget())
    if trace.budget_failed:
        status, reason = 'unknown', 'DIPLOMATIC_REPUTATION_READ_BUDGET_EXCEEDED'
    field = {'status': status, 'raw_inputs': raw}
    if status == 'known':
        field.update(value=value, raw=value, raw_hex=value.to_bytes(4, 'little', signed=True).hex(),
                     unit=UNIT, scale=SCALE, period='current', partial=True, complete=False,
                     basis=BASIS, value_origin=VALUE_ORIGIN)
    else:
        field['reason'] = reason
    result[FIELD] = field
    return result
