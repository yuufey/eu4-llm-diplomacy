"""Expose a validated current province trade-power cache annotation internally.

This reader reuses the session owner and province admission and discovery checks,
and strict capture replay. It never invokes a game function and does not infer
an acquisition delta, UI rendering, or cache refresh time.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from importlib import import_module
import hashlib
import re
from typing import Any

from .model import canonical
from .province_trade_power_memory import FIELD_PROVINCE_TRADE_POWER
from .province_trade_value_memory import FIELD as _VALUE_CALCULATION_FIELD
from .trade_income import (
    NativeTradeIncomeSource,
    _observer_context_reason as _base_context_reason,
    _identity,
    _session_binding,
)


SCHEMA = "information.province_trade_power_annotation.v1"
BASIS = "native_province_trade_power_trigger_cache"
_CAPTURE_SCHEMA = "information.province_trade_power_capture.v1"
_INNER_SCHEMA = "information.province_trade_power_observer_snapshot.v1"
_MAX_PROVINCE_ID = 0xFFFF
_INT32_MIN = -(1 << 31)
_INT32_MAX = (1 << 31) - 1
_REASON = re.compile(r"[A-Z0-9_:-]{1,128}\Z")
_PASS_PHASES = ("pass1", "pass2")
_NUMERIC_FIELDS = {
    "G02.province_trade_power_value": "trade_power",
    "G02.province_trade_power_modifier": "ratio",
    "G02.province_trade_power_further_modifier": "ratio",
}
_NUMERIC_BASIS = "native_province_numeric_modifier_processor_absent"
_COUNTRY_FIELDS = {
    'G02.controller_global_province_trade_power_modifier': 'controller',
    'G02.observer_global_province_trade_power_modifier': 'observer',
}
_COUNTRY_BASIS = 'native_country_province_trade_power_modifier_processor_absent'
_GATES_FIELD = 'G02.province_trade_power_calculation_gates'
_CALCULATION_BASIS = 'native_province_trade_power_cache_writer_reconstruction'
_ALLOCATION_FIELD = 'G02.province_node_allocation'
_ALLOCATION_BASIS = 'native_trade_node_province_component_reconstruction'
_VALUE_CALCULATION_BASIS = 'native_province_trade_value_processor_absent'
_VALUE_INPUT_KEYS = {
    'province_goods_base_raw', 'owner_goods_base_raw',
    'province_goods_modifier_raw', 'owner_goods_modifier_raw', 'goods_price_raw',
    'province_value_add_raw', 'province_value_modifier_raw',
}
_VALUE_CALCULATION_KEYS = {
    'goods_base_raw', 'combined_goods_modifier_raw', 'goods_factor_raw', 'goods_raw',
    'priced_raw', 'subtotal_raw', 'value_factor_raw', 'value_raw',
}
_VALUE_PUBLIC_KEYS = (
    'province_id', 'owner', 'resource', 'inputs', 'calculation', 'scale', 'unit',
    'extra_arguments_zero', 'description_absent', 'current_only',
    'individual_monthly_contribution_claimed',
)


def _public_reason(value: Any, fallback: str) -> str:
    """Return only a fixed-looking reason token, never raw reader details."""
    if (isinstance(value, str) and _REASON.fullmatch(value)
            and "0x" not in value.lower()):
        return value
    return fallback


def _positive_admission(value: Any, observer: str) -> bool:
    if not isinstance(value, Mapping):
        return False
    role = value.get("observer_nonplayer_role")
    return (
        value.get("status") == "known"
        and type(value.get("admitted")) is bool
        and value["admitted"] is True
        and isinstance(role, Mapping)
        and role.get("observer") == observer
    )


def _positive_discovery(value: Any) -> bool:
    return (
        isinstance(value, Mapping)
        and value.get("status") == "known"
        and type(value.get("value")) is bool
        and value["value"] is True
    )


def _access_valid(inner: Mapping[str, Any]) -> bool:
    access = inner.get("access")
    rows = inner.get("raw_reads")
    if not isinstance(access, Mapping) or not isinstance(rows, list):
        return False
    expected = {
        "read_only": True,
        "native_function_invoked": False,
        "writes": False,
        "UI_control": False,
        "date_advance": False,
        "save_or_reload": False,
    }
    if any(access.get(key) is not value for key, value in expected.items()):
        return False
    limit = access.get("limit_bytes")
    calls = access.get("calls")
    requested = access.get("bytes_requested")
    sizes = [row.get("size") for row in rows if isinstance(row, Mapping)]
    if (type(limit) is not int or not 0 < limit <= 16 * 1024 * 1024
            or type(calls) is not int or calls != len(rows)
            or type(requested) is not int or not 0 < requested <= limit
            or len(sizes) != len(rows)
            or any(type(size) is not int or not 0 < size <= 65536 for size in sizes)):
        return False
    return requested == sum(sizes)


def _capture_target(
    report: Any,
    context: Mapping[str, Any],
    creation: int,
    province_id: int,
    *, numeric_inputs: bool = False, country_inputs: bool = False, calculation: bool = False,
    node_allocation: bool = False, value_calculation: bool = False, node_cash: bool = False,
) -> tuple[dict[str, Any] | None, str | None]:
    """Extract one target only after the module-level strict replay succeeded."""
    if not isinstance(report, Mapping) or set(report) != {"schema", "observer", "object", "capture"}:
        return None, "PROVINCE_TRADE_POWER_CAPTURE_ENVELOPE_INVALID"
    observer = context.get("observer")
    if report.get("schema") != _CAPTURE_SCHEMA or report.get("observer") != observer:
        return None, "PROVINCE_TRADE_POWER_CAPTURE_IDENTITY_INVALID"
    outer = report.get("object")
    if (not isinstance(outer, Mapping) or set(outer) != {"type", "province_id"}
            or outer.get("type") != "province"
            or type(outer.get("province_id")) is not int
            or outer.get("province_id") != province_id):
        return None, "PROVINCE_TRADE_POWER_CAPTURE_PROVINCE_MISMATCH"

    inner = report.get("capture")
    if (not isinstance(inner, Mapping) or inner.get("schema") != _INNER_SCHEMA
            or inner.get("status") != "observed" or inner.get("completed") is not True
            or not _access_valid(inner)):
        return None, "PROVINCE_TRADE_POWER_CAPTURE_UNVERIFIED"
    cleanup = inner.get("cleanup")
    if (not isinstance(cleanup, Mapping) or cleanup.get("status") != "closed"
            or cleanup.get("closed") is not True or cleanup.get("success") is not True):
        return None, "PROVINCE_TRADE_POWER_CAPTURE_CLEANUP_UNVERIFIED"

    request = inner.get("request")
    if (not isinstance(request, Mapping) or request.get("country") != observer
            or request.get("observer") != observer
            or request.get("session_id") != context.get("session_id")
            or type(request.get("creation_filetime")) is not int
            or request["creation_filetime"] != creation):
        return None, "PROVINCE_TRADE_POWER_CAPTURE_SESSION_MISMATCH"

    observation = inner.get("observation")
    if not isinstance(observation, Mapping) or observation.get("stable") is not True:
        return None, "PROVINCE_TRADE_POWER_CAPTURE_UNSTABLE"
    date = context.get("game_date")
    before = observation.get("context_before")
    after = observation.get("context_after")
    if (not isinstance(before, Mapping) or not isinstance(after, Mapping)
            or type(date) is not int or type(before.get("game_date")) is not int
            or type(after.get("game_date")) is not int
            or before.get("game_date") != date or after.get("game_date") != date):
        return None, "PROVINCE_TRADE_POWER_CAPTURE_DATE_MISMATCH"

    backend = observation.get("backend")
    consistency = backend.get("consistency") if isinstance(backend, Mapping) else None
    backend_observer = backend.get("observer") if isinstance(backend, Mapping) else None
    if (not isinstance(backend, Mapping) or backend.get("status") != "observed"
            or not isinstance(consistency, Mapping) or consistency.get("status") != "stable"):
        return None, "PROVINCE_TRADE_POWER_BACKEND_UNSTABLE"
    if not isinstance(backend_observer, Mapping) or backend_observer.get("tag") != observer:
        return None, "PROVINCE_TRADE_POWER_BACKEND_OBSERVER_MISMATCH"
    targets = backend.get("targets")
    if not isinstance(targets, list) or len(targets) != 1 or not isinstance(targets[0], Mapping):
        return None, "PROVINCE_TRADE_POWER_TARGET_INVALID"
    target = targets[0]
    if type(target.get("province_id")) is not int or target.get("province_id") != province_id:
        return None, "PROVINCE_TRADE_POWER_TARGET_PROVINCE_MISMATCH"

    admissions = target.get("admission_by_pass")
    discoveries = target.get("discovery_by_pass")
    if (not isinstance(admissions, Mapping) or not isinstance(discoveries, Mapping)
            or any(not _positive_admission(admissions.get(phase), observer) for phase in _PASS_PHASES)
            or any(not _positive_discovery(discoveries.get(phase)) for phase in _PASS_PHASES)):
        return None, "PROVINCE_TRADE_POWER_ADMISSION_OR_DISCOVERY_UNVERIFIED"

    field_consistency = target.get("field_consistency")
    expected_fields = {FIELD_PROVINCE_TRADE_POWER} | (set(_NUMERIC_FIELDS) if numeric_inputs else set())
    if country_inputs:
        expected_fields.update(_COUNTRY_FIELDS)
    if calculation:
        expected_fields.add(_GATES_FIELD)
    if node_allocation:
        expected_fields.add(_ALLOCATION_FIELD)
    if value_calculation:
        expected_fields.add(_VALUE_CALCULATION_FIELD)
    if node_cash:
        expected_fields.add('G02.node_cash_aggregate')
    if not isinstance(field_consistency, Mapping) or set(field_consistency) != expected_fields:
        return None, "PROVINCE_TRADE_POWER_FIELD_CONSISTENCY_MISSING"
    field_state = field_consistency[FIELD_PROVINCE_TRADE_POWER]
    if (not isinstance(field_state, Mapping)
            or field_state.get("status") not in ("stable", "unknown", "changed")):
        return None, "PROVINCE_TRADE_POWER_FIELD_CONSISTENCY_INVALID"
    if field_state.get("status") == "changed":
        return None, "PROVINCE_TRADE_POWER_FIELD_CHANGED_BETWEEN_PASSES"
    fields = target.get("fields")
    if not isinstance(fields, Mapping) or set(fields) != expected_fields:
        return None, "PROVINCE_TRADE_POWER_FIELD_MISSING"
    return dict(target), None


def _project_value(target: Mapping[str, Any]) -> tuple[str, str | None, dict[str, Any] | None]:
    fields = target.get("fields")
    raw = fields.get(FIELD_PROVINCE_TRADE_POWER) if isinstance(fields, Mapping) else None
    if not isinstance(raw, Mapping):
        return "unknown", "PROVINCE_TRADE_POWER_FIELD_MISSING", None
    if raw.get("status") != "known":
        return "unknown", "PROVINCE_TRADE_POWER_VALUE_UNKNOWN", None
    consistency = target.get("field_consistency")
    field_state = consistency.get(FIELD_PROVINCE_TRADE_POWER) if isinstance(consistency, Mapping) else None
    if not isinstance(field_state, Mapping) or field_state.get("status") != "stable":
        return "unknown", "PROVINCE_TRADE_POWER_FIELD_NOT_STABLE", None
    value = raw.get("value")
    if (raw.get("complete") is not False or raw.get("period") != "current"
            or raw.get("basis") != BASIS or not isinstance(value, Mapping)
            or set(value) != {"raw", "scale", "unit"}
            or type(value.get("raw")) is not int
            or not _INT32_MIN <= value["raw"] <= _INT32_MAX
            or type(value.get("scale")) is not int or value["scale"] != 1000
            or value.get("unit") != "trade_power"):
        return "unknown", "PROVINCE_TRADE_POWER_FIELD_INVALID", None
    return "known", None, {
        "raw": value["raw"],
        "scale": 1000,
        "unit": "trade_power",
    }


def _project_numeric_modifiers(target):
    """Project only typed values; private pointer/trace details stay in capture."""
    result = {}
    for field, unit in _NUMERIC_FIELDS.items():
        item = {'status': 'unknown', 'reason': 'PROVINCE_TRADE_POWER_NUMERIC_INPUT_UNKNOWN',
            'basis': _NUMERIC_BASIS, 'period': 'current', 'partial': True, 'complete': False}
        raw = target['fields'].get(field)
        consistency = target['field_consistency'].get(field)
        if isinstance(raw, Mapping) and isinstance(consistency, Mapping):
            value = raw.get('value')
            if (raw.get('status') == 'known' and raw.get('complete') is False
                    and raw.get('basis') == _NUMERIC_BASIS and raw.get('period') == 'current'
                    and consistency.get('status') == 'stable' and isinstance(value, Mapping)
                    and set(value) == {'raw', 'scale', 'unit'}
                    and type(value.get('raw')) is int and _INT32_MIN <= value['raw'] <= _INT32_MAX
                    and type(value.get('scale')) is int and value['scale'] == 1000
                    and value.get('unit') == unit):
                item.pop('reason')
                item.update(status='known', value=deepcopy(dict(value)))
        result[field.removeprefix('G02.')] = item
    return result


def _project_country_modifiers(target, observer):
    result = {}
    for field, role in _COUNTRY_FIELDS.items():
        item = {'status': 'unknown', 'reason': 'PROVINCE_TRADE_POWER_COUNTRY_INPUT_UNKNOWN',
                'basis': _COUNTRY_BASIS, 'period': 'current', 'partial': True, 'complete': False}
        raw = target['fields'].get(field)
        consistency = target['field_consistency'].get(field)
        if isinstance(raw, Mapping) and isinstance(consistency, Mapping):
            value = raw.get('value')
            if (raw.get('status') == 'known' and raw.get('complete') is False
                    and raw.get('basis') == _COUNTRY_BASIS and raw.get('period') == 'current'
                    and consistency.get('status') == 'stable' and isinstance(value, Mapping)
                    and set(value) == {'country', 'raw', 'scale', 'unit'}
                    and isinstance(value.get('country'), str)
                    and re.fullmatch(r'[A-Z0-9]{3}', value['country'])
                    and (role != 'observer' or value['country'] == observer)
                    and type(value.get('raw')) is int and _INT32_MIN <= value['raw'] <= _INT32_MAX
                    and type(value.get('scale')) is int and value['scale'] == 1000
                    and value.get('unit') == 'ratio'):
                item.pop('reason')
                item.update(status='known', value=deepcopy(dict(value)))
        result[role] = item
    return result


def _project_calculation(target, cache_value, observer):
    result = {'status': 'unknown', 'reason': 'PROVINCE_TRADE_POWER_CALCULATION_INPUT_UNKNOWN',
              'basis': _CALCULATION_BASIS, 'period': 'current', 'partial': True, 'complete': False,
              'argument_mode': 'cache_writer_zero_additional_inputs',
              'native_function_invoked': False, 'acquisition_delta_evaluated': False}
    item = target['fields'].get(_GATES_FIELD)
    state = target['field_consistency'].get(_GATES_FIELD)
    if (not isinstance(item, Mapping) or item.get('status') != 'known'
            or item.get('basis') != 'native_province_trade_power_cache_writer_gates'
            or item.get('period') != 'current' or item.get('complete') is not False
            or not isinstance(state, Mapping) or state.get('status') != 'stable'):
        return result
    gates = item.get('value')
    if not isinstance(gates, Mapping) or set(gates) != {
            'province_node_enabled', 'controller_type_enabled', 'owner_bonus_active', 'owner_bonus_raw'}:
        return result
    node, country, active, bonus = (gates[k] for k in (
        'province_node_enabled', 'controller_type_enabled', 'owner_bonus_active', 'owner_bonus_raw'))
    if type(node) is not bool:
        return result
    if node is False:
        if any(v is not None for v in (country, active, bonus)):
            return result
        value = 0
    elif type(country) is not bool:
        return result
    elif country is False:
        if active is not None or bonus is not None:
            return result
        value = 0
    else:
        if (type(active) is not bool or type(bonus) is not int
                or not _INT32_MIN <= bonus <= _INT32_MAX or (not active and bonus != 0)):
            return result
        numeric = _project_numeric_modifiers(target)
        controller = _project_country_modifiers(target, observer)['controller']
        if controller['status'] != 'known' or any(v['status'] != 'known' for v in numeric.values()):
            return result
        from .province_trade_power_calculation import calculate_current
        parts = calculate_current(numeric['province_trade_power_value']['value']['raw'],
            numeric['province_trade_power_modifier']['value']['raw'], controller['value']['raw'],
            numeric['province_trade_power_further_modifier']['value']['raw'], bonus)
        value = parts['raw']
    result.pop('reason')
    result.update(status='known', value={'raw': value, 'scale': 1000, 'unit': 'trade_power'},
                  matches_cache=value == cache_value['raw'])
    return result


def _project_node_allocation(target, cache_value, observer):
    result = {'status': 'unknown', 'reason': 'PROVINCE_NODE_ALLOCATION_INPUT_UNKNOWN',
        'basis': _ALLOCATION_BASIS, 'period': 'current', 'partial': True, 'complete': False,
        'component': 'TP_PROVINCE_POWER', 'cache_refresh_timing_verified': False,
        'atomic_game_snapshot': False, 'acquisition_delta_evaluated': False}
    item = target['fields'].get(_ALLOCATION_FIELD)
    state = target['field_consistency'].get(_ALLOCATION_FIELD)
    if (not isinstance(item, Mapping) or item.get('status') != 'known'
            or item.get('complete') is not False or item.get('basis') != _ALLOCATION_BASIS
            or item.get('period') != 'current' or not isinstance(state, Mapping)
            or state.get('status') != 'stable'):
        return result
    value = item.get('value')
    expected = {'node_id', 'center_province_id', 'province_id', 'recipient_country', 'contribution_raw',
        'observer_country', 'observer_contribution_raw', 'observer_node_province_power_cache_raw',
        'observed_observer_province_power_sum_raw', 'observer_sum_complete', 'matches_observer_cache',
        'member_count', 'observed_member_count', 'owner_present', 'scale', 'unit'}
    if not isinstance(value, Mapping) or set(value) != expected:
        return result
    if (not isinstance(value['node_id'], str) or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', value['node_id']) is None
            or type(value['province_id']) is not int or value['province_id'] != target['province_id']
            or type(value['center_province_id']) is not int or not 1 <= value['center_province_id'] <= _MAX_PROVINCE_ID
            or not isinstance(value['recipient_country'], str) or re.fullmatch(r'[A-Z0-9]{3}', value['recipient_country']) is None
            or value['observer_country'] != observer
            or type(value['member_count']) is not int or not 1 <= value['member_count'] <= 512
            or type(value['observed_member_count']) is not int or not 1 <= value['observed_member_count'] <= value['member_count']
            or type(value['owner_present']) is not bool or type(value['observer_sum_complete']) is not bool
            or type(value['scale']) is not int or value['scale'] != 1000 or value['unit'] != 'trade_power'):
        return result
    for key in ('contribution_raw', 'observer_contribution_raw', 'observer_node_province_power_cache_raw',
                'observed_observer_province_power_sum_raw'):
        if type(value[key]) is not int or not _INT32_MIN <= value[key] <= _INT32_MAX:
            return result
    if value['contribution_raw'] != (cache_value['raw'] if value['owner_present'] else 0):
        return result
    if value['observer_contribution_raw'] != (value['contribution_raw'] if value['recipient_country'] == observer else 0):
        return result
    if value['observer_sum_complete']:
        if (value['observed_member_count'] != value['member_count']
                or type(value['matches_observer_cache']) is not bool
                or value['matches_observer_cache'] != (value['observed_observer_province_power_sum_raw'] == value['observer_node_province_power_cache_raw'])):
            return result
    elif value['matches_observer_cache'] is not None:
        return result
    result.pop('reason')
    result.update(status='known', value=deepcopy(dict(value)))
    return result


def _unknown_value_calculation(reason='PROVINCE_TRADE_VALUE_CALCULATION_INPUT_UNKNOWN'):
    return {
        'status': 'unknown',
        'reason': reason,
        'basis': _VALUE_CALCULATION_BASIS,
        'period': 'current',
        'partial': True,
        'complete': False,
        'native_function_invoked': False,
    }


def _validate_value_calculation_annotation(item, province_id):
    """Return a safe typed annotation, or a local unknown without private data."""
    if not isinstance(item, Mapping):
        return _unknown_value_calculation('PROVINCE_TRADE_VALUE_CALCULATION_INVALID')
    common = {'status', 'basis', 'period', 'partial', 'complete', 'native_function_invoked'}
    if (item.get('basis') != _VALUE_CALCULATION_BASIS or item.get('period') != 'current'
            or item.get('partial') is not True or item.get('complete') is not False
            or item.get('native_function_invoked') is not False):
        return _unknown_value_calculation('PROVINCE_TRADE_VALUE_CALCULATION_INVALID')
    if item.get('status') == 'unknown':
        if set(item) != common | {'reason'}:
            return _unknown_value_calculation('PROVINCE_TRADE_VALUE_CALCULATION_INVALID')
        return _unknown_value_calculation(
            _public_reason(item.get('reason'), 'PROVINCE_TRADE_VALUE_CALCULATION_INPUT_UNKNOWN'))
    if item.get('status') != 'known' or set(item) != common | {'value'}:
        return _unknown_value_calculation('PROVINCE_TRADE_VALUE_CALCULATION_INVALID')
    value = item.get('value')
    if not isinstance(value, Mapping) or set(value) != set(_VALUE_PUBLIC_KEYS):
        return _unknown_value_calculation('PROVINCE_TRADE_VALUE_CALCULATION_INVALID')
    if (type(value.get('province_id')) is not int or value['province_id'] != province_id
            or not isinstance(value.get('owner'), str)
            or re.fullmatch(r'[A-Z0-9]{3}', value['owner']) is None
            or type(value.get('scale')) is not int or value['scale'] != 1000
            or value.get('unit') != 'native_trade_value_input'
            or type(value.get('extra_arguments_zero')) is not bool
            or value['extra_arguments_zero'] is not True
            or type(value.get('description_absent')) is not bool
            or value['description_absent'] is not True
            or type(value.get('current_only')) is not bool or value['current_only'] is not True
            or type(value.get('individual_monthly_contribution_claimed')) is not bool
            or value['individual_monthly_contribution_claimed'] is not False):
        return _unknown_value_calculation('PROVINCE_TRADE_VALUE_CALCULATION_INVALID')
    resource = value.get('resource')
    if (not isinstance(resource, Mapping) or set(resource) != {'localization_key', 'icon_index'}
            or not isinstance(resource.get('localization_key'), str)
            or re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', resource['localization_key']) is None
            or type(resource.get('icon_index')) is not int
            or not 0 <= resource['icon_index'] < 1024):
        return _unknown_value_calculation('PROVINCE_TRADE_VALUE_CALCULATION_INVALID')
    for name, keys in (('inputs', _VALUE_INPUT_KEYS), ('calculation', _VALUE_CALCULATION_KEYS)):
        values = value.get(name)
        if (not isinstance(values, Mapping) or set(values) != keys
                or any(type(number) is not int or not _INT32_MIN <= number <= _INT32_MAX
                       for number in values.values())):
            return _unknown_value_calculation('PROVINCE_TRADE_VALUE_CALCULATION_INVALID')
    return {
        'status': 'known',
        'basis': _VALUE_CALCULATION_BASIS,
        'period': 'current',
        'partial': True,
        'complete': False,
        'native_function_invoked': False,
        'value': {key: deepcopy(value[key]) for key in _VALUE_PUBLIC_KEYS},
    }


def _project_value_calculation(target, province_id):
    fields = target.get('fields')
    consistency = target.get('field_consistency')
    raw = fields.get(_VALUE_CALCULATION_FIELD) if isinstance(fields, Mapping) else None
    state = consistency.get(_VALUE_CALCULATION_FIELD) if isinstance(consistency, Mapping) else None
    if not isinstance(raw, Mapping) or not isinstance(state, Mapping):
        return _unknown_value_calculation('PROVINCE_TRADE_VALUE_CALCULATION_FIELD_MISSING')
    if raw.get('status') == 'unknown' and 'value' not in raw:
        return _unknown_value_calculation()
    if (raw.get('status') != 'known' or set(raw) != {
            'status', 'basis', 'period', 'complete', 'value', 'raw_inputs'}
            or raw.get('basis') != _VALUE_CALCULATION_BASIS
            or raw.get('period') != 'current' or raw.get('complete') is not False
            or not isinstance(raw.get('raw_inputs'), Mapping)
            or state.get('status') != 'stable'):
        return _unknown_value_calculation('PROVINCE_TRADE_VALUE_CALCULATION_INVALID')
    candidate = {
        'status': 'known',
        'basis': _VALUE_CALCULATION_BASIS,
        'period': 'current',
        'partial': True,
        'complete': False,
        'native_function_invoked': False,
        'value': raw.get('value'),
    }
    return _validate_value_calculation_annotation(candidate, province_id)


class NativeProvinceTradePowerReader(NativeTradeIncomeSource):
    """Read validated trade power from a province discovered by the observer."""

    event_types: tuple[str, ...] = ()

    def __init__(self, base_source: Any, capture=None, *, with_numeric_inputs=False,
                 with_country_inputs=False, with_calculation=False, with_node_allocation=False,
                 with_value_calculation=False, with_node_cash=False):
        if type(with_numeric_inputs) is not bool:
            raise ValueError('PROVINCE_TRADE_POWER_NUMERIC_INPUT_OPTION_INVALID')
        if type(with_country_inputs) is not bool or (with_country_inputs and not with_numeric_inputs):
            raise ValueError('PROVINCE_TRADE_POWER_COUNTRY_INPUT_OPTION_INVALID')
        if type(with_calculation) is not bool or (with_calculation and not with_country_inputs):
            raise ValueError('PROVINCE_TRADE_POWER_CALCULATION_OPTION_INVALID')
        if type(with_node_allocation) is not bool or (with_node_allocation and not with_calculation):
            raise ValueError('PROVINCE_NODE_ALLOCATION_OPTION_INVALID')
        if (type(with_value_calculation) is not bool
                or (with_value_calculation and not (with_numeric_inputs and with_country_inputs
                    and with_calculation and with_node_allocation))):
            raise ValueError('PROVINCE_TRADE_VALUE_OPTION_INVALID')
        if type(with_node_cash) is not bool or (with_node_cash and not with_value_calculation):
            raise ValueError('NODE_CASH_OPTION_INVALID')
        super().__init__(base_source, capture=capture)
        self.with_numeric_inputs = with_numeric_inputs
        self.with_country_inputs = with_country_inputs
        self.with_calculation = with_calculation
        self.with_node_allocation = with_node_allocation
        self.with_value_calculation = with_value_calculation
        self.with_node_cash = with_node_cash

    @staticmethod
    def _context_reason(context: Any) -> str | None:
        reason = _base_context_reason(context)
        return reason.replace("TRADE_INCOME_", "PROVINCE_TRADE_POWER_", 1) if reason else None

    @staticmethod
    def _result(
        province_id: int,
        context: Mapping[str, Any],
        status: str,
        reason: str | None,
        provenance: Mapping[str, Any],
        *,
        value: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        source_status = (
            "observed" if provenance.get("capture_report_sha256")
            else "unavailable" if status == "unavailable"
            else "unknown"
        )
        result: dict[str, Any] = {
            "schema": SCHEMA,
            "status": status,
            "province_id": province_id,
            "game_date": context.get("game_date"),
            "period": "current",
            "basis": BASIS,
            "partial": True,
            "complete": False,
            "acquisition_delta_evaluated": False,
            "cache_refresh_timing_verified": False,
            "source": {
                "name": "NativeProvinceTradePowerReader",
                "mode": "live",
                "status": source_status,
                "observer": context.get("observer"),
                "session_id": context.get("session_id")
                    if isinstance(context.get("session_id"), str) else None,
                "provenance": deepcopy(dict(provenance)),
            },
        }
        if reason is not None:
            result["reason"] = reason
        if status == "known" and value is not None:
            result["value"] = deepcopy(dict(value))
        return result

    def _failure(
        self,
        province_id: int,
        context: Mapping[str, Any],
        status: str,
        reason: Any,
        provenance: Mapping[str, Any],
        fallback: str,
    ) -> dict[str, Any]:
        safe_reason = _public_reason(reason, fallback)
        return self._result(province_id, context, status, safe_reason, provenance)

    def read(self, province_id: int, context: dict[str, Any] | None = None) -> dict[str, Any]:
        public_id = province_id if type(province_id) is int else 0
        empty_context: dict[str, Any] = {}
        provenance: dict[str, Any] = {
            "province_id": public_id,
            "read_only": True,
            "native_function_invoked": False,
            "actual_UI_observed": False,
        }
        if type(province_id) is not int or not 1 <= province_id <= _MAX_PROVINCE_ID:
            return self._failure(
                public_id, empty_context, "unknown",
                "PROVINCE_TRADE_POWER_INVALID_PROVINCE_ID", provenance,
                "PROVINCE_TRADE_POWER_INVALID_PROVINCE_ID",
            )

        try:
            if context is None:
                current = self.context()
            elif isinstance(context, dict):
                current = deepcopy(context)
            else:
                return self._failure(
                    province_id, empty_context, "unavailable",
                    "PROVINCE_TRADE_POWER_CONTEXT_INVALID", provenance,
                    "PROVINCE_TRADE_POWER_CONTEXT_INVALID",
                )
        except Exception:
            return self._failure(
                province_id, empty_context, "unavailable",
                "PROVINCE_TRADE_POWER_CONTEXT_UNAVAILABLE", provenance,
                "PROVINCE_TRADE_POWER_CONTEXT_UNAVAILABLE",
            )

        if not isinstance(current, dict):
            return self._failure(
                province_id, empty_context, "unavailable",
                "PROVINCE_TRADE_POWER_CONTEXT_INVALID", provenance,
                "PROVINCE_TRADE_POWER_CONTEXT_INVALID",
            )
        observer = current.get("observer")
        provenance.update({
            "observer": observer,
            "session_id": current.get("session_id")
                if isinstance(current.get("session_id"), str) else None,
        })
        reason = self._context_reason(current)
        if reason:
            return self._failure(
                province_id, current, "unavailable", reason, provenance,
                "PROVINCE_TRADE_POWER_CONTEXT_UNAVAILABLE",
            )

        try:
            before = self.context()
        except Exception:
            before = None
        if not isinstance(before, dict):
            return self._failure(
                province_id, current, "unavailable",
                "PROVINCE_TRADE_POWER_CONTEXT_UNAVAILABLE", provenance,
                "PROVINCE_TRADE_POWER_CONTEXT_UNAVAILABLE",
            )
        reason = self._context_reason(before)
        if reason:
            return self._failure(
                province_id, before, "unavailable", reason, provenance,
                "PROVINCE_TRADE_POWER_CONTEXT_UNAVAILABLE",
            )
        if _identity(current) != _identity(before):
            return self._failure(
                province_id, before, "unavailable",
                "PROVINCE_TRADE_POWER_CONTEXT_STALE", provenance,
                "PROVINCE_TRADE_POWER_CONTEXT_STALE",
            )

        installation, creation, binding_reason = _session_binding(self.base_source)
        if binding_reason or installation is None or creation is None:
            safe_binding_reason = (
                binding_reason.replace("TRADE_INCOME_", "PROVINCE_TRADE_POWER_", 1)
                if isinstance(binding_reason, str) else None
            )
            return self._failure(
                province_id, before, "unavailable", safe_binding_reason, provenance,
                "PROVINCE_TRADE_POWER_SESSION_UNAVAILABLE",
            )

        try:
            module = import_module(".node_cash_aggregate_capture" if self.with_node_cash
                                   else ".province_trade_value_capture" if self.with_value_calculation
                                   else ".province_node_allocation_capture" if self.with_node_allocation
                                   else ".province_trade_power_calculation_capture" if self.with_calculation
                                   else ".province_trade_power_country_capture" if self.with_country_inputs
                                   else ".province_trade_power_inputs_capture" if self.with_numeric_inputs
                                   else ".province_trade_power_capture", __package__)
        except Exception:
            module = None
        validate_capture = getattr(module, "validate_capture", None)
        capture = self.capture if self.capture is not None else getattr(module, "capture", None)
        if not callable(validate_capture) or not callable(capture):
            return self._failure(
                province_id, before, "unavailable",
                "PROVINCE_TRADE_POWER_CAPTURE_UNAVAILABLE", provenance,
                "PROVINCE_TRADE_POWER_CAPTURE_UNAVAILABLE",
            )

        report = None
        capture_failed = False
        try:
            report = capture(installation, province_id=province_id, observer=observer)
        except Exception:
            capture_failed = True

        capture_digest = None
        if report is not None:
            try:
                capture_digest = hashlib.sha256(canonical(report).encode("utf-8")).hexdigest()
            except Exception:
                pass
        if capture_digest is not None:
            provenance["capture_report_sha256"] = capture_digest

        try:
            after = self.context()
        except Exception:
            after = {}
        if (not isinstance(after, dict) or self._context_reason(after)
                or _identity(before) != _identity(after)):
            return self._failure(
                province_id, before, "unavailable",
                "PROVINCE_TRADE_POWER_CONTEXT_CHANGED_DURING_CAPTURE", provenance,
                "PROVINCE_TRADE_POWER_CONTEXT_CHANGED_DURING_CAPTURE",
            )
        final_installation, final_creation, final_reason = _session_binding(self.base_source)
        if (final_reason or final_installation != installation
                or final_creation != creation):
            return self._failure(
                province_id, before, "unavailable",
                "PROVINCE_TRADE_POWER_SESSION_CHANGED_DURING_CAPTURE", provenance,
                "PROVINCE_TRADE_POWER_SESSION_CHANGED_DURING_CAPTURE",
            )
        if capture_failed or report is None:
            return self._failure(
                province_id, before, "unknown", "PROVINCE_TRADE_POWER_CAPTURE_FAILED",
                provenance, "PROVINCE_TRADE_POWER_CAPTURE_FAILED",
            )

        # Strict replay is mandatory; a well-shaped signed integer is not proof.
        try:
            valid = validate_capture(report, before, creation, province_id)
        except Exception:
            valid = False
        if valid is not True:
            return self._failure(
                province_id, before, "unknown", "PROVINCE_TRADE_POWER_CAPTURE_INVALID",
                provenance, "PROVINCE_TRADE_POWER_CAPTURE_INVALID",
            )

        try:
            target, envelope_reason = _capture_target(report, before, creation, province_id,
                                                      numeric_inputs=self.with_numeric_inputs,
                                                      country_inputs=self.with_country_inputs,
                                                      calculation=self.with_calculation,
                                                      node_allocation=self.with_node_allocation,
                                                      value_calculation=self.with_value_calculation,
                                                      node_cash=self.with_node_cash)
        except Exception:
            target, envelope_reason = None, "PROVINCE_TRADE_POWER_CAPTURE_UNVERIFIED"
        if target is None:
            return self._failure(
                province_id, before, "unknown", envelope_reason,
                provenance, "PROVINCE_TRADE_POWER_CAPTURE_UNVERIFIED",
            )

        status, field_reason, value = _project_value(target)
        if status != "known":
            return self._failure(
                province_id, before, "unknown", field_reason,
                provenance, "PROVINCE_TRADE_POWER_FIELD_INVALID",
            )
        result = self._result(province_id, before, "known", None, provenance, value=value)
        if self.with_numeric_inputs:
            result['numeric_modifiers'] = _project_numeric_modifiers(target)
        if self.with_country_inputs:
            result['country_modifiers'] = _project_country_modifiers(target, observer)
        if self.with_calculation:
            result['calculation'] = _project_calculation(target, value, observer)
        if self.with_node_allocation:
            result['node_allocation'] = _project_node_allocation(target, value, observer)
        if self.with_value_calculation:
            result['value_calculation'] = _project_value_calculation(target, province_id)
        if self.with_node_cash:
            from .node_cash_aggregate import project
            result['node_cash_aggregate'] = project(target)
        return result


__all__ = ["BASIS", "FIELD_PROVINCE_TRADE_POWER", "NativeProvinceTradePowerReader", "SCHEMA"]
