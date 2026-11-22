"""Current directional direct-truce expiry, using verified raw calendar inputs."""
from copy import deepcopy
from importlib import import_module
import hashlib
import re

from .catalog import get_topic, validate_query
from .model import InformationError, canonical
from .sources import _result, _source_info
from .trade_income import NativeTradeIncomeSource, _observer_context_reason, _identity as _base_identity, _session_binding
from .truce_date_math import direct_truce_expiry

_FIELD = 'truce_until'
_INPUT = 'R03.truce_until.inputs'
_REASON = re.compile(r'[A-Za-z0-9_:-]{1,128}\Z')


def _identity(context):
    return (*_base_identity(context), context.get('mode'), context.get('status'),
            context.get('dll_sha256'), context.get('physical_client_country'), context.get('world_id'))


class NativeTruceDatesSource(NativeTradeIncomeSource):
    event_types = ()

    def __init__(self, base_source, *, capture_module=None):
        super().__init__(base_source)
        self.capture_module = capture_module

    def catalog(self):
        topic = get_topic('R03')
        topic.update(source=type(self).__name__, status='available', object_types=['country_pair'],
                     observer_roles=['actor', 'recipient'], observer_scope=[],
                     context_scope='visible_scope', visibility='visible_scope',
                     supported_versions=['1.37.4'], triggers=['query', 'periodic'])
        topic['fields'] = {_FIELD: {
            'coverage': 'partial', 'complete': False, 'source': type(self).__name__,
            'unit': 'eu4_hour_tick', 'scale': 1, 'period': 'current',
            'supported_object_types': ['country_pair'], 'direction': 'actor_to_recipient',
            'basis': 'direct_pair_flag_and_native_calendar_expiry_projection',
            'description': '指定方向的直接停战截止日期，观察国须为参与方。',
            'gaps': ['LINKED_COUNTRY_TRUCES_NOT_ENUMERATED', 'ACTUAL_UI_RENDERING_NOT_OBSERVED',
                     'NONATOMIC_SAMPLED_CACHE_INPUTS', 'PRE_REFERENCE_AND_DATE_OVERFLOW_UNSUPPORTED'],
        }}
        return [topic]

    def validate_query(self, query, context=None):
        if context is not None and not isinstance(context, dict):
            raise InformationError('invalid_context', 'Truce context must be an object')
        # The static R03 fallback assumes actor-only observation. This source
        # admits either end of the pair and validates that scope explicitly.
        normalized = validate_query(query)
        if normalized['topic'] != 'R03':
            raise InformationError('unsupported_topic', 'Truce dates support R03 only')
        observer = context.get('observer') if context is not None else None
        obj = normalized['object']
        if (context is not None and obj.get('session_id') is not None
                and context.get('session_id') is not None
                and obj['session_id'] != context['session_id']):
            raise InformationError('context_mismatch', 'The query belongs to another session')
        if obj['type'] == 'country_pair':
            if (obj['actor'] == obj['recipient']
                    or (observer is not None and observer not in (obj['actor'], obj['recipient']))):
                raise InformationError('observer_scope_mismatch', 'A distinct pair involving the observer is required')
        return normalized

    @staticmethod
    def _project(report, obj, target, observer):
        targets = report['observation']['backend']['targets']
        if not isinstance(targets, list) or len(targets) != 1 or targets[0].get('tag') != target:
            raise ValueError('TRUCE_TARGET_INVALID')
        field = targets[0]['fields'][_INPUT]
        if field.get('status') != 'known':
            status, reason = field.get('status'), field.get('reason')
            if (status not in {'unknown', 'unavailable', 'invisible', 'stale', 'not_applicable'}
                    or not isinstance(reason, str) or not _REASON.fullmatch(reason)
                    or re.search(r'0x[0-9a-fA-F]{6,}', reason)):
                return {'status': 'unknown', 'reason': 'TRUCE_INPUTS_UNAVAILABLE'}
            return {'status': status, 'reason': reason}
        values = field['value']
        configurations = values['configuration_inputs']
        if not isinstance(configurations, list) or len(configurations) != 2:
            raise ValueError('TRUCE_CONFIGURATION_INVALID')
        parameters = {}
        for row in configurations:
            rva, value, raw_hex = row['rva'], row['signed_i32'], row['raw_hex']
            if (rva not in ('0x233dc88', '0x233dd8c') or rva in parameters
                    or type(value) is not int or not -(1 << 31) <= value < (1 << 31)
                    or not isinstance(raw_hex, str) or raw_hex != value.to_bytes(4, 'little', signed=True).hex()):
                raise ValueError('TRUCE_CONFIGURATION_INVALID')
            parameters[rva] = value
        records = values['directed_records']
        if not isinstance(records, list) or len(records) != 2:
            raise ValueError('TRUCE_DIRECTIONS_INVALID')
        if {(row.get('actor'), row.get('target')) for row in records} != {(observer, target), (target, observer)}:
            raise ValueError('TRUCE_DIRECTIONS_INVALID')
        selected = next(row for row in records if row['actor'] == obj['actor'] and row['target'] == obj['recipient'])
        flag = selected['direct_flag']
        if type(flag) is not bool:
            raise ValueError('TRUCE_FLAG_INVALID')
        if not flag:
            return {'status': 'not_applicable', 'reason': 'DIRECT_PAIR_TRUCE_FLAG_NOT_SET',
                    'direct_record_flag': False}
        derived = direct_truce_expiry(selected['date_input_signed_i32'], selected['adjustment_signed_i8'],
                                      parameters['0x233dc88'], parameters['0x233dd8c'])
        return {'status': 'known', 'value': derived['raw'], 'raw': derived['raw'],
                'date': derived['date'], 'hour': derived['hour'], 'direct_record_flag': True}

    def read(self, query, context=None):
        query = self.validate_query(query, context)
        before = self.context()
        observer = before.get('observer')
        fields = {name: {'status': 'unsupported', 'reason': 'R03_FIELD_NOT_IMPLEMENTED'}
                  for name in query['fields']}
        provenance = {'read_only': True, 'native_function_invoked': False,
                      'basis': 'direct_pair_flag_and_native_calendar_expiry_projection',
                      'direction': 'actor_to_recipient', 'linked_truces_included': False}
        if _FIELD in fields:
            obj = query['object']
            if obj['type'] != 'country_pair':
                fields[_FIELD] = {'status': 'unsupported', 'reason': 'TRUCE_COUNTRY_ENUMERATION_NOT_IMPLEMENTED'}
            elif (_observer_context_reason(before) or observer not in (obj['actor'], obj['recipient'])
                  or (context is not None and _identity(context) != _identity(before))):
                fields[_FIELD] = {'status': 'unavailable', 'reason': 'TRUCE_CONTEXT_MISMATCH'}
            else:
                try:
                    installation, creation, reason = _session_binding(self.base_source)
                    if reason:
                        raise ValueError('TRUCE_SESSION_UNAVAILABLE')
                    module = self.capture_module or import_module('bridge.information.truce_capture')
                    target = obj['recipient'] if obj['actor'] == observer else obj['actor']
                    report = module.capture(installation, target, observer=observer)
                    if module.validate_capture(report, before, creation, target) is not True:
                        raise ValueError('TRUCE_CAPTURE_INVALID')
                    projected = self._project(report, obj, target, observer)
                    if (_identity(self.context()) != _identity(before)
                            or _session_binding(self.base_source) != (installation, creation, reason)):
                        raise ValueError('TRUCE_CONTEXT_CHANGED')
                    provenance['capture_report_sha256'] = hashlib.sha256(canonical(report).encode()).hexdigest()
                    fields[_FIELD] = projected
                except Exception:
                    fields[_FIELD] = {'status': 'unavailable', 'reason': 'TRUCE_CAPTURE_OR_PROJECTION_FAILED'}
            fields[_FIELD].update(unit='eu4_hour_tick', scale=1, period='current', partial=True, complete=False)
        source = _source_info(type(self).__name__, before, complete=False, provenance=provenance)
        source['context_scope'] = 'visible_scope'
        return _result(query, before, fields, False, source)
