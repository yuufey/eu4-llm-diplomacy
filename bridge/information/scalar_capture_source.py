"""Shared public boundary for one identity-bound signed fixed-point scalar."""
from copy import deepcopy
import hashlib
from importlib import import_module
import re

from .catalog import get_topic, _validate_schema
from .country_state import _parameter_schema
from .model import InformationError, canonical
from .sources import _result, _source_info
from .trade_income import _context_reason, _identity, _session_binding


class ScalarCaptureSource:
    """Subclasses declare a pinned capture; all native access stays in it."""
    event_types = ()

    def __init__(self, base_source, *, capture=None):
        self.base_source, self.capture = base_source, capture

    def context(self):
        return deepcopy(self.base_source.context())

    def catalog(self):
        topic = get_topic(self.TOPIC)
        topic.update(status='available', source=type(self).__name__, observer_roles=['country'],
                     observer_scope=['FRA'], visibility='country_scope', context_scope='country_scope',
                     supported_versions=['1.37.4'], triggers=['query', 'periodic'])
        topic['parameters'] = _parameter_schema(self.TOPIC)
        topic['fields'] = {self.FIELD: {
            'coverage': 'partial', 'complete': False, 'source': self.CAPTURE_MODULE + '.capture',
            'unit': self.UNIT, 'scale': self.SCALE, 'period': 'current', 'basis': self.BASIS,
            'value_origin': self.VALUE_ORIGIN, 'supported_countries': ['FRA'],
            'description': self.DESCRIPTION, 'raw_semantics': 'value == raw; physical quantity = raw / scale',
            'gaps': ['MODIFIER_PROCESSOR_PATH_NOT_IMPLEMENTED', 'CALCULATING_CACHE_PATH_NOT_IMPLEMENTED',
                     'CACHE_FRESHNESS_NOT_PROVEN', 'MAIN_THREAD_ATOMICITY_NOT_PROVEN'],
        }}
        return [topic]

    def validate_query(self, query, context=None):
        if (not isinstance(query, dict) or set(query) - {'topic', 'object', 'fields', 'parameters'}
                or not {'topic', 'object', 'fields'} <= set(query)):
            raise InformationError('invalid_parameters', 'Invalid scalar query')
        if query['topic'] != self.TOPIC:
            raise InformationError('unknown_topic', 'Unsupported scalar topic')
        if query['object'] != {'type': 'country', 'country': 'FRA'}:
            raise InformationError('observer_scope_mismatch', 'This scalar requires the FRA country object')
        if query['fields'] != [self.FIELD]:
            raise InformationError('unknown_field', 'Select the declared scalar field once')
        parameters = query.get('parameters', {})
        _validate_schema(parameters, _parameter_schema(self.TOPIC), 'parameters')
        if parameters.get('reference_recipient') == 'FRA':
            raise InformationError('invalid_parameters', 'reference_recipient must name another country')
        if context is not None and context.get('observer') not in (None, 'FRA'):
            raise InformationError('observer_scope_mismatch', 'Scalar observer is FRA')
        return dict(deepcopy(query), parameters=deepcopy(parameters))

    def _field(self, status, reason=None, value=None):
        result = {'status': status, 'unit': self.UNIT, 'scale': self.SCALE, 'period': 'current',
                  'partial': True, 'complete': False, 'basis': self.BASIS, 'value_origin': self.VALUE_ORIGIN}
        if status == 'known':
            result.update(value=value, raw=value, raw_hex=value.to_bytes(4, 'little', signed=True).hex())
        else:
            result['reason'] = reason
        return result

    def _sanitize(self, item):
        if not isinstance(item, dict):
            raise ValueError('scalar field missing')
        if item.get('status') in ('unknown', 'invisible', 'unavailable'):
            reason = item.get('reason')
            if not isinstance(reason, str) or not re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}', reason):
                raise ValueError('unsafe scalar state')
            return self._field(item['status'], reason)
        value = item.get('value')
        expected = self._field('known', value=value) if type(value) is int and -(1<<31) <= value < (1<<31) else None
        if expected is None or set(item) != set(expected) or any(
                type(item[key]) is not type(expected[key]) or item[key] != expected[key] for key in expected):
            raise ValueError('invalid scalar projection')
        return expected

    def read(self, query, context=None):
        try:
            current = deepcopy(context) if isinstance(context, dict) else self.context()
        except Exception:
            current = {}
        normalized = self.validate_query(query, current)
        provenance = {'read_only': True, 'native_function_invoked': False,
                      'observer': 'FRA', 'context_guard': 'not_read'}
        field = self._field('unknown', 'NATIVE_SCALAR_NOT_READ')

        def result():
            source = _source_info(type(self).__name__, current, complete=False, provenance=deepcopy(provenance))
            source.update(context_scope='country_scope', projection_version=1)
            return _result(normalized, current, {self.FIELD: deepcopy(field)}, False, source)

        try:
            if _context_reason(current, 'FRA') is not None:
                raise ValueError('NATIVE_SCALAR_CONTEXT_UNAVAILABLE')
            before = self.context()
            if _context_reason(before, 'FRA') is not None or _identity(before) != _identity(current):
                raise ValueError('NATIVE_SCALAR_CONTEXT_STALE')
            installation, creation, error = _session_binding(self.base_source)
            if error or installation is None or creation is None:
                raise ValueError('NATIVE_SCALAR_SESSION_UNAVAILABLE')
            module, report, failed = None, None, False
            try:
                module = import_module(self.CAPTURE_MODULE)
                report = (self.capture or module.capture)(installation, observer='FRA')
            except Exception:
                failed = True
            # Context/session are checked after every attempted capture, including failures.
            after = self.context()
            final_installation, final_creation, final_error = _session_binding(self.base_source)
            if (_context_reason(after, 'FRA') is not None or _identity(before) != _identity(after)
                    or final_error or installation != final_installation or creation != final_creation):
                raise ValueError('NATIVE_SCALAR_CONTEXT_CHANGED_DURING_CAPTURE')
            if failed or module is None:
                raise ValueError('NATIVE_SCALAR_CAPTURE_FAILED')
            if module.validate_capture(report, before, creation) is not True:
                raise ValueError('NATIVE_SCALAR_CAPTURE_NOT_VALIDATED')
            projected = module.project_fields(report)
            if not isinstance(projected, dict) or set(projected) != {self.FIELD}:
                raise ValueError('NATIVE_SCALAR_CAPTURE_SHAPE_INVALID')
            field = self._sanitize(projected[self.FIELD])
            if not re.fullmatch(r'[0-9a-f]{64}', module.PROFILE_SHA256):
                raise ValueError('NATIVE_SCALAR_PROFILE_INVALID')
            provenance.update(context_guard='passed', profile_sha256=module.PROFILE_SHA256,
                              capture_report_sha256=hashlib.sha256(canonical(report).encode('utf-8')).hexdigest())
        except Exception as error:
            reason = str(error)
            if not re.fullmatch(r'NATIVE_SCALAR_[A-Z0-9_]+', reason):
                reason = 'NATIVE_SCALAR_CAPTURE_SHAPE_INVALID'
            provenance['context_guard'] = reason
            state = ('stale' if reason in ('NATIVE_SCALAR_CONTEXT_STALE', 'NATIVE_SCALAR_CONTEXT_CHANGED_DURING_CAPTURE')
                     else 'unavailable' if reason in ('NATIVE_SCALAR_CONTEXT_UNAVAILABLE', 'NATIVE_SCALAR_SESSION_UNAVAILABLE')
                     else 'unknown')
            field = self._field(state, reason)
        return result()

    def poll_events(self, context, cursor):
        return {'events': [], 'cursor': deepcopy(cursor or {}), 'complete': True, 'gaps': []}
