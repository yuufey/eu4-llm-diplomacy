"""Current admitted country papacy state with explicit applicability."""
from __future__ import annotations

from copy import deepcopy
import hashlib
from importlib import import_module
import re

from .country_faith import NativeCountryFaithSource
from . import papacy_values as values
from .model import InformationError, canonical
from .sources import _result, _source_info
from .trade_income import NativeTradeIncomeSource, _identity, _session_binding

FIELD = 'papacy'
BACKEND_FIELD = 'S02.papacy'
BASIS = 'bounded_native_country_papacy_state'
ORIGIN = 'copied_native_papacy_state'
GAPS = ['CARDINALS_ELECTION_INVESTMENTS_AND_ANNUAL_INFLUENCE_NOT_READ',
        'ELIGIBILITY_AND_FULL_TOOLTIP_NOT_READ',
        'ACTUAL_UI_RENDERING_NOT_OBSERVED',
        'MAIN_THREAD_ATOMICITY_AND_FRESHNESS_NOT_PROVEN']


class NativePapacySource(NativeTradeIncomeSource):
    event_types: tuple[str, ...] = ()

    def catalog(self):
        topic = deepcopy(NativeCountryFaithSource.catalog(self)[0])
        topic.update(source=type(self).__name__, fields={FIELD: {
            'coverage': 'partial', 'complete': False, 'unit': 'papacy_summary',
            'scale': 1, 'period': 'current', 'basis': BASIS, 'value_origin': ORIGIN,
            'source': 'bridge.information.papacy_capture.capture',
            'triggers': ['query', 'periodic'],
            'runtime_validation': 'papacy_capture.validate_capture',
            'paths': ["observation.backend.targets[0].fields['S02.papacy'].value"],
            'raw_semantics': ('native papacy-definition presence, country papal influence, current controller '
                              'reference and curia treasury; fixed-point components have scale1000; '
                              'invalid controller references remain unknown'),
            'gaps': list(GAPS),
        }})
        topic['scope_note'] = ('读取准入国家的教廷适用性、影响力、控制者与金库；'
                               '按当前观察国的国家视角准入。不适用与未知分别标记。')
        return [topic]

    def validate_query(self, query, context=None):
        if not isinstance(query, dict) or query.get('fields') != [FIELD]:
            raise InformationError('invalid_fields', 'S02.papacy requires its single field')
        projected = deepcopy(query)
        projected['fields'] = ['faith']
        normalized = NativeCountryFaithSource.validate_query(self, projected, context)
        normalized['fields'] = [FIELD]
        return normalized

    @staticmethod
    def _context_reason(context):
        reason = NativeCountryFaithSource._context_reason(context)
        return reason.replace('COUNTRY_FAITH_', 'PAPACY_', 1) if reason else None

    @staticmethod
    def _field(status, reason=None, value=None):
        result = {'status': status, 'period': 'current', 'unit': 'papacy_summary',
                  'scale': 1, 'partial': True, 'complete': False,
                  'basis': BASIS, 'value_origin': ORIGIN}
        if reason is not None:
            result['reason'] = reason
        if status == 'known' and value is not None:
            result['value'] = value
        return result

    @staticmethod
    def _public_value(value, target):
        return values.public_value(value, target)

    def read(self, query, context=None):
        current = deepcopy(context) if isinstance(context, dict) else self.context()
        normalized = self.validate_query(query, current)
        target = normalized['object']['country']
        provenance = {'read_only': True, 'native_function_invoked': False,
                      'observer': current.get('observer'), 'target': target, 'actual_UI_observed': False}

        def result(field, ctx):
            source = _source_info(type(self).__name__, ctx, complete=False,
                                  provenance=deepcopy(provenance))
            source.update(context_scope='visible_scope', projection_version=1)
            return _result(normalized, ctx, {FIELD: field}, False, source)

        def fail(reason, ctx, unavailable=False):
            return result(self._field('unavailable' if unavailable else 'unknown', reason), ctx)

        reason = self._context_reason(current)
        if reason:
            return fail(reason, current, True)
        try:
            before = self.context()
        except Exception:
            return fail('PAPACY_CONTEXT_UNAVAILABLE', current, True)
        if self._context_reason(before) or _identity(current) != _identity(before):
            return fail('PAPACY_CONTEXT_STALE', before, True)
        installation, creation, binding_reason = _session_binding(self.base_source)
        if binding_reason or installation is None or creation is None:
            return fail('PAPACY_SESSION_UNAVAILABLE', before, True)
        report = None
        error = None
        try:
            module = import_module('.papacy_capture', __package__)
            capture = self.capture if self.capture is not None else module.capture
            report = capture(installation, country=target, observer=before['observer'])
        except Exception as exc:
            error = 'PAPACY_CAPTURE_FAILED:' + type(exc).__name__
        try:
            after = self.context()
        except Exception:
            after = {}
        if self._context_reason(after) or _identity(before) != _identity(after):
            return fail('PAPACY_CONTEXT_CHANGED_DURING_CAPTURE', before, True)
        next_installation, next_creation, next_reason = _session_binding(self.base_source)
        if next_reason or next_installation != installation or next_creation != creation:
            return fail('PAPACY_SESSION_CHANGED_DURING_CAPTURE', before, True)
        if error:
            return fail(error, before)
        try:
            if module.validate_capture(report, before, creation, target) is not True:
                raise ValueError('CAPTURE_INVALID')
            provenance['capture_report_sha256'] = hashlib.sha256(canonical(report).encode('utf-8')).hexdigest()
            provenance['profile_sha256'] = module.PROFILE_SHA256
            item = report['observation']['backend']['targets'][0]
            if item.get('tag') != target:
                raise ValueError('TARGET_MISMATCH')
            admission = item['admission_by_pass']['pass2']
            if admission.get('status') != 'known' or type(admission.get('admitted')) is not bool:
                return fail('PAPACY_VIEW_ADMISSION_UNKNOWN', before)
            if not admission['admitted']:
                return result(self._field('invisible', 'PAPACY_NOT_ADMITTED'), before)
            field = item['fields'][BACKEND_FIELD]
            status = field.get('status')
            if status in ('unknown', 'invisible'):
                reason = NativeCountryFaithSource._safe_reason(field.get('reason'), 'PAPACY_BACKEND_UNKNOWN')
                return result(self._field(status, reason), before)
            if status != 'known' or field.get('complete') is not False or field.get('basis') != BASIS:
                raise ValueError('FIELD_SHAPE')
            return result(self._field('known', value=self._public_value(field['value'], target)), before)
        except Exception:
            return fail('PAPACY_CAPTURE_INVALID', before)
