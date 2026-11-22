"""Current primary religion's verified defender country for admitted countries."""
from __future__ import annotations

from copy import deepcopy
import hashlib
from importlib import import_module
import re

from .country_faith import NativeCountryFaithSource
from .model import InformationError, canonical
from .sources import _result, _source_info
from .trade_income import NativeTradeIncomeSource, _identity, _session_binding

FIELD = 'defender'
BACKEND_FIELD = 'S02.defender'
BASIS = 'bounded_native_religion_defender_country_reference'
ORIGIN = 'copied_native_religion_state_and_verified_country_reference'
GAPS = ['ABSENT_DEFENDER_SENTINEL_NOT_ESTABLISHED',
        'DEFENDER_ELIGIBILITY_AND_TOOLTIP_NOT_READ',
        'COUNTRY_VIEW_PROJECTION_NOT_ACTUAL_UI_OBSERVATION',
        'MAIN_THREAD_ATOMICITY_AND_CACHE_FRESHNESS_NOT_PROVEN']


class NativeReligionDefenderSource(NativeTradeIncomeSource):
    event_types: tuple[str, ...] = ()

    def catalog(self):
        topic = deepcopy(NativeCountryFaithSource.catalog(self)[0])
        topic.update(source=type(self).__name__, fields={FIELD: {
            'coverage': 'partial', 'complete': False, 'unit': 'country_and_membership',
            'scale': 1, 'period': 'current', 'basis': BASIS, 'value_origin': ORIGIN,
            'source': 'bridge.information.religion_defender_tier_capture.capture',
            'triggers': ['query', 'periodic'],
            'runtime_validation': 'religion_defender_tier_capture.validate_capture',
            'paths': ["observation.backend.targets[0].fields['S02.defender'].value"],
            'raw_semantics': ('current primary religion state holder reference, resolved against '
                              'the country database with exact full-reference equality; invalid '
                              'or unproven absent references remain unknown. Tier uses the current '
                              'world same-faith country count and first matching loaded native interval'),
            'tier_units': {'level': 'native_level', 'same_faith_country_count': 'countries',
                           'range_from': 'countries', 'range_to_exclusive': 'countries_or_unbounded'},
            'gaps': list(GAPS),
        }})
        topic['scope_note'] = ('读取准入国家当前主宗教的守护者国家，并判断该国家是否就是守护者；'
                               '等级来自运行时表，无效引用保持未知。')
        return [topic]

    def validate_query(self, query, context=None):
        if not isinstance(query, dict) or query.get('fields') != [FIELD]:
            raise InformationError('invalid_fields', 'S02.defender requires its single field')
        projected = deepcopy(query)
        projected['fields'] = ['faith']
        normalized = NativeCountryFaithSource.validate_query(self, projected, context)
        normalized['fields'] = [FIELD]
        return normalized

    @staticmethod
    def _context_reason(context):
        reason = NativeCountryFaithSource._context_reason(context)
        return reason.replace('COUNTRY_FAITH_', 'RELIGION_DEFENDER_', 1) if reason else None

    @staticmethod
    def _field(status, reason=None, value=None):
        result = {'status': status, 'period': 'current', 'unit': 'country_and_membership',
                  'scale': 1, 'partial': True, 'complete': False,
                  'basis': BASIS, 'value_origin': ORIGIN}
        if reason is not None:
            result['reason'] = reason
        if status == 'known' and value is not None:
            result['value'] = value
        return result

    @staticmethod
    def _public_value(value, target):
        if not isinstance(value, dict) or set(value) != {'defender_country', 'is_target_defender', 'tier'}:
            raise ValueError('DEFENDER_VALUE_KEYS')
        tag = value['defender_country']
        member = value['is_target_defender']
        if (not isinstance(tag, str) or re.fullmatch(r'[A-Z0-9]{3}', tag) is None
                or type(member) is not bool or member != (tag == target)):
            raise ValueError('DEFENDER_VALUE_INVALID')
        tier = value['tier']
        if not isinstance(tier, dict):
            raise ValueError('DEFENDER_TIER_INVALID')
        if tier.get('status') == 'unknown':
            if tier != {'status': 'unknown', 'reason': 'RELIGION_DEFENDER_TIER_UNAVAILABLE'}:
                raise ValueError('DEFENDER_TIER_UNKNOWN_INVALID')
        elif tier.get('status') == 'known':
            if set(tier) != {'status', 'level', 'same_faith_country_count', 'range_from', 'range_to_exclusive'}:
                raise ValueError('DEFENDER_TIER_KEYS')
            for name in ('level', 'range_from'):
                if type(tier[name]) is not int or not -(1 << 31) <= tier[name] < (1 << 31):
                    raise ValueError('DEFENDER_TIER_INTEGER')
            count, upper = tier['same_faith_country_count'], tier['range_to_exclusive']
            if type(count) is not int or not 0 <= count <= 2048:
                raise ValueError('DEFENDER_TIER_COUNTRY_COUNT')
            if upper is not None and (type(upper) is not int or not -(1 << 31) <= upper < (1 << 31) or upper == 0):
                raise ValueError('DEFENDER_TIER_UPPER')
            if count < tier['range_from'] or (upper is not None and count >= upper):
                raise ValueError('DEFENDER_TIER_INTERVAL')
        else:
            raise ValueError('DEFENDER_TIER_STATUS')
        return {'defender_country': tag, 'is_target_defender': member, 'tier': deepcopy(tier)}

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
            return fail('RELIGION_DEFENDER_CONTEXT_UNAVAILABLE', current, True)
        if self._context_reason(before) or _identity(current) != _identity(before):
            return fail('RELIGION_DEFENDER_CONTEXT_STALE', before, True)
        installation, creation, binding_reason = _session_binding(self.base_source)
        if binding_reason or installation is None or creation is None:
            return fail('RELIGION_DEFENDER_SESSION_UNAVAILABLE', before, True)
        report = None
        error = None
        try:
            module = import_module('.religion_defender_tier_capture', __package__)
            capture = self.capture if self.capture is not None else module.capture
            report = capture(installation, country=target, observer=before['observer'])
        except Exception as exc:
            error = 'RELIGION_DEFENDER_CAPTURE_FAILED:' + type(exc).__name__
        try:
            after = self.context()
        except Exception:
            after = {}
        if self._context_reason(after) or _identity(before) != _identity(after):
            return fail('RELIGION_DEFENDER_CONTEXT_CHANGED_DURING_CAPTURE', before, True)
        next_installation, next_creation, next_reason = _session_binding(self.base_source)
        if next_reason or next_installation != installation or next_creation != creation:
            return fail('RELIGION_DEFENDER_SESSION_CHANGED_DURING_CAPTURE', before, True)
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
                return fail('RELIGION_DEFENDER_VIEW_ADMISSION_UNKNOWN', before)
            if not admission['admitted']:
                return result(self._field('invisible', 'RELIGION_DEFENDER_NOT_ADMITTED'), before)
            field = item['fields'][BACKEND_FIELD]
            status = field.get('status')
            if status in ('unknown', 'invisible'):
                reason = NativeCountryFaithSource._safe_reason(field.get('reason'), 'RELIGION_DEFENDER_BACKEND_UNKNOWN')
                return result(self._field(status, reason), before)
            if status != 'known' or field.get('complete') is not False or field.get('basis') != BASIS:
                raise ValueError('FIELD_SHAPE')
            return result(self._field('known', value=self._public_value(field['value'], target)), before)
        except Exception:
            return fail('RELIGION_DEFENDER_CAPTURE_INVALID', before)
