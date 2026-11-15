"""Read current province core/claim memberships for the logical FRA observer."""
from __future__ import annotations

from copy import deepcopy
import hashlib
from importlib import import_module
import re

from .catalog import get_topic
from .model import InformationError, canonical
from .province_interest_parameters import parameters_schema, validate_parameters
from .sources import _result, _source_info
from .trade_income import _context_reason as _base_reason, _identity, _session_binding

FIELDS = ('cores', 'claims')
ALL_FIELDS = frozenset(get_topic('G01')['fields'])


class NativeProvinceInterestsSource:
    event_types = ()

    def __init__(self, base_source, *, capture=None):
        self.base_source = base_source
        self.capture = capture

    def context(self):
        return deepcopy(self.base_source.context())

    def catalog(self):
        topic = get_topic('G01')
        topic.update(status='available', source=type(self).__name__,
                     visibility='visible_scope', context_scope='visible_scope',
                     supported_versions=['1.37.4'], triggers=['query', 'periodic'])
        topic['parameters'] = parameters_schema()
        topic['fields'] = {name: {
            'coverage': 'partial', 'source': type(self).__name__, 'complete': False,
            'unit': 'country_tag', 'scale': 1, 'period': 'current',
            'value_origin': 'copied_native_canonical_country_references',
            'basis': 'native_province_membership_after_positive_actor_discovery',
            'supported_object_types': ['province'],
            'description': '逻辑法国已发现省份的当前核心国家列表。' if name == 'cores'
                           else '逻辑法国已发现省份的当前宣称国家列表。',
            'gaps': ['COUNTRY_REVERSE_ENUMERATION_NOT_IMPLEMENTED',
                     'COMPLETE_PROVINCE_UI_VISIBILITY_NOT_PROVEN',
                     'CORE_TYPE_DETAILS_NOT_CAPTURED' if name == 'cores'
                     else 'CLAIM_EXPIRY_AND_PERMANENCE_NOT_CAPTURED'],
        } for name in FIELDS}
        return [topic]

    def validate_query(self, query, context=None):
        if (not isinstance(query, dict) or not {'topic', 'object', 'fields'} <= set(query)
                or set(query) - {'topic', 'object', 'fields', 'parameters'}):
            raise InformationError('invalid_parameters', 'G01 query has missing or unknown keys')
        if query['topic'] != 'G01':
            raise InformationError('unsupported_topic', 'Native province interests support G01')
        obj = query['object']
        valid = False
        if isinstance(obj, dict) and obj.get('type') == 'province':
            valid = (set(obj) == {'type', 'province_id'} and type(obj.get('province_id')) is int
                     and 1 <= obj['province_id'] <= 65535)
        elif isinstance(obj, dict) and obj.get('type') == 'country':
            valid = (set(obj) == {'type', 'country'} and isinstance(obj.get('country'), str)
                     and re.fullmatch(r'[A-Z0-9]{3}', obj['country']) is not None)
        if not valid:
            raise InformationError('invalid_object', 'G01 requires an explicit province or country')
        fields = query['fields']
        if (not isinstance(fields, list) or not fields
                or any(not isinstance(name, str) or name not in ALL_FIELDS for name in fields)
                or len(fields) != len(set(fields))):
            raise InformationError('invalid_fields', 'G01 requires unique declared fields')
        parameters = validate_parameters(query.get('parameters', {}))
        return {'topic': 'G01', 'object': deepcopy(obj), 'fields': list(fields), 'parameters': parameters}

    @staticmethod
    def _context_reason(context):
        reason = _base_reason(context, 'FRA')
        return reason.replace('TRADE_INCOME_', 'PROVINCE_INTEREST_', 1) if reason else None

    def read(self, query, context=None):
        query = self.validate_query(query, context)
        current = deepcopy(context) if isinstance(context, dict) else self.context()
        selected = [name for name in query['fields'] if name in FIELDS]
        fields = {name: {'status': 'unsupported', 'reason': 'G01_FIELD_NOT_IMPLEMENTED'}
                  for name in query['fields']}
        provenance = {'observer': 'FRA', 'read_only': True, 'native_function_invoked': False,
                      'actual_UI_observed': False, 'full_province_visibility_complete': False}

        def result(ctx):
            source = _source_info(type(self).__name__, ctx, complete=False, provenance=provenance)
            source.update(context_scope='visible_scope', projection_version=1)
            return _result(query, ctx, fields, False, source)

        def failure(reason, ctx=current, unavailable=False):
            for name in selected:
                fields[name] = {'status': 'unavailable' if unavailable else 'unknown',
                                'reason': reason, 'period': 'current', 'complete': False}
            return result(ctx)

        if not selected:
            return result(current)
        reason = self._context_reason(current)
        if reason:
            return failure(reason, unavailable=True)
        if query['object']['type'] != 'province':
            return failure('COUNTRY_REVERSE_ENUMERATION_NOT_IMPLEMENTED')
        province_id = query['object']['province_id']
        provenance['province_id'] = province_id
        try:
            before = self.context()
        except Exception:
            return failure('PROVINCE_INTEREST_CONTEXT_UNAVAILABLE', unavailable=True)
        reason = self._context_reason(before)
        if reason or _identity(current) != _identity(before):
            return failure(reason or 'PROVINCE_INTEREST_CONTEXT_STALE', before, True)
        installation, creation, binding_reason = _session_binding(self.base_source)
        if binding_reason or installation is None or creation is None:
            return failure(binding_reason or 'PROVINCE_INTEREST_INSTALLATION_UNAVAILABLE', before, True)
        try:
            module = import_module('.province_interest_capture', __package__)
            capture = self.capture if self.capture is not None else module.capture
            report = capture(installation, province_id=province_id, observer='FRA')
        except Exception:
            return failure('PROVINCE_INTEREST_CAPTURE_FAILED', before)
        try:
            after = self.context()
        except Exception:
            after = {}
        if self._context_reason(after) or _identity(before) != _identity(after):
            return failure('PROVINCE_INTEREST_CONTEXT_CHANGED_DURING_CAPTURE', before, True)
        final_installation, final_creation, final_reason = _session_binding(self.base_source)
        if final_reason or final_installation != installation or final_creation != creation:
            return failure('PROVINCE_INTEREST_SESSION_CHANGED_DURING_CAPTURE', before, True)
        try:
            if module.validate_capture(report, before, creation, province_id) is not True:
                return failure('PROVINCE_INTEREST_CAPTURE_NOT_VALIDATED', before)
            projected = module.project_fields(report)
            provenance['capture_report_sha256'] = hashlib.sha256(canonical(report).encode('utf-8')).hexdigest()
            provenance['profile_sha256'] = module.PROFILE_SHA256
            for name in selected:
                fields[name] = deepcopy(projected[name])
        except (KeyError, TypeError, ValueError):
            return failure('PROVINCE_INTEREST_CAPTURE_SHAPE_INVALID', before)
        return result(before)

    def poll_events(self, context, cursor):
        return {'events': [], 'cursor': deepcopy(cursor or {}), 'complete': True, 'gaps': []}


__all__ = ['NativeProvinceInterestsSource']
