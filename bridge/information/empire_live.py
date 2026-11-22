"""Expose the current global HRE emperor and elector references read-only.

Country selectors refer to the same empire record as a session selector. They
do not assert that the selected country exists, belongs to the HRE, or has a
particular imperial role. The native capture owns reference and role checks.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
from importlib import import_module
import re

from .catalog import get_topic
from .model import InformationError, canonical
from .sources import _result, _source_info
from .trade_income import _identity, _observer_context_reason, _session_binding


FIELDS = ('emperor', 'electors')
ALL_FIELDS = frozenset(get_topic('S01')['fields'])
_TAG = re.compile(r'[A-Z0-9]{3}\Z')
_SESSION_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z')
_BASIS = 'native_global_hre_country_references_with_static_ui_binding'


def _context_identity(context):
    return (*_identity(context), context.get('dll_sha256'),
            context.get('world_id'), context.get('world_generation'),
            context.get('game_day'), context.get('game_date_raw'),
            context.get('physical_client_country'))


class NativeEmpireSource:
    event_types = ()
    field_names = FIELDS
    capture_module = '.empire_capture'
    projection_version = 1

    def __init__(self, base_source, *, capture=None):
        self.base_source = base_source
        self.capture = capture

    def context(self):
        return deepcopy(self.base_source.context())

    def catalog(self):
        topic = get_topic('S01')
        topic.update(status='available', source=type(self).__name__,
                     visibility='global_empire_record', context_scope='visible_scope',
                     supported_versions=['1.37.4'], triggers=['query', 'periodic'],
                     observer_roles=[],
                     object_semantics='global_empire_record_country_selector_does_not_filter')
        topic['parameters'] = {'type': 'object', 'properties': {}, 'additionalProperties': False}
        topic['fields'] = {name: {
            'coverage': 'partial', 'source': type(self).__name__, 'complete': False,
            'unit': 'country_tag', 'scale': 1, 'period': 'current',
            'value_origin': 'copied_native_canonical_country_references',
            'basis': _BASIS, 'supported_object_types': ['country', 'session'],
            'description': ('当前神罗皇帝国家标签。' if name == 'emperor'
                            else '当前神罗选帝侯国家标签列表。'),
            'gaps': ['ACTUAL_UI_DRAW_NOT_OBSERVED', 'NON_ATOMIC_TWO_PASS_OBSERVATION',
                     'EMPIRE_MEMBERSHIP_AND_OTHER_MECHANICS_NOT_CAPTURED'],
        } for name in FIELDS}
        return [topic]

    def validate_query(self, query, context=None):
        if (not isinstance(query, dict) or not {'topic', 'object', 'fields'} <= set(query)
                or set(query) - {'topic', 'object', 'fields', 'parameters'}):
            raise InformationError('invalid_parameters', 'S01 query has missing or unknown keys')
        if query['topic'] != 'S01':
            raise InformationError('unsupported_topic', 'Native empire supports S01')
        obj = query['object']
        valid = False
        if isinstance(obj, dict) and obj.get('type') == 'country':
            valid = (set(obj) == {'type', 'country'} and isinstance(obj.get('country'), str)
                     and _TAG.fullmatch(obj['country']) is not None)
        elif isinstance(obj, dict) and obj.get('type') == 'session':
            valid = (set(obj) <= {'type', 'session_id'}
                     and ('session_id' not in obj or (isinstance(obj['session_id'], str)
                          and _SESSION_ID.fullmatch(obj['session_id']) is not None)))
        if not valid:
            raise InformationError('invalid_object', 'S01 requires a country or session selector')
        fields = query['fields']
        if (not isinstance(fields, list) or not fields
                or any(not isinstance(name, str) or name not in ALL_FIELDS for name in fields)
                or len(fields) != len(set(fields))):
            raise InformationError('invalid_fields', 'S01 requires unique declared fields')
        if not isinstance(query.get('parameters', {}), dict) or query.get('parameters', {}):
            raise InformationError('invalid_parameters', 'S01 native parameters must be empty')
        return {'topic': 'S01', 'object': deepcopy(obj), 'fields': list(fields), 'parameters': {}}

    @staticmethod
    def _context_reason(context):
        reason = _observer_context_reason(context)
        return reason.replace('TRADE_INCOME_', 'EMPIRE_', 1) if reason else None

    def _binding(self, context):
        installation, creation, reason = _session_binding(self.base_source)
        if reason:
            return None, None, reason.replace('TRADE_INCOME_', 'EMPIRE_', 1)
        session = getattr(self.base_source, 'session', None)
        record = getattr(session, 'record', None)
        if (not isinstance(record, dict) or record.get('session_id') != context.get('session_id')
                or type(creation) is not int or creation <= 0):
            return None, None, 'EMPIRE_SESSION_RECORD_MISMATCH'
        return installation, creation, None

    @staticmethod
    def _projected_fields(projected):
        """Copy only contracted scalars/lists even from an injected backend."""
        if not isinstance(projected, dict) or set(projected) != set(FIELDS):
            raise ValueError('EMPIRE_PROJECTION_FIELDS')
        fields = {}
        for name in FIELDS:
            value = projected[name]
            if not isinstance(value, dict) or value.get('status') != 'known':
                fields[name] = {'status': 'unknown', 'reason': 'EMPIRE_REFERENCE_NOT_ESTABLISHED',
                                'period': 'current', 'complete': False}
                continue
            tags = value.get('value')
            if name == 'emperor':
                if not isinstance(tags, str) or _TAG.fullmatch(tags) is None:
                    raise ValueError('EMPIRE_EMPEROR_TAG_INVALID')
                public_value = tags
            else:
                if (not isinstance(tags, list) or len(tags) > 64
                        or any(not isinstance(tag, str) or _TAG.fullmatch(tag) is None for tag in tags)
                        or len(tags) != len(set(tags))):
                    raise ValueError('EMPIRE_ELECTORS_INVALID')
                public_value = sorted(tags)
            fields[name] = {
                'status': 'known', 'value': public_value, 'unit': 'country_tag', 'scale': 1,
                'period': 'current', 'complete': False, 'basis': _BASIS,
                'value_origin': 'copied_native_canonical_country_references',
            }
        return fields

    def read(self, query, context=None):
        query = self.validate_query(query, context)
        current = deepcopy(context) if isinstance(context, dict) else self.context()
        selected = [name for name in query['fields'] if name in self.field_names]
        fields = {name: {'status': 'unsupported', 'reason': 'S01_LIVE_FIELD_NOT_IMPLEMENTED'}
                  for name in query['fields']}
        provenance = {'observer': current.get('observer'), 'read_only': True, 'native_function_invoked': False,
                      'actual_UI_observed': False, 'atomic_snapshot': False,
                      'country_selector_semantics': 'global_empire_record_not_membership',
                      'visibility_basis': 'static_native_hre_window_data_binding'}

        def result(ctx):
            source = _source_info(type(self).__name__, ctx, complete=False, provenance=provenance)
            source.update(context_scope='visible_scope', projection_version=self.projection_version)
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
        selector_session = query['object'].get('session_id', current['session_id'])
        if selector_session != current['session_id']:
            return failure('EMPIRE_SELECTOR_SESSION_MISMATCH', unavailable=True)
        try:
            before = self.context()
        except Exception:
            return failure('EMPIRE_CONTEXT_UNAVAILABLE', unavailable=True)
        reason = self._context_reason(before)
        if reason or _context_identity(current) != _context_identity(before):
            return failure(reason or 'EMPIRE_CONTEXT_STALE', before, True)
        installation, creation, reason = self._binding(before)
        if reason:
            return failure(reason, before, True)
        try:
            module = import_module(self.capture_module, __package__)
            capture = self.capture if self.capture is not None else module.capture
            report = capture(installation, observer=before['observer'])
        except Exception:
            return failure('EMPIRE_CAPTURE_FAILED', before)
        try:
            after = self.context()
        except Exception:
            after = {}
        if self._context_reason(after) or _context_identity(before) != _context_identity(after):
            return failure('EMPIRE_CONTEXT_CHANGED_DURING_CAPTURE', before, True)
        final_installation, final_creation, reason = self._binding(after)
        if reason or final_installation != installation or final_creation != creation:
            return failure('EMPIRE_SESSION_CHANGED_DURING_CAPTURE', before, True)
        try:
            if module.validate_capture(report, before, creation) is not True:
                return failure('EMPIRE_CAPTURE_NOT_VALIDATED', before)
            projected = self._projected_fields(module.project_fields(report))
            # Validation/replay can be nontrivial: reject a concurrent session
            # change that occurs while it is running, before returning values.
            final = self.context()
            final_binding = self._binding(final)
            if (self._context_reason(final) or _context_identity(final) != _context_identity(before)
                    or final_binding != (installation, creation, None)):
                return failure('EMPIRE_CONTEXT_CHANGED_DURING_VALIDATION', before, True)
            provenance['capture_report_sha256'] = hashlib.sha256(canonical(report).encode('utf-8')).hexdigest()
            provenance['profile_sha256'] = module.PROFILE_SHA256
            for name in selected:
                fields[name] = projected[name]
        except Exception:
            return failure('EMPIRE_CAPTURE_SHAPE_INVALID', before)
        return result(before)

    def poll_events(self, context, cursor):
        return {'events': [], 'cursor': deepcopy(cursor or {}), 'complete': True, 'gaps': []}


__all__ = ['NativeEmpireSource']
