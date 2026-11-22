"""S02 current religion-group display name; configuration identity stays unknown."""
from __future__ import annotations

from copy import deepcopy
import hashlib
from importlib import import_module
import re

from ..native_text import decode_native_text_hex
from .country_faith import NativeCountryFaithSource
from .model import InformationError, canonical
from .religion_binding import binding_digests
from .sources import _result, _source_info
from .trade_income import NativeTradeIncomeSource, _identity, _session_binding

FIELD = 'religion_group'
BACKEND_FIELD = 'S02.religion_group'
BASIS = 'native_primary_religion_group_display_name'
VALUE_ORIGIN = 'copied_native_religion_group_name_string32'


class NativeReligionGroupSource(NativeTradeIncomeSource):
    """Reuse the country owner and its non-player observer/view admission."""

    event_types: tuple[str, ...] = ()

    def catalog(self):
        topic = deepcopy(NativeCountryFaithSource.catalog(self)[0])
        topic['source'] = type(self).__name__
        topic['fields'] = {FIELD: {
            'coverage': 'partial', 'complete': False,
            'source': 'bridge.information.religion_group_capture.capture',
            'unit': 'native_display_name', 'scale': 1, 'period': 'current',
            'basis': BASIS, 'value_origin': VALUE_ORIGIN,
            'paths': ["observation.backend.targets[0].fields['S02.religion_group'].value.religion_group_name"],
            'runtime_validation': 'religion_group_capture.validate_capture',
            'raw_semantics': 'current primary religion group cached display-name bytes, strictly decoded; not a configuration key or ID',
            'gaps': ['RELIGION_GROUP_CONFIGURATION_IDENTITY_NOT_READ',
                     'FULL_RELIGION_GROUP_RULES_AND_TOOLTIP_NOT_READ',
                     'COUNTRY_VIEW_PROJECTION_NOT_ACTUAL_UI_OBSERVATION',
                     'MAIN_THREAD_ATOMICITY_NOT_PROVEN'],
        }}
        topic['scope_note'] = ('复制观察国可见国家的主宗教组显示名。'
                               '不把本地化显示名解释为配置key或数字ID。')
        return [topic]

    def validate_query(self, query, context=None):
        if not isinstance(query, dict) or query.get('fields') != [FIELD]:
            raise InformationError('invalid_fields', 'S02.religion_group requires its single field')
        projected = deepcopy(query); projected['fields'] = ['faith']
        normalized = NativeCountryFaithSource.validate_query(self, projected, context)
        normalized['fields'] = [FIELD]
        return normalized

    @staticmethod
    def _field(status, reason=None, value=None):
        result = {'status': status, 'period': 'current', 'unit': 'native_display_name',
                  'scale': 1, 'partial': True, 'complete': False,
                  'basis': BASIS, 'value_origin': VALUE_ORIGIN}
        if reason is not None:
            result['reason'] = reason
        if status == 'known' and value is not None:
            result['value'] = value
        return result

    @staticmethod
    def _public_value(value):
        if not isinstance(value, dict) or set(value) != {'religion_group_name'}:
            raise ValueError('GROUP_VALUE_KEYS')
        name = value['religion_group_name']
        if not isinstance(name, dict) or set(name) != {'text', 'raw_hex', 'encoding'}:
            raise ValueError('GROUP_NAME_KEYS')
        raw = name.get('raw_hex')
        if (not isinstance(raw, str) or re.fullmatch(r'(?:[0-9a-f]{2}){1,128}', raw) is None
                or name.get('encoding') != 'eu4_escape' or not isinstance(name.get('text'), str)):
            raise ValueError('GROUP_NAME_SHAPE')
        payload = bytes.fromhex(raw)
        if b'\0' in payload:
            raise ValueError('GROUP_NAME_NUL')
        decoded = decode_native_text_hex(raw, codec='eu4_escape', max_bytes=128)
        if not decoded or decoded != name['text']:
            raise ValueError('GROUP_NAME_DECODE')
        return {'religion_group_name': {'text': decoded, 'raw_hex': raw, 'encoding': 'eu4_escape'}}

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

        def failure(reason, ctx, unavailable=False):
            return result(self._field('unavailable' if unavailable else 'unknown', reason), ctx)

        def context_reason(ctx):
            reason = NativeCountryFaithSource._context_reason(ctx)
            return reason.replace('COUNTRY_FAITH_', 'RELIGION_GROUP_', 1) if reason else None

        reason = context_reason(current)
        if reason:
            return failure(reason, current, True)
        try:
            before = self.context()
        except Exception:
            return failure('RELIGION_GROUP_CONTEXT_UNAVAILABLE', current, True)
        if context_reason(before) or _identity(current) != _identity(before):
            return failure('RELIGION_GROUP_CONTEXT_STALE', before, True)
        installation, creation, binding_reason = _session_binding(self.base_source)
        if binding_reason or installation is None or creation is None:
            return failure('RELIGION_GROUP_SESSION_UNAVAILABLE', before, True)
        try:
            module = import_module('.religion_group_capture', __package__)
            capture = self.capture if self.capture is not None else module.capture
        except Exception:
            return failure('RELIGION_GROUP_CAPTURE_UNAVAILABLE', before, True)
        report = None; error = None
        try:
            report = capture(installation, country=target, observer=before['observer'])
        except Exception as exc:
            error = 'RELIGION_GROUP_CAPTURE_FAILED:' + type(exc).__name__
        try:
            after = self.context()
        except Exception:
            after = {}
        if context_reason(after) or _identity(before) != _identity(after):
            return failure('RELIGION_GROUP_CONTEXT_CHANGED_DURING_CAPTURE', before, True)
        next_installation, next_creation, next_reason = _session_binding(self.base_source)
        if next_reason or next_installation != installation or next_creation != creation:
            return failure('RELIGION_GROUP_SESSION_CHANGED_DURING_CAPTURE', before, True)
        if error:
            return failure(error, before)
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
                return failure('RELIGION_GROUP_VIEW_ADMISSION_UNKNOWN', before)
            if not admission['admitted']:
                return result(self._field('invisible', 'RELIGION_GROUP_NOT_ADMITTED_FOR_OBSERVER'), before)
            field = item['fields'][BACKEND_FIELD]
            status = field.get('status')
            if status in ('unknown', 'invisible'):
                safe_reason = NativeCountryFaithSource._safe_reason(field.get('reason'), 'RELIGION_GROUP_BACKEND_UNKNOWN')
                return result(self._field(status, safe_reason), before)
            if status != 'known' or field.get('complete') is not False:
                raise ValueError('FIELD_SHAPE')
            try:
                provenance.update(binding_digests(field, target, require_group=True))
            except Exception:
                pass
            return result(self._field('known', value=self._public_value(field['value'])), before)
        except Exception:
            return failure('RELIGION_GROUP_CAPTURE_INVALID', before)
