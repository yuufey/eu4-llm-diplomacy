"""Extend the global HRE identity query with recorded passed-reform IDs."""
from __future__ import annotations

from copy import deepcopy
import re

from .empire_live import FIELDS as LEGACY_FIELDS, NativeEmpireSource


FIELDS = (*LEGACY_FIELDS, 'reforms')
_IDENTIFIER = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.:-]{0,127}\Z')
_REASON = re.compile(r'[A-Z][A-Z0-9_]{0,159}\Z')
_BASIS = 'native_global_hre_passed_reform_identifiers'


class NativeEmpireReformsSource(NativeEmpireSource):
    """Keep identity fields compatible while isolating unreadable reform data."""

    field_names = FIELDS
    capture_module = '.empire_capture_v2'
    projection_version = 2

    def catalog(self):
        topics = super().catalog()
        topic = topics[0]
        topic['fields']['reforms'] = {
            'coverage': 'partial', 'source': type(self).__name__, 'complete': False,
            'unit': 'reform_id', 'scale': 1, 'period': 'current',
            'value_origin': 'copied_native_reform_identifiers', 'basis': _BASIS,
            'supported_object_types': ['country', 'session'],
            'description': '当前全局神罗记录中的已通过改革标识；不计算生效效果或改革可用条件。',
            'gaps': ['REFORM_EFFECTS_AND_ENACTMENT_CONDITIONS_NOT_EVALUATED',
                     'ACTUAL_UI_DRAW_NOT_OBSERVED', 'NON_ATOMIC_TWO_PASS_OBSERVATION'],
        }
        return topics

    @staticmethod
    def _projected_fields(projected):
        if not isinstance(projected, dict) or set(projected) != set(FIELDS):
            raise ValueError('EMPIRE_V2_PROJECTION_FIELDS')
        output = NativeEmpireSource._projected_fields({name: projected[name] for name in LEGACY_FIELDS})
        field = projected['reforms']
        metadata = {'unit': 'reform_id', 'scale': 1, 'period': 'current',
                    'complete': False, 'basis': _BASIS,
                    'value_origin': 'copied_native_reform_identifiers',
                    'active_effects_evaluated': False, 'enactment_conditions_evaluated': False}
        result = {**metadata, 'status': 'unknown', 'reason': 'EMPIRE_REFORMS_NOT_ESTABLISHED'}
        if isinstance(field, dict) and field.get('status') == 'known':
            identifiers = field.get('value')
            if (isinstance(identifiers, list) and len(identifiers) <= 4096
                    and all(isinstance(value, str) and _IDENTIFIER.fullmatch(value) for value in identifiers)
                    and len(identifiers) == len(set(identifiers))):
                result = {**metadata, 'status': 'known', 'value': list(identifiers),
                          'order': 'native_record_order'}
            else:
                result['reason'] = 'EMPIRE_REFORM_IDENTIFIERS_INVALID'
        elif isinstance(field, dict):
            reason = field.get('reason')
            if isinstance(reason, str) and _REASON.fullmatch(reason):
                result['reason'] = reason
        output['reforms'] = result
        return deepcopy(output)


__all__ = ['NativeEmpireReformsSource']
