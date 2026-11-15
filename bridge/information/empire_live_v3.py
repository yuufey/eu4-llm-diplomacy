"""Publish only the passed-ID projection of the current global HRE record."""
from __future__ import annotations

from copy import deepcopy

from .empire_live_v2 import NativeEmpireReformsSource


_BASIS = 'native_global_hre_passed_ids_with_selected_frame_binding'


class NativeEmpirePassedReformsSource(NativeEmpireReformsSource):
    """Keep the established emperor/elector owner separate from the new field."""

    field_names = ('reforms',)
    capture_module = '.empire_capture_v3'
    projection_version = 3

    def catalog(self):
        topic = super().catalog()[0]
        topic['fields'] = {'reforms': topic['fields']['reforms']}
        topic['fields']['reforms'].update(
            basis=_BASIS,
            description='当前全局神罗记录中的已通过改革标识，依据独立状态图标的静态数据流；不表示效果或按钮可执行条件。',
            gaps=['REFORM_EFFECTS_AND_ENACTMENT_CONDITIONS_NOT_EVALUATED',
                  'ACTUAL_UI_DRAW_NOT_OBSERVED', 'COMPLETE_OBSERVER_VISIBILITY_NOT_EVALUATED',
                  'NON_ATOMIC_TWO_PASS_OBSERVATION'],
        )
        return [topic]

    @staticmethod
    def _projected_fields(projected):
        # Validate and sanitize the full internal projection before selecting
        # this owner's single field. The two tag fields are never published
        # through this adapter, even when the backend includes private extras.
        checked = NativeEmpireReformsSource._projected_fields(projected)
        field = deepcopy(checked['reforms'])
        field['basis'] = _BASIS
        return {'reforms': field}

    def read(self, query, context=None):
        value = super().read(query, context)
        provenance = value['source']['provenance']
        provenance.update(
            visibility_basis='static_global_hre_passed_table_to_selected_frame',
            admission_scope='global_stored_passed_reform_identifiers',
            complete_observer_visibility_evaluated=False,
            active_effects_evaluated=False,
            enactment_conditions_evaluated=False,
        )
        return value


__all__ = ['NativeEmpirePassedReformsSource']
