"""Publish positive territorial-core detail as part of the existing cores field."""
from __future__ import annotations

from .province_interests import SavedProvinceInterestsSource


class SavedProvinceInterestsSourceV2(SavedProvinceInterestsSource):
    def catalog(self):
        topics = super().catalog()
        topic = next(item for item in topics if item['topic_id'] == 'G01')
        core = topic['fields']['cores']
        core['description'] = '保存时省份核心归属及显式领地核心标记；国家列表仅含观察方已发现省份。'
        core['detail_fields'] = {
            'territorial_core_membership': {
                'coverage': 'partial', 'basis': 'saved_province.territorial_core',
                'missing_marker': 'unknown', 'legacy_snapshot': 'unknown',
                'scope': 'explicit_markers_on_observer_discovered_provinces_in_snapshot'},
            'full_core_classification': {'coverage': 'planned', 'status': 'unknown'},
        }
        core['gaps'] = ['HISTORICAL_SNAPSHOT_NOT_LIVE', 'COMPLETE_UI_VISIBILITY_NOT_VERIFIED',
                        'UNMARKED_CORE_TYPE_NOT_ESTABLISHED', 'FULL_CORE_CLASSIFICATION_NOT_EVALUATED']
        return topics


__all__ = ['SavedProvinceInterestsSourceV2']
