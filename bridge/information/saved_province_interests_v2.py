"""Add explicit territorial-core markers while keeping v1 membership intact."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path

from .saved_province_interests import SavedProvinceInterestsSnapshot, _tag_list

DEFAULT_MANIFEST = Path(__file__).resolve().parents[2] / 'tools/rust/eu4-save-provinces-v2/adapter-manifest.json'
V1_SCHEMA = 'eu4.save_provinces_snapshot.v1'
V2_SCHEMA = 'eu4.save_provinces_snapshot.v2'


class SavedProvinceInterestsSnapshotV2(SavedProvinceInterestsSnapshot):
    def __init__(self, path, observer, *, parser=None, parser_manifest=None):
        super().__init__(path, observer, parser=parser,
                         parser_manifest=parser_manifest or DEFAULT_MANIFEST)

    def _load(self, document):
        if not isinstance(document, dict) or document.get('schema') not in (V1_SCHEMA, V2_SCHEMA):
            raise ValueError('SAVED_INTERESTS_DOCUMENT_SCHEMA')
        self._snapshot_schema = document['schema']
        # The immutable v1 validator still owns all common membership, ID,
        # date and country checks. Legacy documents do not gain new evidence.
        common = dict(document)
        common['schema'] = V1_SCHEMA
        super()._load(common)
        self._territorial = {}
        for row in document['provinces']:
            pid = row['province_id']
            detail = {'status': 'unknown', 'reason': 'TERRITORIAL_CORE_MARKER_NOT_ESTABLISHED'}
            if self._snapshot_schema == V1_SCHEMA:
                detail['reason'] = 'LEGACY_SNAPSHOT_CORE_TYPE_NOT_CAPTURED'
            else:
                try:
                    values = _tag_list(row.get('territorial_core'), optional=True)
                    if values:
                        if set(values) <= set(self._provinces[pid]['cores']):
                            detail = {'status': 'known', 'value': values, 'unit': 'country_tag',
                                      'scale': 1, 'period': 'saved_snapshot', 'complete': False,
                                      'basis': 'saved_province.territorial_core'}
                        else:
                            detail['reason'] = 'TERRITORIAL_CORE_MEMBERSHIP_CONFLICT'
                except ValueError:
                    detail['reason'] = 'TERRITORIAL_CORE_MARKER_INVALID'
            self._territorial[pid] = detail

    def context(self):
        result = super().context()
        result['parser']['snapshot_schema'] = self._snapshot_schema
        return result

    def discovered_provinces(self):
        """Project only the bound observer's explicit discovery memberships.

        Missing discovery lists do not establish a negative membership.  The
        completeness flag below describes the parsed snapshot rows, never the
        running game's map or the full UI visibility rules.
        """
        self._assert_current()
        missing = sum(row['discovered_by'] is None for row in self._provinces.values())
        ids = sorted(pid for pid, row in self._provinces.items()
                     if row['discovered_by'] is not None
                     and self.observer in row['discovered_by'])
        common = {'unit': 'province_id', 'scale': 1, 'period': 'saved_snapshot',
                  'complete': False, 'basis': 'saved_province.discovered_by',
                  'snapshot_membership_complete': missing == 0,
                  'omitted_unknown_discovery_records': missing}
        if not ids and missing:
            return {**common, 'status': 'unknown',
                    'reason': 'SNAPSHOT_DISCOVERY_NOT_ESTABLISHED'}
        return {**common, 'status': 'known', 'value': ids}

    def lookup(self, obj, field):
        result = super().lookup(obj, field)
        if field != 'cores' or result.get('status') != 'known':
            return result
        if obj['type'] == 'province':
            detail = deepcopy(self._territorial[obj['province_id']])
        else:
            visible_marked = [
                (pid, item) for pid, item in self._territorial.items()
                if item['status'] == 'known'
                and self._provinces[pid]['discovered_by'] is not None
                and self.observer in self._provinces[pid]['discovered_by']
            ]
            if visible_marked:
                detail = {'status': 'known', 'value': sorted(
                    pid for pid, item in visible_marked if obj['country'] in item['value']),
                    'unit': 'province_id', 'scale': 1, 'period': 'saved_snapshot',
                    'complete': False, 'basis': 'saved_province.territorial_core',
                    'collection_scope': 'explicit_markers_on_observer_discovered_provinces_in_snapshot',
                    'unmarked_and_unobserved_provinces_omitted': True}
            else:
                detail = {'status': 'unknown', 'reason': (
                    'LEGACY_SNAPSHOT_CORE_TYPE_NOT_CAPTURED' if self._snapshot_schema == V1_SCHEMA
                    else 'TERRITORIAL_CORE_MARKER_NOT_ESTABLISHED')}
        result['territorial_core_membership'] = detail
        result['full_core_classification'] = {
            'status': 'unknown', 'reason': 'FULL_CORE_CLASSIFICATION_NOT_EVALUATED'}
        return result


__all__ = ['SavedProvinceInterestsSnapshotV2']
