"""Dated, presence-aware opinion records parsed by the pinned Jomini CLI."""
from __future__ import annotations

from copy import deepcopy
import calendar
from decimal import Decimal
from pathlib import Path
import re
import subprocess
import tempfile

from .saved_province_interests import (
    JOMINI_COMMIT, ROOT, SHA, SavedProvinceInterestsSnapshot, _json, _pin, _tag_list,
)

DEFAULT_MANIFEST = ROOT / 'tools/rust/eu4-save-opinions/adapter-manifest.json'
SCHEMA = 'eu4.save_opinion_snapshot.v1'
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
_DECIMAL = re.compile(r'[+-]?[0-9]+(?:\.[0-9]+)?\Z')
_DATE = re.compile(r'(-?[0-9]{1,6})\.([0-9]{1,2})\.([0-9]{1,2})\Z')


def _date(value, *, optional=False):
    if value is None and optional:
        return None
    match = _DATE.fullmatch(value) if isinstance(value, str) else None
    if not match or not 1 <= int(match[2]) <= 12 or not 1 <= int(match[3]) <= 31:
        raise ValueError('SAVED_OPINION_DATE_INVALID')
    return value


def _record(row):
    if not isinstance(row, dict):
        raise ValueError('SAVED_OPINION_RECORD_INVALID')
    modifier = row.get('modifier')
    if (not isinstance(modifier, str) or not 1 <= len(modifier) <= 256
            or any(ord(char) < 32 or ord(char) == 127 for char in modifier)):
        raise ValueError('SAVED_OPINION_MODIFIER_INVALID')
    value = row.get('current_opinion')
    if value is not None and (not isinstance(value, str) or len(value) > 64
                              or _DECIMAL.fullmatch(value) is None or not Decimal(value).is_finite()):
        raise ValueError('SAVED_OPINION_VALUE_INVALID')
    expiry = row.get('expiry_date')
    if expiry is not None and type(expiry) is not bool:
        raise ValueError('SAVED_OPINION_EXPIRY_FLAG_INVALID')
    return {'modifier_id': modifier, 'recorded_date': _date(row.get('date'), optional=True),
            'current_opinion_decimal': value, 'expiry_date_flag': expiry}


class SavedOpinionSnapshot(SavedProvinceInterestsSnapshot):
    """Reuse the existing snapshot's input identity, freshness and context."""

    def __init__(self, path, observer, *, parser=None, parser_manifest=None):
        super().__init__(path, observer, parser=parser,
                         parser_manifest=parser_manifest or DEFAULT_MANIFEST)

    def _prepare_parser(self, manifest_path):
        manifest_pin = _pin(manifest_path, 128 * 1024)
        manifest = _json(Path(manifest_pin['path']).read_bytes())
        if (not isinstance(manifest, dict) or manifest.get('schema') != 'eu4.save_opinion.parser.v1'
                or manifest.get('jomini_commit') != JOMINI_COMMIT):
            raise ValueError('SAVED_OPINION_PARSER_MANIFEST')
        sources = manifest.get('sources')
        if not isinstance(sources, list) or not 1 <= len(sources) <= 512:
            raise ValueError('SAVED_OPINION_PARSER_SOURCES')
        pins, seen = [manifest_pin], set()
        for row in [manifest.get('binary'), *sources]:
            if (not isinstance(row, dict) or not isinstance(row.get('path'), str)
                    or Path(row['path']).is_absolute() or '\\' in row['path']
                    or '..' in Path(row['path']).parts or type(row.get('bytes')) is not int
                    or not isinstance(row.get('sha256'), str) or SHA.fullmatch(row['sha256']) is None):
                raise ValueError('SAVED_OPINION_PARSER_PIN')
            path = (ROOT / row['path']).resolve()
            path.relative_to(ROOT)
            if path in seen:
                raise ValueError('SAVED_OPINION_DUPLICATE_PARSER_PIN')
            seen.add(path)
            actual = _pin(path, 128 * 1024 * 1024)
            if (actual['size_bytes'], actual['sha256']) != (row['bytes'], row['sha256']):
                raise ValueError('SAVED_OPINION_PARSER_PIN_MISMATCH')
            pins.append(actual)
        self._dependencies = pins
        self._parser_info = {'kind': 'jomini_eu4save', 'commit': JOMINI_COMMIT,
                             'manifest_sha256': manifest_pin['sha256'],
                             'binary_sha256': pins[1]['sha256']}

        def parse(path):
            with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
                try:
                    result = subprocess.run([pins[1]['path'], str(path)], stdin=subprocess.DEVNULL,
                                            stdout=output, stderr=errors, timeout=45, close_fds=True)
                except (OSError, subprocess.TimeoutExpired) as error:
                    raise ValueError('SAVED_OPINION_PARSER_EXECUTION_FAILED') from error
                if result.returncode != 0:
                    raise ValueError('SAVED_OPINION_PARSER_FAILED')
                output.seek(0)
                raw = output.read(MAX_OUTPUT_BYTES + 1)
                if not raw or len(raw) > MAX_OUTPUT_BYTES:
                    raise ValueError('SAVED_OPINION_PARSER_OUTPUT_SIZE')
                return _json(raw)
        return parse

    def _load(self, document):
        if not isinstance(document, dict) or document.get('schema') != SCHEMA:
            raise ValueError('SAVED_OPINION_DOCUMENT_SCHEMA')
        projection = document.get('relation_projection', 'all_serialized_relation_entries')
        if projection not in ('all_serialized_relation_entries', 'serialized_opinion_entries_only'):
            raise ValueError('SAVED_OPINION_RELATION_PROJECTION_INVALID')
        self._parser_info['relation_projection'] = projection
        self.date = _date(document.get('saved_date'))
        year, month, day = map(int, self.date.split('.'))
        if not 1 <= year <= 9999 or day > calendar.monthrange(year, month)[1]:
            raise ValueError('SAVED_OPINION_DATE_INVALID')
        version = document.get('saved_version')
        if (not isinstance(version, dict)
                or any(type(version.get(key)) is not int or not 0 <= version[key] <= 65535
                       for key in ('first', 'second', 'third', 'fourth'))):
            raise ValueError('SAVED_OPINION_VERSION_INVALID')
        self.version = '.'.join(str(version[key]) for key in ('first', 'second', 'third'))
        if self.version != '1.37.4':
            raise ValueError('SAVED_OPINION_VERSION_UNSUPPORTED')
        self.player = document.get('saved_player')
        if _tag_list([self.player]) != [self.player]:
            raise ValueError('SAVED_OPINION_PLAYER_INVALID')
        self._countries = frozenset(_tag_list(document.get('country_tags')))
        if self.observer not in self._countries:
            raise ValueError('SAVED_OPINION_OBSERVER_ABSENT')
        countries = document.get('countries')
        if not isinstance(countries, list) or not 1 <= len(countries) <= 4096:
            raise ValueError('SAVED_OPINION_COUNTRIES_INVALID')
        self._relations = {}
        relation_count = opinion_count = 0
        for country in countries:
            if not isinstance(country, dict):
                raise ValueError('SAVED_OPINION_COUNTRY_INVALID')
            tag = country.get('country')
            if not isinstance(tag, str) or tag not in self._countries or tag in self._relations:
                raise ValueError('SAVED_OPINION_COUNTRY_ID_INVALID')
            entries = country.get('active_relations')
            self._relations[tag] = None
            if entries is None:
                continue
            if not isinstance(entries, list) or len(entries) > 4096:
                raise ValueError('SAVED_OPINION_RELATIONS_INVALID')
            relations = {}
            for entry in entries:
                relation_count += 1
                if not isinstance(entry, dict) or relation_count > 65536:
                    raise ValueError('SAVED_OPINION_RELATION_LIMIT_OR_SHAPE')
                target = entry.get('country')
                if not isinstance(target, str) or target not in self._countries or target in relations:
                    raise ValueError('SAVED_OPINION_RELATION_TARGET_INVALID')
                opinions = entry.get('opinions')
                if opinions is None:
                    relations[target] = None
                    continue
                if not isinstance(opinions, list) or len(opinions) > 65536:
                    raise ValueError('SAVED_OPINION_RECORDS_INVALID')
                opinion_count += len(opinions)
                if opinion_count > 65536:
                    raise ValueError('SAVED_OPINION_RECORD_LIMIT')
                relations[target] = [_record(row) for row in opinions]
            self._relations[tag] = relations
        if set(self._relations) != self._countries:
            raise ValueError('SAVED_OPINION_COUNTRY_SET_MISMATCH')

    def context(self):
        context = super().context()
        context['parser']['snapshot_schema'] = SCHEMA
        return context

    def lookup_pair(self, obj):
        self._assert_current()
        actor, recipient = obj['actor'], obj['recipient']
        directions = []
        for holder, target in ((actor, recipient), (recipient, actor)):
            item = {'holder': holder, 'target': target}
            if holder not in self._countries or target not in self._countries:
                reason = 'COUNTRY_NOT_IN_SNAPSHOT'
            elif self._relations[holder] is None:
                reason = 'SAVED_ACTIVE_RELATIONS_NOT_CAPTURED'
            elif target not in self._relations[holder]:
                reason = ('SAVED_OPINION_RECORDS_NOT_ESTABLISHED'
                          if self._parser_info['relation_projection'] == 'serialized_opinion_entries_only'
                          else 'SAVED_RELATION_NOT_RECORDED')
            elif not self._relations[holder][target]:
                reason = 'SAVED_OPINION_RECORDS_NOT_ESTABLISHED'
            else:
                item.update(status='known', records=deepcopy(self._relations[holder][target]))
                directions.append(item)
                continue
            item.update(status='unknown', reason=reason)
            directions.append(item)
        common = {'unit': 'directed_saved_opinion_modifiers', 'scale': 1,
                  'period': 'saved_snapshot', 'complete': False,
                  'basis': 'saved_country.active_relations.opinion'}
        if any(item['status'] == 'known' for item in directions):
            return {**common, 'status': 'known', 'value': directions}
        return {**common, 'status': 'unknown', 'reason': 'SAVED_OPINION_RELATIONS_NOT_ESTABLISHED',
                'directions': directions}


__all__ = ['SavedOpinionSnapshot']
