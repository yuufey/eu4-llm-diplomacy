"""Own a dated province-interest snapshot produced by the pinned Jomini CLI."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = ROOT / 'tools/rust/eu4-save-provinces/adapter-manifest.json'
JOMINI_COMMIT = '8fbd6861f453c719da59daac6970babd9ddc19ac'
MAX_SAVE_BYTES = 128 * 1024 * 1024
MAX_OUTPUT_BYTES = 32 * 1024 * 1024
TAG = re.compile(r'[A-Z0-9]{3}\Z')
SHA = re.compile(r'[0-9a-f]{64}\Z')


def _json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('SAVED_INTERESTS_DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('NONFINITE_JSON')))


def _pin(path, maximum):
    path = Path(path).resolve()
    before = path.stat()
    if not path.is_file() or not 0 < before.st_size <= maximum:
        raise ValueError('SAVED_INTERESTS_FILE_SIZE')
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    after = path.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError('SAVED_INTERESTS_INPUT_CHANGED')
    return {'path': str(path), 'size_bytes': after.st_size, 'mtime_ns': after.st_mtime_ns,
            'sha256': digest.hexdigest()}


def _tag_list(value, *, optional=False):
    if value is None and optional:
        return None
    if (not isinstance(value, list) or len(value) > 4096
            or any(not isinstance(tag, str) or TAG.fullmatch(tag) is None for tag in value)
            or len(value) != len(set(value))):
        raise ValueError('SAVED_INTERESTS_TAG_LIST_INVALID')
    return sorted(value)


class SavedProvinceInterestsSnapshot:
    def __init__(self, path, observer, *, parser=None, parser_manifest=None):
        if not isinstance(observer, str) or TAG.fullmatch(observer) is None:
            raise ValueError('SAVED_INTERESTS_OBSERVER_INVALID')
        self.path = Path(path).resolve()
        self.observer = observer
        self._file = _pin(self.path, MAX_SAVE_BYTES)
        self._dependencies = []
        self._parser_info = {'kind': 'injected_parser'}
        if parser is None:
            parser = self._prepare_parser(parser_manifest or DEFAULT_MANIFEST)
        document = parser(self.path)
        if _pin(self.path, MAX_SAVE_BYTES) != self._file:
            raise ValueError('SAVED_INTERESTS_INPUT_CHANGED')
        self._load(document)
        self._assert_current()

    def _prepare_parser(self, manifest_path):
        manifest_pin = _pin(manifest_path, 128 * 1024)
        manifest = _json(Path(manifest_pin['path']).read_bytes())
        if (not isinstance(manifest, dict)
                or manifest.get('schema') != 'eu4.save_provinces.parser.v1'
                or manifest.get('jomini_commit') != JOMINI_COMMIT):
            raise ValueError('SAVED_INTERESTS_PARSER_MANIFEST')
        sources = manifest.get('sources')
        if not isinstance(sources, list) or not 1 <= len(sources) <= 512:
            raise ValueError('SAVED_INTERESTS_PARSER_SOURCES')
        records = [manifest.get('binary'), *sources]
        pins = [manifest_pin]
        seen = set()
        for record in records:
            if (not isinstance(record, dict) or not isinstance(record.get('path'), str)
                    or Path(record['path']).is_absolute() or '\\' in record['path']
                    or '..' in Path(record['path']).parts
                    or type(record.get('bytes')) is not int
                    or not isinstance(record.get('sha256'), str)
                    or SHA.fullmatch(record['sha256']) is None):
                raise ValueError('SAVED_INTERESTS_PARSER_PIN')
            source_path = (ROOT / record['path']).resolve()
            source_path.relative_to(ROOT)
            if source_path in seen:
                raise ValueError('SAVED_INTERESTS_DUPLICATE_PARSER_PIN')
            seen.add(source_path)
            measured = _pin(source_path, 128 * 1024 * 1024)
            if (measured['size_bytes'], measured['sha256']) != (record['bytes'], record['sha256']):
                raise ValueError('SAVED_INTERESTS_PARSER_PIN_MISMATCH')
            pins.append(measured)
        self._dependencies = pins
        self._parser_info = {'kind': 'jomini_eu4save', 'commit': JOMINI_COMMIT,
                             'manifest_sha256': manifest_pin['sha256'],
                             'binary_sha256': pins[1]['sha256']}
        executable = pins[1]['path']

        def parse(path):
            # A trusted, hash-checked local executable is configured by the
            # operator. Neither tool arguments nor save contents choose it.
            with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
                try:
                    result = subprocess.run([executable, str(path)], stdin=subprocess.DEVNULL,
                                            stdout=output, stderr=errors, timeout=45,
                                            close_fds=True)
                except (OSError, subprocess.TimeoutExpired) as exc:
                    raise ValueError('SAVED_INTERESTS_PARSER_EXECUTION_FAILED') from exc
                if result.returncode != 0:
                    raise ValueError('SAVED_INTERESTS_PARSER_FAILED')
                output.seek(0)
                raw = output.read(MAX_OUTPUT_BYTES + 1)
                if not raw or len(raw) > MAX_OUTPUT_BYTES:
                    raise ValueError('SAVED_INTERESTS_PARSER_OUTPUT_SIZE')
                return _json(raw)
        return parse

    def _load(self, document):
        if not isinstance(document, dict) or document.get('schema') != 'eu4.save_provinces_snapshot.v1':
            raise ValueError('SAVED_INTERESTS_DOCUMENT_SCHEMA')
        date = document.get('saved_date')
        if not isinstance(date, str) or re.fullmatch(r'[0-9]{1,4}\.[0-9]{1,2}\.[0-9]{1,2}', date) is None:
            raise ValueError('SAVED_INTERESTS_DATE_INVALID')
        year, month, day = map(int, date.split('.'))
        if not 1 <= year <= 9999 or not 1 <= month <= 12 or not 1 <= day <= (29 if month == 2 and year % 4 == 0 else 28 if month == 2 else 30 if month in (4, 6, 9, 11) else 31):
            raise ValueError('SAVED_INTERESTS_DATE_INVALID')
        version = document.get('saved_version')
        if (not isinstance(version, dict)
                or any(type(version.get(k)) is not int or not 0 <= version[k] <= 65535
                       for k in ('first', 'second', 'third', 'fourth'))):
            raise ValueError('SAVED_INTERESTS_VERSION_INVALID')
        self.version = '.'.join(str(version[k]) for k in ('first', 'second', 'third'))
        if self.version != '1.37.4':
            raise ValueError('SAVED_INTERESTS_VERSION_UNSUPPORTED')
        player = document.get('saved_player')
        if not isinstance(player, str) or TAG.fullmatch(player) is None:
            raise ValueError('SAVED_INTERESTS_PLAYER_INVALID')
        self._countries = frozenset(_tag_list(document.get('country_tags')))
        if self.observer not in self._countries:
            raise ValueError('SAVED_INTERESTS_OBSERVER_ABSENT')
        rows = document.get('provinces')
        if not isinstance(rows, list) or not 1 <= len(rows) <= 65535:
            raise ValueError('SAVED_INTERESTS_PROVINCES_INVALID')
        provinces = {}
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError('SAVED_INTERESTS_PROVINCE_INVALID')
            pid = row.get('province_id')
            if type(pid) is not int or not 1 <= pid <= 65535 or pid in provinces:
                raise ValueError('SAVED_INTERESTS_PROVINCE_ID_INVALID')
            provinces[pid] = {field: _tag_list(row.get(field), optional=field == 'discovered_by')
                              for field in ('cores', 'claims', 'discovered_by')}
        self.date, self.player = date, player
        self._provinces = provinces

    def _assert_current(self):
        if _pin(self.path, MAX_SAVE_BYTES) != self._file:
            raise ValueError('SAVED_INTERESTS_INPUT_CHANGED')
        for expected in self._dependencies:
            if _pin(expected['path'], 128 * 1024 * 1024) != expected:
                raise ValueError('SAVED_INTERESTS_PARSER_CHANGED')

    def context(self):
        reason = None
        try:
            self._assert_current()
        except (OSError, ValueError):
            reason = 'SAVED_INTERESTS_INPUT_OR_PARSER_CHANGED'
        return {'mode': 'recorded', 'status': 'unready' if reason else 'ready',
                'complete': reason is None, 'observer': self.observer,
                'game_version': self.version, 'game_date': self.date,
                'game_date_kind': 'saved_calendar_date', 'game_day': None,
                'session_id': None, 'world_id': None, 'game_sha256': None,
                'dll_sha256': None, 'paused': None,
                'archive': {**deepcopy(self._file), 'player': self.player},
                'parser': deepcopy(self._parser_info),
                'reasons': [{'code': reason}] if reason else []}

    def lookup(self, obj, field):
        self._assert_current()
        if field not in ('cores', 'claims'):
            return {'status': 'unsupported', 'reason': 'SAVED_INTEREST_FIELD_NOT_IMPLEMENTED'}
        common = {'scale': 1, 'period': 'saved_snapshot', 'complete': False,
                  'basis': 'saved_province_current_membership',
                  'visibility_basis': 'positive_snapshot_discovered_by',
                  'claim_expiry_evaluated': False}
        if obj['type'] == 'province':
            row = self._provinces.get(obj['province_id'])
            if row is None:
                return {'status': 'unknown', 'reason': 'PROVINCE_NOT_IN_SNAPSHOT'}
            if row['discovered_by'] is None or self.observer not in row['discovered_by']:
                return {'status': 'unknown', 'reason': 'SNAPSHOT_DISCOVERY_NOT_ESTABLISHED'}
            return {**common, 'status': 'known', 'value': list(row[field]), 'unit': 'country_tag'}
        country = obj['country']
        if country not in self._countries:
            return {'status': 'unknown', 'reason': 'COUNTRY_NOT_IN_SNAPSHOT'}
        known_rows = [(pid, row) for pid, row in self._provinces.items()
                      if row['discovered_by'] is not None and self.observer in row['discovered_by']]
        if not known_rows:
            return {'status': 'unknown', 'reason': 'SNAPSHOT_DISCOVERY_NOT_ESTABLISHED'}
        return {**common, 'status': 'known', 'unit': 'province_id',
                'value': sorted(pid for pid, row in known_rows if country in row[field]),
                'collection_scope': 'observer_discovered_provinces_in_snapshot',
                'unobserved_provinces_omitted': True}


__all__ = ['SavedProvinceInterestsSnapshot']
