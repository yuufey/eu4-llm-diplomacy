"""Pinned CWTools syntax parser for effective EU4 script files.

This boundary invokes the upstream library through a small .NET CLI. It does
not evaluate triggers, execute effects, or infer runtime mission membership.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import math
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from .saved_province_interests import _json, _pin
from work.local_config import get_path

ROOT = Path(__file__).resolve().parents[2]
SOURCE_MANIFEST = ROOT / 'tools/dotnet/cwtools-script/adapter-manifest.json'
DEFAULT_MANIFEST = ROOT / 'work/deps/cwtools-script/adapter-manifest.json'
PACKAGE_VERSION = '0.6.0-alpha'
SCHEMA = 'eu4.cwtools.script_ast.v1'
SOURCE_MANIFEST_SCHEMA = 'eu4.cwtools.parser.source.v1'
LOCAL_MANIFEST_SCHEMA = 'eu4.cwtools.parser.local.v1'
LEGACY_MANIFEST_SCHEMA = 'eu4.cwtools.parser.v1'
MAX_BATCH_FILES = 64
MAX_BATCH_BYTES = 4 * 1024 * 1024
MAX_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_ARTIFACT_BYTES = 128 * 1024 * 1024
MAX_NODES = 262144
MAX_DEPTH = 96
SHA = re.compile(r'[0-9a-f]{64}\Z')
BUILD_COMMAND = 'python tools/build_cwtools_parser.py'


def _build_required(reason):
    suffix = f' ({reason})' if reason else ''
    return ValueError(f'CWTOOLS_PARSER_BUILD_REQUIRED: run `{BUILD_COMMAND}`{suffix}')


def _input_pin(path):
    path = Path(path).resolve()
    stat = path.stat()
    if path.is_file() and stat.st_size == 0:
        return {'path': str(path), 'size_bytes': 0, 'mtime_ns': stat.st_mtime_ns,
                'sha256': hashlib.sha256(b'').hexdigest()}
    return _pin(path, MAX_BATCH_BYTES)


class CwtoolsScriptParser:
    def __init__(self, manifest=None, *, runner=None):
        self.manifest = Path(manifest or DEFAULT_MANIFEST).resolve()
        self._runner = runner or self._run
        if not self.manifest.is_file() and self.manifest == DEFAULT_MANIFEST.resolve():
            raise _build_required('local parser artifacts are missing')
        manifest_pin = _pin(self.manifest, 256 * 1024)
        document = _json(self.manifest.read_bytes())
        if not isinstance(document, dict):
            raise ValueError('CWTOOLS_MANIFEST_INVALID')
        self._pins = [manifest_pin]
        if document.get('schema') == LEGACY_MANIFEST_SCHEMA:
            self._load_legacy_manifest(document)
        elif document.get('schema') == LOCAL_MANIFEST_SCHEMA:
            self._load_local_manifest(document)
        else:
            raise ValueError('CWTOOLS_MANIFEST_INVALID')
        self._metadata = {'name': 'CWTools', 'version': PACKAGE_VERSION,
                          'manifest_sha256': manifest_pin['sha256'],
                          'semantics': 'syntax_only', 'conditions_evaluated': False,
                          'effects_executed': False}
        self.assert_current()

    def _repo_file(self, relative, code):
        if (not isinstance(relative, str) or not relative or Path(relative).is_absolute()
                or '\\' in relative or '..' in Path(relative).parts):
            raise ValueError(code)
        path = (ROOT / relative).resolve()
        try:
            path.relative_to(ROOT.resolve())
        except ValueError as exc:
            raise ValueError(code) from exc
        return path

    @staticmethod
    def _valid_pin_record(record):
        return (isinstance(record, dict) and isinstance(record.get('path'), str)
                and type(record.get('bytes')) is int and record['bytes'] > 0
                and isinstance(record.get('sha256'), str) and SHA.fullmatch(record['sha256']))

    def _pin_records(self, records, *, minimum, maximum, seen, error_prefix,
                     max_each=MAX_ARTIFACT_BYTES, max_total=MAX_ARTIFACT_BYTES):
        if not isinstance(records, list) or not minimum <= len(records) <= maximum:
            raise ValueError(f'{error_prefix}_FILES_INVALID')
        total = 0
        pinned = []
        for record in records:
            if not self._valid_pin_record(record):
                raise ValueError(f'{error_prefix}_PIN_INVALID')
            path = self._repo_file(record['path'], f'{error_prefix}_PATH_INVALID')
            if path in seen:
                raise ValueError(f'{error_prefix}_DUPLICATE_PIN')
            seen.add(path)
            measured = _pin(path, max_each)
            if (measured['size_bytes'], measured['sha256']) != (record['bytes'], record['sha256']):
                raise ValueError(f'{error_prefix}_PIN_MISMATCH')
            total += measured['size_bytes']
            if total > max_total:
                raise ValueError(f'{error_prefix}_SIZE_LIMIT')
            pinned.append(measured)
        self._pins.extend(pinned)
        return pinned

    def _load_legacy_manifest(self, document):
        if (document.get('package') != {'id': 'CWTools', 'version': PACKAGE_VERSION}
                or document.get('license') != 'MIT'):
            raise ValueError('CWTOOLS_MANIFEST_INVALID')
        self._max_batch_files = document.get('max_batch_files', 16)
        if type(self._max_batch_files) is not int or not 1 <= self._max_batch_files <= MAX_BATCH_FILES:
            raise ValueError('CWTOOLS_MANIFEST_BATCH_SIZE_INVALID')
        records = document.get('files')
        command = document.get('command')
        if (not isinstance(records, list) or not 2 <= len(records) <= 64
                or not isinstance(command, list) or len(command) != 2):
            raise ValueError('CWTOOLS_MANIFEST_FILES_INVALID')
        seen = set()
        pinned = self._pin_records(records, minimum=2, maximum=64, seen=seen,
                                   error_prefix='CWTOOLS_MANIFEST', max_total=512 * 1024 * 1024)
        self._command = []
        for relative in command:
            if not isinstance(relative, str):
                raise ValueError('CWTOOLS_COMMAND_INVALID')
            path = self._repo_file(relative, 'CWTOOLS_COMMAND_INVALID')
            if path not in seen:
                raise ValueError('CWTOOLS_COMMAND_NOT_PINNED')
            self._command.append(str(path))

    def _load_local_manifest(self, document):
        if (document.get('package') != {'id': 'CWTools', 'version': PACKAGE_VERSION}
                or document.get('license') != 'MIT'):
            raise ValueError('CWTOOLS_MANIFEST_INVALID')
        self._max_batch_files = document.get('max_batch_files')
        if type(self._max_batch_files) is not int or not 1 <= self._max_batch_files <= MAX_BATCH_FILES:
            raise ValueError('CWTOOLS_MANIFEST_BATCH_SIZE_INVALID')

        seen = {self.manifest}
        source = document.get('source_manifest')
        expected_source_path = SOURCE_MANIFEST.resolve().relative_to(ROOT.resolve()).as_posix()
        if (not isinstance(source, dict) or source.get('path') != expected_source_path
                or type(source.get('bytes')) is not int or source['bytes'] <= 0
                or not isinstance(source.get('sha256'), str) or not SHA.fullmatch(source['sha256'])):
            raise ValueError('CWTOOLS_SOURCE_MANIFEST_REFERENCE_INVALID')
        source_path = self._repo_file(source['path'], 'CWTOOLS_SOURCE_MANIFEST_PATH_INVALID')
        source_pin = _pin(source_path, 256 * 1024)
        if (source_pin['size_bytes'], source_pin['sha256']) != (source['bytes'], source['sha256']):
            raise _build_required('the local manifest is stale for the current source manifest')
        if source_path in seen:
            raise ValueError('CWTOOLS_MANIFEST_DUPLICATE_PIN')
        seen.add(source_path)
        self._pins.append(source_pin)
        source_document = _json(source_path.read_bytes())
        if (not isinstance(source_document, dict)
                or source_document.get('schema') != SOURCE_MANIFEST_SCHEMA
                or source_document.get('package') != {'id': 'CWTools', 'version': PACKAGE_VERSION}
                or source_document.get('license') != 'MIT'
                or source_document.get('target_framework') != 'net8.0'
                or source_document.get('max_batch_files') != self._max_batch_files
                or source_document.get('assembly') != 'work/deps/cwtools-script/publish/CwtoolsScript.dll'
                or source_document.get('output_directory') != 'work/deps/cwtools-script/publish'):
            raise ValueError('CWTOOLS_SOURCE_MANIFEST_INVALID')
        source_records = source_document.get('files')
        source_pins = self._pin_records(source_records, minimum=5, maximum=32, seen=seen,
                                        error_prefix='CWTOOLS_SOURCE', max_each=8 * 1024 * 1024,
                                        max_total=32 * 1024 * 1024)
        package_lock = next((Path(pin['path']) for pin in source_pins
                             if Path(pin['path']).name == 'packages.lock.json'), None)
        if package_lock is None:
            raise ValueError('CWTOOLS_PACKAGE_LOCK_MISSING')
        lock = _json(package_lock.read_bytes())
        locked = lock.get('dependencies', {}).get('net8.0', {}) if isinstance(lock, dict) else {}
        if (locked.get('CWTools', {}).get('resolved') != PACKAGE_VERSION
                or locked.get('FSharp.Core', {}).get('resolved') != '9.0.303'):
            raise ValueError('CWTOOLS_PACKAGE_LOCK_MISMATCH')

        artifact_directory = source_document['output_directory']
        assembly_relative = source_document['assembly']
        assembly_path = self._repo_file(assembly_relative, 'CWTOOLS_ARTIFACT_PATH_INVALID')
        artifacts = document.get('artifacts')
        try:
            artifact_pins = self._pin_records(artifacts, minimum=2, maximum=128, seen=seen,
                                              error_prefix='CWTOOLS_ARTIFACT',
                                              max_each=MAX_ARTIFACT_BYTES,
                                              max_total=MAX_ARTIFACT_BYTES)
        except (OSError, ValueError) as exc:
            raise _build_required(f'local parser artifacts are missing or invalid: {exc}') from exc
        directory_prefix = artifact_directory.rstrip('/') + '/'
        artifact_paths = {Path(record['path']) for record in artifacts}
        if (Path(assembly_relative) not in artifact_paths
                or any(not path.as_posix().startswith(directory_prefix) for path in artifact_paths)):
            raise _build_required('local parser artifact manifest is invalid')
        self._command = [self._dotnet_command(), str(assembly_path)]

    @staticmethod
    def _dotnet_command():
        configured = get_path('EU4_DOTNET', required=False)
        candidates = []
        if configured is not None:
            configured = Path(configured)
            if configured.is_dir():
                candidates.extend((configured / 'dotnet.exe', configured / 'dotnet'))
            else:
                candidates.append(configured)
        for candidate in candidates:
            if candidate.is_file():
                return str(candidate.resolve())
        if configured is not None:
            found = shutil.which(str(configured))
            if found:
                return found
        found = shutil.which('dotnet')
        if found:
            return found
        raise ValueError(
            'CWTOOLS_DOTNET_NOT_CONFIGURED: set EU4_DOTNET, then run '
            '`python tools/build_cwtools_parser.py`')

    def assert_current(self):
        for expected in self._pins:
            if _pin(expected['path'], 128 * 1024 * 1024) != expected:
                raise ValueError('CWTOOLS_PARSER_CHANGED')

    def context(self):
        try:
            self.assert_current()
        except (OSError, ValueError):
            return {'status': 'unready', 'complete': False, **deepcopy(self._metadata),
                    'reasons': [{'code': 'CWTOOLS_PARSER_CHANGED'}]}
        return {'status': 'ready', 'complete': True, **deepcopy(self._metadata), 'reasons': []}

    @staticmethod
    def _run(command):
        # Files and executable are selected by the operator/index, never by an
        # information query. Temporary streams keep stdout off the pipe heap.
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
            try:
                result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=output,
                                        stderr=errors, timeout=60, close_fds=True, cwd=ROOT)
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise ValueError('CWTOOLS_PARSER_EXECUTION_FAILED') from exc
            output.seek(0)
            raw = output.read(MAX_OUTPUT_BYTES + 1)
            if not raw or len(raw) > MAX_OUTPUT_BYTES:
                raise ValueError('CWTOOLS_PARSER_OUTPUT_SIZE')
            document = _json(raw)
            # The CLI may report a syntax error per file with a nonzero exit;
            # its document still has to satisfy the ordinary strict schema.
            if result.returncode not in (0, 1):
                raise ValueError('CWTOOLS_PARSER_PROCESS_FAILED')
            return document

    def parse_files(self, paths):
        paths = [Path(path).resolve() for path in paths]
        if len(paths) != len(set(paths)):
            raise ValueError('CWTOOLS_DUPLICATE_INPUT')
        output, batch, size = {}, [], 0
        for path in paths:
            measured = _input_pin(path)
            if batch and (len(batch) == self._max_batch_files or size + measured['size_bytes'] > MAX_BATCH_BYTES):
                output.update(self._parse_batch(batch))
                batch, size = [], 0
            batch.append((path, measured))
            size += measured['size_bytes']
        if batch:
            output.update(self._parse_batch(batch))
        return output

    def _parse_batch(self, batch):
        self.assert_current()
        document = self._runner([*self._command, *(str(path) for path, _ in batch)])
        self.assert_current()
        parser = document.get('parser', {}) if isinstance(document, dict) else {}
        rows = document.get('files') if isinstance(document, dict) else None
        if (not isinstance(document, dict) or document.get('schema') != SCHEMA
                or not isinstance(parser, dict) or parser.get('name') != 'CWTools'
                or parser.get('version') != PACKAGE_VERSION or not isinstance(rows, list)
                or len(rows) != len(batch)):
            raise ValueError('CWTOOLS_OUTPUT_SCHEMA_INVALID')
        output = {}
        for row, (path, expected) in zip(rows, batch):
            if (not isinstance(row, dict) or Path(row.get('path', '')).resolve() != path
                    or row.get('sha256') != expected['sha256']
                    or type(row.get('bytes')) is not int or row['bytes'] != expected['size_bytes']
                    or type(row.get('parse_ok')) is not bool
                    or row.get('encoding') not in ('utf-8', 'utf-8-bom', 'utf-8-sig', 'windows-1252')
                    or not isinstance(row.get('items'), list) or not isinstance(row.get('errors'), list)):
                raise ValueError('CWTOOLS_FILE_RESULT_INVALID')
            if _input_pin(path) != expected:
                raise ValueError('CWTOOLS_INPUT_CHANGED')
            if not row['parse_ok']:
                output[str(path)] = {'error': 'CWTOOLS_SCRIPT_PARSE_FAILED',
                                     'diagnostics': deepcopy(row['errors'][:16])}
                continue
            if row['errors']:
                raise ValueError('CWTOOLS_SUCCESS_HAS_ERRORS')
            raw = path.read_bytes()
            encoding = {'name': row['encoding'], 'structural_only': False}
            if row['encoding'] == 'windows-1252':
                # .NET's codepage 1252 preserves its five undefined byte slots
                # as the corresponding C1 controls. Python's strict codec
                # rejects those slots. Preserve every byte, matching the CLI
                # decoder rather than dropping or replacing source content.
                text = raw.decode('cp1252', errors='surrogateescape')
                undefined = [byte for byte in (0x81, 0x8d, 0x8f, 0x90, 0x9d) if byte in raw]
                text = text.translate({0xdc00 + byte: byte for byte in undefined})
                if undefined:
                    encoding.update(structural_only=True,
                                    c1_byte_slots_preserved=[f'{byte:02x}' for byte in undefined])
            else:
                text = raw.decode('utf-8-sig')
            output[str(path)] = {'nodes': self._normalise(row['items']), 'text': text,
                                 'encoding': encoding,
                                 'parser': deepcopy(self._metadata)}
        return output

    @staticmethod
    def _normalise(items):
        from .mission_definitions import _ScriptNode
        count = 0

        def nodes(rows, depth):
            nonlocal count
            if depth > MAX_DEPTH or not isinstance(rows, list):
                raise ValueError('CWTOOLS_AST_DEPTH_OR_SHAPE')
            output = []
            for row in rows:
                count += 1
                if count > MAX_NODES or not isinstance(row, dict):
                    raise ValueError('CWTOOLS_AST_NODE_LIMIT_OR_SHAPE')
                kind = row.get('value_kind')
                statement = row.get('statement_kind')
                if kind == 'comment' and statement == 'comment':
                    continue
                line, end = row.get('source_line'), row.get('end_line')
                if type(line) is not int or type(end) is not int or not 1 <= line <= end:
                    raise ValueError('CWTOOLS_AST_LOCATION')
                key, value, children = row.get('key'), row.get('value'), row.get('children', [])
                operator = row.get('operator')
                if operator not in (None, '=', '==', '!=', '<', '>', '<=', '>=', '?='):
                    raise ValueError('CWTOOLS_AST_OPERATOR')
                if statement == 'bare_value' and (key is not None or operator is not None):
                    raise ValueError('CWTOOLS_AST_BARE_SHAPE')
                if statement == 'key_value' and operator is None:
                    raise ValueError('CWTOOLS_AST_ASSIGNMENT_MISSING')
                if statement == 'bare_value':
                    if kind == 'block':
                        # CWTools intentionally represents `command { ... }`
                        # as adjacent bare-name and bare-clause statements.
                        # Join that library result for the existing mission
                        # AST contract; no input is reparsed or discarded.
                        start_column = row.get('source_column')
                        if type(start_column) is not int or start_column < 0:
                            raise ValueError('CWTOOLS_AST_COLUMN')
                        if (operator is not None or value is not None or not output
                                or output[-1].kind != 'bare' or output[-1].assignment is not None):
                            raise ValueError('CWTOOLS_UNBOUND_BARE_CLAUSE')
                        previous = output[-1]
                        previous.kind, previous.raw_value, previous.end_line = 'block', '{', end
                        previous.children = nodes(children, depth + 1)
                        column = row.get('end_column')
                        if type(column) is not int or column < 0:
                            raise ValueError('CWTOOLS_AST_COLUMN')
                        previous.end_column = column
                        previous.cwtools_normalization = 'adjacent_bare_name_and_clause'
                        continue
                    key = CwtoolsScriptParser._scalar_text(kind, value)
                    if children:
                        raise ValueError('CWTOOLS_AST_BARE_CHILDREN')
                    value, normal_kind = None, 'bare'
                elif kind == 'block' and statement == 'key_value':
                    if value is not None:
                        raise ValueError('CWTOOLS_AST_BLOCK_VALUE')
                    normal_kind = 'block'
                    value = None
                else:
                    normal_kind = 'scalar'
                    value = CwtoolsScriptParser._scalar_text(kind, value)
                    if statement != 'key_value' or children:
                        raise ValueError('CWTOOLS_AST_SCALAR')
                if not isinstance(key, str) or not key or len(key) > 65536:
                    raise ValueError('CWTOOLS_AST_KEY')
                node = _ScriptNode(key=key, line=line, end_line=end, value=value,
                    children=nodes(children, depth + 1), kind=normal_kind, assignment=operator,
                    raw_key=row.get('raw_key', key), raw_value=row.get('raw_value', value))
                for name in ('source_column', 'end_column'):
                    column = row.get(name)
                    if type(column) is not int or column < 0:
                        raise ValueError('CWTOOLS_AST_COLUMN')
                    setattr(node, name, column)
                output.append(node)
            return output
        return nodes(items, 0)

    @staticmethod
    def _scalar_text(kind, value):
        if kind in ('string', 'quoted_string', 'date') and isinstance(value, str):
            return value
        if kind == 'boolean' and type(value) is bool:
            return 'yes' if value else 'no'
        if kind == 'integer' and type(value) is int:
            return str(value)
        if kind == 'decimal' and type(value) in (int, float) and math.isfinite(value):
            return str(value)
        raise ValueError('CWTOOLS_AST_SCALAR_TYPE')


__all__ = ['CwtoolsScriptParser', 'DEFAULT_MANIFEST']
