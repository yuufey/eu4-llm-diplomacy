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
import subprocess
import tempfile

from .saved_province_interests import _json, _pin

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = ROOT / 'tools/dotnet/cwtools-script/adapter-manifest.json'
PACKAGE_VERSION = '0.6.0-alpha'
SCHEMA = 'eu4.cwtools.script_ast.v1'
MAX_BATCH_FILES = 64
MAX_BATCH_BYTES = 4 * 1024 * 1024
MAX_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_NODES = 262144
MAX_DEPTH = 96
SHA = re.compile(r'[0-9a-f]{64}\Z')


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
        manifest_pin = _pin(self.manifest, 256 * 1024)
        document = _json(self.manifest.read_bytes())
        if (not isinstance(document, dict) or document.get('schema') != 'eu4.cwtools.parser.v1'
                or document.get('package') != {'id': 'CWTools', 'version': PACKAGE_VERSION}
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
        self._pins = [manifest_pin]
        seen = set()
        for record in records:
            if (not isinstance(record, dict) or not isinstance(record.get('path'), str)
                    or Path(record['path']).is_absolute() or '\\' in record['path']
                    or '..' in Path(record['path']).parts or type(record.get('bytes')) is not int
                    or not isinstance(record.get('sha256'), str) or not SHA.fullmatch(record['sha256'])):
                raise ValueError('CWTOOLS_MANIFEST_PIN_INVALID')
            path = (ROOT / record['path']).resolve()
            path.relative_to(ROOT)
            if path in seen:
                raise ValueError('CWTOOLS_MANIFEST_DUPLICATE_PIN')
            seen.add(path)
            measured = _pin(path, 128 * 1024 * 1024)
            if (measured['size_bytes'], measured['sha256']) != (record['bytes'], record['sha256']):
                raise ValueError('CWTOOLS_MANIFEST_PIN_MISMATCH')
            self._pins.append(measured)
        self._command = []
        for relative in command:
            if not isinstance(relative, str):
                raise ValueError('CWTOOLS_COMMAND_INVALID')
            path = (ROOT / relative).resolve()
            if path not in seen:
                raise ValueError('CWTOOLS_COMMAND_NOT_PINNED')
            self._command.append(str(path))
        self._metadata = {'name': 'CWTools', 'version': PACKAGE_VERSION,
                          'manifest_sha256': manifest_pin['sha256'],
                          'semantics': 'syntax_only', 'conditions_evaluated': False,
                          'effects_executed': False}
        self.assert_current()

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
                                        stderr=errors, timeout=60, close_fds=True)
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
