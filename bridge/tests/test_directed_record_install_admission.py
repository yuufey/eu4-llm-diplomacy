"""Formal v59 admission through the installation, control and probe entries."""
from copy import deepcopy
import json
from pathlib import Path
import shutil

import pytest

from bridge.tests.test_royal_record_install_admission import (
    _assert_all_accept, _assert_all_reject, _copy_candidate,
    _fixture_for_version, _set_cpp_hash, _write,
)
from tools import start_diplomacy_observer as start

ROOT = Path(__file__).resolve().parents[2]
FORMAL = ROOT / 'work/runtime/diplomacy-observer-20261110-directed-v59-351-001'
PROTOTYPE = ROOT / 'work/runtime/diplomacy-observer-20261110-directed-v59-350-001'


def test_formal_v59_passes_the_three_normal_static_entries():
    manifest = json.loads((FORMAL / 'build-manifest.json').read_text(encoding='utf-8'))
    assert manifest['version'] == 59 and len(manifest['sources']) == 185
    assert manifest['prototype_only'] is False and manifest['formal_installation_admitted'] is True
    assert manifest['native_relation_change_wire'] == 4
    assert manifest['native_relation_change_scope'] == start.DIRECTED_RECORD_SCOPE
    assert manifest[start.DIRECTED_RECORD_CAPABILITY] is True
    assert set(start.DIRECTED_RECORD_SOURCES) <= {row['name'] for row in manifest['sources']}
    assert manifest['compiler_arguments'].count(f'-D{start.DIRECTED_RECORD_DEFINE}=1') == 1
    result = _assert_all_accept(manifest, FORMAL)
    assert result['observer_version'] == 59 and result['source_count'] == 185


@pytest.mark.parametrize('version', [55, 56, 57, 58])
def test_current_cpp_disabled_directed_blocks_preserve_old_formal_contracts(version, tmp_path):
    manifest, directory = _fixture_for_version(tmp_path, version)
    shutil.copyfile(FORMAL / start.MACRO_EVENT_ACK_SOURCE, directory / start.MACRO_EVENT_ACK_SOURCE)
    _set_cpp_hash(manifest, directory)
    assert not start._compiler_define_values(manifest['compiler_arguments'], start.DIRECTED_RECORD_DEFINE)
    assert start.DIRECTED_RECORD_CAPABILITY not in manifest
    _assert_all_accept(manifest, directory)


@pytest.mark.parametrize('mutation', [
    'wire_bool', 'wire_old', 'scope', 'capability_missing', 'capability_integer',
    'define_missing', 'define_zero', 'define_duplicate', 'source_missing', 'source_duplicate',
    'source_tampered', 'ack_missing', 'ack_wrong_scope', 'ack_duplicate',
    'marker_missing', 'marker_wrong_digit', 'marker_duplicate',
    'prototype_true', 'formal_false', 'formal_integer',
])
def test_v59_rejects_incomplete_or_mixed_directed_contracts(tmp_path, mutation):
    manifest, directory = _copy_candidate(FORMAL, tmp_path / 'candidate')
    define = f'-D{start.DIRECTED_RECORD_DEFINE}=1'
    if mutation == 'wire_bool':
        manifest['native_relation_change_wire'] = True
    elif mutation == 'wire_old':
        manifest['native_relation_change_wire'] = 3
    elif mutation == 'scope':
        manifest['native_relation_change_scope'] = start.ROYAL_RECORD_SCOPE
    elif mutation == 'capability_missing':
        manifest.pop(start.DIRECTED_RECORD_CAPABILITY)
    elif mutation == 'capability_integer':
        manifest[start.DIRECTED_RECORD_CAPABILITY] = 1
    elif mutation.startswith('define_'):
        if mutation != 'define_duplicate':
            manifest['compiler_arguments'].remove(define)
        if mutation == 'define_zero':
            manifest['compiler_arguments'].append(f'-D{start.DIRECTED_RECORD_DEFINE}=0')
        elif mutation == 'define_duplicate':
            manifest['compiler_arguments'].append(define)
    elif mutation.startswith('source_'):
        name = start.DIRECTED_RECORD_SOURCES[0]
        row = next(row for row in manifest['sources'] if row['name'] == name)
        if mutation == 'source_missing':
            manifest['sources'].remove(row)
        elif mutation == 'source_duplicate':
            manifest['sources'].append(deepcopy(row))
        else:
            path = directory / name
            path.write_bytes(path.read_bytes() + b'\n// tampered\n')
    elif mutation.startswith(('ack_', 'marker_')):
        path = directory / start.MACRO_EVENT_ACK_SOURCE
        text = path.read_text(encoding='utf-8')
        block = (start.DIRECTED_RECORD_RELATION_ACK_BLOCK if mutation.startswith('ack_')
                 else start.DIRECTED_RECORD_V59_VERSION_BLOCK)
        if mutation.endswith('_missing'):
            text = text.replace(block, '')
        elif mutation.endswith('_duplicate'):
            text += '\n' + block + '\n'
        elif mutation == 'ack_wrong_scope':
            text = text.replace(block, block.replace(start.DIRECTED_RECORD_SCOPE, start.ROYAL_RECORD_SCOPE))
        else:
            text = text.replace(block, block.replace("]='9';", "]='0';"))
        path.write_text(text, encoding='utf-8')
        _set_cpp_hash(manifest, directory)
    elif mutation == 'prototype_true':
        manifest['prototype_only'] = True
    elif mutation == 'formal_false':
        manifest['formal_installation_admitted'] = False
    else:
        manifest['formal_installation_admitted'] = 1
    _assert_all_reject(manifest, directory)


def test_prototype_is_rejected_by_the_three_normal_entries(tmp_path):
    manifest, directory = _copy_candidate(PROTOTYPE, tmp_path / 'prototype')
    assert manifest['prototype_only'] is True and manifest['formal_installation_admitted'] is False
    _assert_all_reject(manifest, directory)


@pytest.mark.parametrize('version', [59, 60])
def test_actual_start_main_admits_formal_v59_and_rejects_future_before_readiness(
        version, tmp_path, monkeypatch):
    manifest, directory = _copy_candidate(FORMAL, tmp_path / 'candidate')
    manifest['version'] = version
    _write(manifest, directory)
    calls = []

    def ready(*args):
        calls.append('readiness')
        return {'session_id': 'fixture'}, {}, None, 'fixture', []

    def install(*args):
        calls.append('install')

    monkeypatch.setattr(start, '_wait_until_ready', ready)
    monkeypatch.setattr(start, '_install_once', install)
    monkeypatch.setattr(start, 'get_value', lambda name: 'fixture-python')
    arguments = ['--pid', '1', '--manifest', str(directory / 'build-manifest.json'),
                 '--native-text-codec', 'utf8']
    if version == 59:
        start.main(arguments)
        assert calls == ['readiness', 'install']
    else:
        with pytest.raises(SystemExit, match='BUILD_MANIFEST_MISMATCH'):
            start.main(arguments)
        assert calls == []
