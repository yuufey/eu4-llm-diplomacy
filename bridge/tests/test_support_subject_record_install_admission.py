"""Prototype rejection and strict v60 contracts through all static entries."""
import json
from pathlib import Path

import pytest

from bridge.tests.test_royal_record_install_admission import (
    _assert_all_accept, _assert_all_reject, _copy_candidate, _fixture_for_version, _set_cpp_hash, _write,
)
from tools import start_diplomacy_observer as start

ROOT = Path(__file__).resolve().parents[2]
CANDIDATE = ROOT / 'work/runtime/diplomacy-observer-20261110-support-subject-v60-353-001'
FORMAL = ROOT / 'work/runtime/diplomacy-observer-20261110-support-subject-v60-354-001'


def test_formal_v60_passes_all_three_static_entries():
    manifest = json.loads((FORMAL / 'build-manifest.json').read_text(encoding='utf-8'))
    assert manifest['prototype_only'] is False and manifest['formal_installation_admitted'] is True
    result = _assert_all_accept(manifest, FORMAL)
    assert result['observer_version'] == 60 and result['source_count'] == 187


@pytest.mark.parametrize('version', [60, 61])
def test_start_main_admits_formal_v60_and_rejects_future_before_readiness(version, tmp_path, monkeypatch):
    manifest, directory = _copy_candidate(FORMAL, tmp_path / 'candidate')
    manifest['version'] = version
    _write(manifest, directory)
    calls = []

    def ready(*args):
        calls.append('ready')
        return {'session_id': 'fixture'}, {}, None, 'fixture', []

    def install(*args):
        calls.append('install')

    monkeypatch.setattr(start, '_wait_until_ready', ready)
    monkeypatch.setattr(start, '_install_once', install)
    monkeypatch.setattr(start, 'get_value', lambda name: 'fixture-python')
    arguments = ['--native-text-codec', 'utf8', '--pid', '1', '--manifest', str(directory / 'build-manifest.json')]
    if version == 60:
        start.main(arguments)
        assert calls == ['ready', 'install']
    else:
        with pytest.raises(SystemExit, match='BUILD_MANIFEST_MISMATCH'):
            start.main(arguments)
        assert calls == []


def test_actual_v60_prototype_is_rejected_by_all_three_entries(tmp_path):
    manifest, directory = _copy_candidate(CANDIDATE, tmp_path / 'candidate')
    assert manifest['prototype_only'] is True and manifest['formal_installation_admitted'] is False
    _assert_all_reject(manifest, directory)


def test_temporary_formal_flags_admit_complete_v60_contract(tmp_path):
    manifest, directory = _copy_candidate(CANDIDATE, tmp_path / 'candidate')
    manifest.update(prototype_only=False, formal_installation_admitted=True)
    _write(manifest, directory)
    result = _assert_all_accept(manifest, directory)
    assert result['observer_version'] == 60 and result['source_count'] == 187


@pytest.mark.parametrize('version', [55, 56, 57, 58])
def test_current_cpp_disabled_support_blocks_preserve_older_contracts(tmp_path, version):
    manifest, directory = _fixture_for_version(tmp_path, version)
    (directory / start.MACRO_EVENT_ACK_SOURCE).write_bytes(
        (CANDIDATE / start.MACRO_EVENT_ACK_SOURCE).read_bytes())
    _set_cpp_hash(manifest, directory)
    _assert_all_accept(manifest, directory)


@pytest.mark.parametrize('mutation', [
    'wire_bool', 'wire_old', 'scope', 'capability', 'define_missing', 'source_missing',
    'ack_missing', 'ack_duplicate', 'ack_scope', 'marker_missing', 'marker_duplicate', 'marker_digit',
])
def test_v60_rejects_incomplete_contracts(tmp_path, mutation):
    manifest, directory = _copy_candidate(CANDIDATE, tmp_path / 'candidate')
    manifest.update(prototype_only=False, formal_installation_admitted=True)
    if mutation == 'wire_bool':
        manifest['native_relation_change_wire'] = True
    elif mutation == 'wire_old':
        manifest['native_relation_change_wire'] = 4
    elif mutation == 'scope':
        manifest['native_relation_change_scope'] = start.DIRECTED_RECORD_SCOPE
    elif mutation == 'capability':
        manifest[start.SUPPORT_SUBJECT_RECORD_CAPABILITY] = 1
    elif mutation == 'define_missing':
        manifest['compiler_arguments'].remove('-DBRIDGE_SUPPORT_SUBJECT_RECORD_OBSERVATION=1')
    elif mutation == 'source_missing':
        manifest['sources'] = [row for row in manifest['sources']
                               if row['name'] != start.SUPPORT_SUBJECT_RECORD_SOURCES[0]]
    else:
        path = directory / start.MACRO_EVENT_ACK_SOURCE
        text = path.read_text(encoding='utf-8')
        block = (start.SUPPORT_SUBJECT_RECORD_RELATION_ACK_BLOCK if mutation.startswith('ack_')
                 else start.SUPPORT_SUBJECT_RECORD_V60_VERSION_BLOCK)
        assert text.count(block) == 1
        if mutation.endswith('_missing'):
            text = text.replace(block, '')
        elif mutation.endswith('_duplicate'):
            text += '\n' + block
        elif mutation == 'ack_scope':
            text = text.replace(block, block.replace(start.SUPPORT_SUBJECT_RECORD_SCOPE, start.DIRECTED_RECORD_SCOPE))
        else:
            text = text.replace(block, block.replace("]='0';", "]='1';"))
        path.write_text(text, encoding='utf-8')
        _set_cpp_hash(manifest, directory)
    _assert_all_reject(manifest, directory)
