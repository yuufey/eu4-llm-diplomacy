"""Validate v61 and its inherited source contract through all entry points."""
import json
from pathlib import Path

import pytest

from bridge.tests.test_royal_record_install_admission import (
    _assert_all_accept, _assert_all_reject, _copy_candidate, _fixture_for_version,
    _set_cpp_hash, _write,
)
from tools import start_diplomacy_observer as start
from tools import control_information_battle_observer as control

ROOT = Path(__file__).resolve().parents[2]
FORMAL = ROOT / 'work/runtime/diplomacy-observer-20261110-rival-record-v61-360-001'
PROTOTYPE = ROOT / 'work/runtime/diplomacy-observer-20261110-rival-record-v61-359-003'
V60 = ROOT / 'work/runtime/diplomacy-observer-20261110-support-subject-v60-354-001'
SHARED = ROOT / 'work/runtime/diplomacy-observer-20261110-rival-record-v61-360-003'
LIFETIME = ROOT / 'work/runtime/diplomacy-observer-20261114-war-lifetime-v61-002'


def test_current_lifetime_release_passes_static_entries():
    manifest = json.loads((LIFETIME / 'build-manifest.json').read_text(encoding='utf-8-sig'))
    assert manifest['dll_sha256'] == 'b6e0f879d99d84cd954315bdb8a9ecd880754c29df8b3ba7af7e0b22fe55a9fa'
    result = _assert_all_accept(manifest, LIFETIME)
    assert result['observer_version'] == 61 and result['source_count'] == 191


def test_current_lifetime_start_reaches_readiness_with_real_manifest(monkeypatch):
    class ReadinessReached(Exception):
        pass

    def ready(pid, manifest, directory, confirm, wait):
        assert pid == 45128 and manifest['version'] == 61
        assert directory == LIFETIME and confirm is True and wait == 300
        raise ReadinessReached

    def install(*args):
        pytest.fail('The manifest regression must stop at the readiness boundary')

    original_exists = Path.exists
    installation = LIFETIME / 'installation.json'
    # The recorded build is shared with the real installer. Only its mutable
    # installation lifecycle is mocked, so this remains repeatable after load.
    monkeypatch.setattr(Path, 'exists',
                        lambda path: False if path == installation else original_exists(path))
    monkeypatch.setattr(start, '_wait_until_ready', ready)
    monkeypatch.setattr(start, '_install_once', install)
    with pytest.raises(ReadinessReached):
        start.main(['--pid', '45128', '--manifest', str(LIFETIME / 'build-manifest.json'),
                    '--confirm-load-warning', '--native-text-codec', 'eu4_escape',
                    '--wait-ready', '300'])


@pytest.mark.parametrize('mutation', [
    'missing_registry', 'duplicate_registry', 'extra_source', 'header_hash',
])
def test_current_lifetime_rejects_changed_source_contract(mutation):
    manifest = json.loads((LIFETIME / 'build-manifest.json').read_text(encoding='utf-8-sig'))
    registry = next(row for row in manifest['sources'] if row['name'] == start.WAR_REGISTRY_SOURCE)
    if mutation == 'missing_registry':
        manifest['sources'].remove(registry)
    elif mutation == 'duplicate_registry':
        manifest['sources'].append(dict(registry))
    elif mutation == 'extra_source':
        manifest['sources'].append({'name': 'unadmitted-source.h', 'sha256': '0' * 64})
    else:
        registry['sha256'] = '0' * 64
    with pytest.raises(SystemExit, match='BUILD_MANIFEST_MISMATCH'):
        start._validate_information_battle_manifest(manifest, LIFETIME)
    with pytest.raises(control.ControlError) as caught:
        control._validate_manifest(manifest, LIFETIME)
    assert caught.value.reason == 'BUILD_MANIFEST_MISMATCH'


def test_formal_v61_passes_all_three_static_entries():
    manifest = json.loads((FORMAL / 'build-manifest.json').read_text(encoding='utf-8'))
    result = _assert_all_accept(manifest, FORMAL)
    assert result['observer_version'] == 61 and result['source_count'] == 189


def test_shared_entry_release_passes_all_three_static_entries():
    manifest = json.loads((SHARED / 'build-manifest.json').read_text(encoding='utf-8-sig'))
    result = _assert_all_accept(manifest, SHARED)
    assert result['observer_version'] == 61 and result['source_count'] == 189


def test_actual_v61_prototype_remains_rejected(tmp_path):
    manifest, directory = _copy_candidate(PROTOTYPE, tmp_path / 'candidate')
    assert manifest['prototype_only'] is True
    _assert_all_reject(manifest, directory)


@pytest.mark.parametrize('version', [61, 62])
def test_main_keeps_real_version_for_readiness_and_install(version, tmp_path, monkeypatch):
    manifest, directory = _copy_candidate(FORMAL, tmp_path / 'candidate')
    manifest['version'] = version
    _write(manifest, directory)
    calls = []

    def ready(*args):
        calls.append(('ready', args[1]['version']))
        return {'session_id': 'fixture'}, {}, None, 'fixture', []

    def install(*args):
        assert args[3].name == 'eu4_bridge_diplomacy_observer_v61.dll'
        assert args[3].is_file()
        calls.append(('install', args[1]['version']))

    monkeypatch.setattr(start, '_wait_until_ready', ready)
    monkeypatch.setattr(start, '_install_once', install)
    monkeypatch.setattr(start, 'get_value', lambda name: 'fixture-python')
    arguments = ['--pid', '1', '--manifest', str(directory / 'build-manifest.json'),
                 '--native-text-codec', 'utf8']
    if version == 61:
        start.main(arguments)
        assert calls == [('ready', 61), ('install', 61)]
    else:
        with pytest.raises(SystemExit, match='BUILD_MANIFEST_MISMATCH'):
            start.main(arguments)
        assert calls == []


def test_split_compiler_define_is_accepted(tmp_path):
    manifest, directory = _copy_candidate(FORMAL, tmp_path / 'candidate')
    arguments = manifest['compiler_arguments']
    index = arguments.index('-D' + start.RIVAL_RECORD_DEFINE + '=1')
    arguments[index:index + 1] = ['-D', start.RIVAL_RECORD_DEFINE + '=1']
    _write(manifest, directory)
    _assert_all_accept(manifest, directory)


@pytest.mark.parametrize('mutation', [
    'wire_bool', 'wire_old', 'scope', 'count_basis', 'capability', 'capability_missing',
    'define_missing', 'define_duplicate', 'define_zero', 'define_bare',
    'source_missing', 'source_duplicate', 'source_tampered', 'source_case',
    'parent_missing', 'prototype_true', 'formal_false',
    'ack_missing', 'ack_duplicate', 'ack_scope', 'ack_count_basis',
    'marker_missing', 'marker_duplicate', 'marker_digit',
])
def test_v61_rejects_incomplete_or_mixed_contracts(tmp_path, mutation):
    manifest, directory = _copy_candidate(FORMAL, tmp_path / 'candidate')
    define = '-D' + start.RIVAL_RECORD_DEFINE + '=1'
    if mutation == 'wire_bool':
        manifest['native_rival_change_wire'] = True
    elif mutation == 'wire_old':
        manifest['native_rival_change_wire'] = 1
    elif mutation == 'scope':
        manifest['native_rival_change_scope'] = start.RIVAL_CHANGE_SCOPE
    elif mutation == 'count_basis':
        manifest['native_rival_record_count_basis'] = 'physical_nodes'
    elif mutation == 'capability':
        manifest[start.RIVAL_RECORD_CAPABILITY] = 1
    elif mutation == 'capability_missing':
        manifest.pop(start.RIVAL_RECORD_CAPABILITY)
    elif mutation == 'define_missing':
        manifest['compiler_arguments'].remove(define)
    elif mutation == 'define_duplicate':
        manifest['compiler_arguments'].append(define)
    elif mutation == 'define_zero':
        manifest['compiler_arguments'][manifest['compiler_arguments'].index(define)] = define[:-1] + '0'
    elif mutation == 'define_bare':
        manifest['compiler_arguments'][manifest['compiler_arguments'].index(define)] = define[:-2]
    elif mutation == 'source_missing':
        manifest['sources'] = [row for row in manifest['sources']
                               if row['name'] != start.RIVAL_RECORD_SOURCES[0]]
    elif mutation == 'source_duplicate':
        manifest['sources'].append(dict(manifest['sources'][-1]))
    elif mutation == 'source_tampered':
        with (directory / start.RIVAL_RECORD_SOURCES[0]).open('ab') as stream:
            stream.write(b'\n// changed\n')
    elif mutation == 'source_case':
        next(row for row in manifest['sources'] if row['name'] == start.RIVAL_RECORD_SOURCES[0])['name'] = start.RIVAL_RECORD_SOURCES[0].upper()
    elif mutation == 'parent_missing':
        manifest.pop(start.SUPPORT_SUBJECT_RECORD_CAPABILITY)
    elif mutation == 'prototype_true':
        manifest['prototype_only'] = True
    elif mutation == 'formal_false':
        manifest['formal_installation_admitted'] = False
    else:
        path = directory / start.MACRO_EVENT_ACK_SOURCE
        text = path.read_text(encoding='utf-8')
        block = start.RIVAL_RECORD_ACK_BLOCK if mutation.startswith('ack_') else start.RIVAL_RECORD_V61_VERSION_BLOCK
        assert text.count(block) == 1
        if mutation.endswith('_missing'):
            replacement = ''
        elif mutation.endswith('_duplicate'):
            replacement = block + '\n' + block
        elif mutation == 'ack_scope':
            replacement = block.replace(start.RIVAL_RECORD_SCOPE, start.RIVAL_CHANGE_SCOPE)
        elif mutation == 'ack_count_basis':
            replacement = block.replace(start.RIVAL_RECORD_COUNT_BASIS, 'physical_nodes')
        else:
            replacement = block.replace("]='1';", "]='2';")
        path.write_text(text.replace(block, replacement), encoding='utf-8')
        _set_cpp_hash(manifest, directory)
    _assert_all_reject(manifest, directory)


@pytest.mark.parametrize('version', [55, 56, 57, 58, 60])
def test_current_cpp_preserves_disabled_older_contracts(version, tmp_path):
    if version == 60:
        manifest, directory = _copy_candidate(V60, tmp_path / 'candidate')
    else:
        manifest, directory = _fixture_for_version(tmp_path, version)
    (directory / start.MACRO_EVENT_ACK_SOURCE).write_bytes((FORMAL / start.MACRO_EVENT_ACK_SOURCE).read_bytes())
    _set_cpp_hash(manifest, directory)
    _assert_all_accept(manifest, directory)


@pytest.mark.parametrize('feature', ['capability', 'define', 'source'])
def test_old_v60_rejects_v61_features(feature, tmp_path):
    manifest, directory = _copy_candidate(V60, tmp_path / 'candidate')
    if feature == 'capability':
        manifest[start.RIVAL_RECORD_CAPABILITY] = False
    elif feature == 'define':
        manifest['compiler_arguments'].append('-D' + start.RIVAL_RECORD_DEFINE + '=1')
    else:
        manifest['sources'].append({'name': start.RIVAL_RECORD_SOURCES[0], 'sha256': '0' * 64})
    _assert_all_reject(manifest, directory)
