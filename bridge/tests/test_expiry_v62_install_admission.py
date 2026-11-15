"""Bounded v62 admission fixtures inherit the complete v61 contract."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from tools import control_information_battle_observer as control
from tools import start_diplomacy_observer as start
from work import probe_information_battle_v23 as probe


ROOT = Path(__file__).resolve().parents[2]
CANDIDATE = ROOT / 'work/runtime/diplomacy-observer-20261115-expiry-v62-002'
V61 = ROOT / 'work/runtime/diplomacy-observer-20261115-war-active-roster-v61-001'


def _manifest(directory=CANDIDATE):
    return json.loads((directory / 'build-manifest.json').read_text(encoding='utf-8-sig'))


class _SourceOverlay:
    """Keep unchanged pinned files in place and copy only the mutated source."""
    def __init__(self, baseline, overrides):
        self.baseline, self.overrides = baseline, overrides

    def __truediv__(self, name):
        return self.overrides.get(name, self.baseline / name)


def _changed_cpp(tmp_path, manifest, text, baseline=CANDIDATE):
    path = tmp_path / start.MACRO_EVENT_ACK_SOURCE
    path.write_text(text, encoding='utf-8')
    next(row for row in manifest['sources'] if row['name'] == path.name)['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
    return _SourceOverlay(baseline, {path.name: path})


def _without(manifest, feature):
    for key in ('capability', 'wire', 'scope_key'):
        manifest.pop(feature[key])
    manifest['sources'] = [row for row in manifest['sources'] if not row['name'].startswith(feature['prefix'])]
    manifest['compiler_arguments'].remove('-D' + feature['define'] + '=1')


def _reject(manifest, directory=CANDIDATE):
    with pytest.raises(SystemExit, match='BUILD_MANIFEST_MISMATCH'):
        start._validate_information_battle_manifest(manifest, directory)
    with pytest.raises(control.ControlError) as caught:
        control._validate_manifest(manifest, directory)
    assert caught.value.reason == 'BUILD_MANIFEST_MISMATCH'


def test_real_v62_candidate_passes_all_static_entries():
    manifest = _manifest()
    assert manifest['dll_sha256'] == '2e377ae3282e08c3f048a01329e0f77634d7e9843fee32c471256c62f5f375d0'
    start._validate_information_battle_manifest(manifest, CANDIDATE)
    control._validate_manifest(manifest, CANDIDATE)
    result = probe._manifest_static_guard(CANDIDATE)
    assert result['status'] == 'observed' and not result['unknown_conditions']
    assert result['observer_version'] == 62 and result['source_count'] == 199


def test_normal_main_keeps_real_v62_manifest_and_dll_for_readiness_and_install(monkeypatch):
    calls = []

    def ready(pid, manifest, directory, confirm, wait):
        assert pid == 1 and manifest['version'] == 62 and directory == CANDIDATE
        assert confirm is True and wait == 300
        calls.append(('ready', manifest['version']))
        return {'session_id': 'offline-fixture'}, {}, None, 'fixture', []

    def install(pid, manifest, directory, dll, python, *rest):
        assert pid == 1 and manifest['version'] == 62 and directory == CANDIDATE
        assert dll == CANDIDATE / 'eu4_bridge_diplomacy_observer_v62.dll' and dll.is_file()
        assert python == 'fixture-python' and rest[-1] == 'eu4_escape'
        calls.append(('install', manifest['version']))

    original_exists = Path.exists
    monkeypatch.setattr(Path, 'exists', lambda path: False if path == CANDIDATE / 'installation.json' else original_exists(path))
    monkeypatch.setattr(start, '_wait_until_ready', ready)
    monkeypatch.setattr(start, '_install_once', install)
    monkeypatch.setattr(start, 'get_value', lambda name: 'fixture-python')
    start.main(['--pid', '1', '--manifest', str(CANDIDATE / 'build-manifest.json'),
                '--confirm-load-warning', '--native-text-codec', 'eu4_escape', '--wait-ready', '300'])
    assert calls == [('ready', 62), ('install', 62)]


@pytest.mark.parametrize('removed', start.EXPIRY_FEATURES, ids=lambda feature: feature['prefix'])
def test_each_feature_can_be_selected_independently_in_source_contract(removed):
    manifest = _manifest()
    _without(manifest, removed)
    assert len(manifest['sources']) == 195
    start._validate_information_battle_manifest(manifest, CANDIDATE)


def test_v62_requires_an_enabled_expiry_feature():
    manifest = _manifest()
    for feature in start.EXPIRY_FEATURES:
        _without(manifest, feature)
    _reject(manifest)


@pytest.mark.parametrize('feature', start.EXPIRY_FEATURES, ids=lambda feature: feature['prefix'])
@pytest.mark.parametrize('mutation', [
    'capability_missing', 'capability_integer', 'capability_false', 'wire_bool', 'wire_other', 'scope',
    'define_missing', 'define_zero', 'define_bare', 'define_duplicate',
    'source_missing', 'source_duplicate', 'source_case', 'source_hash',
])
def test_v62_rejects_partial_feature_contracts(feature, mutation):
    manifest = _manifest()
    define = '-D' + feature['define'] + '=1'
    if mutation == 'capability_missing':
        manifest.pop(feature['capability'])
    elif mutation == 'capability_integer':
        manifest[feature['capability']] = 1
    elif mutation == 'capability_false':
        manifest[feature['capability']] = False
    elif mutation == 'wire_bool':
        manifest[feature['wire']] = True
    elif mutation == 'wire_other':
        manifest[feature['wire']] = 2
    elif mutation == 'scope':
        manifest[feature['scope_key']] = 'all_records'
    elif mutation == 'define_missing':
        manifest['compiler_arguments'].remove(define)
    elif mutation == 'define_zero':
        manifest['compiler_arguments'][manifest['compiler_arguments'].index(define)] = define[:-1] + '0'
    elif mutation == 'define_bare':
        manifest['compiler_arguments'][manifest['compiler_arguments'].index(define)] = define[:-2]
    elif mutation == 'define_duplicate':
        manifest['compiler_arguments'].append(define)
    else:
        row = next(row for row in manifest['sources'] if row['name'] == feature['prefix'] + '.h')
        if mutation == 'source_missing':
            manifest['sources'].remove(row)
        elif mutation == 'source_duplicate':
            manifest['sources'].append(deepcopy(row))
        elif mutation == 'source_case':
            row['name'] = row['name'].upper()
        else:
            row['sha256'] = '0' * 64
    _reject(manifest)


@pytest.mark.parametrize('feature', start.EXPIRY_FEATURES, ids=lambda feature: feature['prefix'])
@pytest.mark.parametrize('mutation', ['missing', 'duplicate', 'wire'])
def test_v62_requires_exact_enabled_ack_block(feature, mutation, tmp_path):
    manifest = _manifest()
    text = (CANDIDATE / start.MACRO_EVENT_ACK_SOURCE).read_text(encoding='utf-8')
    block = feature['ack']
    assert text.count(block) == 1
    replacement = {'missing': '', 'duplicate': block + '\n' + block,
                   'wire': block.replace(feature['wire'] + '\\":1', feature['wire'] + '\\":2')}[mutation]
    assert replacement != block
    directory = _changed_cpp(tmp_path, manifest, text.replace(block, replacement))
    _reject(manifest, directory)


@pytest.mark.parametrize('mutation', ['missing', 'duplicate', 'digit'])
def test_v62_requires_exact_version_selector(mutation, tmp_path):
    manifest = _manifest()
    text = (CANDIDATE / start.MACRO_EVENT_ACK_SOURCE).read_text(encoding='utf-8')
    block = start.EXPIRY_V62_VERSION_BLOCK
    replacement = {'missing': start.RIVAL_RECORD_V61_VERSION_BLOCK,
                   'duplicate': block + '\n' + block,
                   'digit': block.replace("]='2';", "]='3';")}[mutation]
    directory = _changed_cpp(tmp_path, manifest, text.replace(block, replacement))
    _reject(manifest, directory)


@pytest.mark.parametrize('feature', start.EXPIRY_FEATURES, ids=lambda feature: feature['prefix'])
def test_v62_accepts_split_define(feature):
    manifest = _manifest()
    index = manifest['compiler_arguments'].index('-D' + feature['define'] + '=1')
    manifest['compiler_arguments'][index:index + 1] = ['-D', feature['define'] + '=1']
    start._validate_information_battle_manifest(manifest, CANDIDATE)


@pytest.mark.parametrize('mutation', ['parent_missing', 'prototype', 'formal_integer', 'extra_source'])
def test_v62_keeps_inherited_admission_rules(mutation):
    manifest = _manifest()
    if mutation == 'parent_missing':
        manifest.pop(start.RIVAL_RECORD_CAPABILITY)
    elif mutation == 'prototype':
        manifest['prototype_only'] = True
    elif mutation == 'formal_integer':
        manifest['formal_installation_admitted'] = 1
    else:
        manifest['sources'].append({'name': 'extra-source.h', 'sha256': '0' * 64})
    _reject(manifest)


def test_disabled_v62_selector_preserves_frozen_v61_source_contract(tmp_path):
    manifest = _manifest(V61)
    text = (CANDIDATE / start.MACRO_EVENT_ACK_SOURCE).read_text(encoding='utf-8')
    directory = _changed_cpp(tmp_path, manifest, text, baseline=V61)
    start._validate_information_battle_manifest(manifest, directory)


@pytest.mark.parametrize('feature', start.EXPIRY_FEATURES, ids=lambda feature: feature['prefix'])
@pytest.mark.parametrize('signal', ['capability', 'wire', 'scope_key', 'define', 'source'])
def test_v61_rejects_expiry_metadata_flags_and_sources(feature, signal):
    manifest = _manifest(V61)
    if signal in ('capability', 'wire', 'scope_key'):
        manifest[feature[signal]] = False
    elif signal == 'define':
        manifest['compiler_arguments'].append('-D' + feature['define'] + '=1')
    else:
        manifest['sources'].append({'name': feature['prefix'] + '.h', 'sha256': '0' * 64})
    _reject(manifest, V61)
