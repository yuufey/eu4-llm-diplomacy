"""Admit the claim-only extension through the existing complete v62 contract."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from bridge.tests.test_expiry_v62_install_admission import _changed_cpp, _without
from tools import control_information_battle_observer as control
from tools import start_diplomacy_observer as start
from work import probe_information_battle_v23 as probe


ROOT = Path(__file__).resolve().parents[2]
CANDIDATE = ROOT / 'work/runtime/diplomacy-observer-20261115-claim-expiry-v63-001'
V62 = ROOT / 'work/runtime/diplomacy-observer-20261115-expiry-v62-002'
V61 = ROOT / 'work/runtime/diplomacy-observer-20261115-war-active-roster-v61-001'
FEATURE = start.CLAIM_EXPIRY_FEATURE


def _manifest(directory=CANDIDATE):
    return json.loads((directory / 'build-manifest.json').read_text(encoding='utf-8-sig'))


def _reject(manifest, directory=CANDIDATE):
    with pytest.raises(SystemExit, match='BUILD_MANIFEST_MISMATCH'):
        start._validate_information_battle_manifest(manifest, directory)
    with pytest.raises(control.ControlError) as caught:
        control._validate_manifest(manifest, directory)
    assert caught.value.reason == 'BUILD_MANIFEST_MISMATCH'


def test_real_v63_candidate_passes_all_static_entries():
    manifest = _manifest()
    assert manifest['dll_sha256'] == '338da9698af47c105e9aed15a7618cad7395212a692b9888b1f37e292adb17d0'
    start._validate_information_battle_manifest(manifest, CANDIDATE)
    control._validate_manifest(manifest, CANDIDATE)
    result = probe._manifest_static_guard(CANDIDATE)
    assert result['status'] == 'observed' and not result['unknown_conditions']
    assert result['observer_version'] == 63 and result['source_count'] == 203


def test_normal_main_preserves_v63_manifest_dll_and_readiness_arguments(monkeypatch):
    calls = []

    def ready(pid, manifest, directory, confirm, wait):
        assert pid == 1 and manifest['version'] == 63 and directory == CANDIDATE
        assert confirm is True and wait == 300
        calls.append(('ready', manifest['version']))
        return {'session_id': 'offline-fixture'}, {}, None, 'fixture', []

    def install(pid, manifest, directory, dll, python, *rest):
        assert pid == 1 and manifest['version'] == 63 and directory == CANDIDATE
        assert dll == CANDIDATE / 'eu4_bridge_diplomacy_observer_v63.dll' and dll.is_file()
        assert python == 'fixture-python' and rest[-1] == 'eu4_escape'
        calls.append(('install', manifest['version']))

    original_exists = Path.exists
    monkeypatch.setattr(Path, 'exists', lambda path: False if path == CANDIDATE / 'installation.json' else original_exists(path))
    monkeypatch.setattr(start, '_wait_until_ready', ready)
    monkeypatch.setattr(start, '_install_once', install)
    monkeypatch.setattr(start, 'get_value', lambda name: 'fixture-python')
    start.main(['--pid', '1', '--manifest', str(CANDIDATE / 'build-manifest.json'),
                '--confirm-load-warning', '--native-text-codec', 'eu4_escape', '--wait-ready', '300'])
    assert calls == [('ready', 63), ('install', 63)]


@pytest.mark.parametrize('mutation', [
    'capability_missing', 'capability_integer', 'capability_false', 'wire_bool', 'wire_other', 'scope',
    'define_missing', 'define_zero', 'define_bare', 'define_duplicate',
    'source_missing', 'source_duplicate', 'source_case', 'source_hash',
])
def test_v63_rejects_partial_claim_contract(mutation):
    manifest = _manifest()
    define = '-D' + FEATURE['define'] + '=1'
    if mutation == 'capability_missing':
        manifest.pop(FEATURE['capability'])
    elif mutation == 'capability_integer':
        manifest[FEATURE['capability']] = 1
    elif mutation == 'capability_false':
        manifest[FEATURE['capability']] = False
    elif mutation == 'wire_bool':
        manifest[FEATURE['wire']] = True
    elif mutation == 'wire_other':
        manifest[FEATURE['wire']] = 2
    elif mutation == 'scope':
        manifest[FEATURE['scope_key']] = 'all_claims'
    elif mutation == 'define_missing':
        manifest['compiler_arguments'].remove(define)
    elif mutation == 'define_zero':
        manifest['compiler_arguments'][manifest['compiler_arguments'].index(define)] = define[:-1] + '0'
    elif mutation == 'define_bare':
        manifest['compiler_arguments'][manifest['compiler_arguments'].index(define)] = define[:-2]
    elif mutation == 'define_duplicate':
        manifest['compiler_arguments'].append(define)
    else:
        row = next(row for row in manifest['sources'] if row['name'] == FEATURE['prefix'] + '.h')
        if mutation == 'source_missing':
            manifest['sources'].remove(row)
        elif mutation == 'source_duplicate':
            manifest['sources'].append(deepcopy(row))
        elif mutation == 'source_case':
            row['name'] = row['name'].upper()
        else:
            row['sha256'] = '0' * 64
    _reject(manifest)


@pytest.mark.parametrize('mutation', ['missing', 'duplicate', 'wire', 'scope'])
def test_v63_requires_exact_claim_ack(mutation, tmp_path):
    manifest = _manifest()
    text = (CANDIDATE / start.MACRO_EVENT_ACK_SOURCE).read_text(encoding='utf-8')
    block = FEATURE['ack']
    assert text.count(block) == 1
    replacement = {'missing': '', 'duplicate': block + '\n' + block,
                   'wire': block.replace(FEATURE['wire'] + '\\":1', FEATURE['wire'] + '\\":2'),
                   'scope': block.replace(FEATURE['scope'], 'all_claims')}[mutation]
    assert replacement != block
    directory = _changed_cpp(tmp_path, manifest, text.replace(block, replacement), baseline=CANDIDATE)
    _reject(manifest, directory)


@pytest.mark.parametrize('mutation', ['missing', 'duplicate', 'digit'])
def test_v63_requires_exact_selector(mutation, tmp_path):
    manifest = _manifest()
    text = (CANDIDATE / start.MACRO_EVENT_ACK_SOURCE).read_text(encoding='utf-8')
    block = start.CLAIM_V63_VERSION_BLOCK
    replacement = {'missing': start.EXPIRY_V62_VERSION_BLOCK,
                   'duplicate': block + '\n' + block,
                   'digit': block.replace("]='3';", "]='4';")}[mutation]
    directory = _changed_cpp(tmp_path, manifest, text.replace(block, replacement), baseline=CANDIDATE)
    _reject(manifest, directory)


def test_v63_accepts_split_claim_define():
    manifest = _manifest()
    index = manifest['compiler_arguments'].index('-D' + FEATURE['define'] + '=1')
    manifest['compiler_arguments'][index:index + 1] = ['-D', FEATURE['define'] + '=1']
    start._validate_information_battle_manifest(manifest, CANDIDATE)


def test_v63_requires_claim_capability():
    manifest = _manifest()
    _without(manifest, FEATURE)
    _reject(manifest)


@pytest.mark.parametrize('feature', start.EXPIRY_FEATURES, ids=lambda feature: feature['prefix'])
@pytest.mark.parametrize('mutation', ['remove_parent', 'scope', 'wire'])
def test_v63_requires_both_complete_v62_parent_features(feature, mutation):
    manifest = _manifest()
    if mutation == 'remove_parent':
        _without(manifest, feature)
    elif mutation == 'scope':
        manifest[feature['scope_key']] = 'all'
    else:
        manifest[feature['wire']] = True
    _reject(manifest)


@pytest.mark.parametrize('mutation', ['rival_missing', 'prototype', 'formal_integer', 'extra_source'])
def test_v63_keeps_complete_ancestor_admission(mutation):
    manifest = _manifest()
    if mutation == 'rival_missing':
        manifest.pop(start.RIVAL_RECORD_CAPABILITY)
    elif mutation == 'prototype':
        manifest['prototype_only'] = True
    elif mutation == 'formal_integer':
        manifest['formal_installation_admitted'] = 1
    else:
        manifest['sources'].append({'name': 'extra-source.h', 'sha256': '0' * 64})
    _reject(manifest)


@pytest.mark.parametrize('baseline', [V62, V61], ids=['v62', 'v61'])
def test_disabled_claim_selector_preserves_older_contracts(baseline, tmp_path):
    manifest = _manifest(baseline)
    text = (CANDIDATE / start.MACRO_EVENT_ACK_SOURCE).read_text(encoding='utf-8')
    directory = _changed_cpp(tmp_path, manifest, text, baseline=baseline)
    start._validate_information_battle_manifest(manifest, directory)


@pytest.mark.parametrize('signal', ['capability', 'wire', 'scope_key', 'define', 'source'])
def test_v62_rejects_claim_extension_signals(signal):
    manifest = _manifest(V62)
    if signal in ('capability', 'wire', 'scope_key'):
        manifest[FEATURE[signal]] = False
    elif signal == 'define':
        manifest['compiler_arguments'].append('-D' + FEATURE['define'] + '=1')
    else:
        manifest['sources'].append({'name': FEATURE['prefix'] + '.h', 'sha256': '0' * 64})
    _reject(manifest, V62)
