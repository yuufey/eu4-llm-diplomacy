"""Strict v48 admission adds only the pinned native rival observer contract."""
import hashlib

import pytest

from bridge.tests.test_start_diplomacy_observer_v46 import fixture as v46_fixture
from bridge.tests.test_start_diplomacy_observer_v47 import fixture as v47_fixture
from tools import control_information_battle_observer as control
from tools import start_diplomacy_observer as start

DEFINE = '-DBRIDGE_RIVAL_OBSERVATION=1'
SCOPE = 'FRA_actor_target_or_old_rival_at_three_country_command_entries'


def fixture(directory, name_handoff=False):
    manifest, directory = v47_fixture(directory, name_handoff)
    manifest.update(version=48, native_rival_change_observation=True,
                    native_rival_change_wire=1, native_rival_change_scope=SCOPE)
    manifest['compiler_arguments'].append(DEFINE)
    for name in start.RIVAL_CHANGE_SOURCES:
        data = ('synthetic rival '+name).encode()
        (directory/name).write_bytes(data)
        manifest['sources'].append({'name': name, 'sha256': hashlib.sha256(data).hexdigest()})
    return manifest, directory


def _reject_both(manifest, directory):
    with pytest.raises(SystemExit, match='BUILD_MANIFEST_MISMATCH'):
        start._validate_information_battle_manifest(manifest, directory)
    with pytest.raises(control.ControlError) as caught:
        control._validate_manifest(manifest, directory)
    assert caught.value.reason == 'BUILD_MANIFEST_MISMATCH'


@pytest.mark.parametrize('name_handoff', [False, True])
def test_v48_exact_inherited_and_rival_contract(tmp_path, name_handoff):
    manifest, directory = fixture(tmp_path/'candidate', name_handoff)
    assert len(manifest['sources']) == (165 if name_handoff else 162)
    start._validate_information_battle_manifest(manifest, directory)
    control._validate_manifest(manifest, directory)


@pytest.mark.parametrize('mutation', [
    'flag_missing', 'flag_integer', 'wire_missing', 'wire_bool', 'wrong_wire',
    'scope_missing', 'scope_wrong', 'define_missing', 'define_duplicate',
    'source_missing', 'source_changed', 'parent_missing', 'old_version', 'future_version',
])
def test_v48_rejects_incomplete_or_malformed_contract(tmp_path, mutation):
    manifest, directory = fixture(tmp_path/'candidate')
    if mutation == 'flag_missing':
        manifest.pop('native_rival_change_observation')
    elif mutation == 'flag_integer':
        manifest['native_rival_change_observation'] = 1
    elif mutation == 'wire_missing':
        manifest.pop('native_rival_change_wire')
    elif mutation == 'wire_bool':
        manifest['native_rival_change_wire'] = True
    elif mutation == 'wrong_wire':
        manifest['native_rival_change_wire'] = 2
    elif mutation == 'scope_missing':
        manifest.pop('native_rival_change_scope')
    elif mutation == 'scope_wrong':
        manifest['native_rival_change_scope'] = 'FRA_only'
    elif mutation == 'define_missing':
        manifest['compiler_arguments'].remove(DEFINE)
    elif mutation == 'define_duplicate':
        manifest['compiler_arguments'].append(DEFINE)
    elif mutation == 'source_missing':
        manifest['sources'].pop()
    elif mutation == 'source_changed':
        manifest['sources'][-1]['sha256'] = '0'*64
    elif mutation == 'parent_missing':
        manifest['native_country_modifier_expiry_observation'] = False
    elif mutation == 'old_version':
        manifest['version'] = 47
    elif mutation == 'future_version':
        manifest['version'] = 49
    _reject_both(manifest, directory)


@pytest.mark.parametrize('version', [46, 47])
@pytest.mark.parametrize('claim', ['flag', 'define', 'source'])
def test_v47_and_older_reject_rival_claims(tmp_path, version, claim):
    if version == 47:
        manifest, directory = v47_fixture(tmp_path/'candidate')
    else:
        manifest, directory = v46_fixture(tmp_path/'candidate')
    if claim == 'flag':
        manifest['native_rival_change_observation'] = True
    elif claim == 'define':
        manifest['compiler_arguments'].append(DEFINE)
    else:
        name = start.RIVAL_CHANGE_SOURCES[0]
        data = b'synthetic rival source'
        (directory/name).write_bytes(data)
        manifest['sources'].append({'name': name, 'sha256': hashlib.sha256(data).hexdigest()})
    _reject_both(manifest, directory)
