"""Strict removal-source admission with the complete inherited feature set."""
from copy import deepcopy
import hashlib

import pytest

from bridge.tests.test_start_diplomacy_observer_v45 import fixture as v45_fixture
from tools import control_information_battle_observer as control
from tools import start_diplomacy_observer as start

DEFINE = '-DBRIDGE_COUNTRY_MODIFIER_REMOVAL=1'


def fixture(directory, name_handoff=False):
    manifest, directory = v45_fixture(directory, name_handoff)
    manifest.update(version=46, native_country_modifier_remove_observation=True,
                    native_country_modifier_remove_wire=1)
    manifest['compiler_arguments'].append(DEFINE)
    for name in start.COUNTRY_MODIFIER_REMOVAL_SOURCES:
        data = ('synthetic removal ' + name).encode()
        (directory/name).write_bytes(data)
        manifest['sources'].append({'name': name, 'sha256': hashlib.sha256(data).hexdigest()})
    return manifest, directory


@pytest.mark.parametrize('name_handoff', [False, True])
def test_v46_exact_contract(tmp_path, name_handoff):
    manifest, directory = fixture(tmp_path/'candidate', name_handoff)
    assert len(manifest['sources']) == (161 if name_handoff else 158)
    start._validate_information_battle_manifest(manifest, directory)
    control._validate_manifest(manifest, directory)


@pytest.mark.parametrize('mutation', [
    'flag_missing', 'flag_integer', 'wire_missing', 'wire_bool', 'wrong_wire',
    'define_missing', 'define_duplicate', 'source_missing', 'source_changed', 'source_extra',
    'parent_missing', 'old_version', 'future_version',
])
def test_v46_rejects_bad_contract(tmp_path, mutation):
    manifest, directory = fixture(tmp_path/'candidate')
    if mutation == 'flag_missing':
        manifest.pop('native_country_modifier_remove_observation')
    elif mutation == 'flag_integer':
        manifest['native_country_modifier_remove_observation'] = 1
    elif mutation == 'wire_missing':
        manifest.pop('native_country_modifier_remove_wire')
    elif mutation == 'wire_bool':
        manifest['native_country_modifier_remove_wire'] = True
    elif mutation == 'wrong_wire':
        manifest['native_country_modifier_remove_wire'] = 2
    elif mutation == 'define_missing':
        manifest['compiler_arguments'].remove(DEFINE)
    elif mutation == 'define_duplicate':
        manifest['compiler_arguments'].append(DEFINE)
    elif mutation == 'source_missing':
        manifest['sources'].pop()
    elif mutation == 'source_changed':
        manifest['sources'][-1]['sha256'] = '0' * 64
    elif mutation == 'source_extra':
        manifest['sources'].append(deepcopy(manifest['sources'][-1]))
    elif mutation == 'parent_missing':
        manifest['native_country_modifier_add_observation'] = False
    elif mutation == 'old_version':
        manifest['version'] = 45
    elif mutation == 'future_version':
        manifest['version'] = 47
    with pytest.raises(SystemExit, match='BUILD_MANIFEST_MISMATCH'):
        start._validate_information_battle_manifest(manifest, directory)


def test_v45_without_removal_remains_admitted(tmp_path):
    manifest, directory = v45_fixture(tmp_path/'legacy')
    start._validate_information_battle_manifest(manifest, directory)


def test_v45_cannot_claim_removal(tmp_path):
    manifest, directory = v45_fixture(tmp_path/'legacy')
    manifest['native_country_modifier_remove_observation'] = True
    with pytest.raises(SystemExit, match='BUILD_MANIFEST_MISMATCH'):
        start._validate_information_battle_manifest(manifest, directory)
