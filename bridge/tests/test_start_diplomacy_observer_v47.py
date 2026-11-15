"""Strict expiry admission requires its real ABI stub and inherited contracts."""
from copy import deepcopy
import hashlib

import pytest

from bridge.tests.test_start_diplomacy_observer_v46 import fixture as v46_fixture
from tools import control_information_battle_observer as control
from tools import start_diplomacy_observer as start

DEFINE = '-DBRIDGE_COUNTRY_MODIFIER_EXPIRY=1'
STUB = 'information-country-modifier-expiry-entry.S'


def fixture(directory, name_handoff=False):
    manifest, directory = v46_fixture(directory, name_handoff)
    manifest.update(version=47, native_country_modifier_expiry_observation=True,
                    native_country_modifier_expiry_wire=1)
    manifest['compiler_arguments'].extend([DEFINE, str(directory/STUB)])
    for name in start.COUNTRY_MODIFIER_EXPIRY_SOURCES:
        data = ('synthetic expiry '+name).encode()
        (directory/name).write_bytes(data)
        manifest['sources'].append({'name': name, 'sha256': hashlib.sha256(data).hexdigest()})
    return manifest, directory


@pytest.mark.parametrize('name_handoff', [False, True])
def test_v47_exact_contract(tmp_path, name_handoff):
    manifest, directory = fixture(tmp_path/'candidate', name_handoff)
    assert len(manifest['sources']) == (163 if name_handoff else 160)
    start._validate_information_battle_manifest(manifest, directory)
    control._validate_manifest(manifest, directory)


@pytest.mark.parametrize('mutation', [
    'flag_missing', 'flag_integer', 'wire_missing', 'wire_bool', 'wrong_wire',
    'define_missing', 'define_duplicate', 'stub_missing', 'stub_duplicate',
    'source_missing', 'source_changed', 'source_extra', 'parent_missing', 'old_version', 'future_version',
])
def test_v47_rejects_bad_contract(tmp_path, mutation):
    manifest, directory = fixture(tmp_path/'candidate')
    if mutation == 'flag_missing':
        manifest.pop('native_country_modifier_expiry_observation')
    elif mutation == 'flag_integer':
        manifest['native_country_modifier_expiry_observation'] = 1
    elif mutation == 'wire_missing':
        manifest.pop('native_country_modifier_expiry_wire')
    elif mutation == 'wire_bool':
        manifest['native_country_modifier_expiry_wire'] = True
    elif mutation == 'wrong_wire':
        manifest['native_country_modifier_expiry_wire'] = 2
    elif mutation == 'define_missing':
        manifest['compiler_arguments'].remove(DEFINE)
    elif mutation == 'define_duplicate':
        manifest['compiler_arguments'].append(DEFINE)
    elif mutation == 'stub_missing':
        manifest['compiler_arguments'].remove(str(directory/STUB))
    elif mutation == 'stub_duplicate':
        manifest['compiler_arguments'].append(str(directory/STUB))
    elif mutation == 'source_missing':
        manifest['sources'].pop()
    elif mutation == 'source_changed':
        manifest['sources'][-1]['sha256'] = '0'*64
    elif mutation == 'source_extra':
        manifest['sources'].append(deepcopy(manifest['sources'][-1]))
    elif mutation == 'parent_missing':
        manifest['native_country_modifier_remove_observation'] = False
    elif mutation == 'old_version':
        manifest['version'] = 46
    elif mutation == 'future_version':
        manifest['version'] = 49
    with pytest.raises(SystemExit, match='BUILD_MANIFEST_MISMATCH'):
        start._validate_information_battle_manifest(manifest, directory)


def test_v46_without_expiry_remains_admitted(tmp_path):
    manifest, directory = v46_fixture(tmp_path/'legacy')
    start._validate_information_battle_manifest(manifest, directory)


def test_v46_cannot_claim_expiry(tmp_path):
    manifest, directory = v46_fixture(tmp_path/'legacy')
    manifest['native_country_modifier_expiry_observation'] = True
    with pytest.raises(SystemExit, match='BUILD_MANIFEST_MISMATCH'):
        start._validate_information_battle_manifest(manifest, directory)
