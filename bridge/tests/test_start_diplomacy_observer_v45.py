"""v45 adds one literal modifier-observation contract to inherited v44 gates."""
from copy import deepcopy
import hashlib

import pytest

from bridge.tests.test_start_diplomacy_observer_v44 import _synthetic_v44
from tools import control_information_battle_observer as control
from tools import start_diplomacy_observer as start

DEFINE = '-DBRIDGE_COUNTRY_MODIFIER_OBSERVATION=1'


def fixture(directory, name_handoff=False):
    manifest, directory = _synthetic_v44(directory, name_handoff=name_handoff)
    manifest.update(version=45, native_country_modifier_add_observation=True,
                    native_country_modifier_add_wire=1, native_country_modifier_scope='FRA_direct_temporary_records')
    manifest['compiler_arguments'].append(DEFINE)
    for name in start.COUNTRY_MODIFIER_OBSERVATION_SOURCES:
        data = ('synthetic modifier observation ' + name).encode()
        (directory / name).write_bytes(data)
        manifest['sources'].append({'name': name, 'sha256': hashlib.sha256(data).hexdigest()})
    return manifest, directory


@pytest.mark.parametrize('name_handoff', [False, True])
def test_v45_exact_contract_and_inherited_features(tmp_path, name_handoff):
    manifest, directory = fixture(tmp_path / 'candidate', name_handoff)
    assert len(manifest['sources']) == (159 if name_handoff else 156)
    start._validate_information_battle_manifest(manifest, directory)
    control._validate_manifest(manifest, directory)


@pytest.mark.parametrize('mutation', ['missing_flag', 'integer_flag', 'false_flag', 'missing_wire',
    'bool_wire', 'wrong_wire', 'wrong_scope', 'missing_define', 'duplicate_define', 'wrong_define',
    'missing_source', 'changed_hash', 'extra_source', 'old_version', 'future_version', 'missing_parent'])
def test_v45_rejects_incomplete_or_mislabeled_sources(tmp_path, mutation):
    manifest, directory = fixture(tmp_path / 'candidate')
    if mutation == 'missing_flag':
        manifest.pop('native_country_modifier_add_observation')
    elif mutation == 'integer_flag':
        manifest['native_country_modifier_add_observation'] = 1
    elif mutation == 'false_flag':
        manifest['native_country_modifier_add_observation'] = False
    elif mutation == 'missing_wire':
        manifest.pop('native_country_modifier_add_wire')
    elif mutation == 'bool_wire':
        manifest['native_country_modifier_add_wire'] = True
    elif mutation == 'wrong_wire':
        manifest['native_country_modifier_add_wire'] = 2
    elif mutation == 'wrong_scope':
        manifest['native_country_modifier_scope'] = 'all_countries'
    elif mutation == 'missing_define':
        manifest['compiler_arguments'].remove(DEFINE)
    elif mutation == 'duplicate_define':
        manifest['compiler_arguments'].append(DEFINE)
    elif mutation == 'wrong_define':
        manifest['compiler_arguments'].remove(DEFINE)
        manifest['compiler_arguments'].append(DEFINE[:-1] + '0')
    elif mutation == 'missing_source':
        manifest['sources'].pop()
    elif mutation == 'changed_hash':
        manifest['sources'][-1]['sha256'] = '0' * 64
    elif mutation == 'extra_source':
        manifest['sources'].append(deepcopy(manifest['sources'][-1]))
    elif mutation == 'old_version':
        manifest['version'] = 44
    elif mutation == 'future_version':
        manifest['version'] = 46
    elif mutation == 'missing_parent':
        manifest['native_support_role_context'] = False
    with pytest.raises(SystemExit, match='BUILD_MANIFEST_MISMATCH'):
        start._validate_information_battle_manifest(manifest, directory)


def test_v44_without_modifier_source_remains_admitted(tmp_path):
    manifest, directory = _synthetic_v44(tmp_path / 'legacy')
    start._validate_information_battle_manifest(manifest, directory)
