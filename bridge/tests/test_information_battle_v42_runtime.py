"""Offline entry preflight and inherited v42 observation capabilities."""
from copy import deepcopy
from pathlib import Path

import pytest

from work import probe_information_battle_v23 as probe
from bridge.tests.test_call_to_arms_observation import make_session

ROOT = Path(__file__).resolve().parents[2]
CANDIDATE = ROOT / 'work/runtime/diplomacy-observer-20261108-independent-line-v42-278-003'


def test_v42_static_preflight_reuses_flattened_source_manifest_contract():
    result = probe._manifest_static_guard(CANDIDATE)
    assert result['status'] == 'observed'
    assert result['source_count'] == 150
    assert result['source_mismatches'] == []


def test_future_observer_version_keeps_preflight_unknown(monkeypatch):
    original = probe._read_json_bounded

    def read(path, limit):
        value, pin = original(path, limit)
        if path.name == 'build-manifest.json':
            value = deepcopy(value)
            value['version'] = 45
        return value, pin

    monkeypatch.setattr(probe, '_read_json_bounded', read)
    result = probe._manifest_static_guard(CANDIDATE)
    assert result['status'] == 'unknown'
    assert 'unsupported_observer_build_version' in result['unknown_conditions']


@pytest.mark.parametrize('version, admitted', [(42, True), ('42', False)])
def test_v42_inherits_only_literal_versioned_call_to_arms_ack(tmp_path, version, admitted):
    session = make_session(tmp_path, [{'session_id': 'synthetic-runtime42'}], version=version)
    assert ('native_call_to_arms_observation' in session.installation_capabilities()) is admitted
