"""Offline preflight coverage for the support-roles v44 candidate."""
from copy import deepcopy
from pathlib import Path

import pytest

from work import probe_information_battle_v23 as probe


ROOT = Path(__file__).resolve().parents[2]
CANDIDATE = ROOT / 'work/runtime/diplomacy-observer-20261108-support-roles-v44-291-001'


def _report() -> dict:
    return probe._base_report(Path('fake-installation.json'), Path('unused-report.json'), 'original')


def test_v44_manifest_and_static_prepare_resolve_entry_and_retreat_coff_symbols():
    manifest_guard = probe._manifest_static_guard(CANDIDATE)
    assert manifest_guard['status'] == 'observed'
    assert manifest_guard['source_count'] == 153
    assert manifest_guard['source_mismatches'] == []

    report = _report()
    build = probe._static_prepare(report, CANDIDATE)

    assert build['manifest']['version'] == 44
    assert report['provenance']['source']['status'] == 'observed'
    assert report['provenance']['source']['source_count'] == 153
    assert report['stub']['symbol'] == probe.STUB_SYMBOL
    assert report['stub']['status'] == 'observed'
    assert isinstance(report['stub']['rva'], str)

    expected_keys = {str(spec['key']) for spec in probe.RETREAT_ENTRY_SPECS}
    assert set(report['retreat_hooks']) == expected_keys
    assert set(build['retreat_hook_rvas']) == expected_keys
    for spec in probe.RETREAT_ENTRY_SPECS:
        key = str(spec['key'])
        hook = report['retreat_hooks'][key]
        assert hook['symbol'] == spec['symbol']
        assert hook['status'] == 'observed'
        assert isinstance(hook['rva'], str)
        assert build['retreat_hook_rvas'][key] == hook['rva']
        assert report['target_build']['retreat_hook_rvas'][key] == hook['rva']


@pytest.mark.parametrize('version', [49, '44'])
def test_future_and_string_version_manifests_are_rejected(monkeypatch, version):
    original = probe._read_json_bounded

    def read(path, limit):
        value, pin = original(path, limit)
        if path.name == 'build-manifest.json':
            value = deepcopy(value)
            value['version'] = version
        return value, pin

    monkeypatch.setattr(probe, '_read_json_bounded', read)
    result = probe._manifest_static_guard(CANDIDATE)
    assert result['status'] == 'unknown'
    assert 'unsupported_observer_build_version' in result['unknown_conditions']
    with pytest.raises(probe.V23ProbeError, match='unsupported_observer_build_version'):
        probe._static_prepare(_report(), CANDIDATE)
