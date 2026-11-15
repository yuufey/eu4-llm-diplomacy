"""v41 uses the same strict manifest admission and both retreat-hook guards."""
import pytest

from bridge.tests.test_call_to_arms_manifest import _make_v41_manifest_fixture
from work import probe_information_battle_v23 as probe


@pytest.mark.parametrize('damage', [None, 'call_pin', 'call_missing', 'tail_missing'])
def test_v41_probe_reuses_installer_source_contract(tmp_path, damage):
    build_dir = tmp_path / 'v41-probe'
    _make_v41_manifest_fixture(build_dir)
    if damage == 'call_pin':
        (build_dir / 'call-to-arms-observer.inc').write_bytes(b'tampered source')
    elif damage == 'call_missing':
        (build_dir / 'call-to-arms-observer.inc').unlink()
    elif damage == 'tail_missing':
        (build_dir / 'information-battle-owned-outcome-tail.h').unlink()
    result = probe._manifest_static_guard(build_dir)
    assert result['status'] == ('observed' if damage is None else 'unknown')
    assert result['source_count'] == 145
    if damage is None:
        assert result['observer_version'] == 41
        assert all(result['checks'].values())


@pytest.mark.parametrize('missing_hook', [False, True])
def test_v41_static_prepare_resolves_all_three_hook_symbols(tmp_path, monkeypatch, missing_hook):
    build_dir = tmp_path / 'v41-coff'
    _manifest, dll = _make_v41_manifest_fixture(build_dir)
    rvas = {probe.STUB_SYMBOL: '0x1040', 'information_battle_outcome_retreat_hook': '0x5000',
            'information_battle_unit_retreat_hook': '0x6000'}
    seen = []

    def coff(path, symbol=probe.STUB_SYMBOL):
        assert path == dll
        seen.append(symbol)
        if missing_hook and symbol == 'information_battle_unit_retreat_hook':
            return {'status': 'unknown', 'symbol': symbol}
        return {'status': 'observed', 'symbol': symbol, 'rva': rvas[symbol], 'source': 'ordinary_pe_coff'}

    monkeypatch.setattr(probe, '_coff_symbol', coff)
    report = {'target_build': {}, 'provenance': {}, 'stub': {}}
    if missing_hook:
        with pytest.raises(probe.V23ProbeError, match='retreat_hook_coff_symbol_unavailable:unit_path'):
            probe._static_prepare(report, build_dir)
    else:
        build = probe._static_prepare(report, build_dir)
        assert build['retreat_hook_rvas'] == {'outcome': '0x5000', 'unit_path': '0x6000'}
        assert report['target_build']['observer_version'] == 41
        assert len(report['target_build']['retreat_entry_specs']) == 2
    assert set(seen) == set(rvas)
