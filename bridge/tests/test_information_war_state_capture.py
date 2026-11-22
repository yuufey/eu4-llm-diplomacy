from copy import deepcopy
import pytest

from bridge.information import war_state_capture as capture
from bridge.tests.test_information_foreign_forces_capture import _make_image, TraceReader
from bridge.tests.test_information_foreign_technology_capture import (
    MODULE_BASE, WORLD, make_valid_capture,
)
from bridge.tests.test_information_country_occupation_memory import put_provinces


@pytest.mark.parametrize('stats_allowed', [True, False])
@pytest.mark.parametrize('observer', ['FRA', 'TUR'])
def test_two_countries_share_country_scan_and_replay_all_requested_fields(monkeypatch, stats_allowed, observer):
    fields = list(capture.FIELDS)
    profile = capture._load_profile(fields)
    image, bindings, refs = _make_image(profile, stats_allowed=stats_allowed, observer=observer)
    own_country = bindings[observer]['country_pointer']
    image.put_u64(own_country + 0xd18, 0)
    image.put_u64(own_country + 0x1338, 0)
    image.put_i32(own_country + 0x1344, 0)
    put_provinces(image, refs['target_fullref'],
        [refs['target_fullref'], refs['observer_fullref']], country=refs['target_pointer'],
        world=WORLD, blockaded=[1])
    monkeypatch.setattr(capture._owner, '_bound_admission', lambda *args: {
        'status': 'known', 'admitted': True, 'observer_nonplayer_role': {'verified': True}})
    countries = ['ENG', observer]
    reader = TraceReader(image)
    observation = capture._observe_for(countries, fields, observer)(reader, MODULE_BASE, 'ENG', profile)
    assert observation['stable'] is True
    targets = {row['tag']: row['fields'] for row in observation['backend']['targets']}
    assert targets['ENG']['W03.blockades']['value']['blockaded_provinces'] == 1
    assert targets['ENG']['W03.occupations']['value']['occupied_provinces'] == 1
    assert targets[observer]['W03.current_forces']['value'] == {
        'army_soldiers': {'status': 'known', 'value': 0},
        'navy_ships': {'status': 'known', 'value': 0}}
    assert targets['ENG']['W03.current_forces']['complete'] is stats_allowed
    assert sum(row['label'] == 'country_reference.slot[0].pointer' for row in reader.read_log) == 2
    report, context, creation, _ = make_valid_capture()
    report.update(schema=capture.SCHEMA, profile_sha256=capture.PROFILE_SHA256,
                  observation=observation, raw_reads=deepcopy(reader.read_log))
    report['request'].update(countries=countries, fields=fields, observer=observer)
    context['observer'] = observer
    report['access'] = {'read_only': True, 'native_function_invoked': False, 'writes': False,
        'UI_control': False, 'date_advance': False, 'save_or_reload': False,
        'limit_bytes': capture._owner.MAX_READ_BYTES,
        'calls': reader.calls, 'bytes_requested': reader.bytes_requested}
    assert capture.validate_capture(report, context, creation, countries, fields)
    assert not capture.validate_capture(report, context, creation, list(reversed(countries)), fields)


def test_territory_only_omits_force_profile():
    profile = capture._load_profile(['blockades'])
    assert 'force_predicates' not in profile


def test_own_force_read_requires_matching_observer_binding():
    binding = {'tag': 'FRA', 'fullref': '0x1', 'country_pointer': '0x10000'}
    observer = dict(binding, fullref='0x2')
    with pytest.raises(ValueError, match='WAR_OWN_COUNTRY_BINDING_MISMATCH'):
        capture._read_forces(None, MODULE_BASE, binding, observer, {})
