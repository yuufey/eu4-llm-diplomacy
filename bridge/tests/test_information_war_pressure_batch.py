"""Batch pressure preserves the existing scalar, visibility and tool results."""
from contextlib import closing
from copy import deepcopy
from types import SimpleNamespace

import pytest

from bridge.information import foreign_pressure as single
from bridge.information import war_pressure_capture as batch
from bridge.information.composite import CompositeSource
from bridge.information.observation_time import sampled_read
from bridge.information.service import InformationService
from bridge.information.tools import InformationTools
from bridge.information.war_exhaustion import NativeWarExhaustionSource
from bridge.tests import test_information_foreign_technology_capture as fixture
from bridge.tests import test_information_foreign_technology_memory as country_fixture
from bridge.tests.test_information_foreign_technology import Base
from bridge.tests.test_information_war_exhaustion import _Pressure, _field
from bridge.tests.test_information_war_participant_pressure import WarBase, war_query


COUNTRIES = ['AMG', 'AUV', 'BOU', 'FOI', 'HAB', 'HES', 'ORL', 'SAV', 'TTL',
             'BUR', 'BRB', 'FLA', 'FRI', 'HOL', 'KNZ']
VALUES = {tag: index * 137 - 100 for index, tag in enumerate(COUNTRIES)}


def image_fixture(*, denied=False):
    entries = {'FRA': (122, 0x1200, 5), 'POR': (189, 0x5500, 3)}
    entries.update({tag: (300 + index, 0x4500, 9) for index, tag in enumerate(COUNTRIES)})
    image, bindings, _ = country_fixture.make_reader(entries, count=320)
    fixture._write_capture_context(image, country=COUNTRIES[0], admitted=not denied)
    admission = fixture.admission
    observer = bindings['FRA']['country_pointer']
    for tag in COUNTRIES:
        slot = bindings[tag]['slot']
        row = fixture.RELATION_TABLE + slot * admission.RELATION_ROW_STRIDE
        image.put_u64(row + admission.RELATION_ROW_OWNER_OFFSET, fixture.RELATION_OWNER)
        image.put_u64(row + admission.RELATION_ROW_RECIPIENT_FULLREF_OFFSET, bindings[tag]['fullref'])
        counter = (fixture.RELATION_COUNTERS + admission.RELATION_COUNTER_FIRST_OFFSET
                   + slot * admission.RELATION_COUNTER_STRIDE)
        image.put_i32(counter, 0 if denied and tag == COUNTRIES[0] else 1)
        image.put_i32(bindings[tag]['country_pointer'] + 0xD10, VALUES[tag])
    assert observer == country_fixture.COUNTRY_BASE + 122 * 0x1000
    for guard in single._load_profile()['code_guards']:
        image.put(fixture.MODULE_BASE + int(guard['rva'], 0), bytes.fromhex(guard['bytes']))
    context = {'status': 'ready', 'complete': True, 'mode': 'live', 'observer': 'FRA',
               'session_id': fixture.SESSION_ID, 'game_version': '1.37.4',
               'game_sha256': single._owner.EXE_SHA256, 'game_date': fixture.GAME_DATE}
    return image, context


def capture_fixture(countries, *, single_country=False, denied=False, changed=False, advance=False):
    image, context = image_fixture(denied=denied)
    first_address = country_fixture.COUNTRY_BASE + 300 * 0x1000 + 0xD10
    first_reads = [0]
    if changed or advance:
        def change(memory, address, size, label, count):
            if changed and address == first_address:
                first_reads[0] += 1
                if first_reads[0] == 2:
                    memory.put_i32(address, VALUES[COUNTRIES[0]] + 1)
            if advance and address == fixture.WORLD + 0x1DD0 and count == 2:
                memory.put_i32(address, fixture.GAME_DATE + 24)
        image.on_read = change
    reader = fixture.RecordingReader(image)
    if single_country:
        observation = single._observe_for(['war_exhaustion'])(
            reader, fixture.MODULE_BASE, countries[0], single._load_profile())
        schema, profile_sha = single.SCHEMA, single.PROFILE_SHA256
    else:
        observation = batch._observe_for(countries)(
            reader, fixture.MODULE_BASE, countries[0], single._load_legacy_profile())
        schema, profile_sha = batch.SCHEMA, batch.PROFILE_SHA256
    identity = {'binding_verified': True, 'process_creation_filetime': fixture.CREATION,
                'process_path': 'synthetic-eu4.exe', 'process_path_sha256': single._owner.EXE_SHA256}
    request = {'country': countries[0], 'observer': 'FRA', 'creation_filetime': fixture.CREATION,
               'session_id': fixture.SESSION_ID, 'countries': list(countries)}
    if single_country:
        request['fields'] = ['war_exhaustion']
    report = {'schema': schema, 'profile_sha256': profile_sha, 'status': 'observed', 'completed': True,
              'request': request, 'module_base': hex(fixture.MODULE_BASE),
              'identity': identity, 'identity_after': deepcopy(identity), 'observation': observation,
              'raw_reads': reader.read_log, 'cleanup': {'status': 'closed', 'success': True, 'closed': True},
              'access': {'read_only': True, 'native_function_invoked': False, 'writes': False,
                         'UI_control': False, 'date_advance': False, 'save_or_reload': False,
                         'limit_bytes': single._owner.MAX_READ_BYTES,
                         'calls': reader.calls, 'bytes_requested': reader.bytes_requested}}
    return report, context


def projected(report):
    return {target['tag']: target['fields'][single.FIELD]
            for target in report['observation']['backend']['targets']}


def test_eight_countries_match_single_captures_with_one_shared_table_scan():
    countries = COUNTRIES[:8]
    report, context = capture_fixture(countries)
    assert batch.validate_capture(report, context, fixture.CREATION, countries)
    singles = [capture_fixture([tag], single_country=True)[0] for tag in countries]
    assert all(single.validate_capture(one, context, fixture.CREATION, tag)
               for tag, one in zip(countries, singles))
    assert projected(report) == {tag: projected(one)[tag] for tag, one in zip(countries, singles)}
    database = hex(fixture.MODULE_BASE + batch._countries.country_reference_memory.DATABASE_GLOBAL_RVA)
    scans = sum(row['address'] == database for row in report['raw_reads'])
    individual_scans = sum(row['address'] == database for one in singles for row in one['raw_reads'])
    assert scans == 2 and individual_scans == 16
    assert sum(row['label'] == 'foreign_pressure.war_exhaustion' for row in report['raw_reads']) == 16
    assert report['access']['bytes_requested'] < sum(one['access']['bytes_requested'] for one in singles)


def test_denied_and_changed_members_preserve_their_known_siblings():
    countries = COUNTRIES[:3]
    denied, context = capture_fixture(countries, denied=True)
    assert batch.validate_capture(denied, context, fixture.CREATION, countries)
    values = projected(denied)
    assert values[countries[0]]['status'] == 'invisible'
    assert values[countries[1]]['value'] == VALUES[countries[1]]
    changed, context = capture_fixture(countries, changed=True)
    assert batch.validate_capture(changed, context, fixture.CREATION, countries)
    assert projected(changed)[countries[0]]['status'] == 'unknown'
    assert projected(changed)[countries[1]]['value'] == VALUES[countries[1]]


def test_sampled_forward_clock_preserves_all_member_values():
    countries = COUNTRIES[:3]
    with sampled_read(war_query(), {'mode': 'live', 'game_date': fixture.GAME_DATE}):
        report, context = capture_fixture(countries, advance=True)
        assert batch.validate_capture(report, context, fixture.CREATION, countries)
        assert all(field['status'] == 'known' for field in projected(report).values())


@pytest.mark.parametrize('damage', ['countries', 'value', 'trace', 'creation', 'session'])
def test_batch_validation_rejects_changed_request_trace_and_identity(damage):
    countries = COUNTRIES[:2]
    report, context = capture_fixture(countries)
    creation = fixture.CREATION
    if damage == 'countries':
        report['request']['countries'].reverse()
    elif damage == 'value':
        report['observation']['backend']['targets'][0]['fields'][single.FIELD]['value'] += 1
    elif damage == 'trace':
        report['raw_reads'][-1]['raw_hex'] = '00'
    elif damage == 'creation':
        creation += 1
    else:
        context['session_id'] = 'other-session'
    assert not batch.validate_capture(report, context, creation, countries)


@pytest.mark.parametrize('countries', [[], ['FRA'], ['AMG', 'AMG'], COUNTRIES[:9]])
def test_batch_scope_stays_within_existing_reader_bounds(countries):
    with pytest.raises(ValueError):
        batch.capture('unused-installation.json', countries)


def test_source_chunks_fifteen_members_and_preserves_injected_single_capture(tmp_path, monkeypatch):
    _, context = image_fixture()
    source = single.NativeForeignPressureSource(Base(tmp_path, context, fixture.CREATION))
    calls = []

    def capture(installation, countries):
        calls.append(list(countries))
        return capture_fixture(countries)[0]

    monkeypatch.setattr(batch, 'capture', capture)
    values = source.read_war_exhaustion_batch(COUNTRIES, context)
    assert [len(tags) for tags in calls] == [8, 7]
    assert {tag: field['value'] for tag, field in values.items()} == VALUES
    calls.clear()

    def injected(installation, *, country, observer):
        calls.append(country)
        return capture_fixture([country], single_country=True)[0]

    source.capture = injected
    assert source.read_war_exhaustion_batch(COUNTRIES[:2], context) == {
        tag: values[tag] for tag in COUNTRIES[:2]}
    assert calls == COUNTRIES[:2]


def test_invalid_batch_falls_back_to_isolated_member_reads(tmp_path, monkeypatch):
    _, context = image_fixture()
    source = single.NativeForeignPressureSource(Base(tmp_path, context, fixture.CREATION))
    monkeypatch.setattr(batch, 'capture', lambda *args: {})
    calls = []

    def read(query, current):
        tag = query['object']['country']
        calls.append(tag)
        field = {'status': 'unknown', 'reason': 'COUNTRY_UNAVAILABLE'} if tag == COUNTRIES[0] else _field(500)
        return {'fields': {'war_exhaustion': field}}

    monkeypatch.setattr(source, 'read', read)
    values = source.read_war_exhaustion_batch(COUNTRIES[:2], context)
    assert calls == COUNTRIES[:2]
    assert values[COUNTRIES[0]]['status'] == 'unknown'
    assert values[COUNTRIES[1]]['value'] == 500


def make_war_source(tmp_path):
    _, context = image_fixture()
    pressure = _Pressure(context=context, field=_field(489))

    class BaseWar(WarBase):
        def read(self, query, current):
            self.calls.append(deepcopy(query))
            members = {'status': 'available', 'source': 'native_war_side_vectors', 'complete': True,
                       'side_a': ['FRA', *COUNTRIES[:9]], 'side_b': COUNTRIES[9:],
                       'actor_side': 'side_a', 'recipient_side': 'side_b', 'reason': None}
            return {'fields': {'war_id': {'status': 'known', 'value': 'war_0123456789abcdef_00000001'},
                               'participants': {'status': 'known', 'value': members}}}

    base = BaseWar(pressure)
    base.session = SimpleNamespace(directory=tmp_path, record={'creation_filetime': fixture.CREATION})
    foreign = single.NativeForeignPressureSource(base)
    return NativeWarExhaustionSource(pressure, foreign, base), pressure, base


def test_normal_war_tool_uses_two_batches_and_retains_all_sixteen_members(tmp_path, monkeypatch):
    source, pressure, base = make_war_source(tmp_path)
    calls = []

    def capture(installation, countries):
        calls.append(list(countries))
        return capture_fixture(countries)[0]

    monkeypatch.setattr(batch, 'capture', capture)
    with closing(InformationService(CompositeSource(base, [source]), tmp_path / 'pressure.sqlite3')) as service:
        result = InformationTools(service).call('information_query', {'request_id': 'batched-war',
            'queries': [dict(war_query(), object={'type': 'war', 'actor': 'FRA', 'recipient': 'BUR'})]})
        values = result['items'][0]['war_exhaustion']
        assert len(values['our_side']) == 10 and len(values['opposing_side']) == 6
        assert values['our_side']['FRA'] == {'current': .489, 'min': 0, 'max': 20}
        assert values['opposing_side']['BUR']['current'] == VALUES['BUR'] / 1000
        assert [len(tags) for tags in calls] == [8, 7]
        assert len(pressure.read_calls) == 1
