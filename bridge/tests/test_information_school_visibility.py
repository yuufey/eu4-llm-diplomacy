"""Source-boundary tests for the 175 foreign scholar visibility projection."""
from __future__ import annotations

from bridge.information.religious_schools import FIELD
from bridge.tests import test_information_religious_schools_source as fixture


def _known_relations(*, group: str, school: str) -> dict:
    return {
        'status': 'known',
        'religion_group_key': group,
        'source_school_key': school,
        'symmetric': True,
        'entries': [{
            'school_key': 'shafi_school', 'status': 'known',
            'value': -1, 'raw_hex': 'ffffffff',
        }],
        'complete': False,
        'basis': 'native_school_pair_relation_cache',
    }


def _foreign_value(invited_scholars: dict) -> dict:
    return fixture._native_value(
        religion_key='sunni',
        religion_group_key='muslim',
        school_key='hanafi_school',
        uses_schools={'status': 'known', 'value': True},
        invited_scholars=invited_scholars,
        relations=_known_relations(group='muslim', school='hanafi_school'),
    )


def _hidden_scholar_payload(*, scholar_key='hanbali_scholar_one', start=-10,
                            date=2147483647, hidden=255, cooldown=True) -> dict:
    direct = {
        'source': 'direct', 'key': scholar_key,
        'start_date_raw': start, 'date_raw': date,
        'flags': {'ruler_modifier': 1, 'parliament_modifier': 0,
                  'permanent': 1, 'hidden': hidden},
    }
    instances = [direct]
    if cooldown:
        instances.append({
            'source': 'secondary', 'key': 'has_invited_scholar_recently',
            'start_date_raw': None, 'date_raw': None, 'flags': None,
        })
    return {
        'status': 'known', 'membership_complete': True,
        'modifier_instances': instances,
    }


def test_self_fra_keeps_known_scholar_membership_and_raw_capture_fingerprint(
        tmp_path, monkeypatch):
    raw_child = _hidden_scholar_payload(scholar_key='jesuit_scholar_one', cooldown=False)
    index = fixture.ScholarMappingIndex()
    source, base, _, _, _ = fixture._make_source(
        tmp_path, monkeypatch, target='FRA',
        report=fixture._report('FRA', value=fixture._native_value(
            invited_scholars=raw_child,
        )),
        definitions=fixture.DefinitionIndex(), scholar_definitions=index,
    )

    result = source.read(fixture._query('FRA'), base.context())
    field = result['fields'][FIELD]

    assert field['status'] == 'known'
    assert field['value']['invited_scholars']['status'] == 'known'
    assert field['value']['invited_scholars']['scholars'][0]['modifier_key'] == 'jesuit_scholar_one'
    assert field['value']['invited_scholars']['scholars'][0]['instances'] == raw_child['modifier_instances']
    assert 'capture_report_sha256' in result['source']['provenance']
    assert 'public_projection_sha256' not in result['source']['provenance']
    assert index.calls == 1


def test_foreign_tur_withholds_scholars_but_preserves_school_and_relations(
        tmp_path, monkeypatch):
    raw_child = _hidden_scholar_payload()
    index = fixture.ScholarMappingIndex(mode='raise')
    source, base, _, _, _ = fixture._make_source(
        tmp_path, monkeypatch, target='TUR',
        report=fixture._report('TUR', value=_foreign_value(raw_child)),
        definitions=fixture.DefinitionIndex(), scholar_definitions=index,
    )

    result = source.read(fixture._query('TUR'), base.context())
    field = result['fields'][FIELD]
    value = field['value']

    assert field['status'] == 'known'
    assert value['current_school'] == {'status': 'known', 'key': 'hanafi_school'}
    assert value['relations'] == _known_relations(group='muslim', school='hanafi_school')
    assert value['uses_schools'] == {'status': 'known', 'value': True}
    assert value['invited_scholars'] == {
        'status': 'unknown', 'reason': 'SCHOLAR_VISIBILITY_UNVERIFIED',
    }
    assert index.calls == 0
    rendered = repr(result)
    for private in ('hanbali_scholar_one', 'has_invited_scholar_recently',
                    'modifier_instances', 'start_date_raw', 'date_raw', 'ruler_modifier'):
        assert private not in rendered
    provenance = result['source']['provenance']
    assert 'capture_report_sha256' not in provenance
    assert len(provenance['public_projection_sha256']) == 64
    assert result['source']['projection_version'] == 2


def test_foreign_hidden_child_changes_do_not_change_public_value_or_projection_hash(
        tmp_path, monkeypatch):
    first_child = _hidden_scholar_payload()
    second_child = _hidden_scholar_payload(
        scholar_key='different_private_modifier', start=123, date=-99,
        hidden=0, cooldown=False,
    )
    outputs = []
    for suffix, child in (('first', first_child), ('second', second_child)):
        source, base, _, _, _ = fixture._make_source(
            tmp_path / suffix, monkeypatch, target='TUR',
            report=fixture._report('TUR', value=_foreign_value(child)),
            definitions=fixture.DefinitionIndex(),
            scholar_definitions=fixture.ScholarMappingIndex(mode='raise'),
        )
        outputs.append(source.read(fixture._query('TUR'), base.context()))

    first, second = outputs
    assert first['fields'][FIELD]['value'] == second['fields'][FIELD]['value']
    assert (first['source']['provenance']['public_projection_sha256']
            == second['source']['provenance']['public_projection_sha256'])
    assert all('capture_report_sha256' not in item['source']['provenance'] for item in outputs)


def test_foreign_unknown_or_failed_backend_never_emits_raw_capture_hash(
        tmp_path, monkeypatch):
    cases = (
        ('unknown', fixture._report(
            'TUR', field_status='unknown', reason='SCHOLAR_MODIFIERS_CHANGED'), None),
        ('failed', fixture._report('TUR'), RuntimeError('capture failed')),
    )
    for name, report, error in cases:
        source, base, _, _, _ = fixture._make_source(
            tmp_path / name, monkeypatch, target='TUR', report=report,
            capture_error=error, definitions=fixture.DefinitionIndex(),
        )
        result = source.read(fixture._query('TUR'), base.context())
        assert result['fields'][FIELD]['status'] == 'unknown'
        assert 'capture_report_sha256' not in result['source']['provenance']
        assert 'public_projection_sha256' not in result['source']['provenance']


def test_catalog_marks_invited_scholar_visibility_as_foreign_unknown():
    field = fixture.NativeReligiousSchoolsSource(None).catalog()[0]['fields'][FIELD]
    assert field['component_scopes']['invited_scholars'] == {
        'scope': 'observer_country',
        'foreign_status': 'unknown',
        'foreign_reason': 'SCHOLAR_VISIBILITY_UNVERIFIED',
    }
    assert 'FOREIGN_SCHOLAR_VISIBILITY_NOT_VERIFIED' in field['gaps']
