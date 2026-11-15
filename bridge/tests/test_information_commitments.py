"""Narrow R07 adapter tests over the validated public F03 projection."""
from __future__ import annotations

from copy import deepcopy

import pytest

from bridge.information.commitments import NativeCommitmentsSource
from bridge.information.model import InformationError, digest
from bridge.information.observation_time import sampled_read
from bridge.information.composite import CompositeSource
from bridge.information.service import InformationService
from bridge.information.tools import InformationTools
from bridge.tests import test_information_foreign_economy as f03_fixture


def _query(*fields, recipient="ENG", object_type="country_pair"):
    if object_type == "war":
        obj = {"type": "war", "war_id": "test-war"}
    else:
        obj = {"type": "country_pair", "actor": "FRA", "recipient": recipient}
    return {"topic": "R07", "object": obj, "fields": list(fields), "parameters": {}}


def test_public_f03_contract_projects_as_limited_evidence(tmp_path, monkeypatch):
    f03, base, _module, capture_calls = f03_fixture.setup(tmp_path, monkeypatch)
    public = f03.read({"topic": "F03", "object": {"type": "country", "country": "ENG"},
                       "fields": ["subsidies"], "parameters": {}}, base.context())
    child = public["fields"]["subsidies"]["value"]["observer_involved_contracts"]
    assert child["status"] == "known"

    source = NativeCommitmentsSource(f03)
    result = source.read(_query("economic_support", "source"), base.context())
    assert len(capture_calls) == 2
    assert result["fields"]["economic_support"]["status"] == "known"
    value = result["fields"]["economic_support"]["value"]
    assert value["registered_subsidy_evidence"] == child
    contract = value["registered_subsidy_evidence"]["contracts"][0]
    assert contract["payer"] == {"tag": "FRA"}
    assert contract["recipient"] == {"tag": "ENG"}
    assert contract["monthly_nominal_amount"] == {
        "raw": -2500, "value": -2.5, "unit": "ducats", "scale": 1000,
        "period": "month"}
    assert value["active_payment_obligations"]["status"] == "unknown"
    assert value["other_economic_support"]["status"] == "unsupported"
    assert "received_previous_month" not in repr(value)

    source_value = result["fields"]["source"]["value"]
    assert source_value["component_sha256"] == digest(child)
    assert source_value["observation_date"] == public["game_date"]
    assert source_value["scope"] == {
        "observer": "FRA", "actor": "FRA", "recipient": "ENG",
        "relation": "observer_target_pair_only", "complete_country_contracts": False}
    provenance = result["source"]["provenance"]
    assert provenance["capture_report_sha256"] == public["source"]["provenance"]["capture_report_sha256"]
    assert provenance["upstream_result_sha256"] == digest(public)


def test_outer_subsidies_known_does_not_hide_unknown_pair_component(tmp_path, monkeypatch):
    f03, base, _module, _calls = f03_fixture.setup(
        tmp_path, monkeypatch, subsidies_consistency="changed")
    public = f03.read({"topic": "F03", "object": {"type": "country", "country": "ENG"},
                       "fields": ["subsidies"], "parameters": {}}, base.context())
    assert public["fields"]["subsidies"]["status"] == "known"
    child = public["fields"]["subsidies"]["value"]["observer_involved_contracts"]
    assert child["status"] == "unknown"

    result = NativeCommitmentsSource(f03).read(_query("economic_support", "source"), base.context())
    for name in ("economic_support", "source"):
        assert result["fields"][name]["status"] == "unknown"
        assert result["fields"][name]["reason"] == child["reason"]


def test_absent_pair_relation_is_evidence_not_inactive_payment(tmp_path, monkeypatch):
    f03, base, _module, _calls = f03_fixture.setup(
        tmp_path, monkeypatch, subsidies_present=False)
    result = NativeCommitmentsSource(f03).read(_query("economic_support"), base.context())
    assert result["fields"]["economic_support"]["status"] == "known"
    value = result["fields"]["economic_support"]["value"]
    child = value["registered_subsidy_evidence"]
    assert child["pair_relation"] == {"status": "known", "present": False}
    assert child["contracts"] == []
    assert value["active_payment_obligations"]["status"] == "unknown"


@pytest.mark.parametrize('capture_raises', [True, False])
def test_economic_capture_failure_survives_fallback_only_in_full_provenance(
        tmp_path, monkeypatch, capture_raises):
    from bridge.information import ongoing_economic_commitments_capture as capture

    f03, base, _module, _calls = f03_fixture.setup(tmp_path, monkeypatch, subsidies_present=False)
    original_errors = [{'type': 'ReadError', 'reason': 'original capture failure detail'}]

    def fail_capture(*_args):
        if capture_raises:
            raise OSError('original capture exception detail')
        return {'status': 'unknown', 'errors': deepcopy(original_errors)}

    adapter = NativeCommitmentsSource(f03, economic_capture=fail_capture)
    monkeypatch.setattr(capture, 'validate_capture', lambda *_args: False)
    service = InformationService(CompositeSource(base, [adapter]), tmp_path / 'information.sqlite3')
    try:
        tools = InformationTools(service)
        full = tools.call('information_query', {'request_id': 'failed-current-support', 'view': 'full',
            'queries': [_query('economic_support')]})
        item = full['items'][0]
        assert item['fields']['economic_support']['status'] == 'known'
        assert item['fields']['economic_support']['value']['active_payment_obligations']['status'] == 'unknown'
        proof = item['source']['provenance']['current_economic_support']
        if capture_raises:
            assert proof['error'] == {'type': 'OSError', 'reason': 'original capture exception detail'}
        else:
            assert proof['error'] == {'type': 'ValueError', 'reason': 'ECONOMIC_COMMITMENTS_CAPTURE_INVALID'}
            assert proof['capture_errors'] == original_errors
        concise = tools.call('information_get_result', {'result_id': full['result_id']})
        assert concise['items'][0]['economic_support'] is None
        assert 'original capture' not in repr(concise)
    finally:
        service.close()


def test_unsupported_war_object_does_not_read_f03(tmp_path, monkeypatch):
    f03, base, _module, capture_calls = f03_fixture.setup(tmp_path, monkeypatch)
    source = NativeCommitmentsSource(f03)
    war = source.read(_query("economic_support", object_type="war"), base.context())
    assert war["fields"]["economic_support"] == {
        "status": "unsupported", "reason": "R07_WAR_OBJECT_NOT_IMPLEMENTED"}
    assert capture_calls == []


def test_only_requested_r07_recipient_mapped_to_f03_subsidies(tmp_path, monkeypatch):
    f03, base, _module, capture_calls = f03_fixture.setup(tmp_path, monkeypatch)
    source = NativeCommitmentsSource(f03)
    result = source.read(_query("economic_support"), base.context())
    assert result["objects"] == [{"type": "country_pair", "actor": "FRA", "recipient": "ENG"}]
    assert capture_calls == [(base.session.directory / "installation.json", "ENG", "FRA")]
    with pytest.raises(InformationError) as exc_info:
        source.validate_query(_query("economic_support").copy() | {
            "object": {"type": "country_pair", "actor": "ENG", "recipient": "FRA"}}, base.context())
    assert exc_info.value.code == "observer_scope_mismatch"


def test_context_mismatch_prevents_upstream_read(tmp_path, monkeypatch):
    f03, base, _module, capture_calls = f03_fixture.setup(tmp_path, monkeypatch)
    stale = deepcopy(base.context())
    base.current["game_date"] += 1
    result = NativeCommitmentsSource(f03).read(_query("economic_support"), stale)
    assert result["fields"]["economic_support"] == {
        "status": "unavailable", "reason": "R07_CONTEXT_MISMATCH"}
    assert capture_calls == []


def test_normal_sample_window_accepts_upstream_from_a_later_game_day(tmp_path, monkeypatch):
    f03, base, _module, _calls = f03_fixture.setup(tmp_path, monkeypatch)
    before = base.context()
    upstream = f03.read({'topic': 'F03', 'object': {'type': 'country', 'country': 'ENG'},
                         'fields': ['subsidies'], 'parameters': {}}, before)
    upstream['game_date'] += 24
    with sampled_read(_query('economic_support'), before):
        evidence, reason = NativeCommitmentsSource._validated_upstream(upstream, before, 'ENG')
    assert reason is None
    assert evidence['upstream_result_sha256'] == digest(upstream)


@pytest.mark.parametrize('read_raises', [False, True])
def test_context_change_during_upstream_read_withdraws_projection(tmp_path, monkeypatch, read_raises):
    f03, base, _module, _calls = f03_fixture.setup(tmp_path, monkeypatch)

    class MutatingForeignSource:
        def context(self):
            return f03.context()

        def read(self, query, context=None):
            result = f03.read(query, context) if not read_raises else None
            base.current["game_date"] += 1
            if read_raises:
                raise OSError('capture failed after context changed')
            return result

    result = NativeCommitmentsSource(MutatingForeignSource()).read(
        _query("economic_support", "source"), base.context())
    for name in ("economic_support", "source"):
        assert result["fields"][name] == {
            "status": "unavailable", "reason": "R07_CONTEXT_CHANGED_DURING_READ"}


def test_current_support_and_combined_deadlines_use_concise_business_lists(tmp_path, monkeypatch):
    f03, base, _module, capture_calls = f03_fixture.setup(tmp_path, monkeypatch)
    adapter = NativeCommitmentsSource(f03)
    subsidy = {'kind': 'subsidy', 'payer': 'FRA', 'recipient': 'ENG',
               'monthly_amount': {'value': 2.5, 'raw': 2500, 'scale': 1000, 'unit': 'ducats'},
               'end_date': {'value': base.context()['game_date'], 'unit': 'game_date_raw'}}
    economic = {'economic_support': {'status': 'known', 'value': {'active_payment_obligations': [subsidy]},
                                     'complete': True},
                'expiry': {'status': 'known', 'value': [{key: value for key, value in subsidy.items()
                                                      if key != 'monthly_amount'}], 'complete': True}}
    preparation = {'status': 'known', 'value': [
        {'kind': 'war_preparation', 'country': 'ENG', 'for': 'FRA', 'until': '1472.10.18'}], 'complete': True}
    calls = []

    def economic_read(query, context):
        calls.append('economic')
        return deepcopy(economic), {}

    monkeypatch.setattr(adapter, '_read_economic', economic_read)
    monkeypatch.setattr(adapter, '_read_preparation', lambda query, context: (deepcopy(preparation), {}))
    service = InformationService(CompositeSource(base, [adapter]), tmp_path / 'information.sqlite3')
    try:
        tools = InformationTools(service)
        full = tools.call('information_query', {'request_id': 'combined-commitments', 'view': 'full',
            'queries': [_query('economic_support', 'war_commitments', 'expiry')]})
        concise = tools.call('information_get_result', {'result_id': full['result_id']})
        item = concise['items'][0]
        assert item['economic_support'][0]['monthly_amount'] == 2.5
        assert len(item['expiry']) == 2
        assert item['expiry'][0]['end_date'] == '1472.10.18'
        assert isinstance(item['expiry'][1]['end_date'], str)
        assert 'registered_subsidy_evidence' not in repr(concise)
        assert 'registered_subsidy_evidence' in full['items'][0]['fields']['economic_support']['value']
        assert calls == ['economic']
        assert len(capture_calls) == 1
        tools.call('information_query', {'request_id': 'deadlines-only', 'queries': [_query('expiry')]})
        assert len(capture_calls) == 1
    finally:
        service.close()


def test_unknown_deadline_source_preserves_available_deadlines():
    known = {'status': 'known', 'value': [
        {'kind': 'war_preparation', 'country': 'ENG', 'for': 'FRA', 'until': '1472.10.18'}]}
    unavailable = {'status': 'unknown'}
    partial = NativeCommitmentsSource._expiry(known, unavailable)
    assert partial['status'] == 'known' and partial['complete'] is False
    assert partial['value'][0]['end_date'] == '1472.10.18'
    empty = {'status': 'known', 'value': []}
    assert NativeCommitmentsSource._expiry(empty, unavailable)['status'] == 'unknown'
    assert NativeCommitmentsSource._expiry(empty, empty)['value'] == []

