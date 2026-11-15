"""Scoped change sampling for N09 final attributes and its source wrappers."""
from __future__ import annotations

from copy import deepcopy

import pytest

from bridge.information import InformationError, InformationService
from bridge.information.battles import BattleInformationSource
from bridge.information.composite import CompositeSource
from bridge.tests.test_information_final_attribute_scalars import (
    SPECS, _configured, _known_item,
)
from bridge.tests.test_information_final_attributes import Upstream, query
from bridge.tests.test_information_service import (
    FakeClock, create_report, create_subscription, tick_results,
)


def _source_with_game_clock():
    military = Upstream()
    military.ctx["game_day"] = 100
    source, _, probes = _configured(military=military)
    return source, military, probes


def _accepted_sample(source):
    context = source.context()
    selected = query()
    sample = source.read(selected, context)
    assert sample["complete"] is False
    return selected, context, sample


def test_final_attribute_hook_returns_stable_scoped_comparison_without_upgrading_sample():
    source, _, _ = _source_with_game_clock()
    selected, context, sample = _accepted_sample(source)
    original_fields = deepcopy(sample["fields"])

    comparison = source.change_comparison(selected, sample, context)
    repeated = source.change_comparison(selected, sample, context)

    assert comparison["schema"] == "information.change_comparison.v1"
    assert isinstance(comparison["scope"], str) and comparison["scope"]
    assert comparison["scope"] == repeated["scope"]
    assert comparison["fields"] == sample["fields"] == original_fields
    assert sample["complete"] is False


@pytest.mark.parametrize("damage", ("wrong_fields", "missing_attribute", "unknown_attribute",
                                     "wrong_identity", "bad_profile"))
def test_final_attribute_hook_refuses_unscoped_or_incomplete_samples(damage):
    source, _, _ = _source_with_game_clock()
    selected, context, sample = _accepted_sample(source)
    if damage == "wrong_fields":
        selected = query(("source_breakdown",))
    elif damage == "missing_attribute":
        sample["fields"]["final_value"]["value"].pop("relations_limit")
    elif damage == "unknown_attribute":
        sample["fields"]["final_value"]["value"]["relations_limit"] = {
            "status": "unknown", "reason": "CACHE_MISSING"}
    elif damage == "wrong_identity":
        sample["objects"] = [{"type": "country", "country": "ENG"}]
    else:
        source_provenance = sample["source"]["provenance"]["delegations"]
        source_provenance["N06.diplomatic_reputation"]["profile_sha256"] = "ff" * 32

    assert source.change_comparison(selected, sample, context) is None
    assert sample["complete"] is False


def test_final_attribute_change_scope_catalog_tracks_only_configured_attributes():
    source, _, _ = _source_with_game_clock()
    entry = source.catalog()[0]

    assert entry["change_scope"]["fields"] == ["final_value"]
    assert set(entry["change_scope"]["attributes"]) == {
        "discipline", "morale.army", "morale.navy", *SPECS}
    selected, context, sample = _accepted_sample(source)
    assert source.change_comparison(selected, sample, context) is not None
    source.scalar_sources.pop("relations_limit")
    selected, context, sample = _accepted_sample(source)
    comparison = source.change_comparison(selected, sample, context)
    assert comparison is not None
    assert "relations_limit" not in comparison["scope"]


class _HookOwner:
    def __init__(self, fields, *, comparison=True):
        self.fields = list(fields)
        self.comparison = comparison
        self.change_calls = []

    def catalog(self):
        return [{"topic_id": "N09", "status": "available",
                 "fields": {field: {"coverage": "partial"} for field in self.fields},
                 "parameters": {}, "supported_versions": ["1.37.4"],
                 "context_scope": "country_scope", "object_types": ["country"],
                 "observer_roles": ["country"], "triggers": ["query", "periodic", "change"]}]

    def change_comparison(self, selected, sample, context):
        self.change_calls.append((deepcopy(selected), deepcopy(sample), deepcopy(context)))
        if not self.comparison:
            return None
        return {"schema": "information.change_comparison.v1", "scope": "N09.test_scope",
                "fields": deepcopy(sample["fields"])}


def test_composite_forwards_only_when_the_query_has_one_owner():
    primary = _HookOwner(("final_value", "source_breakdown"))
    final_owner = _HookOwner(("final_value",))
    breakdown_owner = _HookOwner(("source_breakdown",))
    composite = CompositeSource(primary, [final_owner, breakdown_owner])
    context = {"status": "ready", "game_version": "1.37.4", "observer": "FRA"}
    final_query = query()
    final_sample = {"query": final_query, "fields": {"final_value": {"status": "known", "value": {}}}}

    forwarded = composite.change_comparison(final_query, final_sample, context)
    mixed_query = query(("final_value", "source_breakdown"))
    mixed_sample = {"query": mixed_query, "fields": {
        "final_value": {"status": "known", "value": {}},
        "source_breakdown": {"status": "known", "value": {}},
    }}

    assert forwarded["scope"] == "N09.test_scope"
    assert len(final_owner.change_calls) == 1
    assert composite.change_comparison(mixed_query, mixed_sample, context) is None
    assert composite.change_comparison(
        query(("final_value", "not_owned")),
        {"fields": {"final_value": {"status": "known", "value": {}}}}, context) is None


def test_composite_without_routes_forwards_to_primary_final_attribute_hook():
    source, _, _ = _source_with_game_clock()
    composite = CompositeSource(source)
    selected, context, sample = _accepted_sample(source)

    comparison = composite.change_comparison(selected, sample, context)

    assert comparison is not None
    assert comparison["schema"] == "information.change_comparison.v1"


class _ChangeReaderStub:
    def __init__(self, result=None):
        self.result = result
        self.calls = []

    def change_comparison(self, selected, sample, context):
        self.calls.append((deepcopy(selected), deepcopy(sample), deepcopy(context)))
        return self.result


def test_battle_wrapper_forwards_partial_comparison_to_its_reads_composite():
    selected, context = query(), {"status": "ready", "observer": "FRA"}
    sample = {"fields": {"final_value": {"status": "unknown", "reason": "incomplete"}}}
    reader = _ChangeReaderStub(None)
    wrapper = BattleInformationSource.__new__(BattleInformationSource)
    wrapper.reads = reader

    assert wrapper.change_comparison(selected, sample, context) is None
    assert reader.calls == [(selected, sample, context)]


def _service_fixture(tmp_path):
    source, military, probes = _source_with_game_clock()
    service = InformationService(source, tmp_path / "final-attribute-change.sqlite3",
                                 clock=FakeClock())
    report = create_report(service, "change-report", query=query())
    subscription = create_subscription(service, report["id"], "change-subscription",
        kind="change", basis="game", every=1, unit="days")
    return service, source, military, probes, subscription


def _tick_at(service, military, game_day):
    military.ctx["game_day"] = game_day
    return tick_results(service.tick())


def _runtime(service, subscription):
    return service.status(subscription["id"])["subscriptions"][0]["runtime"]


def test_service_compares_partial_final_values_and_keeps_incomplete_status(tmp_path):
    service, source, military, probes, subscription = _service_fixture(tmp_path)
    try:
        assert _tick_at(service, military, 101) == []
        assert _runtime(service, subscription)["last_attempt"]["status"] == "baseline_created"

        # Capture hashes may advance while the projected values and scope stay fixed.
        probes["diplomats_total"].report_hash = "cd" * 32
        assert _tick_at(service, military, 102) == []
        assert _runtime(service, subscription)["last_attempt"]["status"] == "unchanged"

        probes["relations_limit"].item = _known_item("relations_limit", 9)
        changed = _tick_at(service, military, 103)
        assert len(changed) == 1
        assert changed[0]["trigger"] == "change"
        assert changed[0]["complete"] is False
        assert changed[0]["status"] == "partial"
        assert changed[0]["items"][0]["complete"] is False
        assert changed[0]["items"][0]["fields"]["final_value"]["value"]["relations_limit"]["value"] == 9
    finally:
        service.close()


def test_service_preserves_baseline_across_unknown_then_compares_recovered_value(tmp_path):
    service, source, military, probes, subscription = _service_fixture(tmp_path)
    try:
        _tick_at(service, military, 101)
        probes["relations_limit"].item = _known_item("relations_limit", 9)
        first_change = _tick_at(service, military, 102)
        assert len(first_change) == 1
        prior = _runtime(service, subscription)
        prior_baseline = prior["baseline"]
        prior_result = prior["last_result_id"]

        probes["relations_limit"].item = {"status": "unknown", "reason": "CACHE_MISSING"}
        assert _tick_at(service, military, 103) == []
        failed = _runtime(service, subscription)
        assert failed["baseline"] == prior_baseline
        assert failed["last_result_id"] == prior_result
        assert failed["last_attempt"]["status"] == "read_failed_baseline_preserved"

        probes["relations_limit"].item = _known_item("relations_limit", 9)
        assert _tick_at(service, military, 104) == []
        assert _runtime(service, subscription)["last_attempt"]["status"] == "unchanged"
        probes["relations_limit"].item = _known_item("relations_limit", 10)
        assert len(_tick_at(service, military, 105)) == 1
    finally:
        service.close()


def test_service_rebaselines_when_supported_scope_changes_without_emitting_change(tmp_path):
    service, source, military, _, subscription = _service_fixture(tmp_path)
    try:
        _tick_at(service, military, 101)
        previous = _runtime(service, subscription)
        source.scalar_sources.pop("relations_limit")

        assert _tick_at(service, military, 102) == []
        current = _runtime(service, subscription)
        assert current["last_attempt"]["status"] == "baseline_scope_changed"
        assert current["baseline_scope"] != previous["baseline_scope"]
        assert current.get("last_result_id") == previous.get("last_result_id")
    finally:
        service.close()


@pytest.mark.parametrize("bad_hook", ("no_hook", "none", "exception", "schema", "scope", "fields"))
def test_service_rejects_bad_partial_hook_and_preserves_old_baseline(tmp_path, bad_hook):
    service, source, military, probes, subscription = _service_fixture(tmp_path)
    try:
        _tick_at(service, military, 101)
        before = _runtime(service, subscription)
        probes["relations_limit"].item = _known_item("relations_limit", 9)
        original_hook = source.change_comparison

        if bad_hook == "no_hook":
            source.change_comparison = None
            assert _tick_at(service, military, 102) == []
            after = _runtime(service, subscription)
            assert after["baseline"] == before["baseline"]
            assert after.get("last_result_id") == before.get("last_result_id")
            assert after["last_attempt"]["status"] == "read_failed_baseline_preserved"
            return

        def bad(*args):
            if bad_hook == "exception":
                raise RuntimeError("comparison failed")
            if bad_hook == "none":
                return None
            accepted = original_hook(*args)
            if bad_hook == "schema":
                accepted["schema"] = "wrong"
            elif bad_hook == "scope":
                accepted["scope"] = "has spaces"
            else:
                accepted["fields"]["extra"] = {"status": "known", "value": 1}
            return accepted

        source.change_comparison = bad
        assert _tick_at(service, military, 102) == []
        after = _runtime(service, subscription)
        assert after["baseline"] == before["baseline"]
        assert after.get("last_result_id") == before.get("last_result_id")
        assert after["last_attempt"]["status"] == "read_failed_baseline_preserved"
    finally:
        service.close()


def test_service_ignores_hook_for_complete_samples_and_canceled_subscription_does_not_read(tmp_path):
    service, source, military, probes, subscription = _service_fixture(tmp_path)
    try:
        hook_calls = []
        original_hook = source.change_comparison

        def counted_hook(*args):
            hook_calls.append(args)
            return original_hook(*args)

        source.change_comparison = counted_hook
        # The service's complete-sample path compares fields directly and skips the hook.
        complete_sample = {"complete": True, "fields": {"final_value": {"status": "known", "value": 1}}}
        assert service._change_comparison(complete_sample, source.context()) == (complete_sample["fields"], None)
        assert hook_calls == []

        _tick_at(service, military, 101)
        reads_before_cancel = len(military.calls)
        probes_before_cancel = {key: len(probe.calls) for key, probe in probes.items()}
        service.manage_subscription("cancel-change", "cancel", subscription_id=subscription["id"],
                                    expected_version=subscription["version"])
        probes["relations_limit"].item = _known_item("relations_limit", 9)
        assert _tick_at(service, military, 102) == []
        assert len(military.calls) == reads_before_cancel
        assert {key: len(probe.calls) for key, probe in probes.items()} == probes_before_cancel
    finally:
        service.close()


@pytest.mark.parametrize("field", ("source_breakdown", "modifier_effects"))
def test_change_subscription_scope_rejects_additional_n09_fields_but_query_and_periodic_work(
        tmp_path, field):
    source, _, _ = _source_with_game_clock()
    source.country_records_source = _ConfiguredRecordsStub()
    service = InformationService(source, tmp_path / f"scope-{field}.sqlite3", clock=FakeClock())
    selected = query(("final_value", field))
    try:
        report = create_report(service, f"scope-report-{field}", query=selected)
        with pytest.raises(InformationError) as error:
            create_subscription(service, report["id"], f"scope-change-{field}", kind="change",
                                basis="game", every=1, unit="days")
        assert error.value.code == "unsupported_trigger"
        periodic = create_subscription(service, report["id"], f"scope-periodic-{field}",
            kind="periodic", basis="game", every=1, unit="days")
        assert periodic["kind"] == "periodic"
        result = service.query(f"scope-query-{field}", queries=[selected])
        assert result["items"][0]["fields"]["final_value"]["status"] in {"known", "unknown"}
    finally:
        service.close()


class _ConfiguredRecordsStub:
    def context(self):
        return {"status": "ready", **_context_for_records()}

    def catalog(self):
        return []

    def read(self, selected_query, context):
        return {"source": {"name": "NativeCountryRecordsSource"},
                "game_date": context.get("game_date"),
                "objects": [deepcopy(selected_query["object"])],
                "fields": {"effects": {"status": "unknown", "reason": "NO_RECORDS"}},
                "complete": False}


def _context_for_records():
    return Upstream().context()
