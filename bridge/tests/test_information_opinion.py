from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

import pytest

from bridge.information import opinion_memory
from bridge.information.composite import CompositeSource
from bridge.information.model import InformationError
from bridge.information.opinion import NativeOpinionSource
from bridge.information.catalog import list_topics
from bridge.information.service import InformationService
from bridge.tests.test_information_service import (
    FakeClock, create_report, create_subscription, tick_results,
)


GAME_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
CONTEXT = {
    "status": "ready", "mode": "live", "complete": True, "observer": "FRA",
    "game_version": "1.37.4", "game_sha256": GAME_SHA, "dll_sha256": "d" * 64,
    "session_id": "opinion-session", "game_date": 56560344, "game_date_raw": 56560344,
    "world_id": "opinion-world", "paused": True,
}
FIELD_IDS = opinion_memory.FIELDS


def _known(holder: str, target: str, value: int) -> dict:
    raw = value.to_bytes(2, "little", signed=True).hex()
    return {
        "status": "known",
        "value": {"holder": holder, "target": target, "opinion": value, "raw_hex": raw},
        "unit": "opinion_points", "scale": 1, "complete": False,
    }


def _report(*, outgoing=-200, incoming=177) -> dict:
    return {
        "schema": "private-capture-report",
        "raw_reads": [{"address": "0xDEADBEEF", "raw_hex": "private-trace"}],
        "observation": {
            "backend": {
                "status": "observed", "consistency": {"status": "stable"},
                "targets": [{
                    "tag": "ENG",
                    "fields": {
                        FIELD_IDS[0]: _known("FRA", "ENG", outgoing),
                        FIELD_IDS[1]: _known("ENG", "FRA", incoming),
                    },
                }],
            },
        },
    }


class Primary:
    def __init__(self, directory, *, context=None):
        self._context = deepcopy(context or CONTEXT)
        self.session = SimpleNamespace(
            directory=directory,
            record={"creation_filetime": 123456789},
            creation_filetime=123456789,
        )

    def context(self):
        return deepcopy(self._context)

    def catalog(self):
        return list_topics()


class CaptureHarness:
    def __init__(self, report=None, *, capture_error=None, validator_result=True,
                 validator_error=None, after_capture=None):
        self.report = deepcopy(report or _report())
        self.capture_error = capture_error
        self.validator_result = validator_result
        self.validator_error = validator_error
        self.after_capture = after_capture
        self.capture_calls = []
        self.validator_calls = []

    def capture(self, installation, target):
        self.capture_calls.append((installation, target))
        if self.after_capture is not None:
            self.after_capture()
        if self.capture_error is not None:
            raise RuntimeError(self.capture_error)
        return deepcopy(self.report)

    def validate(self, report, context, creation, target):
        self.validator_calls.append((deepcopy(context), creation, target))
        if self.validator_error is not None:
            raise RuntimeError(self.validator_error)
        return self.validator_result


def _query(actor="FRA", recipient="ENG", *, fields=None, parameters=None):
    return {
        "topic": "R04", "object": {"type": "country_pair", "actor": actor, "recipient": recipient},
        "fields": list(fields or ["opinion"]), "parameters": {} if parameters is None else parameters,
    }


def _source(tmp_path, *, context=None, harness=None):
    primary = Primary(tmp_path, context=context)
    harness = harness or CaptureHarness()
    source = NativeOpinionSource(primary, capture=harness.capture, validator=harness.validate)
    return source, primary, harness


def _field(result):
    return result["fields"]["opinion"]


def test_catalog_adds_only_partial_live_opinion_and_keeps_siblings_planned(tmp_path):
    source, _primary, _harness = _source(tmp_path)
    entries = source.catalog()
    assert len(entries) == 1
    r04 = entries[0]
    assert r04["topic_id"] == "R04"
    assert r04["status"] == "available"
    assert r04["object_types"] == ["country_pair"]
    assert r04["observer_roles"] == ["actor", "recipient"]
    assert r04["parameters"]["additionalProperties"] is False
    assert r04["triggers"] == ["query", "periodic", "change"]
    assert r04["fields"]["opinion"]["coverage"] == "partial"
    assert r04["fields"]["opinion"]["complete"] is False
    assert r04["fields"]["opinion"]["period"] == "current_cached"
    assert set(r04["fields"]) == {"opinion"}
    base_r04 = next(row for row in list_topics() if row["topic_id"] == "R04")
    assert {name for name, meta in base_r04["fields"].items() if meta["coverage"] == "planned"} == {
        "opinion", "opinion_modifiers", "decay", "end_date",
    }


def test_capture_validates_once_and_projects_both_directions_without_private_trace(tmp_path):
    source, _primary, harness = _source(tmp_path)
    result = source.read(_query(), source.context())
    assert len(harness.capture_calls) == 1
    installation, target = harness.capture_calls[0]
    assert installation == tmp_path / "installation.json"
    assert target == "ENG"
    assert len(harness.validator_calls) == 1
    field = _field(result)
    assert field == {
        "unit": "opinion_points", "scale": 1, "period": "current_cached", "complete": False,
        "partial": True, "basis": "native_bilateral_country_opinion_signed_i16_cache",
        "value_origin": "copied_native_bilateral_opinion_cache",
        "gaps": ["NATIVE_CACHE_FRESHNESS_NOT_PROVEN", "ACTUAL_UI_DISPLAY_NOT_VERIFIED"],
        "status": "known",
        "value": [
            {"holder": "FRA", "target": "ENG", "status": "known", "opinion": -200, "raw_hex": "38ff"},
            {"holder": "ENG", "target": "FRA", "status": "known", "opinion": 177, "raw_hex": "b100"},
        ],
    }
    assert "DEADBEEF" not in repr(result) and "private-trace" not in repr(result)
    assert "raw_reads" not in result["source"]["provenance"]
    assert result["complete"] is False


def test_reversed_pair_reverses_public_direction_order(tmp_path):
    source, _primary, harness = _source(tmp_path)
    result = source.read(_query("ENG", "FRA"), source.context())
    assert harness.capture_calls[0][1] == "ENG"
    assert [(row["holder"], row["target"]) for row in _field(result)["value"]] == [
        ("ENG", "FRA"), ("FRA", "ENG"),
    ]
    assert [row["opinion"] for row in _field(result)["value"]] == [177, -200]


def test_one_unknown_direction_keeps_the_other_known(tmp_path):
    report = _report()
    report["observation"]["backend"]["targets"][0]["fields"][FIELD_IDS[1]] = {
        "status": "unknown", "reason": "OPINION_TABLE_SLOT_ABSENT",
    }
    source, _primary, _harness = _source(tmp_path, harness=CaptureHarness(report))
    field = _field(source.read(_query(), source.context()))
    assert field["status"] == "known"
    assert field["value"][0]["status"] == "known"
    assert field["value"][1] == {
        "holder": "ENG", "target": "FRA", "status": "unknown",
        "reason": "OPINION_TABLE_SLOT_ABSENT",
    }


def test_invisible_direction_is_preserved_and_never_exposes_a_value(tmp_path):
    report = _report()
    report["observation"]["backend"]["targets"][0]["fields"][FIELD_IDS[1]] = {
        "status": "invisible", "reason": "admission_denied",
    }
    source, _primary, _harness = _source(tmp_path, harness=CaptureHarness(report))
    field = _field(source.read(_query(), source.context()))
    assert field["status"] == "known"
    assert field["value"][0]["status"] == "known"
    assert field["value"][1] == {
        "holder": "ENG", "target": "FRA", "status": "invisible",
        "reason": "OPINION_ADMISSION_DENIED",
    }

    report["observation"]["backend"]["targets"][0]["fields"][FIELD_IDS[0]] = {
        "status": "invisible", "reason": "admission_denied",
    }
    source, _primary, _harness = _source(tmp_path, harness=CaptureHarness(report))
    field = _field(source.read(_query(), source.context()))
    assert field["status"] == "invisible"
    assert "value" not in field
    assert all(row["status"] == "invisible" for row in field["directions"])


@pytest.mark.parametrize("mutate", [
    lambda value: value.update(holder="POR"),
    lambda value: value.update(target="SWE"),
    lambda value: value.update(opinion=True),
    lambda value: value.update(raw_hex="zzzz"),
    lambda value: value.update(raw_hex="39ff"),
    lambda value: value.update(extra="secret"),
])
def test_malformed_direction_is_withheld_without_dropping_valid_sibling(tmp_path, mutate):
    report = _report()
    mutate(report["observation"]["backend"]["targets"][0]["fields"][FIELD_IDS[0]]["value"])
    source, _primary, _harness = _source(tmp_path, harness=CaptureHarness(report))
    field = _field(source.read(_query(), source.context()))
    assert field["status"] == "known"
    assert field["value"][0] == {
        "holder": "FRA", "target": "ENG", "status": "unknown",
        "reason": "OPINION_BACKEND_FIELD_INVALID",
    }
    assert field["value"][1]["status"] == "known"


def test_validator_failure_retracts_all_capture_values(tmp_path):
    source, _primary, harness = _source(tmp_path, harness=CaptureHarness(validator_result=False))
    field = _field(source.read(_query(), source.context()))
    assert len(harness.capture_calls) == len(harness.validator_calls) == 1
    assert field == {"status": "unknown", "reason": "OPINION_CAPTURE_INVALID"}


@pytest.mark.parametrize("failure", ["reader detail contains address 0x1234", "bad trace"])
def test_capture_and_validator_exceptions_are_fixed_and_do_not_leak(tmp_path, failure):
    source, _primary, _harness = _source(
        tmp_path, harness=CaptureHarness(capture_error=failure),
    )
    field = _field(source.read(_query(), source.context()))
    assert field == {"status": "unknown", "reason": "OPINION_CAPTURE_FAILED"}
    assert failure not in repr(source.read(_query(), source.context()))

    source, _primary, _harness = _source(
        tmp_path, harness=CaptureHarness(validator_error=failure),
    )
    field = _field(source.read(_query(), source.context()))
    assert field == {"status": "unknown", "reason": "OPINION_CAPTURE_INVALID"}
    assert failure not in repr(source.read(_query(), source.context()))


def test_non_live_context_is_unavailable_and_never_captured(tmp_path):
    recorded = dict(CONTEXT, mode="recorded")
    source, _primary, harness = _source(tmp_path, context=recorded)
    field = _field(source.read(_query(), source.context()))
    assert field == {"status": "unavailable", "reason": "LIVE_CONTEXT_REQUIRED"}
    assert harness.capture_calls == []


def test_context_drift_during_capture_retracts_the_observation(tmp_path):
    primary = Primary(tmp_path)
    harness = CaptureHarness(after_capture=lambda: primary._context.update(game_date=56560345,
                                                                              game_date_raw=56560345))
    source = NativeOpinionSource(primary, capture=harness.capture, validator=harness.validate)
    field = _field(source.read(_query(), source.context()))
    assert field == {"status": "unknown", "reason": "CONTEXT_CHANGED_DURING_CAPTURE"}
    assert len(harness.capture_calls) == 1
    assert harness.validator_calls == []


@pytest.mark.parametrize("query", [
    _query("ENG", "POR"),
    _query("FRA", "FRA"),
    _query(fields=["opinion", "decay"]),
    _query(parameters={"direction": "both"}),
    {**_query(), "object": {"type": "country_pair", "actor": "FRA", "recipient": "ENG", "extra": True}},
])
def test_pair_field_and_parameter_contract_is_strict(tmp_path, query):
    source, _primary, _harness = _source(tmp_path)
    with pytest.raises(InformationError):
        source.read(query, source.context())


def test_change_hook_requires_two_valid_known_directions_and_binds_pair_identity(tmp_path):
    source, _primary, _harness = _source(tmp_path)
    selected = _query()
    context = source.context()
    sample = source.read(selected, context)
    comparison = source.change_comparison(selected, sample, context)
    assert comparison == {
        "schema": "information.change_comparison.v1",
        "scope": "R04.opinion.FRA.ENG.native_i16_v1",
        "fields": sample["fields"],
    }
    assert sample["complete"] is False

    repeated = source.change_comparison(selected, deepcopy(sample), context)
    assert repeated == comparison

    unknown = deepcopy(sample)
    unknown["fields"]["opinion"]["value"][1] = {
        "holder": "ENG", "target": "FRA", "status": "unknown",
        "reason": "OPINION_BACKEND_FIELD_UNKNOWN",
    }
    assert source.change_comparison(selected, unknown, context) is None

    stale = dict(context, session_id="other-session")
    assert source.change_comparison(selected, sample, stale) is None
    wrong_pair = _query("ENG", "FRA")
    assert source.change_comparison(wrong_pair, sample, context) is None


def test_service_change_baseline_same_value_single_value_change_and_unknown(tmp_path):
    context = dict(CONTEXT, game_day=100, game_date=100, game_date_raw=100)
    primary = Primary(tmp_path, context=context)
    harness = CaptureHarness()
    adapter = NativeOpinionSource(primary, capture=harness.capture, validator=harness.validate)
    source = CompositeSource(primary, [adapter])
    service = InformationService(source, tmp_path / "opinion-change.sqlite3", clock=FakeClock())
    try:
        report = create_report(service, "opinion-change-report", query=_query())
        subscription = create_subscription(
            service, report["id"], "opinion-change-subscription",
            kind="change", basis="game", every=1, unit="days",
        )

        def tick(day):
            primary._context.update(game_day=day, game_date=day, game_date_raw=day)
            return tick_results(service.tick())

        assert tick(101) == []
        state = service.status(subscription["id"])["subscriptions"][0]["runtime"]
        assert state["last_attempt"]["status"] == "baseline_created"

        assert tick(102) == []
        state = service.status(subscription["id"])["subscriptions"][0]["runtime"]
        assert state["last_attempt"]["status"] == "unchanged"

        harness.report = _report(outgoing=-199, incoming=177)
        changed = tick(103)
        assert len(changed) == 1
        assert changed[0]["trigger"] == "change"
        assert changed[0]["complete"] is False
        assert changed[0]["items"][0]["fields"]["opinion"]["value"][0]["opinion"] == -199

        prior = service.status(subscription["id"])["subscriptions"][0]["runtime"]
        harness.report["observation"]["backend"]["targets"][0]["fields"][FIELD_IDS[1]] = {
            "status": "unknown", "reason": "OPINION_TABLE_SLOT_ABSENT",
        }
        assert tick(104) == []
        after = service.status(subscription["id"])["subscriptions"][0]["runtime"]
        assert after["baseline"] == prior["baseline"]
        assert after["last_result_id"] == prior["last_result_id"]
        assert after["last_attempt"]["status"] == "read_failed_baseline_preserved"
    finally:
        service.close()

