"""M05 composes the existing chain and reward-timing projections once."""
from copy import deepcopy

import pytest

from bridge.information.composite import CompositeSource
from bridge.information.mission_analysis import MissionAnalysisSource
from bridge.information.mission_chain_targets import MissionChainTargetsSource
from bridge.information.mission_chain_timing import MissionChainTimingSource
from bridge.information.missions import MissionInformationSource
from bridge.information.model import InformationError
from bridge.tests import test_information_mission_chain_targets as chain_fixture


def _query(fields=("linked_targets", "basis", "reward_timing"), *, country="FRA",
           root_id="root_main", task_id="task_core", parameters=None):
    return {
        "topic": "M05",
        "object": {"type": "country", "country": country},
        "fields": list(fields),
        "parameters": (deepcopy(parameters) if parameters is not None else {
            "root_id": root_id, "task_id": task_id,
        }),
    }


def _analysis_setup():
    _chain, missions, primary, state, _definitions = chain_fixture.setup_source()
    return MissionAnalysisSource(missions), missions, primary, state


def test_mixed_projection_reads_original_state_once_and_matches_legacy_projectors():
    source, missions, primary, state = _analysis_setup()
    captured = []
    original_reader = missions.reader

    def recording_reader(country):
        sample = original_reader(country)
        captured.append(deepcopy(sample))
        return sample

    missions.reader = recording_reader
    context = primary.context()
    request = _query()
    result = source.read(request, context)

    assert state.calls == 1
    assert len(captured) == 1
    assert set(result["fields"]) == set(request["fields"])
    assert all(field["status"] == "known" for field in result["fields"].values())

    # Re-run the established projectors against the same captured sample. Their
    # fixture readers are frozen copies and do not call the original reader.
    frozen = MissionInformationSource(
        missions.base_source,
        missions.definitions,
        lambda country: deepcopy(captured[0]),
        scheduling=False,
        scope_index=missions.scope_index,
    )
    legacy_chain = MissionChainTargetsSource(frozen).read(
        _query(("linked_targets", "basis")), context,
    )
    legacy_timing = MissionChainTimingSource(frozen).read(
        _query(("reward_timing",)), context,
    )
    assert result["fields"]["linked_targets"] == legacy_chain["fields"]["linked_targets"]
    assert result["fields"]["basis"] == legacy_chain["fields"]["basis"]
    assert result["fields"]["reward_timing"] == legacy_timing["fields"]["reward_timing"]
    assert state.calls == 1

    provenance = result["source"]["provenance"]
    assert provenance["single_captured_state"] is True
    components = provenance["components"]
    assert len(components) == 2
    chain_proof = next(item["provenance"] for item in components
                       if "prerequisites" in item.get("provenance", {}))
    timing_proof = next(item["provenance"] for item in components
                        if "reward_timing_projection" in item.get("provenance", {}))
    assert chain_proof["prerequisites"]["provenance"]["state"] == chain_proof["targets"]["provenance"]["state"]
    assert chain_proof["prerequisites"]["provenance"]["definitions"]
    assert timing_proof["reward_timing_projection"]["duration_provenance"]


def test_invalid_scope_parameters_and_duplicate_fields_are_rejected_before_capture():
    source, _missions, primary, state = _analysis_setup()
    context = primary.context()

    with pytest.raises(InformationError) as scope_error:
        source.read(_query(country="ENG"), context)
    assert scope_error.value.code == "observer_scope_mismatch"

    for parameters in (
        {"task_id": "task_core"},
        {"root_id": "root_main", "task_id": "bad/task"},
    ):
        with pytest.raises(InformationError):
            source.read(_query(parameters=parameters), context)

    with pytest.raises(InformationError) as duplicate_error:
        source.read(_query(("basis", "basis")), context)
    assert duplicate_error.value.code == "invalid_fields"
    assert state.calls == 0


def test_wrong_state_identity_withholds_every_projection():
    source, _missions, primary, state = _analysis_setup()
    state.sample["session_id"] = "old-session"

    result = source.read(_query(), primary.context())

    assert state.calls == 1
    assert all(field["status"] == "unavailable"
               and field["reason"] == "mission_context_changed"
               and "value" not in field
               for field in result["fields"].values())


def test_definition_drift_between_components_withholds_the_join():
    source, _missions, primary, state = _analysis_setup()
    source.missions.definitions.mutate_after_first_context = True

    result = source.read(_query(), primary.context())

    assert state.calls == 1
    assert all(field["status"] == "unknown"
               and field["reason"] == "MISSION_ANALYSIS_DEFINITIONS_CHANGED"
               and "value" not in field
               for field in result["fields"].values())


def test_context_change_after_last_projection_withholds_the_join(monkeypatch):
    source, _missions, primary, state = _analysis_setup()
    original_read = MissionChainTimingSource.read

    def change_context_after_projection(adapter, query, context=None):
        result = original_read(adapter, query, context)
        primary.state.current["game_date"] += 1
        return result

    monkeypatch.setattr(MissionChainTimingSource, "read", change_context_after_projection)
    result = source.read(_query(), primary.context())

    assert state.calls == 1
    assert all(field["status"] == "unknown"
               and field["reason"] == "MISSION_ANALYSIS_CONTEXT_CHANGED"
               and "value" not in field
               for field in result["fields"].values())


def test_unready_context_does_not_read_mission_state():
    source, _missions, primary, state = _analysis_setup()
    context = dict(primary.context(), status="unavailable")

    result = source.read(_query(), context)

    assert all(field["status"] == "unavailable" for field in result["fields"].values())
    assert state.calls == 0


def test_composite_keeps_original_selector_and_leaves_costs_planned():
    source, missions, primary, state = _analysis_setup()
    composite = CompositeSource(primary, [source])
    catalog_topic = next(item for item in composite.catalog() if item["topic_id"] == "M05")
    chain_selector = MissionChainTargetsSource(missions).catalog()[0]["parameters"]
    timing_selector = MissionChainTimingSource(missions).catalog()[0]["parameters"]

    assert catalog_topic["parameters"] == chain_selector == timing_selector
    assert catalog_topic["fields"]["costs"]["coverage"] == "planned"
    assert catalog_topic["fields"]["reward_timing"]["coverage"] == "partial"

    request = _query(("linked_targets", "reward_timing"))
    assert composite.validate_query(request)["parameters"] == request["parameters"]

    cost_result = composite.read(
        {"topic": "M05", "object": {"type": "country", "country": "FRA"},
         "fields": ["costs"], "parameters": {"root_id": "root_main", "task_id": "task_core"}},
        primary.context(),
    )
    assert cost_result["fields"]["costs"]["status"] == "unsupported"
    assert cost_result["fields"]["costs"]["reason"] == "FIELD_NOT_IMPLEMENTED_BY_ADAPTER"
    assert "value" not in cost_result["fields"]["costs"]
    # The fixture includes a numeric trigger and a treasury effect. Neither is
    # reported as candidate cost by the aggregate route.
    assert state.calls == 0

