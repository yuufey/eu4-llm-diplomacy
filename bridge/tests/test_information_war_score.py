"""W02 war-score contract over recorded 1.37.4 public projections.

The native fixture and the selected-public wrapper are immutable recordings.
The small diplomacy stub only replays those bytes through the real
``DiplomacySource`` and ``InformationService``; mutations exercise the
adapter's explicit unknown, truncation, no-goal, and identity boundaries.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from bridge.information import InformationService
from bridge.information.catalog import get_topic, validate_query
from bridge.information.model import InformationError
from bridge.information.sources import DiplomacySource
from bridge.war_score import project_live_war_score, unknown_war_score


ROOT = Path(__file__).resolve().parents[2]
RAW_FIXTURE = ROOT / "bridge/tests/fixtures/r74_live_war_score_real.json"
SELECTED_PUBLIC = (
    ROOT
    / "work/runtime/r74-live-war-queries-20261020-003"
    / "cases/selected_forward/public.json"
)
RAW_SHA256 = "0c2436fad13aad8936a32e354fff47e467a613a23a65131ffc485da9eb46b2f8"
SELECTED_PUBLIC_SHA256 = "efb5da78eefd96e434c1c94461840dae6e0625e412cbf28ca48130ccdbce edf5".replace(" ", "")
WAR_ID = "war_46823559cad32865_00000001"
GAME_DATE = 56553384
SESSION_ID = "43288-1dd60138fd31a12"
CAPABILITY = "native_live_war_score_query"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _recordings() -> tuple[list[dict], dict]:
    assert RAW_FIXTURE.is_file() and SELECTED_PUBLIC.is_file()
    assert _sha256(RAW_FIXTURE) == RAW_SHA256
    assert _sha256(SELECTED_PUBLIC) == SELECTED_PUBLIC_SHA256
    events = json.loads(RAW_FIXTURE.read_text(encoding="utf-8"))
    wrapper = json.loads(SELECTED_PUBLIC.read_text(encoding="utf-8"))
    assert len(events) == 2
    assert wrapper["action_id"] == "white_peace"
    assert wrapper["actor"] == "FRA" and wrapper["recipient"] == "BUR"
    assert wrapper["phase"] == "initiate"
    assert wrapper["session"]["date_raw"] == GAME_DATE
    assert wrapper["war_context"]["war_id"] == WAR_ID
    return events, wrapper


class _StubSession:
    def __init__(self, *, observer: str = "FRA", capabilities=(CAPABILITY,)):
        self.observer = observer
        self.session_id = SESSION_ID
        self.date_raw = GAME_DATE
        self.capabilities = tuple(capabilities)
        self.change_date_after_call = False
        self.record = {
            "session_id": SESSION_ID,
            "experiment_id": "information-war-score-test",
            "pid": 36432,
            "creation_filetime": 134375780666987441,
            "observer": observer,
            "game_date": GAME_DATE,
            "game_version": "1.37.4",
            "world_id": "r74-score-world",
            "paused": True,
        }

    def health(self) -> dict:
        return {
            "status": "ready",
            "complete": True,
            "session_id": self.session_id,
            "observer": self.observer,
            "game_version": "1.37.4",
            "game_sha256": "r74-game-sha",
            "dll_sha256": "r74-dll-sha",
            "game_date": self.date_raw,
            "game_day": self.date_raw // 24,
            "world_id": "r74-score-world",
            "paused": True,
        }

    def installation_capabilities(self):
        return self.capabilities


class _StubDiplomacyTools:
    def __init__(self, session: _StubSession, response: dict):
        self.session = session
        self.response = deepcopy(response)
        self.calls: list[tuple] = []

    def inspect_diplomatic_action(self, *args):
        self.calls.append(deepcopy(args))
        if self.session.change_date_after_call:
            self.session.date_raw += 24
        return deepcopy(self.response)


def _projected_event(events: list[dict], index: int = 0, **mutations) -> dict:
    event = deepcopy(events[index])
    for path, value in mutations.items():
        target = event
        parts = path.split(".")
        for key in parts[:-1]:
            target = target[key]
        target[parts[-1]] = value
    identity = {key: event[key] for key in (
        "query_id", "session_id", "action_id", "actor", "recipient",
        "phase", "date_raw", "war_id",
    )}
    projected = project_live_war_score(event, codec="eu4_escape", **identity)
    assert projected is not None
    return projected


def _wrapper(events: list[dict], selected: dict, *, index: int = 0,
             direction: str = "demand", score: dict | None = None,
             **mutations) -> dict:
    event = events[index]
    response = deepcopy(selected)
    response["actor"] = event["actor"]
    response["recipient"] = event["recipient"]
    response["phase"] = "initiate"
    response["session"]["date_raw"] = event["date_raw"]
    response["peace_context"]["direction"] = direction
    response["peace_context"]["war_id"] = event["war_id"]
    response["war_context"]["war_id"] = event["war_id"]
    response["peace_context"]["war_context"]["war_id"] = event["war_id"]
    projected = score if score is not None else _projected_event(events, index, **mutations)
    response["war_context"]["war_score"] = deepcopy(projected)
    response["peace_context"]["war_context"]["war_score"] = deepcopy(projected)
    return response


def _query(*fields: str, actor: str = "FRA", recipient: str = "BUR",
           object_type: str = "country_pair", war_id: str = WAR_ID,
           direction: str = "demand", top_war_id: str | None = None,
           **parameter_overrides) -> dict:
    params = {
        "action_id": "white_peace",
        "phase": "initiate",
        "peace_context": {"war_id": war_id, "direction": direction, "terms": []},
    }
    if top_war_id is not None:
        params["war_id"] = top_war_id
    params.update(parameter_overrides)
    obj = {"type": object_type, "actor": actor, "recipient": recipient}
    if object_type == "war":
        obj["war_id"] = war_id
    return {"topic": "W02", "object": obj, "fields": list(fields), "parameters": params}


def _service(tmp_path: Path, response: dict, *, observer: str = "FRA",
             capabilities=(CAPABILITY,), change_date_after_call: bool = False):
    session = _StubSession(observer=observer, capabilities=capabilities)
    session.change_date_after_call = change_date_after_call
    tools = _StubDiplomacyTools(session, response)
    service = InformationService(
        DiplomacySource(tools, observer=observer),
        tmp_path / "information.sqlite3",
    )
    return service, session, tools


def _item(result: dict) -> dict:
    assert len(result["items"]) == 1
    return result["items"][0]


def test_w02_catalog_is_explicit_and_does_not_advertise_peace_terms():
    topic = get_topic("W02")
    assert set(topic["parameters"]["properties"]) == {
        "action_id", "phase", "war_id", "peace_context",
    }
    context = topic["parameters"]["properties"]["peace_context"]
    assert set(context["properties"]) == {"war_id", "direction", "terms"}
    assert context["properties"]["direction"]["enum"] == ["demand", "offer"]
    assert context["properties"]["terms"]["maxItems"] == 0
    assert context["additionalProperties"] is False
    assert topic["capability_required"] == CAPABILITY
    assert topic["fields"]["cumulative_goal_score"]["paths"][0] == (
        "war_context.war_score.goal.cumulative"
    )
    assert topic["object_requirements"]["country_pair"]["required"] == [
        "actor", "recipient",
    ]
    assert "parameters.peace_context.war_id" in topic["object_requirements"]["war"]["war_id_sources"]
    assert topic["fields"]["war_score"]["coverage"] == "partial"

    good = _query("war_score")
    validate_query(good)
    with pytest.raises(InformationError):
        validate_query({**good, "parameters": {**good["parameters"], "selection": {}}})
    with pytest.raises(InformationError):
        validate_query({**good, "parameters": {
            **good["parameters"],
            "peace_context": {"war_id": WAR_ID, "direction": "demand", "terms": [{"x": 1}]},
        }})


def test_recorded_public_wrapper_projects_both_actor_perspectives():
    events, _selected = _recordings()
    expected = (-400, 400)
    for index, value in enumerate(expected):
        score = _projected_event(events, index)
        assert score["total"] == {
            "raw": 0, "value": 0, "unit": "war_score_point", "scale": 1,
            "scale_verified": True,
        }
        assert score["goal"]["cumulative"]["raw"] == value
        assert score["goal"]["cumulative"]["scale"] == 1000
        assert score["goal"]["present"] is True
        assert score["goal"]["inapplicable"] is False
        assert score["goal"]["presence"] == "configured"


def test_real_information_route_uses_one_selected_empty_peace_call(tmp_path):
    events, selected = _recordings()
    response = _wrapper(events, selected)
    service, _session, tools = _service(tmp_path, response)
    try:
        result = service.query(
            "w02-real-selected",
            queries=[_query("war_score", "cumulative_goal_score")],
        )
        item = _item(result)
        score = item["fields"]["war_score"]["value"]
        assert item["fields"]["war_score"]["status"] == "known"
        assert item["fields"]["cumulative_goal_score"] == {
            "status": "known", "value": score["goal"]["cumulative"],
        }
        assert score["goal"]["cumulative_raw"] == -400
        assert score["goal"]["present"] is True
        assert score["goal"]["inapplicable"] is False
        assert score["goal"]["presence"] == "configured"
        assert item["complete"] is True
        assert tools.calls == [(
            "white_peace", "FRA", "BUR", "initiate",
            {"peace_context": {"war_id": WAR_ID, "direction": "demand", "terms": []}},
        )]
    finally:
        service.close()


def test_zero_no_goal_and_goal_getter_failure_keep_distinct_public_states(tmp_path):
    events, selected = _recordings()

    # The recorded whole-war total is a verified zero, not missing data.
    score = _projected_event(events, 0)
    assert score["total"]["raw"] == 0 and score["total"]["value"] == 0

    no_goal_event = deepcopy(events[0])
    no_goal_event["score"]["goal"].update(
        available=False, cumulative_raw=None, complete=False,
        presence="inapplicable", present=False, inapplicable=True,
        presence_verified=True,
    )
    no_goal = _projected_event([no_goal_event])
    assert no_goal["goal"]["available"] is False
    assert no_goal["goal"]["present"] is False
    assert no_goal["goal"]["inapplicable"] is True
    assert no_goal["goal"]["presence"] == "inapplicable"
    assert no_goal["goal"]["cumulative"]["raw"] is None
    service, _session, tools = _service(tmp_path / "no-goal", _wrapper(
        [no_goal_event], selected, score=no_goal,
    ))
    try:
        result = service.query(
            "w02-no-goal",
            queries=[_query("war_score", "cumulative_goal_score")],
        )
        item = _item(result)
        assert item["fields"]["war_score"]["status"] == "known"
        assert item["fields"]["cumulative_goal_score"] == {
            "status": "not_applicable", "reason": "WAR_GOAL_NOT_CONFIGURED",
        }
        assert len(tools.calls) == 1
    finally:
        service.close()

    failed_goal_event = deepcopy(events[0])
    failed_goal_event["score"]["goal"].update(
        available=False, cumulative_raw=None, complete=False,
        presence="configured", present=True, inapplicable=False,
        presence_verified=True,
    )
    failed_goal_event["score"]["complete"] = False
    failed_goal_event["score"]["verified"] = True
    failed_goal = _projected_event([failed_goal_event])
    assert failed_goal["status"] == "partial"
    assert failed_goal["goal"]["present"] is True
    assert failed_goal["goal"]["inapplicable"] is False
    assert failed_goal["goal"]["presence"] == "configured"
    service, _session, tools = _service(tmp_path / "failed-goal", _wrapper(
        [failed_goal_event], selected, score=failed_goal,
    ))
    try:
        result = service.query(
            "w02-failed-goal",
            queries=[_query("war_score", "cumulative_goal_score")],
        )
        item = _item(result)
        assert item["fields"]["war_score"]["status"] == "known"
        assert item["fields"]["cumulative_goal_score"] == {
            "status": "unknown", "reason": "WAR_GOAL_SCORE_UNAVAILABLE",
        }
        assert item["complete"] is False
        assert len(tools.calls) == 1
    finally:
        service.close()


def test_truncated_unknown_and_unimplemented_fields_never_fabricate_zero(tmp_path):
    events, selected = _recordings()
    truncated_event = deepcopy(events[0])
    truncated_event["tooltip"]["text_truncated"] = True
    truncated_event["tooltip"]["complete"] = False
    truncated = _projected_event([truncated_event])
    assert truncated["status"] == "truncated"
    assert truncated["total"]["raw"] == 0
    service, _session, tools = _service(tmp_path / "truncated", _wrapper(
        [truncated_event], selected, score=truncated,
    ))
    try:
        result = service.query(
            "w02-truncated",
            queries=[_query("war_score", "cumulative_goal_score")],
        )
        item = _item(result)
        assert item["fields"]["war_score"]["status"] == "known"
        assert item["fields"]["war_score"]["value"]["status"] == "truncated"
        assert item["fields"]["war_score"]["value"]["total"]["raw"] == 0
        assert item["complete"] is False
        assert len(tools.calls) == 1
    finally:
        service.close()

    unknown = unknown_war_score()
    assert unknown["total"]["raw"] is None
    assert unknown["goal"]["present"] is None
    assert unknown["goal"]["inapplicable"] is None
    assert unknown["goal"]["presence"] == "unknown"
    service, _session, tools = _service(tmp_path / "unknown", _wrapper(
        events, selected, score=unknown,
    ))
    try:
        result = service.query(
            "w02-unknown",
            queries=[_query("war_score")],
        )
        field = _item(result)["fields"]["war_score"]
        assert field == {"status": "unknown", "reason": "WAR_SCORE_NOT_VERIFIED"}
        assert len(tools.calls) == 1
    finally:
        service.close()

    service, _session, tools = _service(tmp_path / "unimplemented", _wrapper(events, selected))
    try:
        result = service.query(
            "w02-unimplemented",
            queries=[_query("war_score_sources")],
        )
        assert _item(result)["fields"]["war_score_sources"] == {
            "status": "unknown", "reason": "WAR_SCORE_FIELD_UNIMPLEMENTED",
        }
        assert len(tools.calls) == 1
    finally:
        service.close()


def test_capability_selection_conflict_and_context_change_are_bounded(tmp_path):
    events, selected = _recordings()
    response = _wrapper(events, selected)

    service, _session, tools = _service(
        tmp_path / "capability", response, capabilities=(),
    )
    try:
        result = service.query("w02-no-cap", queries=[_query("war_score")])
        assert _item(result)["fields"]["war_score"] == {
            "status": "unavailable", "reason": "WAR_SCORE_CAPABILITY_UNAVAILABLE",
        }
        assert tools.calls == []
    finally:
        service.close()

    service, _session, tools = _service(
        tmp_path / "missing-selection", response,
    )
    try:
        missing = _query("war_score")
        del missing["parameters"]["peace_context"]
        result = service.query("w02-missing-selection", queries=[missing])
        assert _item(result)["fields"]["war_score"] == {
            "status": "unavailable", "reason": "WAR_SELECTION_REQUIRED",
        }
        assert tools.calls == []
    finally:
        service.close()

    service, _session, tools = _service(
        tmp_path / "conflict", response,
    )
    try:
        conflict = _query("war_score", object_type="war", top_war_id=WAR_ID)
        conflict["object"]["war_id"] = "war_0123456789abcdef_00000002"
        with pytest.raises(InformationError) as exc:
            service.query("w02-conflict", queries=[conflict])
        assert exc.value.code == "object_parameter_conflict"
        assert tools.calls == []
    finally:
        service.close()

    service, _session, tools = _service(
        tmp_path / "identity", response, change_date_after_call=True,
    )
    try:
        result = service.query("w02-context-change", queries=[_query("war_score")])
        assert _item(result)["fields"]["war_score"] == {
            "status": "unknown", "reason": "WAR_SCORE_CONTEXT_CHANGED",
        }
        assert len(tools.calls) == 1
    finally:
        service.close()

