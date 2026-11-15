"""W01 war discovery contract over a pinned R64 native observation.

The small ``peace-live002`` JSON is the real boundary: its bytes and the
operator/session/date/submitted markers are pinned.  Every other case is an
in-memory mutation of that response.  The mutations never stand for another
native observation; they exercise the public adapter's bounded selection,
identity, and privacy behavior through the real ``DiplomacySource`` and
``InformationService``.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re

import pytest

from bridge.information import InformationService
from bridge.information.catalog import get_topic
from bridge.information.model import InformationError
from bridge.information.sources import DiplomacySource
from bridge.information.tools import InformationTools


ROOT = Path(__file__).resolve().parents[2]
DISCOVERY_FIXTURE = (
    ROOT
    / "work/runtime/information-battle-autonomous-live-20261027-001"
    / "peace-live-002/discovery-response.json"
)
DISCOVERY_FIXTURE_SHA256 = (
    "76548cd075df3a8c67e3d75cfe787d27e8a7b5e2a243c45f67794e6b43b6af5e"
)
SESSION_ID = "36432-1dd660f811253b1"
GAME_DATE = 56562768
GAME_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
DLL_SHA256 = "3d9e1fea9d8f34297a4a20646ea0b45d7d0f6a4af11cef6411586dd8b3264964"
WAR_ID = "war_850cdff5caccf091_00000003"
WAR_ID_RE = re.compile(r"war_[0-9a-f]{16}_[0-9a-f]{8}\Z")
PUBLIC_WAR_KEYS = {"type", "war_id", "actor", "recipient"}
PRIVATE_WAR_KEYS = {
    "actor_is_war_leader", "actor_war_role", "context_complete",
    "identity_scope", "leaders_verified", "recipient_is_war_leader",
    "recipient_war_role", "roles_verified", "leaders", "participants",
    "join_dates", "co_belligerent_roles", "pair_at_war",
}


def _load_pinned_fixture() -> dict:
    assert DISCOVERY_FIXTURE.is_file()
    assert hashlib.sha256(DISCOVERY_FIXTURE.read_bytes()).hexdigest() == DISCOVERY_FIXTURE_SHA256
    value = json.loads(DISCOVERY_FIXTURE.read_text(encoding="utf-8"))
    assert value["event"] == "native_peace_context_inspection"
    assert value["action_id"] == "white_peace"
    assert value["actor"] == "FRA" and value["recipient"] == "BUR"
    assert value["phase"] == "initiate"
    assert value["session_id"] == SESSION_ID and value["date_raw"] == GAME_DATE
    assert value["query_complete"] is True and value["submitted"] is False
    assert value["war_context_enumeration_complete"] is True
    rows = value["war_contexts"]
    assert isinstance(rows, list) and len(rows) == 1
    row = rows[0]
    assert row["actor"] == "FRA" and row["recipient"] == "BUR"
    assert row["identity_scope"] == "observer_session"
    assert row["pair_at_war"] is True
    assert WAR_ID_RE.fullmatch(row["war_id"])
    return value


class _StubSession:
    """Bounded ObserverSession stand-in; no native or game access."""

    def __init__(self, response: dict, *, mutation: str | None = None):
        self.response = deepcopy(response)
        self.mutation = mutation
        self.session_id = SESSION_ID
        self.experiment_id = "information-war-discovery-test"
        self.observer = "FRA"
        self.date_raw = GAME_DATE
        self.inspect_calls: list[tuple[str, str, str, str]] = []
        self.health_calls = 0
        self.record = {
            "session_id": SESSION_ID,
            "experiment_id": self.experiment_id,
            "pid": 36432,
            "creation_filetime": 134375780666987441,
            "game_sha256": GAME_SHA256,
            "dll_sha256": DLL_SHA256,
            "observer": "FRA",
            "game_date": GAME_DATE,
            "game_version": "1.37.4",
            "world_id": "r64-test-world",
            "paused": True,
        }

    def health(self) -> dict:
        self.health_calls += 1
        return {
            "status": "ready",
            "complete": True,
            "session_id": self.session_id,
            "observer": self.observer,
            "game_version": "1.37.4",
            "game_sha256": GAME_SHA256,
            "dll_sha256": DLL_SHA256,
            "game_date": self.date_raw,
            "game_day": self.date_raw // 24,
            "world_id": "r64-test-world",
            "paused": True,
        }

    def inspect_peace_contexts(
            self, action_id: str, actor: str, recipient: str, phase: str) -> dict:
        self.inspect_calls.append((action_id, actor, recipient, phase))
        if self.mutation == "session":
            self.session_id = "changed-session-after-discovery"
        elif self.mutation == "date":
            self.date_raw += 24
        result = deepcopy(self.response)
        if self.mutation == "response-session":
            result["session_id"] = "foreign-session"
        elif self.mutation == "response-date":
            result["date_raw"] = GAME_DATE + 24
        elif self.mutation == "submitted":
            result["submitted"] = True
        return result


class _StubDiplomacyTools:
    def __init__(self, session: _StubSession):
        self.session = session
        self.inspect_diplomatic_calls: list[tuple] = []

    def inspect_diplomatic_action(self, *args):
        self.inspect_diplomatic_calls.append(args)
        raise AssertionError("W01 must use ObserverSession.inspect_peace_contexts")


def _service(tmp_path: Path, response: dict, *, mutation: str | None = None):
    session = _StubSession(response, mutation=mutation)
    tools = _StubDiplomacyTools(session)
    source = DiplomacySource(tools, observer="FRA")
    service = InformationService(source, tmp_path / "information.sqlite3")
    return service, session, tools


def _query(
        object_value: dict,
        *,
        action_id: str = "white_peace",
        phase: str = "initiate",
        war_id: str | None = None,
        fields: list[str] | None = None,
        extra_parameters: dict | None = None,
) -> dict:
    parameters = {"action_id": action_id, "phase": phase}
    if war_id is not None:
        parameters["war_id"] = war_id
    if extra_parameters:
        parameters.update(extra_parameters)
    return {
        "topic": "W01",
        "object": deepcopy(object_value),
        "fields": fields or ["war_id"],
        "parameters": parameters,
    }


def _pair_object(actor: str = "FRA", recipient: str = "BUR") -> dict:
    return {"type": "country_pair", "actor": actor, "recipient": recipient}


def _war_object(war_id: str = WAR_ID) -> dict:
    return {"type": "war", "war_id": war_id, "actor": "FRA", "recipient": "BUR"}


def _item(result: dict) -> dict:
    assert isinstance(result.get("items"), list) and len(result["items"]) == 1
    return result["items"][0]


def _provenance(item: dict) -> dict:
    source = item.get("source")
    assert isinstance(source, dict)
    provenance = source.get("provenance")
    assert isinstance(provenance, dict)
    return provenance


def _war_objects(item: dict) -> list[dict]:
    objects = item.get("objects")
    assert isinstance(objects, list)
    for value in objects:
        assert isinstance(value, dict)
        assert PUBLIC_WAR_KEYS <= set(value)
        assert not PRIVATE_WAR_KEYS.intersection(value)
        assert value["type"] == "war"
        assert WAR_ID_RE.fullmatch(value["war_id"])
        assert value["actor"] == "FRA" and value["recipient"] == "BUR"
    return objects


def _assert_native_route(session: _StubSession, tools: _StubDiplomacyTools) -> None:
    assert session.inspect_calls == [("white_peace", "FRA", "BUR", "initiate")]
    assert tools.inspect_diplomatic_calls == []


def test_w01_real_r64_fixture_country_pair_and_war_forms(tmp_path):
    """The real R64 row selects one public war through both supported objects."""
    fixture = _load_pinned_fixture()
    service, session, tools = _service(tmp_path, fixture)
    try:
        pair_result = service.query(
            "w01-real-pair",
            queries=[_query(_pair_object())],
        )
        pair_item = _item(pair_result)
        assert pair_item["complete"] is True
        assert pair_item["fields"]["war_id"] == {
            "status": "known", "value": WAR_ID,
        }
        assert pair_result["complete"] is True and pair_result["status"] == "complete"
        assert _war_objects(pair_item) == [{
            "type": "war", "war_id": WAR_ID, "actor": "FRA", "recipient": "BUR",
        }]
        provenance = _provenance(pair_item)
        assert provenance["enumeration_complete"] is True
        assert provenance["scope"] == "selected_country_pair"
        assert provenance["candidate_count"] == 1
        _assert_native_route(session, tools)

        # A fresh service query covers the explicit W01 war identity while the
        # native route remains exactly the same four-argument read.
        service.close()
        service, session, tools = _service(tmp_path / "explicit", fixture)
        war_result = service.query(
            "w01-real-war",
            queries=[_query(_war_object(), war_id=WAR_ID)],
        )
        war_item = _item(war_result)
        assert war_item["fields"]["war_id"] == {"status": "known", "value": WAR_ID}
        assert war_item["complete"] is True
        _assert_native_route(session, tools)
    finally:
        service.close()


def test_w01_catalog_limits_parameters_and_service_rejects_conflict_without_native(tmp_path):
    topic = get_topic("W01")
    assert set(topic["parameters"]["properties"]) == {"action_id", "phase", "war_id"}
    assert topic["parameters"]["additionalProperties"] is False

    fixture = _load_pinned_fixture()
    service, session, tools = _service(tmp_path, fixture)
    try:
        with pytest.raises(InformationError) as conflict:
            service.query(
                "w01-conflict",
                queries=[_query(_war_object(), war_id="war_0123456789abcdef_00000001")],
            )
        assert conflict.value.code == "object_parameter_conflict"
        assert session.inspect_calls == []
        with pytest.raises(InformationError) as unsupported:
            service.query(
                "w01-unsupported-parameter",
                queries=[_query(_pair_object(), extra_parameters={"selection": {}})],
            )
        assert unsupported.value.code in {"invalid_parameters", "invalid_schema"}
        assert session.inspect_calls == []
        assert tools.inspect_diplomatic_calls == []
    finally:
        service.close()


def test_w01_multiple_candidates_require_llm_selection_and_expose_only_war_objects(tmp_path):
    fixture = _load_pinned_fixture()
    second = deepcopy(fixture["war_contexts"][0])
    second["war_id"] = "war_0123456789abcdef_00000004"
    fixture["war_contexts"].append(second)
    service, session, tools = _service(tmp_path, fixture)
    try:
        result = service.query("w01-multiple", queries=[_query(_pair_object())])
        item = _item(result)
        assert item["fields"]["war_id"] == {
            "status": "unknown", "reason": "WAR_SELECTION_REQUIRED",
        }
        assert item["complete"] is False and result["complete"] is False
        objects = _war_objects(item)
        assert {entry["war_id"] for entry in objects} == {
            WAR_ID, "war_0123456789abcdef_00000004",
        }
        assert len(objects) == 2
        provenance = _provenance(item)
        assert provenance["enumeration_complete"] is True
        assert provenance["scope"] == "selected_country_pair"
        assert provenance["candidate_count"] == 2
        _assert_native_route(session, tools)
    finally:
        service.close()


def test_w01_concise_candidates_support_selection_and_survive_cold_reopen(tmp_path):
    fixture = _load_pinned_fixture()
    second = deepcopy(fixture["war_contexts"][0])
    second["war_id"] = "war_850cdff5caccf091_00000004"
    fixture["war_contexts"].append(second)
    service, session, _ = _service(tmp_path, fixture)
    source = service.source
    try:
        tools = InformationTools(service)
        arguments = {"request_id": "w01-concise-candidates", "queries": [_query(_pair_object())]}
        result = tools.call("information_query", arguments)
        candidates = result["items"][0]["war_candidates"]
        full = tools.call("information_get_result", {"result_id": result["result_id"], "view": "full"})
        assert candidates == _war_objects(_item(full))
        assert {candidate["war_id"] for candidate in candidates} == {WAR_ID, second["war_id"]}
        assert all(set(candidate) == PUBLIC_WAR_KEYS for candidate in candidates)
        assert tools.call("information_query", arguments) == result
        assert tools.call("information_list_results", {})["results"] == [result]
        assert len(session.inspect_calls) == 1

        selected = tools.call("information_query", {
            "request_id": "w01-selected-candidate", "queries": [_query(candidates[1])],
        })
        assert selected["items"][0]["war_id"] == second["war_id"]
        assert len(session.inspect_calls) == 2
    finally:
        service.close()

    reopened = InformationService(source, tmp_path / "information.sqlite3")
    try:
        tools = InformationTools(reopened)
        assert tools.call("information_get_result", {"result_id": result["result_id"]}) == result
        assert tools.call("information_get_result", {"result_id": selected["result_id"]}) == selected
        assert len(session.inspect_calls) == 2
    finally:
        reopened.close()


def test_w01_zero_candidate_is_not_applicable_and_complete(tmp_path):
    fixture = _load_pinned_fixture()
    fixture["war_contexts"] = []
    service, session, tools = _service(tmp_path, fixture)
    try:
        result = service.query("w01-zero", queries=[_query(_pair_object())])
        item = _item(result)
        assert item["fields"]["war_id"] == {
            "status": "not_applicable", "reason": "NO_MATCHING_WAR",
        }
        assert item["complete"] is True
        assert result["complete"] is True and result["status"] == "complete"
        assert _war_objects(item) == []
        provenance = _provenance(item)
        assert provenance["enumeration_complete"] is True
        assert provenance["scope"] == "selected_country_pair"
        assert provenance["candidate_count"] == 0
        _assert_native_route(session, tools)
    finally:
        service.close()


def test_w01_explicit_missing_war_is_unknown_without_fallback_selection(tmp_path):
    fixture = _load_pinned_fixture()
    missing = "war_0123456789abcdef_00000009"
    service, session, tools = _service(tmp_path, fixture)
    try:
        result = service.query(
            "w01-explicit-missing",
            queries=[_query(_war_object(missing), war_id=missing)],
        )
        item = _item(result)
        assert item["fields"]["war_id"] == {
            "status": "unknown", "reason": "WAR_NOT_FOUND_IN_CURRENT_CONTEXT",
        }
        assert item["complete"] is False
        assert _war_objects(item) == [{
            "type": "war", "war_id": WAR_ID, "actor": "FRA", "recipient": "BUR",
        }]
        assert _provenance(item)["enumeration_complete"] is True
        _assert_native_route(session, tools)
    finally:
        service.close()


def test_w01_incomplete_enumeration_and_over32_rows_fail_closed(tmp_path):
    fixture = _load_pinned_fixture()
    fixture["war_context_enumeration_complete"] = False
    fixture["war_contexts"] = [
        {
            **deepcopy(fixture["war_contexts"][0]),
            "war_id": f"war_{index:016x}_{index:08x}",
        }
        for index in range(1, 3)
    ]
    service, session, tools = _service(tmp_path, fixture)
    try:
        result = service.query("w01-incomplete", queries=[_query(_pair_object())])
        item = _item(result)
        assert item["fields"]["war_id"] == {
            "status": "unknown", "reason": "WAR_ENUMERATION_INCOMPLETE",
        }
        assert item["complete"] is False
        objects = _war_objects(item)
        assert len(objects) == 2
        provenance = _provenance(item)
        assert provenance["enumeration_complete"] is False
        assert provenance["scope"] == "selected_country_pair"
        assert provenance["candidate_count"] == 2
        _assert_native_route(session, tools)
    finally:
        service.close()

    # The adapter rejects an overlarge native result rather than truncating it.
    fixture = _load_pinned_fixture()
    fixture["war_contexts"] = [
        {
            **deepcopy(fixture["war_contexts"][0]),
            "war_id": f"war_{index:016x}_{index:08x}",
        }
        for index in range(1, 34)
    ]
    service, session, tools = _service(tmp_path / "over32", fixture)
    try:
        result = service.query("w01-over32", queries=[_query(_pair_object())])
        item = _item(result)
        assert item["fields"]["war_id"] == {
            "status": "unknown", "reason": "WAR_DISCOVERY_RESULT_INVALID",
        }
        assert item["complete"] is False
        assert _war_objects(item) == []
        assert _provenance(item)["candidate_count"] is None
        _assert_native_route(session, tools)
    finally:
        service.close()


def test_w01_duplicate_native_row_is_invalid_without_public_candidates(tmp_path):
    fixture = _load_pinned_fixture()
    fixture["war_contexts"].append(deepcopy(fixture["war_contexts"][0]))
    service, session, tools = _service(tmp_path, fixture)
    try:
        result = service.query("w01-duplicate", queries=[_query(_pair_object())])
        item = _item(result)
        assert item["fields"]["war_id"] == {
            "status": "unknown", "reason": "WAR_DISCOVERY_RESULT_INVALID",
        }
        assert item["complete"] is False
        assert _war_objects(item) == []
        assert _provenance(item)["candidate_count"] is None
        _assert_native_route(session, tools)
    finally:
        service.close()


@pytest.mark.parametrize(
    "mutation,expected_reason",
    [
        ("session", "WAR_DISCOVERY_CONTEXT_CHANGED"),
        ("response-session", "WAR_DISCOVERY_IDENTITY_MISMATCH"),
        ("response-date", "WAR_DISCOVERY_IDENTITY_MISMATCH"),
        ("submitted", "WAR_DISCOVERY_IDENTITY_MISMATCH"),
    ],
)
def test_w01_identity_date_and_submission_anomalies_are_unknown_without_retry(
        tmp_path, mutation, expected_reason):
    fixture = _load_pinned_fixture()
    service, session, tools = _service(tmp_path, fixture, mutation=mutation)
    try:
        result = service.query(
            f"w01-anomaly-{mutation}", queries=[_query(_pair_object())]
        )
        item = _item(result)
        field = item["fields"]["war_id"]
        assert field["status"] == "unknown"
        assert field["reason"] == expected_reason
        assert item["complete"] is False
        assert len(session.inspect_calls) == 1
        assert tools.inspect_diplomatic_calls == []
    finally:
        service.close()


@pytest.mark.parametrize("our_side", ["side_a", "side_b"])
@pytest.mark.parametrize("fields", [["leaders"], ["war_id", "leaders", "participants"]])
def test_w01_current_leaders_reuse_native_vector_order(tmp_path, our_side, fields):
    response = _load_pinned_fixture()
    opposing = "side_b" if our_side == "side_a" else "side_a"
    participants = {
        "source": "native_war_side_vectors", "status": "available", "complete": True,
        our_side: ["SAV", "FRA", "ORL"], opposing: ["BUR", "BRB"],
        "actor_side": our_side, "recipient_side": opposing, "reason": None,
    }
    response["war_contexts"][0]["participants"] = participants
    service, session, diplomacy = _service(tmp_path, response)
    session.installation_capabilities = lambda: {"native_war_participants_query"}
    try:
        tools = InformationTools(service)
        result = tools.call("information_query", {
            "request_id": "w01-current-leaders",
            "queries": [_query(_pair_object(), fields=fields)]})
        item = result["items"][0]
        assert item["leaders"] == {"our_side": "SAV", "opposing_side": "BUR"}
        assert ("participants" in item) == ("participants" in fields)
        assert "leaders_source" not in repr(result)
        full = tools.call("information_get_result", {"result_id": result["result_id"], "view": "full"})
        assert full["complete"] is True
        assert _provenance(full["items"][0])["leaders_verified"] is True
        _assert_native_route(session, diplomacy)
    finally:
        service.close()


@pytest.mark.parametrize("damage", ["capability", "missing", "duplicate", "unknown"])
def test_w01_leaders_require_the_existing_verified_participant_source(tmp_path, damage):
    response = _load_pinned_fixture()
    participants = {
        "source": "native_war_side_vectors", "status": "available", "complete": True,
        "side_a": ["BUR"], "side_b": ["SAV", "FRA"],
        "actor_side": "side_b", "recipient_side": "side_a", "reason": None,
    }
    if damage == "duplicate":
        participants["side_b"].append("FRA")
    elif damage == "unknown":
        participants.update(status="unknown", complete=False, side_a=[], side_b=[],
                            actor_side=None, recipient_side=None, reason="PARTICIPANT_CAPTURE_FAILED")
    if damage != "missing":
        response["war_contexts"][0]["participants"] = participants
    service, session, diplomacy = _service(tmp_path, response)
    session.installation_capabilities = lambda: (() if damage == "capability" else {"native_war_participants_query"})
    try:
        result = service.query("w01-leader-source-unavailable", queries=[
            _query(_pair_object(), fields=["war_id", "leaders"])])
        assert result["items"][0]["fields"]["war_id"]["value"] == WAR_ID
        assert result["items"][0]["fields"]["leaders"]["status"] == "unknown"
        assert result["complete"] is False
        _assert_native_route(session, diplomacy)
    finally:
        service.close()


def test_w01_keeps_the_sampled_war_when_time_advances(tmp_path):
    service, session, diplomacy = _service(tmp_path, _load_pinned_fixture(), mutation="date")
    try:
        result = service.query("w01-forward-clock", queries=[_query(_pair_object())])
        item = result["items"][0]
        assert item["fields"]["war_id"]["value"] == WAR_ID
        assert item["complete"] is True
        assert item["observation_window"]["start_game_date"] == GAME_DATE
        assert item["observation_window"]["end_game_date"] == GAME_DATE + 24
        _assert_native_route(session, diplomacy)
    finally:
        service.close()
