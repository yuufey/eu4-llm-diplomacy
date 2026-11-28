from __future__ import annotations

from copy import deepcopy

import pytest

from bridge import map_military_wars as scope


ID_A = "war_0123456789abcdef_00000001"
ID_B = "war_0123456789abcdef_00000002"
DATE = 56896992


def _war(first=("TUR", "SER"), second=("GRE",), *, war_id=ID_A, target_side="side_a"):
    identity = ({"status": "known", "value": war_id, "identity_scope": "observer_session",
                 "lifetime_verified": False} if war_id is not None
                else {"status": "unknown", "reason": "WAR_ID_REGISTRY_NO_MATCH"})
    return {"war_id": identity, "target_side": target_side,
            "side_a": [{"status": "known", "country": tag} for tag in first],
            "side_b": [{"status": "known", "country": tag} for tag in second],
            "membership_complete": True, "identities_complete": True, "roles_verified": False}


def _report(wars):
    context = {"game_date": DATE, "world_pointer": "0x20000000"}
    field = {
        "status": "known", "unit": "native_country_wars", "scale": 1,
        "partial": True, "complete": False,
        "basis": "current_country_war_index_and_side_vector_projection",
        "value": {"at_war": bool(wars), "war_count": len(wars), "wars": wars,
                  "enumeration_scope": "current_country_opponent_index",
                  "global_membership_verified": False, "lifetime_verified": False},
    }
    return {
        "status": "observed", "completed": True,
        "request": {"pid": 42, "creation_filetime": 99, "session_id": "session"},
        "observation": {
            "stable": True, "context_before": deepcopy(context), "context_after": deepcopy(context),
            "runtime_code_before": [{"matches": True}], "runtime_code_after": [{"matches": True}],
            "backend": {"status": "observed", "observer": {"tag": "TUR"}, "targets": [{
                "tag": "TUR", "field_consistency": {"F01.wars": {"status": "stable"}},
                "fields": {"F01.wars": field},
            }]},
        },
    }


@pytest.fixture
def source(monkeypatch, tmp_path):
    path = tmp_path / "installation.json"
    path.write_text("{}", encoding="utf-8")
    state = {"report": _report([_war()]), "valid": True, "calls": []}

    def capture(installation, country, *, observer):
        state["calls"].append((installation, country, observer))
        return deepcopy(state["report"])

    monkeypatch.setattr(scope._capture, "capture", capture)
    monkeypatch.setattr(scope._capture, "validate_capture", lambda *args: state["valid"])
    return path, state


def test_single_war_and_known_session_id(source):
    path, state = source
    result = scope.capture_war_scope(path, "TUR")
    assert result["status"] == "known"
    assert result["war_id"] == ID_A
    assert result["participants"] == ["TUR", "SER", "GRE"]
    assert result["sides"] == {"side_a": ["TUR", "SER"], "side_b": ["GRE"]}
    assert result["reason"] is None
    assert result["date"] == "1495.2.3" and result["date_raw"] == DATE
    assert result["identity"] == {"pid": 42, "creation_filetime": 99, "session_id": "session"}
    assert result["world_token"] == scope._map._world_token({"world_pointer": "0x20000000"})
    assert state["calls"] == [(path, "TUR", "TUR")]
    assert scope.capture_war_scope(path, "TUR", war_id=ID_A)["participants"] == result["participants"]


def test_peace_is_known_empty_but_explicit_absent_war_is_unavailable(source):
    path, state = source
    state["report"] = _report([])
    result = scope.capture_war_scope(path, "TUR")
    assert result["status"] == "known" and result["participants"] == []
    assert result["war_id"] is None and result["reason"] == "OBSERVER_NO_ACTIVE_WARS"
    result = scope.capture_war_scope(path, "TUR", ID_A)
    assert result["status"] == "unavailable" and result["reason"] == "WAR_ID_NOT_ACTIVE_FOR_OBSERVER"


def test_single_unregistered_war_can_be_defaulted_but_not_selected_by_id(source):
    path, state = source
    state["report"] = _report([_war(war_id=None)])
    result = scope.capture_war_scope(path, "TUR")
    assert result["status"] == "known" and result["participants"] == ["TUR", "SER", "GRE"]
    assert result["war_id"] is None and result["reason"] == "WAR_ID_REGISTRY_NO_MATCH"
    result = scope.capture_war_scope(path, "TUR", ID_A)
    assert result["status"] == "unavailable" and result["reason"] == "WAR_ID_UNRESOLVED"


def test_multiple_wars_require_id_and_select_only_its_members(source):
    path, state = source
    state["report"] = _report([_war(), _war(("TUR",), ("FRA", "ENG"), war_id=ID_B)])
    result = scope.capture_war_scope(path, "TUR")
    assert result["status"] == "unavailable" and result["reason"] == "WAR_SELECTION_REQUIRED"
    assert result["participants"] == []
    result = scope.capture_war_scope(path, "TUR", ID_B)
    assert result["status"] == "known" and result["participants"] == ["TUR", "FRA", "ENG"]
    assert result["war_id"] == ID_B
    result = scope.capture_war_scope(path, "TUR", "war_0123456789abcdef_00000003")
    assert result["status"] == "unavailable" and result["reason"] == "WAR_ID_NOT_ACTIVE_FOR_OBSERVER"


def test_recycled_registry_lifetime_serial_is_selected_without_slot_truncation(source):
    path, state = source
    recycled_id = "war_0123456789abcdef_00000258"  # lifetime serial 600
    state["report"] = _report([_war(), _war(("TUR",), ("FRA",), war_id=recycled_id)])
    result = scope.capture_war_scope(path, "TUR", recycled_id)
    assert result["status"] == "known" and result["war_id"] == recycled_id
    assert result["participants"] == ["TUR", "FRA"]


def test_member_redaction_and_wrong_observer_cannot_become_complete_scope(source):
    path, state = source
    war = _war()
    war["side_b"] = [{"status": "invisible", "reason": "NOT_ADMITTED"}]
    war["identities_complete"] = False
    state["report"] = _report([war])
    result = scope.capture_war_scope(path, "TUR")
    assert result["status"] == "unavailable" and result["reason"] == "WAR_PARTICIPANTS_INCOMPLETE"
    assert result["participants"] == []
    state["report"] = _report([_war(first=("SER",))])
    result = scope.capture_war_scope(path, "TUR")
    assert result["status"] == "unavailable" and result["reason"] == "WAR_OBSERVER_MEMBERSHIP_INVALID"


@pytest.mark.parametrize("mutation", ["replay", "context", "code", "field", "world", "date", "identity"])
def test_invalid_or_changed_capture_fails_closed(source, mutation):
    path, state = source
    report = state["report"]
    observation = report["observation"]
    if mutation == "replay":
        state["valid"] = False
    elif mutation == "context":
        observation["context_after"]["game_date"] += 24
    elif mutation == "code":
        observation["runtime_code_after"] = []
    elif mutation == "field":
        observation["backend"]["targets"][0]["field_consistency"]["F01.wars"] = {"status": "changed"}
    elif mutation == "world":
        observation["context_before"]["world_pointer"] = None
        observation["context_after"]["world_pointer"] = None
    elif mutation == "date":
        observation["context_before"]["game_date"] = -1
        observation["context_after"]["game_date"] = -1
    else:
        report["request"]["creation_filetime"] = None
    result = scope.capture_war_scope(path, "TUR")
    assert result["status"] == "unavailable" and result["participants"] == []
    assert result["reason"] == "WAR_SCOPE_CAPTURE_INVALID"


def test_capture_failure_and_bad_requests(source):
    path, state = source
    state["report"] = {"status": "unknown", "completed": False}
    assert scope.capture_war_scope(path, "TUR")["reason"] == "WAR_SCOPE_CAPTURE_FAILED_OR_UNSTABLE"
    with pytest.raises(scope._map.MapLiveCaptureError, match="WAR_ID_INVALID"):
        scope.capture_war_scope(path, "TUR", "not-a-war")
    with pytest.raises(scope._map.MapLiveCaptureError, match="OBSERVER_INVALID"):
        scope.capture_war_scope(path, "tur")
    with pytest.raises(scope._map.MapLiveCaptureError, match="INSTALLATION_MISSING"):
        scope.capture_war_scope(path.parent / "missing", "TUR")


def test_real_replay_rejects_tampered_trace_and_keeps_redacted_member_unknown(monkeypatch, tmp_path):
    # Reuse the existing bounded memory image and the actual capture replay;
    # only process attachment is replaced by the already captured report.
    from bridge.tests.test_information_country_scale_capture import _bundle

    report, _, _, _ = _bundle(country="FRA", registry_id=True)
    report["request"]["pid"] = 42
    path = tmp_path / "installation.json"
    path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(scope._capture, "capture", lambda *args, **kwargs: deepcopy(report))
    result = scope.capture_war_scope(path, "FRA")
    assert result["reason"] == "WAR_PARTICIPANTS_INCOMPLETE"
    assert result["participants"] == []
    report["raw_reads"][0]["raw_hex"] = "00" * report["raw_reads"][0]["size"]
    assert scope.capture_war_scope(path, "FRA")["reason"] == "WAR_SCOPE_CAPTURE_INVALID"
