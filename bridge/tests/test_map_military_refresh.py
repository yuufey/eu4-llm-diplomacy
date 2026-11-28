import sys
from types import SimpleNamespace

import numpy as np
import pytest

from bridge import map_live_capture, map_live_service
from bridge.map_military import capture_layers, layers_for_view


def test_fort_capture_scope_skips_overview_hidden_land_and_wrong_session(monkeypatch):
    calls = []
    identity = {"pid": 42, "creation_filetime": 43, "session_id": "fixture"}

    def capture_forts(installation, observer, province_ids, *, participants, **kwargs):
        calls.append((province_ids, participants))
        return {"identity": identity, "date": "1495.2.3", "status": "known",
                "records": [{"province_id": pid, "level": 2} for pid in province_ids]}

    monkeypatch.setitem(sys.modules, "bridge.map_military_forts", SimpleNamespace(capture_forts=capture_forts))
    siege_calls = []

    def capture_sieges(installation, observer, province_ids, *, participants):
        siege_calls.append((province_ids, participants))
        return {"identity": identity, "date": "1495.2.3", "status": "partial",
                "records": [{"province_id": 1, "elapsed_days": 42}]}

    monkeypatch.setitem(sys.modules, "bridge.map_military_siege",
                        SimpleNamespace(capture_sieges=capture_sieges))
    war_requests = []
    scope = {"identity": identity, "date": "1495.2.3", "status": "known",
             "participants": ["FRA", "ENG"]}

    def capture_war_scope(installation, observer, war_id=None):
        war_requests.append(war_id)
        return scope

    monkeypatch.setitem(sys.modules, "bridge.map_military_wars",
                        SimpleNamespace(capture_war_scope=capture_war_scope))
    service = SimpleNamespace(installation="fixture", observer="FRA", game_root=None, user_data=None)
    base = {"date": "1495.2.3", "identity": identity}
    views = [
        {"scale": "overview", "records": {"3": {"status": "known", "province_id": 3}}},
        {"scale": "local", "records": {
            "0": {"status": "hidden"}, "1": {"status": "known", "province_id": 1},
            "2": {"status": "water", "province_id": 2},
        }},
    ]
    assert capture_layers(service, base, views[:1], ("forts",), same_date=True)["forts"]["status"] == "not_applicable"
    assert war_requests == []
    captured = capture_layers(service, base, views, ("forts",), same_date=True, war_id="sample")
    assert captured["forts"]["records"] == [{"province_id": 1, "level": 2, "siege_elapsed_days": 42}]
    assert captured["forts"]["fields"]["siege_progress"]["status"] == "partial"
    assert calls == [([1], ["FRA", "ENG"])]
    assert siege_calls == calls
    assert war_requests == ["sample"]
    # Transported armies can be anchored in known sea provinces. Forts cannot.
    both = {key: {"status": "known", "records": [{"province_id": 2}]}
            for key in ("armies", "forts")}
    assert layers_for_view(views[1], both)["armies"]["records"] == [{"province_id": 2}]
    assert layers_for_view(views[1], both)["forts"]["records"] == []
    with pytest.raises(map_live_capture.MapLiveCaptureError, match="MAP_MILITARY_BASELINE_SESSION_CHANGED"):
        capture_layers(service, {**base, "identity": {"pid": 99}}, views, ("forts",), same_date=False)
    scope.update(participants=[], reason="MAP_NO_ACTIVE_WARS")
    assert capture_layers(service, base, views, ("forts",), same_date=True)["forts"]["status"] == "not_applicable"
    assert len(calls) == 1  # Without a selected war, do not read any fort levels.
    scope.update(status="unavailable", reason="MAP_WAR_SELECTION_REQUIRED")
    result = capture_layers(service, base, views, ("forts",), same_date=True)["forts"]
    assert result["status"] == "unavailable" and result["records"] == []
    assert len(calls) == 1


def test_armies_only_resolves_war_sides_and_restricts_enemy_scope_to_land(monkeypatch):
    identity = {"pid": 42, "creation_filetime": 43, "session_id": "fixture"}
    base = {"identity": identity, "date": "1495.2.3"}
    calls = []
    war = {**base, "status": "known", "participants": ["FRA", "ENG", "SCO"],
           "sides": {"side_a": ["ENG"], "side_b": ["FRA", "SCO"]}}

    def capture_armies(installation, observer, ids, **scope):
        calls.append((ids, scope))
        return {**base, "status": "partial", "records": []}

    monkeypatch.setitem(sys.modules, "bridge.map_military_wars", SimpleNamespace(
        capture_war_scope=lambda *args, **kwargs: war))
    monkeypatch.setitem(sys.modules, "bridge.map_military_armies",
                        SimpleNamespace(capture_armies=capture_armies))
    service = SimpleNamespace(installation="fixture", observer="FRA")
    view = {"scale": "overview", "records": {
        "1": {"status": "known", "province_id": 1},
        "2": {"status": "water", "province_id": 2},
        "0": {"status": "hidden"},
    }}
    capture_layers(service, base, [view], ("armies",), same_date=True)
    assert calls == [([1, 2], {"allies": ["FRA", "SCO"], "enemies": ["ENG"],
                              "land_province_ids": {1}})]


def test_military_scope_keeps_baseline_and_skips_duplicate_png(monkeypatch):
    base_calls = []
    military_calls = []
    draws = []
    entered = [{"province_id": 2, "owner": "ENG", "relation": "enemy", "men": 780}]
    military = {"armies": {"status": "known", "date": "1495.2.4", "records": []}}
    identity = {"pid": 42, "creation_filetime": 43, "session_id": "fixture"}

    def capture_base(*args):
        base_calls.append(args)
        return {"owners": {1: "FRA", 2: "ENG"}, "date": "1495.2.3", "identity": identity}

    def capture_layers(service, snapshot, views, layers, *, same_date, war_id=None):
        if layers:
            military_calls.append((tuple(layers), same_date))
            return military
        return {}

    original = map_live_service.draw_snapshot

    def draw(*args, **kwargs):
        draws.append(kwargs)
        return original(*args, **kwargs)

    geometry = SimpleNamespace(
        province_ids=np.repeat(np.tile(np.array([1, 2], dtype=np.uint16), (20, 24)), 4, axis=1),
        sea_province_ids=set(), lake_province_ids=set(), source_files={},
        definitions={1: SimpleNamespace(name="One"), 2: SimpleNamespace(name="Two")},
        kind_for_province=lambda _: "land",
    )
    monkeypatch.setattr(map_live_capture, "capture_live", capture_base)
    monkeypatch.setattr(map_live_service, "load_map_geometry", lambda *_: geometry)
    monkeypatch.setattr(map_live_service, "load_country_colors", lambda *_a, **_kw: SimpleNamespace(colors={}))
    monkeypatch.setattr(map_live_service, "capture_layers", capture_layers)
    monkeypatch.setattr(map_live_service, "draw_snapshot", draw)
    service = map_live_service.LivePoliticalMap("fixture.json", "FRA")
    query = {"xy": (25, 10), "scale": "local"}
    with pytest.raises(ValueError, match="MAP_MILITARY_BASELINE_REQUIRED"):
        service.render(**query, refresh_scope="military", layers=["armies"])
    service.render(**query, refresh_scope="full")
    service.invalidate()
    image, previous, _ = service.render(**query, refresh_scope="military", layers=["armies"])
    duplicate, view, metrics = service.render(**query, refresh_scope="military", layers=["armies"],
                                               previous_view_id=previous["view_id"])
    assert image is not None and duplicate is None
    assert view["unchanged_from"] == previous["view_id"]
    assert view["date"] == "1495.2.3"
    assert view["military"]["armies"]["date"] == "1495.2.4"
    assert metrics["refresh_scope"] == "military"
    assert len(base_calls) == len(draws) == 1
    assert military_calls == [(("armies",), False)] * 2
    military["armies"]["records"] = entered
    updated, changed, _ = service.render(**query, refresh_scope="military", layers=["armies"],
                                         previous_view_id=view["view_id"])
    assert updated is not None and changed["records"]["2"]["armies"] == entered
    military["armies"]["records"] = []
    cleared, cleared_view, _ = service.render(**query, refresh_scope="military", layers=["armies"],
                                              previous_view_id=changed["view_id"])
    assert cleared is not None and "armies" not in cleared_view["records"]["2"]
    assert cleared.tobytes() == image.tobytes()
    service.render(**query, refresh_scope="full")
    assert len(base_calls) == len(draws) == 2
