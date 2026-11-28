from __future__ import annotations

import sys
import types
from types import SimpleNamespace

import numpy as np
import pytest
from PIL import Image

import bridge.map_live_service as live_service


def _geometry():
    definitions = {
        1: SimpleNamespace(name="Alpha"),
        2: SimpleNamespace(name="Beta"),
    }
    return SimpleNamespace(
        definitions=definitions,
        province_ids=np.array([[1, 1], [2, 2]], dtype=np.uint16),
        sea_province_ids=frozenset(),
        lake_province_ids=frozenset(),
        source_files={},
        kind_for_province=lambda province_id: "land",
    )


def _install_fakes(monkeypatch, snapshots):
    calls = []
    capture_module = types.ModuleType("bridge.map_live_capture")

    def capture_live(pid, observer, province_ids):
        calls.append((pid, observer, tuple(province_ids)))
        item = snapshots[len(calls) - 1]
        if isinstance(item, BaseException):
            raise item
        return {"date": item["date"], "owners": dict(item["owners"])}

    capture_module.capture_live = capture_live
    monkeypatch.setitem(sys.modules, "bridge.map_live_capture", capture_module)
    monkeypatch.setattr(live_service, "load_map_geometry", lambda *_args: _geometry())
    monkeypatch.setattr(
        live_service,
        "load_country_colors",
        lambda *_args, **_kwargs: SimpleNamespace(colors={}),
    )

    def draw_snapshot(geometry, date, owners, observer, colors_for, **_kwargs):
        colors_for(set(owners.values()))
        view = {
            "date": date,
            "records": {str(pid): {"province_id": pid, "owner": owner}
                        for pid, owner in owners.items()},
        }
        return Image.new("RGB", (2, 2)), view, (0, 0), 0.0

    monkeypatch.setattr(live_service, "draw_snapshot", draw_snapshot)
    return calls


def test_reuses_snapshot_until_explicit_refresh_and_keeps_old_view(monkeypatch):
    calls = _install_fakes(
        monkeypatch,
        [
            {"date": "1.1.1", "owners": {1: "AAA", 2: "BBB"}},
            {"date": "1.1.2", "owners": {1: "CCC", 2: "BBB"}},
        ],
    )
    service = live_service.LivePoliticalMap(42, "AAA")

    _, old_view, first_metrics = service.render()
    _, reused_view, reused_metrics = service.render()
    _, new_view, refresh_metrics = service.render(refresh=True)

    assert len(calls) == 2
    assert old_view["records"]["1"]["owner"] == "AAA"
    assert reused_view["records"]["1"]["owner"] == "AAA"
    assert new_view["records"]["1"]["owner"] == "CCC"
    assert first_metrics["fresh_capture"] is True
    assert reused_metrics["fresh_capture"] is False
    assert refresh_metrics["fresh_capture"] is True
    assert old_view["snapshot_id"]
    assert old_view["snapshot_id"] != new_view["snapshot_id"]


def test_reuse_does_not_read_game_again(monkeypatch):
    calls = _install_fakes(
        monkeypatch,
        [{"date": "2.1.1", "owners": {1: "AAA", 2: "BBB"}}],
    )
    service = live_service.LivePoliticalMap(7, "AAA")

    service.render()
    service.render(center_country="AAA", scale="local", size="detailed")
    service.render(xy=(1, 1), scale="overview")

    assert len(calls) == 1


def test_failed_refresh_does_not_replace_last_good_snapshot(monkeypatch):
    calls = _install_fakes(
        monkeypatch,
        [
            {"date": "3.1.1", "owners": {1: "AAA", 2: "BBB"}},
            RuntimeError("live capture failed"),
        ],
    )
    service = live_service.LivePoliticalMap(9, "AAA")
    _, old_view, _ = service.render()

    with pytest.raises(RuntimeError, match="live capture failed"):
        service.render(refresh=True)

    _, reused_view, metrics = service.render()
    assert len(calls) == 2
    assert old_view["records"]["1"]["owner"] == "AAA"
    assert reused_view["records"]["1"]["owner"] == "AAA"
    assert metrics["fresh_capture"] is False


def test_archive_bundle_keeps_interactive_view_cache_isolated(monkeypatch):
    calls = _install_fakes(
        monkeypatch,
        [
            {"date": "4.1.1", "owners": {1: "AAA", 2: "BBB"}},
            {"date": "4.1.2", "owners": {1: "BBB", 2: "BBB"}},
        ],
    )
    service = live_service.LivePoliticalMap("installation.json", "AAA")
    _, interactive, _ = service.render()
    result = service.render_bundle()

    assert len(calls) == 2
    assert interactive["view_id"] in service._views
    assert set(result["views"]) == {"overview", "region", "local"}
    assert {view["snapshot_id"] for view in result["views"].values()} == {result["snapshot_id"]}
    _, after_archive, metrics = service.render()
    assert after_archive["date"] == "4.1.1"
    assert after_archive["records"]["1"]["owner"] == "AAA"
    assert metrics["fresh_capture"] is False

def test_due_brief_refreshes_only_the_next_map(monkeypatch):
    from tools.run_information_decisions import due_brief

    calls = _install_fakes(monkeypatch, [
        {"date": "1.1.1", "owners": {1: "AAA"}},
        {"date": "1.1.2", "owners": {1: "BBB"}},
    ])
    maps = live_service.LivePoliticalMap("installation.json", "AAA")
    maps.render()
    service = SimpleNamespace(map_live=maps, tick=lambda: {"state": "processed", "context": {}})
    queue = SimpleNamespace(binding={}, claim_latest=lambda *args, **kwargs: {"result_id": "next"})
    brief = due_brief(service, queue, "subscription")
    assert brief["political_map"]["tool"] == "render_political_map"
    assert len(calls) == 1
    _, view, metrics = maps.render()
    assert view["date"] == "1.1.2" and metrics["fresh_capture"]
    assert maps.render()[2]["fresh_capture"] is False
    assert len(calls) == 2
