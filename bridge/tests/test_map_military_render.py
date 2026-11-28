from __future__ import annotations

from types import SimpleNamespace

import numpy as np
from PIL import Image, ImageDraw, ImageFont

from bridge.map_military_render import _Badge, _Occupancy, _layout, draw_military


def _fixture(scale="region"):
    grid = np.zeros((200, 320), dtype=np.uint16)
    for pid, (x, y) in enumerate(((40, 50), (60, 50), (180, 50), (65, 70), (260, 150)), 1):
        grid[y - 3:y + 4, x - 3:x + 4] = pid
    geometry = SimpleNamespace(province_ids=grid)
    view = {"source_rect": [0, 0, 320, 200], "size": [320, 200], "scale": scale,
            "records": {str(pid): {"status": "known", "province_id": pid} for pid in range(1, 5)}}
    return Image.new("RGB", (320, 200), (188, 196, 181)), geometry, view


def _capture_text(monkeypatch):
    texts = []
    original = ImageDraw.ImageDraw.text

    def capture(self, xy, text, *args, **kwargs):
        texts.append(text)
        return original(self, xy, text, *args, **kwargs)

    monkeypatch.setattr(ImageDraw.ImageDraw, "text", capture)
    return texts


def test_empty_and_hidden_layers_preserve_existing_pixels_and_input():
    image, geometry, view = _fixture()
    before = image.tobytes()
    for armies, forts in (([], []),
                          ([{"province_id": 5, "relation": "enemy", "men": 3000}],
                           [{"province_id": 5, "level": 2}])):
        rendered = draw_military(image, geometry, view, armies=armies, forts=forts)
        assert rendered is not image
        assert rendered.tobytes() == before
        assert image.tobytes() == before


def test_region_preserves_country_strength_and_unknown_values(monkeypatch):
    image, geometry, view = _fixture()
    texts = _capture_text(monkeypatch)
    original = image.tobytes()
    rendered = draw_military(
        image, geometry, view,
        armies=[{"province_id": 1, "owner": "FRA", "relation": "own", "men": 3000},
                {"province_id": 1, "owner": "FRA", "relation": "own", "men": None},
                {"province_id": 2, "owner": "HAB", "relation": "enemy", "men": 4123}],
        forts=[{"province_id": 1, "level": 2, "terrain": "hills",
                "terrain_bonus": 1, "siege_percent": -14},
               {"province_id": 2, "level": 3}],
    )
    assert {"O", "E", "FRA 3,000+?", "HAB 4,123", "F2 hills +1 S-14%"} <= set(texts)
    assert "F3" in texts and "F3 ?" not in texts
    assert rendered.tobytes() != original
    assert image.tobytes() == original
    assert view["records"]["1"] == {"status": "known", "province_id": 1}


def test_overview_clusters_only_nearby_units_with_same_relation(monkeypatch):
    image, geometry, view = _fixture("overview")
    texts = _capture_text(monkeypatch)
    draw_military(image, geometry, view, armies=[
        {"province_id": 1, "owner": "FRA", "relation": "own", "men": 3000},
        {"province_id": 2, "owner": "FRA", "relation": "own", "men": 4000},
        {"province_id": 3, "owner": "FRA", "relation": "own", "men": 5000},
        {"province_id": 4, "owner": "HAB", "relation": "enemy", "men": 6000},
    ], forts=[])
    assert texts.count("O") == 2
    assert texts.count("E") == 1
    assert {"~7k", "~5k", "~6k"} <= set(texts)


def test_nearby_badges_are_kept_in_bounds_and_separated():
    font = ImageFont.load_default(size=12)
    badges = [_Badge(160, 100, str(index), "army", "own") for index in range(6)]
    boxes = [entry[2] for entry in _layout(badges, (320, 200), font)]
    assert len(boxes) == len(badges)
    for i, box in enumerate(boxes):
        assert 0 <= box[0] < box[2] <= 320
        assert 0 <= box[1] < box[3] <= 200
        for other in boxes[:i]:
            assert (box[2] + 2 <= other[0] or other[2] + 2 <= box[0] or
                    box[3] + 2 <= other[1] or other[3] + 2 <= box[1])


def test_occupancy_keeps_spacing_and_counts_overlap_in_dense_regions():
    index = _Occupancy((120, 120))
    index.add((40, 40, 60, 60))
    assert index.overlap_area((62, 40, 80, 60)) == 0
    assert index.overlap_area((61, 40, 80, 60)) > 0
    before = index.overlap_area((40, 40, 60, 60))
    index.add((40, 40, 60, 60))
    assert index.overlap_area((40, 40, 60, 60)) == 2 * before
