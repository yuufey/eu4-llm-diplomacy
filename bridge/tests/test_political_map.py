from __future__ import annotations

import numpy as np
import pytest
from PIL import Image

from bridge.political_map import inspect_view, render_view


@pytest.fixture
def political_fixture():
    """A small full-map fixture with visible, hidden, and water provinces."""
    provinces = np.array(
        [
            [0, 0, 1, 1, 1, 2, 2, 2, 0, 0, 0, 0, 0],
            [0, 1, 1, 1, 1, 2, 2, 2, 3, 3, 3, 4, 0],
            [0, 1, 1, 1, 1, 2, 2, 2, 3, 3, 3, 4, 0],
            [0, 1, 1, 1, 1, 2, 2, 2, 3, 3, 3, 4, 0],
            [0, 1, 1, 1, 1, 2, 2, 2, 3, 3, 3, 4, 0],
            [0, 1, 1, 1, 1, 2, 2, 2, 3, 3, 3, 4, 0],
            [0, 0, 1, 1, 1, 2, 2, 2, 3, 3, 3, 4, 0],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ],
        dtype=np.uint16,
    )
    owners = {1: "FRA", 2: "HAB", 3: "HUN", 4: "REB"}
    visible = {1, 2, 3}
    water = {0}
    colors = {"FRA": (40, 80, 160), "HAB": (180, 120, 50), "HUN": (60, 150, 80)}
    return provinces, owners, visible, water, colors


def _render(political_fixture):
    provinces, owners, visible, water, colors = political_fixture
    return render_view(
        provinces,
        owners,
        visible,
        water,
        colors,
        center=(6, 4),
        scale="overview",
        size="compact",
    )


def _pixel_for_source(view, source_x, source_y):
    x0, y0, width, height = view["source_rect"]
    output_width, output_height = view["size"]
    x = int((source_x + 0.5 - x0) * output_width / width)
    y = int((source_y + 0.5 - y0) * output_height / height)
    return min(x, output_width - 1), min(y, output_height - 1)


def test_render_view_returns_image_and_reusable_view_metadata(political_fixture):
    image, view = _render(political_fixture)

    assert isinstance(image, Image.Image)
    assert image.mode in {"RGB", "RGBA"}
    assert tuple(image.size) == tuple(view["size"])
    assert view["version"] == 1
    assert len(view["source_rect"]) == 4
    assert view["cells"]


def test_inspect_view_returns_known_owner_for_visible_land(political_fixture):
    _, view = _render(political_fixture)

    for source_x, source_y, province_id, owner in (
        (2, 3, 1, "FRA"),
        (6, 3, 2, "HAB"),
        (9, 3, 3, "HUN"),
    ):
        point = _pixel_for_source(view, source_x, source_y)
        result = inspect_view(view, *point)
        assert result["status"] == "known"
        assert result["province_id"] == province_id
        assert result["owner"] == owner


def test_inspect_view_hides_unobserved_province_identity(political_fixture):
    _, view = _render(political_fixture)

    point = _pixel_for_source(view, 11, 3)
    result = inspect_view(view, *point)

    assert result == {"status": "hidden"}
    assert "province_id" not in result
    assert "owner" not in result


def test_inspect_view_reports_a_scaled_pixel_covering_two_provinces(political_fixture):
    # A real EU4 map is larger than the compact output.  Use a bounded synthetic
    # map in the same direction so one output pixel can cover a source boundary.
    provinces = np.zeros((600, 900), dtype=np.uint16)
    provinces[:, :301] = 1
    provinces[:, 301:601] = 2
    provinces[:, 601:] = 3
    _, owners, visible, water, colors = political_fixture
    _, view = render_view(
        provinces,
        owners,
        visible,
        water,
        colors,
        center=(450, 300),
        scale="overview",
        size="compact",
    )
    output_width, output_height = view["size"]
    boundary_x = output_width * 301 / view["source_rect"][2]
    y = output_height // 2

    mixed = None
    for x in range(max(0, int(boundary_x) - 3), min(output_width, int(boundary_x) + 4)):
        result = inspect_view(view, x, y)
        if result["status"] == "mixed":
            mixed = result
            break

    assert mixed is not None
    assert {candidate["province_id"] for candidate in mixed["candidates"]} == {1, 2}


def test_inspect_view_rejects_non_integer_and_out_of_bounds_points(political_fixture):
    _, view = _render(political_fixture)
    width, height = view["size"]

    for point in ((-1, 0), (0, -1), (width, 0), (0, height), (0.0, 0)):
        with pytest.raises(ValueError):
            inspect_view(view, *point)


def test_render_view_rejects_unknown_center(political_fixture):
    provinces, owners, visible, water, colors = political_fixture

    with pytest.raises(ValueError):
        render_view(provinces, owners, visible, water, colors, center=(99, 99), scale="local")
