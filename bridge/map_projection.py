"""Draw live and recorded snapshots with the same projection and observer masking."""
from time import perf_counter

import numpy as np
from PIL import ImageDraw

from bridge.political_map import render_view, viewport


def province_center(grid, province_id):
    # Find a real pixel of the province near its centroid, including for concave provinces.
    ys, xs = np.nonzero(grid == province_id)
    if not len(xs):
        raise ValueError("Province has no pixels on the selected map")
    i = np.argmin((xs - xs.mean()) ** 2 + (ys - ys.mean()) ** 2)
    return int(xs[i]), int(ys[i])


def draw_snapshot(geometry, date, owners, observer, colors_for, *, center_country=None,
                  province=None, xy=None, scale="region", size="compact"):
    if sum(value is not None for value in (center_country, province, xy)) > 1:
        raise ValueError("Choose only one map center")
    visible = owners.keys()
    if province is not None and province not in visible:
        raise ValueError("Province is unavailable from this observer's perspective")
    grid = geometry.province_ids
    if xy is not None:
        center = xy
    elif province is not None:
        center = province_center(grid, province)
    else:
        country = center_country or observer
        member = np.zeros(int(grid.max()) + 1, dtype=bool)
        for pid, owner in owners.items():
            if owner == country and pid < len(member):
                member[pid] = True
        ys, xs = np.nonzero(member[grid])
        if len(xs):
            i = np.argmin((xs - np.median(xs)) ** 2 + (ys - np.median(ys)) ** 2)
            center = int(xs[i]), int(ys[i])
        elif center_country is None:
            # A landless observer can still export its discovered layer.
            center = grid.shape[1] // 2, grid.shape[0] // 2
        else:
            raise ValueError("Country has no visible territory on the map")
    x, y, w, h = viewport(grid.shape, center, scale)
    tags = {owners.get(int(pid)) for pid in np.unique(grid[y:y+h, x:x+w])}
    colors = colors_for(tags - {None})
    ready = perf_counter()
    water = geometry.sea_province_ids | geometry.lake_province_ids
    image, view = render_view(grid, owners, visible, water, colors,
                              center, scale, size)
    if province is not None:
        x0, y0, w, h = view["source_rect"]
        px = round((center[0] + 0.5 - x0) * image.width / w - 0.5)
        py = round((center[1] + 0.5 - y0) * image.height / h - 0.5)
        draw = ImageDraw.Draw(image)
        draw.polygon(((px, py+6), (px-4, py+13), (px+4, py+13)), fill="white", outline="black")
        view["focus"] = {"province_id": province, "owner": owners.get(province),
                         "pixel": [px, py]}
    for record in view["records"].values():
        pid = record.get("province_id")
        if pid is not None:
            record["kind"] = geometry.kind_for_province(pid)
            record["definition_name"] = geometry.definitions[pid].name
    view.update(date=date, observer=observer,
                map_inputs={key: entry["sha256"] for key, entry in geometry.source_files.items()})
    return image, view, center, ready
