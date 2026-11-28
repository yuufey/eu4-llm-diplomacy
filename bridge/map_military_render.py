"""Draw observer-visible armies and forts on an existing political map.

The caller supplies the same ``view`` produced for the political image and a
``scale`` entry (``overview``, ``region`` or ``local``).  Coordinates are
derived from that view's source rectangle; no game data is read here.  The
result is a new image, and neither the input image nor view is modified.

Army keys: O = own, A = ally, E = enemy, X = other.  Overview badges combine
nearby armies of the same relation and use approximate strength; the other
scales show one exact, comma-separated total per province, owner and relation.
Fort badges use a castle icon, followed by the level, terrain bonus
and, when supplied, siege timing or percentage.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
from numbers import Real
from typing import Any, Mapping, Sequence

import numpy as np
from PIL import Image, ImageDraw, ImageFont


# White letters and a dark outline remain legible over the political palette.
ARMY_COLORS = {
    "own": (34, 103, 188),
    "ally": (31, 135, 76),
    "enemy": (194, 52, 49),
    "other": (145, 105, 36),
}
ARMY_KEYS = {"own": "O", "ally": "A", "enemy": "E", "other": "X"}
FORT_COLOR = (100, 71, 140)
_INK = (25, 28, 32)
_PAPER = (255, 255, 255)
_CLUSTER_RADIUS = 42


@dataclass
class _Badge:
    x: int
    y: int
    label: str
    kind: str
    relation: str = "other"


def _province_id(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        pid = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    # The source identity raster stores province IDs in uint16.
    return pid if 0 < pid <= 65535 and str(value).strip() == str(pid) else None


def _strength(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if not math.isfinite(number) or number < 0 or not number.is_integer():
        return None
    return int(number)


def _number(value: Any, *, signed: bool = False) -> str | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if not math.isfinite(number):
        return None
    return f"{number:+g}" if signed else f"{number:g}"


def _sum_strengths(values: Sequence[Any], *, approximate: bool) -> str:
    amounts = [_strength(value) for value in values]
    known = [number for number in amounts if number is not None]
    if not known:
        return "?"
    total = sum(known)
    if approximate and total >= 1000:
        amount = f"{total / 1000:.1f}".removesuffix(".0") + "k"
    else:
        amount = f"{total:,}"
    if approximate:
        amount = "~" + amount
    if len(known) != len(amounts):
        amount += "+?"
    return amount


def _centers(geometry: Any, view: Mapping[str, Any], pids: set[int],
             size: tuple[int, int]) -> dict[int, tuple[int, int]]:
    """Find a real source pixel near each visible province's cropped centroid.

    One indexed raster pass handles all requested provinces, avoiding a scan of
    the entire map for every stack.  Only the requested viewport is examined.
    """
    if not pids:
        return {}
    x0, y0, width, height = view["source_rect"]
    raster = geometry.province_ids[y0:y0 + height, x0:x0 + width]
    if raster.shape != (height, width):
        raise ValueError("Military view source rectangle is outside the map")
    wanted = np.zeros(65536, dtype=bool)
    wanted[list(pids)] = True
    ys, xs = np.nonzero(wanted[raster])
    if not len(xs):
        return {}
    ids = raster[ys, xs].astype(np.int64, copy=False)
    counts = np.bincount(ids, minlength=65536)
    sum_x = np.bincount(ids, weights=xs, minlength=65536)
    sum_y = np.bincount(ids, weights=ys, minlength=65536)
    means_x = np.divide(sum_x, counts, out=np.zeros_like(sum_x), where=counts != 0)
    means_y = np.divide(sum_y, counts, out=np.zeros_like(sum_y), where=counts != 0)
    distance = (xs - means_x[ids]) ** 2 + (ys - means_y[ids]) ** 2
    best = np.full(65536, np.inf)
    np.minimum.at(best, ids, distance)
    closest = np.flatnonzero(distance == best[ids])
    centers: dict[int, tuple[int, int]] = {}
    for index in closest:
        pid = int(ids[index])
        if pid not in centers:
            x = round((int(xs[index]) + 0.5) * size[0] / width - 0.5)
            y = round((int(ys[index]) + 0.5) * size[1] / height - 0.5)
            centers[pid] = (max(0, min(size[0] - 1, x)),
                            max(0, min(size[1] - 1, y)))
    return centers


def _army_badges(armies: Sequence[Mapping[str, Any]], centers: Mapping[int, tuple[int, int]],
                  scale: str) -> list[_Badge]:
    groups: dict[tuple[int, str, str], list[tuple[str, str, Any]]] = {}
    for army in armies:
        pid = _province_id(army.get("province_id"))
        if pid not in centers:
            continue
        relation = army.get("relation")
        if relation not in ARMY_KEYS:
            relation = "other"
        owner = str(army.get("owner") or "?").strip()[:12] or "?"
        side = "ally" if relation == "own" else relation
        groups.setdefault((pid, side, owner if side == "other" else ""), []).append(
            (owner, relation, army.get("men")))

    by_province = {}
    for (pid, side, _), members in groups.items():
        owners = {owner for owner, _, _ in members}
        owner = min(owners) if len(owners) == 1 else ""
        relation = "own" if side == "ally" and all(rel == "own" for _, rel, _ in members) else side
        by_province[pid, relation, owner] = [value for _, _, value in members]

    if scale != "overview":
        return [_Badge(*centers[pid], f"{owner} {_sum_strengths(values, approximate=False)}".strip(),
                       "army", relation)
                for (pid, relation, owner), values in sorted(by_province.items())]

    # Greedy, deterministic clusters avoid connecting a continent-wide chain of
    # armies merely because consecutive provinces happen to be near each other.
    clusters: list[dict[str, Any]] = []
    rows = sorted(by_province.items(),
                  key=lambda item: (item[0][1], centers[item[0][0]][1],
                                    centers[item[0][0]][0], item[0][0], item[0][2]))
    for (pid, relation, _), values in rows:
        x, y = centers[pid]
        matches = []
        for cluster in clusters:
            if cluster["relation"] != relation:
                continue
            distance = (x - cluster["x"] / cluster["count"]) ** 2 + (y - cluster["y"] / cluster["count"]) ** 2
            if distance <= _CLUSTER_RADIUS ** 2:
                matches.append((distance, cluster))
        if matches:
            cluster = min(matches, key=lambda item: item[0])[1]
            cluster["x"] += x
            cluster["y"] += y
            cluster["count"] += 1
            cluster["strengths"].extend(values)
        else:
            clusters.append({"relation": relation, "x": x, "y": y,
                             "count": 1, "strengths": list(values)})
    return [_Badge(round(cluster["x"] / cluster["count"]),
                   round(cluster["y"] / cluster["count"]),
                   _sum_strengths(cluster["strengths"], approximate=True), "army",
                   cluster["relation"]) for cluster in clusters]


def _fort_badges(forts: Sequence[Mapping[str, Any]], centers: Mapping[int, tuple[int, int]]) -> list[_Badge]:
    badges = []
    for fort in forts:
        pid = _province_id(fort.get("province_id"))
        if pid not in centers:
            continue
        level = _number(fort.get("level")) or "?"
        bonus = _number(fort.get("terrain_bonus"), signed=True)
        elapsed = _number(fort.get("siege_elapsed_days"))
        siege = _number(fort.get("siege_percent"))
        fields = ["F" + level]
        if bonus is not None:
            fields.append(bonus)
        if elapsed is not None:
            fields.append("S" + elapsed + "d")
        if siege is not None:
            fields.append("S" + siege + "%")
        badges.append(_Badge(*centers[pid], " ".join(fields), "fort"))
    return badges


class _Occupancy:
    """Count occupied pixels in bounded image memory, independent of badge count."""

    def __init__(self, size: tuple[int, int]) -> None:
        self.pixels = np.zeros((size[1], size[0]), dtype=np.uint32)

    def add(self, box: tuple[int, int, int, int]) -> None:
        left, top, right, bottom = box
        height, width = self.pixels.shape
        self.pixels[max(0, top - 2):min(height, bottom + 2),
                    max(0, left - 2):min(width, right + 2)] += 1

    def overlap_area(self, box: tuple[int, int, int, int]) -> int:
        left, top, right, bottom = box
        return int(self.pixels[top:bottom, left:right].sum(dtype=np.uint64))


def _positions(anchor: tuple[int, int], width: int, height: int,
               image_size: tuple[int, int]):
    """Try nearby positions before longer leaders, keeping badges on screen."""
    x, y = anchor
    raw = [(x - width // 2, y - height // 2)]
    for r in (6, 16, 28, 42, 60, 85):
        raw.extend(((x - width // 2, y - height - r),
                    (x - width // 2, y + r),
                    (x - width - r, y - height // 2),
                    (x + r, y - height // 2),
                    (x - width - r, y - height - r),
                    (x + r, y - height - r),
                    (x - width - r, y + r),
                    (x + r, y + r)))
    seen = set()
    for left, top in raw:
        left = max(0, min(image_size[0] - width, left))
        top = max(0, min(image_size[1] - height, top))
        box = left, top, left + width, top + height
        if box not in seen:
            seen.add(box)
            yield box


def _layout(badges: Sequence[_Badge], size: tuple[int, int], font: ImageFont.ImageFont):
    occupied = _Occupancy(size)
    placements = []
    for badge in sorted(badges, key=lambda b: (b.y, b.x, b.kind, b.relation, b.label)):
        label = badge.label
        max_width = max(1, size[0] - 4)
        # Keep unusually long mod-provided names inside the image.
        while label and 27 + math.ceil(font.getlength(label)) > max_width:
            label = label[:-1]
        if label != badge.label:
            label = (label[:-1] + "~") if label else ""
        width = min(max_width, 27 + math.ceil(font.getlength(label)))
        height = min(21, size[1])
        candidates = list(_positions((badge.x, badge.y), width, height, size))
        # In an overfull view, draw all badges and minimise overlap instead of
        # silently hiding armies.  The usual case uses the first free position.
        box = candidates[0]
        best_overlap = None
        for candidate in candidates:
            overlap = occupied.overlap_area(candidate)
            if best_overlap is None or overlap < best_overlap:
                best_overlap = overlap
                box = candidate
            if overlap == 0:
                break
        occupied.add(box)
        placements.append((badge, label, box))
    return placements


def _castle(draw: ImageDraw.ImageDraw, left: int, top: int) -> None:
    # Three battlements and a gate, drawn directly to avoid external assets.
    draw.polygon(((left + 3, top + 5), (left + 3, top + 2), (left + 5, top + 2),
                  (left + 5, top + 5), (left + 8, top + 5), (left + 8, top + 2),
                  (left + 10, top + 2), (left + 10, top + 5), (left + 13, top + 5),
                  (left + 13, top + 14), (left + 3, top + 14)), fill=_PAPER)
    draw.rectangle((left + 7, top + 10, left + 9, top + 14), fill=FORT_COLOR)


def draw_military(image: Image.Image, geometry: Any, view: Mapping[str, Any], *,
                  armies: Sequence[Mapping[str, Any]],
                  forts: Sequence[Mapping[str, Any]]) -> Image.Image:
    """Return a copy of ``image`` with supplied visible military data drawn."""
    result = image.copy()
    if not armies and not forts:
        return result
    records = view.get("records", {})
    known = {int(key): record.get("status") for key, record in records.items()
             if isinstance(record, Mapping) and str(key).isdigit() and 0 < int(key) <= 65535}
    armies = [row for row in armies if known.get(row.get("province_id")) in ("known", "water")]
    forts = [row for row in forts if known.get(row.get("province_id")) == "known"]
    pids = {_province_id(row.get("province_id")) for row in (*armies, *forts)}
    pids.discard(None)
    centers = _centers(geometry, view, pids, result.size)
    scale = view.get("scale", "region")
    badges = _army_badges(armies, centers, scale) + _fort_badges(forts, centers)
    if not badges:
        return result

    font = ImageFont.load_default(size=12)
    font_key = ImageFont.load_default(size=12)
    draw = ImageDraw.Draw(result)
    placements = _layout(badges, result.size, font)
    # Draw connectors first so later badges cannot be crossed by their lines.
    for badge, _, (left, top, right, bottom) in placements:
        edge_x = max(left, min(right - 1, badge.x))
        edge_y = max(top, min(bottom - 1, badge.y))
        if (edge_x, edge_y) != (badge.x, badge.y):
            draw.line((badge.x, badge.y, edge_x, edge_y), fill=_PAPER, width=3)
            draw.line((badge.x, badge.y, edge_x, edge_y), fill=_INK, width=1)
            draw.ellipse((badge.x - 2, badge.y - 2, badge.x + 2, badge.y + 2),
                         fill=_INK, outline=_PAPER)
    for badge, label, (left, top, right, bottom) in placements:
        draw.rounded_rectangle((left, top, right - 1, bottom - 1), radius=4,
                               fill=_INK, outline=_PAPER, width=1)
        color = FORT_COLOR if badge.kind == "fort" else ARMY_COLORS[badge.relation]
        draw.rounded_rectangle((left + 2, top + 2, left + 19, bottom - 3), radius=2,
                               fill=color)
        if badge.kind == "fort":
            _castle(draw, left + 3, top + 2)
        else:
            draw.text((left + 10, top + 10), ARMY_KEYS[badge.relation], font=font_key,
                      anchor="mm", fill=_PAPER, stroke_width=0)
        draw.text((left + 23, top + 10), label, font=font, anchor="lm", fill=_PAPER)
    return result


__all__ = ["draw_military"]
