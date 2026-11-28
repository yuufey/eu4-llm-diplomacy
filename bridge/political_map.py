"""Render an observer's political map and resolve pixels against the same visible snapshot."""
from __future__ import annotations

import base64
import hashlib
import math
import zlib

import numpy as np
from PIL import Image, ImageDraw, ImageFont

SIZES = {"compact": (768, 512), "detailed": (1152, 768)}
WIDTHS = {"overview": 1350, "region": 650, "local": 160}
HIDDEN_COLOR = (98, 102, 109)
WATER_COLOR = (145, 189, 207)
LAND_COLOR = (216, 210, 188)


def viewport(shape, center, scale):
    height, width = shape
    cx, cy = center
    if not (0 <= cx < width and 0 <= cy < height):
        raise ValueError("Center outside source map")
    w = min(WIDTHS[scale], width, max(1, height * 3 // 2))
    h = min(height, max(1, round(w * 2 / 3)))
    x = min(max(0, cx - w // 2), width - w)
    y = min(max(0, cy - h // 2), height - h)
    return x, y, w, h


def _country_color(tag):
    digest = hashlib.sha256(tag.encode()).digest()
    return tuple(70 + value % 136 for value in digest[:3])


def _labels(image, country_grid, tags):
    # Test multiple interior positions on a coarse grid to avoid borders and collisions.
    small = np.asarray(Image.fromarray(country_grid).resize(image.size, Image.Resampling.NEAREST))[::5, ::5]
    draw = ImageDraw.Draw(image)
    font = ImageFont.load_default(size=14)
    occupied = np.zeros_like(small, dtype=bool)
    codes, counts = np.unique(small, return_counts=True)
    for code in codes[np.argsort(counts)[::-1]]:
        if code not in tags:
            continue
        ys, xs = np.nonzero(small == code)
        if len(xs) < 35:
            continue
        indices = np.argsort((xs - np.median(xs)) ** 2 + (ys - np.median(ys)) ** 2)
        for index in indices:
            x, y = xs[index], ys[index]
            if x < 4 or y < 2 or x + 4 >= small.shape[1] or y + 2 >= small.shape[0]:
                continue
            box = np.s_[y-1:y+2, x-3:x+4]
            if np.count_nonzero(small[box] == code) >= 17 and not occupied[box].any():
                draw.text((int(x*5), int(y*5)), tags[code], font=font, anchor="mm",
                          fill="black", stroke_width=1, stroke_fill="white")
                occupied[box] = True
                break


def render_view(provinces, owners, visible, water, colors, center, scale="region", size="compact"):
    x, y, w, h = viewport(provinces.shape, center, scale)
    crop = provinces[y:y+h, x:x+w]
    limit = int(crop.max()) + 1
    cells = np.zeros(limit, dtype="<u2")
    political = np.zeros(limit, dtype=np.uint16)
    records = {"0": {"status": "hidden"}}
    palette = [HIDDEN_COLOR, WATER_COLOR, LAND_COLOR]
    countries = {}
    for raw in np.unique(crop):
        pid = int(raw)
        if not pid or pid not in visible:
            continue
        cells[pid] = pid
        if pid in water:
            political[pid] = 1
            records[str(pid)] = {"status": "water", "province_id": pid}
            continue
        tag = owners.get(pid)
        records[str(pid)] = {"status": "known", "province_id": pid, "owner": tag}
        if tag and tag not in countries:
            countries[tag] = len(palette)
            palette.append(colors.get(tag) or _country_color(tag))
        political[pid] = countries.get(tag, 2)

    grid = political[crop]
    output_size = SIZES[size]
    if output_size[0] > w:
        # Outline in output pixels so a local zoom keeps narrow political borders.
        grid = np.asarray(Image.fromarray(grid).resize(output_size, Image.Resampling.NEAREST))
        crop_for_borders = np.asarray(Image.fromarray(crop).resize(output_size, Image.Resampling.NEAREST))
    else:
        crop_for_borders = crop
    rgb = np.asarray(palette, dtype=np.uint8)[grid]
    if scale == "local":
        provincial = np.zeros(grid.shape, dtype=bool)
        provincial[:, 1:] |= crop_for_borders[:, 1:] != crop_for_borders[:, :-1]
        provincial[1:, :] |= crop_for_borders[1:, :] != crop_for_borders[:-1, :]
        provincial &= grid >= 2
        rgb[provincial] = (rgb[provincial].astype(np.uint16) * 4 // 5).astype(np.uint8)
    border = np.zeros(grid.shape, dtype=bool)
    border[:, 1:] |= grid[:, 1:] != grid[:, :-1]
    border[1:, :] |= grid[1:, :] != grid[:-1, :]
    rgb[border] = (74, 77, 78)
    image = Image.fromarray(rgb).resize(SIZES[size], Image.Resampling.LANCZOS)
    _labels(image, grid, {code: tag for tag, code in countries.items()})
    view = {"version": 1, "source_rect": [x, y, w, h], "size": list(image.size),
            "records": records, "cells": base64.b64encode(zlib.compress(cells[crop].tobytes())).decode("ascii")}
    return image, view


def inspect_view(view, x, y):
    width, height = view["size"]
    if not (isinstance(x, int) and isinstance(y, int) and 0 <= x < width and 0 <= y < height):
        raise ValueError("Point outside output image")
    _, _, w, h = view["source_rect"]
    if not (0 < w <= 2048 and 0 < h <= 2048):
        raise ValueError("Invalid source dimensions")
    expected = 2 * w * h
    decoder = zlib.decompressobj()
    raw = decoder.decompress(base64.b64decode(view["cells"], validate=True), expected + 1)
    if len(raw) != expected or not decoder.eof:
        raise ValueError("Invalid province raster")
    cells = np.frombuffer(raw, dtype="<u2").reshape(h, w)
    region = cells[y*h//height:math.ceil((y+1)*h/height), x*w//width:math.ceil((x+1)*w/width)]
    hits = [view["records"][str(int(pid))] for pid in np.unique(region)]
    if len(hits) == 1:
        return hits[0]
    return {"status": "mixed", "candidates": hits}
