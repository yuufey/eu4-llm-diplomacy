"""Export a live or saved EU4 political map or inspect a pixel in an exported PNG."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from time import perf_counter

from PIL import Image, PngImagePlugin

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bridge.political_map import SIZES, WIDTHS, inspect_view
from bridge.map_projection import draw_snapshot
from bridge.map_png import write_png


def write_image(path, image, view):
    write_png(path, image, view)


def inspect(args):
    with Image.open(args.image) as image:
        view = json.loads(image.info["eu4_view"])
        if view["size"] != list(image.size):
            raise ValueError("Image dimensions do not match the embedded view")
    return {"date": view["date"], "observer": view["observer"],
            **inspect_view(view, args.x, args.y)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    export = commands.add_parser("render")
    source = export.add_mutually_exclusive_group(required=True)
    source.add_argument("--save", type=Path)
    source.add_argument("--installation", type=Path)
    export.add_argument("--samples", type=int, default=1,
                        help="Independent live captures to time (1-20); write the final view")
    export.add_argument("--observer", required=True)
    export.add_argument("--game-root", type=Path)
    export.add_argument("--user-data", type=Path)
    center = export.add_mutually_exclusive_group()
    center.add_argument("--country", help="Center on visible territory of the country tag")
    center.add_argument("--province", type=int)
    center.add_argument("--xy", nargs=2, type=int, metavar=("X", "Y"))
    export.add_argument("--scale", choices=WIDTHS, default="region")
    export.add_argument("--size", choices=SIZES, default="compact")
    export.add_argument("--out", type=Path, required=True)
    query = commands.add_parser("inspect")
    query.add_argument("image", type=Path)
    query.add_argument("x", type=int)
    query.add_argument("y", type=int)
    args = parser.parse_args()
    try:
        result = render(args) if args.command == "render" else inspect(args)
    except (OSError, ValueError, KeyError) as exc:
        parser.exit(2, f"{exc}\n")
    print(json.dumps(result, ensure_ascii=True))

def render(args):
    from bridge.map_colors import load_country_colors
    from bridge.map_geometry import load_map_geometry
    from bridge.map_view_cache import load_visible_snapshot

    if args.out.suffix.lower() != ".png" or (args.save is not None and args.out.resolve() == args.save.resolve()):
        raise ValueError("Choose a PNG output path distinct from the save")
    if not 1 <= args.samples <= 20:
        raise ValueError("--samples must be between 1 and 20")
    if args.installation is not None:
        from bridge.map_live_service import LivePoliticalMap
        live = LivePoliticalMap(args.installation, args.observer, args.game_root, args.user_data)
        samples = []
        for _ in range(args.samples):
            image, view, metrics = live.render(center_country=args.country, province=args.province,
                                               xy=args.xy, scale=args.scale, size=args.size, refresh=True)
            samples.append(metrics)
        start = perf_counter()
        write_image(args.out, image, view)
        return {"path": str(args.out), "observer": args.observer, "date": view["date"],
                "samples": samples, "write_final_png_seconds": perf_counter()-start}
    if args.samples != 1:
        raise ValueError("--samples requires --installation")
    start = perf_counter()
    geometry = load_map_geometry(args.game_root, args.user_data)
    loaded = perf_counter()
    date, owners, digest, cache_hit = load_visible_snapshot(
        args.save, args.observer, ROOT / "work" / "runtime" / "political-map-cache")
    parsed = perf_counter()
    def colors_for(tags):
        return load_country_colors(args.game_root, args.user_data, only_tags=tags).colors

    image, view, center, ready = draw_snapshot(
        geometry, date, owners, args.observer, colors_for, center_country=args.country,
        province=args.province, xy=args.xy, scale=args.scale, size=args.size)
    view["save_sha256"] = digest
    write_image(args.out, image, view)
    return {"path": str(args.out), "date": view["date"], "observer": view["observer"],
            "center": list(center), "source_rect": view["source_rect"], "size": view["size"],
            "snapshot_cache_hit": cache_hit, "seconds": {"map": round(loaded-start, 3), "save": round(parsed-loaded, 3),
                        "viewport_and_colors": round(ready-parsed, 3),
                        "draw_and_write": round(perf_counter()-ready, 3)}}


if __name__ == "__main__":
    main()
