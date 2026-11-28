import hashlib
import json
from argparse import Namespace
from types import SimpleNamespace

import numpy as np
from PIL import Image

from bridge.map_view_cache import load_visible_snapshot


def test_cache_binds_save_bytes_and_observer_and_excludes_old_schema(tmp_path):
    path = tmp_path / "sample.eu4"
    path.write_bytes(b'EU4txt\ndate=1495.2.3\nplayer="TUR"\ncountries={ TUR={} FRN={} }\n'
                     b'provinces={ -1876={owner="FRN" controller="TUR" discovered_by={ TUR }}\n'
                     b'-1877={owner="FRN" controller="FRN" discovered_by={ TUR }}\n'
                     b'-1878={owner="FRN" controller="TUR" discovered_by={ FRN }}\n'
                     b'-1879={controller="TUR" discovered_by={ TUR }}\n'
                     b'-1880={owner="FRN" discovered_by={ TUR }}\n'
                     b'-1881={owner="FRN" controller="---" discovered_by={ TUR }}\n'
                     b'-1882={owner="FRN" history={controller="TUR"} discovered_by={ TUR }} }\n')
    cache = tmp_path / "cache"
    old_directory = cache / "v1" / hashlib.sha256(path.read_bytes()).hexdigest()
    old_directory.mkdir(parents=True)
    (old_directory / "TUR.json").write_text(json.dumps({
        "observer": "TUR", "save_sha256": old_directory.name,
        "date": "1495.2.3", "owners": {"1876": "FRN"},
    }))

    date, owners, controllers, digest, hit = load_visible_snapshot(path, "TUR", cache)
    assert (date, owners, controllers, hit) == (
        "1495.2.3", {1876: "FRN", 1877: "FRN", 1879: None, 1880: "FRN", 1881: "FRN", 1882: "FRN"},
        {1876: "TUR"}, False,
    )
    assert load_visible_snapshot(path, "TUR", cache) == (date, owners, controllers, digest, True)
    assert (cache / "v2" / digest / "TUR.json").is_file()
    _, other_owners, other_controllers, _, _ = load_visible_snapshot(path, "FRN", cache)
    assert other_owners == {1878: "FRN"}
    assert other_controllers == {1878: "TUR"}

    path.write_bytes(path.read_bytes().replace(b'controller="TUR"', b'controller="FRN"'))
    assert load_visible_snapshot(path, "TUR", cache)[2] == {}


def test_save_without_controllers_still_roundtrips(tmp_path):
    path = tmp_path / "old.eu4"
    path.write_bytes(b'EU4txt\ndate=1495.2.3\nplayer="TUR"\ncountries={ TUR={} FRN={} }\n'
                     b'provinces={ -1876={owner="FRN" discovered_by={ TUR }} }\n')
    result = load_visible_snapshot(path, "TUR", tmp_path / "cache")
    assert result[:3] == ("1495.2.3", {1876: "FRN"}, {})
    assert load_visible_snapshot(path, "TUR", tmp_path / "cache") == (*result[:4], True)


def test_cli_passes_saved_occupations_to_projection(tmp_path, monkeypatch):
    import bridge.map_colors
    import bridge.map_geometry
    import tools.political_map as cli

    path = tmp_path / "sample.eu4"
    path.write_bytes(b'EU4txt\ndate=1495.2.3\nplayer="TUR"\ncountries={ TUR={} FRN={} }\n'
                     b'provinces={ -1876={owner="FRN" controller="TUR" discovered_by={ TUR }} }\n')
    geometry = SimpleNamespace(
        province_ids=np.full((80, 120), 1876, dtype=np.uint16),
        sea_province_ids=set(), lake_province_ids=set(), source_files={},
        kind_for_province=lambda pid: "land",
        definitions={1876: SimpleNamespace(name="Example")},
    )
    requested_tags = []

    def load_colors(_root, _user, *, only_tags):
        requested_tags.append(set(only_tags))
        return SimpleNamespace(colors={"FRN": (40, 80, 160), "TUR": (180, 30, 50)})

    monkeypatch.setattr(cli, "ROOT", tmp_path)
    monkeypatch.setattr(bridge.map_geometry, "load_map_geometry", lambda *_: geometry)
    monkeypatch.setattr(bridge.map_colors, "load_country_colors", load_colors)
    args = Namespace(out=tmp_path / "out.png", save=path, installation=None, samples=1,
                     observer="TUR", game_root=None, user_data=None, country=None,
                     province=None, xy=None, scale="region", size="compact")
    assert cli.render(args)["snapshot_cache_hit"] is False
    assert cli.render(args)["snapshot_cache_hit"] is True
    assert requested_tags == [{"FRN", "TUR"}] * 2
    inspected = cli.inspect(Namespace(image=args.out, x=100, y=100))
    assert (inspected["province_id"], inspected["owner"], inspected["controller"]) == (1876, "FRN", "TUR")
    with Image.open(args.out) as image:
        pixels = np.asarray(image.crop((100, 100, 125, 125))).reshape(-1, 3)
        assert {(40, 80, 160), (180, 30, 50)} <= set(map(tuple, pixels))

    path.write_bytes(path.read_bytes().replace(b' controller="TUR"', b''))
    assert cli.render(args)["snapshot_cache_hit"] is False
    assert requested_tags[-1] == {"FRN"}
    inspected = cli.inspect(Namespace(image=args.out, x=100, y=100))
    assert inspected["owner"] == "FRN" and "controller" not in inspected
    with Image.open(args.out) as image:
        pixels = np.asarray(image.crop((100, 100, 125, 125))).reshape(-1, 3)
        assert set(map(tuple, pixels)) == {(40, 80, 160)}
