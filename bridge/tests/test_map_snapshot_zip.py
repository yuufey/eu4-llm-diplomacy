import zipfile

from bridge.map_snapshot import parse_map_snapshot


def test_zip_date_in_meta_current_discovery_in_gamestate(tmp_path):
    path = tmp_path / "observer.eu4"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("meta", 'EU4txt\ndate=1495.2.3\nplayer="O00"\n')
        z.writestr("gamestate", 'EU4txt\ncountries={ TUR={} FRN={} O00={} }\n'
                   'provinces={ -1876={ owner="FRN" controller="TUR" history={ owner="TUR" controller="FRN" } discovered_by={ TUR FRN } }'
                   ' -3={ owner="FRN" history={ discovered_by={ TUR } } } }')
    data = parse_map_snapshot(path, "TUR")
    assert (data["date"], data["player"], data["visible_provinces"]) == ("1495.2.3", "O00", [1876])
    province = next(p for p in data["provinces"] if p["province_id"] == 1876)
    assert (province["owner"], province["controller"], province["controller_present"]) == ("FRN", "TUR", True)
    old_province = next(p for p in data["provinces"] if p["province_id"] == 3)
    assert (old_province["controller"], old_province["controller_present"]) == (None, False)
