from bridge.map_view_cache import load_visible_snapshot


def test_cache_binds_save_bytes_and_observer(tmp_path):
    path = tmp_path / "sample.eu4"
    path.write_bytes(b'EU4txt\ndate=1495.2.3\nplayer="TUR"\ncountries={ TUR={} FRN={} }\n'
                     b'provinces={ -1876={owner="FRN" discovered_by={ TUR }} }\n')
    cache = tmp_path / "cache"
    date, owners, digest, hit = load_visible_snapshot(path, "TUR", cache)
    assert (date, owners, hit) == ("1495.2.3", {1876: "FRN"}, False)
    assert load_visible_snapshot(path, "TUR", cache) == (date, owners, digest, True)
    assert load_visible_snapshot(path, "FRN", cache)[1] == {}
    path.write_bytes(path.read_bytes().replace(b'owner="FRN"', b'owner="TUR"'))
    assert load_visible_snapshot(path, "TUR", cache)[1] == {1876: "TUR"}
