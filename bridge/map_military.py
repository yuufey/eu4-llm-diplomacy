"""Capture and compose explicitly requested live military overlays."""
from __future__ import annotations

LAYERS = ("armies", "forts")


def normalize_layers(layers):
    if not isinstance(layers, (list, tuple)) or any(layer not in LAYERS for layer in layers):
        raise ValueError("MAP_MILITARY_LAYERS_INVALID")
    if len(set(layers)) != len(layers):
        raise ValueError("MAP_MILITARY_LAYERS_DUPLICATE")
    return tuple(layer for layer in LAYERS if layer in layers)


def visible_layers(layers, scale):
    return tuple(layer for layer in layers if scale != "overview" or layer != "forts")


def _view_provinces(view, layer):
    statuses = {"known", "water"} if layer == "armies" else {"known"}
    return {record["province_id"] for record in view["records"].values()
            if record.get("status") in statuses}


def capture_layers(service, snapshot, views, layers, *, same_date, war_id=None):
    if not layers:
        return {}

    from bridge.map_live_capture import MapLiveCaptureError

    scopes = {layer: set() for layer in layers}
    land = set()
    for view in views:
        if "armies" in scopes:
            land.update(_view_provinces(view, "forts"))
        for layer in visible_layers(layers, view["scale"]):
            scopes[layer].update(_view_provinces(view, layer))

    result = {}
    dates = set()
    raw_dates = set()
    def validate(capture):
        date = capture.get("date")
        if capture.get("identity") is not None and capture["identity"] != snapshot.get("identity"):
            raise MapLiveCaptureError("MAP_MILITARY_BASELINE_SESSION_CHANGED")
        if capture.get("world_token") is not None and capture["world_token"] != snapshot.get("world_token"):
            raise MapLiveCaptureError("MAP_MILITARY_BASELINE_SESSION_CHANGED")
        if capture["status"] != "unavailable" or capture.get("records") or date is not None:
            if (not isinstance(date, str) or capture.get("identity") != snapshot.get("identity")
                    or (same_date and date != snapshot["date"])):
                raise MapLiveCaptureError("MAP_MILITARY_SNAPSHOT_CHANGED")
            if tuple(map(int, date.split("."))) < tuple(map(int, snapshot["date"].split("."))):
                raise MapLiveCaptureError("MAP_MILITARY_BASELINE_DATE_REWOUND")
            dates.add(date)
            raw_date = capture.get("date_raw")
            if type(raw_date) is int:
                if same_date and snapshot.get("date_raw", raw_date) != raw_date:
                    raise MapLiveCaptureError("MAP_MILITARY_SNAPSHOT_CHANGED")
                raw_dates.add(raw_date)

    war = None
    scope_info = {}
    participants = []
    army_scope = {}
    if any(scopes.values()):
        from bridge.map_military_wars import capture_war_scope

        war = capture_war_scope(service.installation, service.observer, war_id=war_id)
        validate(war)
        scope_info["war"] = {key: war[key] for key in
                             ("war_id", "status", "reason", "participants", "choices", "sides")
                             if key in war}
        if war["status"] == "known":
            participants = war.get("participants") or []
            sides = war.get("sides") or {}
            if participants:
                allies, enemies = sides.get("side_a", []), sides.get("side_b", [])
                if service.observer in enemies:
                    allies, enemies = enemies, allies
                if service.observer in allies:
                    army_scope = {"allies": allies, "enemies": enemies, "land_province_ids": land}

    for layer, ids in scopes.items():
        if not ids:
            result[layer] = {"status": "not_applicable", "date": None, "records": []}
            continue
        if layer == "armies":
            from bridge.map_military_armies import capture_armies

            capture = capture_armies(service.installation, service.observer, sorted(ids), **army_scope)
        else:
            from bridge.map_military_forts import capture_forts

            if war["status"] != "known" or not participants:
                result[layer] = {"status": "unavailable" if war["status"] != "known" else "not_applicable",
                                 "date": war.get("date"), "records": [],
                                 "reason": war.get("reason") or "MAP_FORT_WAR_SCOPE_UNAVAILABLE",
                                 **scope_info}
                continue
            capture = capture_forts(service.installation, service.observer, sorted(ids),
                                    game_root=service.game_root, user_data=service.user_data,
                                    participants=participants)
        validate(capture)
        if layer == "forts":
            forts = [row["province_id"] for row in capture.get("records", [])
                     if row.get("level", 0) > 0 and row["province_id"] in ids]
            if forts:
                from bridge.map_military_siege import capture_sieges

                siege = capture_sieges(service.installation, service.observer, forts,
                                       participants=participants)
                validate(siege)
                # Only attach siege observations to the same province and date.
                siege_by_province = {row["province_id"]: row for row in siege.get("records", [])}
                rows = []
                for row in capture["records"]:
                    observed = siege_by_province.get(row["province_id"], {})
                    if observed.get("owner", row.get("owner")) != row.get("owner"):
                        raise MapLiveCaptureError("MAP_MILITARY_SNAPSHOT_CHANGED")
                    timing = {}
                    if "elapsed_days" in observed:
                        timing["siege_elapsed_days"] = observed["elapsed_days"]
                    rows.append({**row, **timing})
                siege_meta = {key: siege[key] for key in ("status", "date", "reason", "fields")
                              if key in siege}
                capture = {**capture, "records": rows,
                           "field_metadata": {**capture.get("field_metadata", {}), "siege_progress": siege_meta}}
        result[layer] = {
            "status": capture["status"],
            "date": capture.get("date"),
            "records": sorted(
                (row for row in capture.get("records", []) if row["province_id"] in ids),
                key=lambda row: (row["province_id"], row.get("relation", ""), row.get("owner", ""),
                                 row.get("men", 0))),
            **{key: capture[key] for key in ("reason", "fields") if key in capture},
            **scope_info,
        }
        if "field_metadata" in capture:
            result[layer]["fields"] = capture["field_metadata"]
    if len(dates) > 1 or len(raw_dates) > 1:
        raise MapLiveCaptureError("MAP_MILITARY_SNAPSHOT_CHANGED")
    return result


def layers_for_view(view, capture):
    result = {}
    shown = visible_layers(capture, view.get("scale"))
    for layer, data in capture.items():
        if layer in shown:
            ids = _view_provinces(view, layer)
            result[layer] = {**data, "records": [row for row in data["records"] if row["province_id"] in ids]}
        else:
            result[layer] = {"status": "not_applicable", "date": None, "records": []}
    return result


def draw_layers(image, geometry, view, military):
    armies = military.get("armies", {}).get("records", [])
    forts = [row for row in military.get("forts", {}).get("records", [])
             if (row.get("level") or 0) > 0 or row.get("siege_percent") is not None]
    if armies or forts:
        from bridge.map_military_render import draw_military

        image = draw_military(image, geometry, view, armies=armies, forts=forts)
    for key, rows in (("armies", armies), ("forts", military.get("forts", {}).get("records", []))):
        for row in rows:
            record = view["records"].get(str(row["province_id"]))
            if record is not None:
                record.setdefault(key, []).append(row)
    return image
