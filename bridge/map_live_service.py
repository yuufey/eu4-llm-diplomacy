"""Observer-scoped live political map with an explicitly refreshable snapshot."""
from collections import OrderedDict
from copy import deepcopy
from threading import Lock
from time import perf_counter
from uuid import uuid4

from bridge.map_colors import load_country_colors
from bridge.map_geometry import load_map_geometry
from bridge.map_military import capture_layers, draw_layers, layers_for_view, normalize_layers
from bridge.map_projection import draw_snapshot
from bridge.political_map import inspect_view


class LivePoliticalMap:
    def __init__(self, installation, observer, game_root=None, user_data=None):
        self.installation = installation
        self.observer = observer
        self.game_root = game_root
        self.user_data = user_data
        self.geometry = None
        self.snapshot = None
        self.snapshot_id = None
        self._colors = {}
        self._searched_tags = set()
        self._lock = Lock()
        self._views = OrderedDict()
        self._max_views = 8
        self._refresh_due = False
        self._base_view = None
        self._last_render = None

    def invalidate(self):
        """Capture again on the first map request of the next decision."""
        with self._lock:
            self._refresh_due = True

    def _colors_for(self, tags):
        missing = tags - self._searched_tags
        if missing:
            colors = load_country_colors(self.game_root, self.user_data, only_tags=missing).colors
            self._colors.update(colors)
            self._searched_tags.update(missing)
        return self._colors

    def render(self, center_country=None, province=None, xy=None, scale="region",
               size="compact", refresh=False, refresh_scope=None, layers=(),
               previous_view_id=None, war_id=None):
        from bridge.map_live_capture import capture_live

        layers = normalize_layers(layers)
        if refresh_scope not in (None, "full", "military") or (refresh and refresh_scope is not None):
            raise ValueError("MAP_REFRESH_SCOPE_INVALID")
        if refresh_scope == "military" and not layers:
            raise ValueError("MAP_MILITARY_LAYERS_REQUIRED")
        with self._lock:
            start = perf_counter()
            if refresh_scope == "military" and self.snapshot is None:
                raise ValueError("MAP_MILITARY_BASELINE_REQUIRED")
            if self.geometry is None:
                self.geometry = load_map_geometry(self.game_root, self.user_data)
            loaded = perf_counter()
            fresh = refresh_scope != "military" and (
                refresh or refresh_scope == "full" or layers or self.snapshot is None or self._refresh_due)
            fresh = bool(fresh)
            if fresh:
                snapshot = capture_live(self.installation, self.observer, self.geometry.definitions.keys())
                if not isinstance(snapshot, dict) or not isinstance(snapshot.get("date"), str):
                    raise ValueError("LIVE_MAP_CAPTURE_INVALID")
                if not isinstance(snapshot.get("owners"), dict):
                    raise ValueError("LIVE_MAP_CAPTURE_OWNERS_INVALID")
                self.snapshot = snapshot
                self.snapshot_id = str(uuid4())
                self._refresh_due = False
            captured = perf_counter()
            base_key = (self.snapshot_id, center_country, province, xy, scale, size)
            base_render_seconds = 0.0
            viewport_seconds = 0.0
            if self._base_view is None or self._base_view[0] != base_key:
                image, view, _, base_render_started = draw_snapshot(
                    self.geometry, self.snapshot["date"], self.snapshot["owners"], self.observer,
                    self._colors_for, center_country=center_country, province=province,
                    xy=xy, scale=scale, size=size)
                base_render_finished = perf_counter()
                if captured <= base_render_started <= base_render_finished:
                    viewport_seconds = base_render_started - captured
                    base_render_seconds = base_render_finished - base_render_started
                else:
                    base_render_seconds = base_render_finished - captured
                view["scale"] = scale
                self._base_view = base_key, image, view
            _, image, base_view = self._base_view
            view = deepcopy(base_view)
            ready = perf_counter()
            capture = capture_layers(self, self.snapshot, [view], layers, same_date=fresh,
                                     war_id=war_id)
            military_done = perf_counter()
            military = layers_for_view(view, capture)
            if layers:
                view["military"] = {key: {field: value for field, value in data.items()
                                          if field != "records"}
                                    for key, data in military.items()}
            signature = (base_key, layers, [(key, data["records"]) for key, data in military.items()])
            unchanged = (previous_view_id in self._views and self._last_render is not None
                         and self._last_render[0] == previous_view_id
                         and self._last_render[1] == signature)
            if unchanged:
                # Preserve pixel inspection records even when no new PNG is sent.
                view["records"] = self._views[previous_view_id]["records"]
                image = None
                view["unchanged_from"] = previous_view_id
            elif military:
                image = draw_layers(image, self.geometry, view, military)
            view_id = str(uuid4())
            view.update(source="live", identity=self.snapshot.get("identity"), snapshot_id=self.snapshot_id,
                        view_id=view_id)
            self._views[view_id] = deepcopy(view)
            self._views.move_to_end(view_id)
            while len(self._views) > self._max_views:
                self._views.popitem(last=False)
            self._last_render = view_id, signature
            end = perf_counter()
            metrics = {
                "date": view["date"], "snapshot_id": self.snapshot_id, "fresh_capture": fresh,
                "visible_provinces": len(self.snapshot["owners"]),
                "geometry_seconds": loaded-start, "capture_seconds": captured-loaded if fresh else 0.0,
                "viewport_and_colors_seconds": viewport_seconds,
                "render_seconds": base_render_seconds + end-military_done,
                "military_capture_seconds": military_done-ready if layers else 0.0,
                "refresh_scope": "full" if fresh else (refresh_scope or "reuse"),
                "unchanged": unchanged,
                "total_seconds": end-start,
            }
            return image, view, metrics

    def render_bundle(self, center_country=None, province=None, xy=None,
                      size="compact", layers=(), war_id=None):
        """Render all three map scales from one newly captured snapshot.

        The lock covers capture and all three renders.  Callers can therefore
        publish the returned images and metadata without risking that a date
        change splits one archive across different snapshots.
        """

        from bridge.map_live_capture import capture_live

        layers = normalize_layers(layers)
        with self._lock:
            started = perf_counter()
            if self.geometry is None:
                self.geometry = load_map_geometry(self.game_root, self.user_data)
            geometry_done = perf_counter()
            snapshot = capture_live(self.installation, self.observer,
                                    self.geometry.definitions.keys())
            if not isinstance(snapshot, dict) or not isinstance(snapshot.get("date"), str):
                raise ValueError("LIVE_MAP_CAPTURE_INVALID")
            if not isinstance(snapshot.get("owners"), dict):
                raise ValueError("LIVE_MAP_CAPTURE_OWNERS_INVALID")
            archive_snapshot_id = str(uuid4())
            captured = perf_counter()
            images = {}
            views = {}
            for scale in ("overview", "region", "local"):
                image, view, center, ready = self._draw_bundle_view_locked(
                    center_country=center_country, province=province, xy=xy,
                    scale=scale, size=size, store_view=False,
                    snapshot=snapshot, snapshot_id=archive_snapshot_id)
                images[scale] = image
                views[scale] = view
            military_started = perf_counter()
            military = capture_layers(self, snapshot, views.values(), layers, same_date=True,
                                      war_id=war_id)
            military_done = perf_counter()
            for scale, view in views.items():
                military_view = layers_for_view(view, military)
                if military_view:
                    images[scale] = draw_layers(images[scale], self.geometry, view, military_view)
                    view["military"] = {layer: {key: val for key, val in data.items()
                                                if key != "records"}
                                        for layer, data in military_view.items()}
            if layers:
                snapshot = {**snapshot, "military": military}
            finished = perf_counter()
            return {
                "images": images,
                "views": views,
                "snapshot": deepcopy(snapshot),
                "observer": self.observer,
                "snapshot_id": archive_snapshot_id,
                "metrics": {
                    "date": snapshot["date"],
                    "visible_provinces": len(snapshot["owners"]),
                    "geometry_seconds": geometry_done - started,
                    "capture_seconds": captured - geometry_done,
                    "render_seconds": military_started - captured + finished - military_done,
                    "military_capture_seconds": military_done - military_started if layers else 0.0,
                    "total_seconds": finished - started,
                },
            }

    def _draw_bundle_view_locked(self, *, center_country=None, province=None,
                                 xy=None, scale="region", size="compact",
                                 store_view=True, snapshot=None, snapshot_id=None):
        snapshot = self.snapshot if snapshot is None else snapshot
        snapshot_id = self.snapshot_id if snapshot_id is None else snapshot_id
        image, view, _, ready = draw_snapshot(
            self.geometry, snapshot["date"], snapshot["owners"],
            self.observer, self._colors_for, center_country=center_country,
            province=province, xy=xy, scale=scale, size=size)
        view_id = str(uuid4())
        view.update(source="live", scale=scale, identity=snapshot.get("identity"),
                    snapshot_id=snapshot_id, view_id=view_id)
        if store_view:
            self._views[view_id] = deepcopy(view)
            self._views.move_to_end(view_id)
            while len(self._views) > self._max_views:
                self._views.popitem(last=False)
        return image, view, None, ready

    def inspect(self, view_id, x, y):
        """Resolve one output pixel against a view from this service session."""

        with self._lock:
            if not isinstance(view_id, str) or view_id not in self._views:
                raise ValueError("LIVE_MAP_VIEW_NOT_FOUND")
            return inspect_view(self._views[view_id], x, y)
