from __future__ import annotations

import base64
import io

from PIL import Image

from bridge.game_tools import GameTools
from bridge.information.mcp import InformationMCPServer
from bridge.tests.test_game_tools import FakeInformationService, initialize


class FakeLiveMap:
    def __init__(self):
        self.calls = []
        self.view = {"view_id": "view-1", "date": "1495.2.3", "size": [2, 2],
                     "source_rect": [0, 0, 2, 2], "cells": "opaque"}

    def render(self, **kwargs):
        self.calls.append(kwargs)
        image = Image.new("RGB", (2, 2), (20, 40, 60))
        return image, dict(self.view), {
            "date": "1495.2.3", "snapshot_id": "snapshot-1", "fresh_capture": kwargs["refresh"]
        }

    def inspect(self, view_id, x, y):
        assert view_id == "view-1"
        return {"status": "known", "province_id": 1876, "owner": "FRN", "x": x, "y": y}


def test_map_tools_return_image_content_and_reuse_requested_arguments():
    service = FakeInformationService()
    service.map_live = FakeLiveMap()
    tools = GameTools(service)

    result = tools.call("render_political_map", {
        "province": 1876, "scale": "local", "size": "compact", "refresh": True,
    })
    assert result["view_id"] == "view-1"
    assert result["_mcp_content"][0]["type"] == "image"
    assert base64.b64decode(result["_mcp_content"][0]["data"])
    assert service.map_live.calls == [{
        "center_country": None, "province": 1876, "xy": None, "scale": "local",
        "size": "compact", "refresh": True,
    }]
    assert tools.call("inspect_political_map", {"view_id": "view-1", "x": 1, "y": 0})["province_id"] == 1876


def test_mcp_preserves_map_image_as_an_image_content_block():
    service = FakeInformationService()
    service.map_live = FakeLiveMap()
    tools = GameTools(service)
    server = InformationMCPServer(service, tools=tools)
    try:
        initialize(server)
        result = server.handle({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "render_political_map", "arguments": {}},
        })
        content = result["result"]["content"]
        assert content[0]["type"] == "image"
        assert content[0]["mimeType"] == "image/png"
        assert content[1]["type"] == "text"
    finally:
        server.close()


def test_mcp_military_refresh_can_return_only_text():
    service = FakeInformationService()
    service.map_live = FakeLiveMap()
    calls = []

    def render(**kwargs):
        calls.append(kwargs)
        return None, {"view_id": "view-2", "unchanged_from": "view-1"}, {"unchanged": True}

    service.map_live.render = render
    server = InformationMCPServer(service, tools=GameTools(service))
    try:
        initialize(server)
        response = server.handle({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "render_political_map", "arguments": {
                "refresh_scope": "military", "layers": ["forts"], "previous_view_id": "view-1",
            }},
        })
        assert calls[0]["refresh_scope"] == "military"
        assert calls[0]["layers"] == ["forts"]
        assert [item["type"] for item in response["result"]["content"]] == ["text"]
    finally:
        server.close()
