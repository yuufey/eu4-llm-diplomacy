"""Installed base-file declarations for fixed-build battle icon candidates.

These are hints from pinned ordinary GUI/GFX files. They neither establish
the effective mod definition nor prove the requested frame was displayed.
"""
from __future__ import annotations


GUI_SHA256 = "4232f2411d0e6a0b757d99e7308d8e104b58cbd6184be1f6265e6a022fad6d1f"
GFX_SHA256 = "1620da4be0e49e405cf8a8c21a254028587bb515f1838cf9af3360b0ff12210f"


def declared_frame_asset(binding: dict) -> dict | None:
    kind = binding.get("value_kind")
    if kind == "numeric_or_frame":
        sprite, frames = "GFX_stars_small", 13
    elif kind == "icon_or_frame":
        sprite, frames = "GFX_leader_types", 7
    else:
        return None
    return {
        "status": "known", "basis": "ordinary_installed_base_file_declaration",
        "widget_type": "iconType", "sprite_type": sprite, "declared_frame_count": frames,
        "active_runtime_definition_verified": False,
        "actual_widget_state_verified": False,
        "sources": [
            {"logical_path": "interface/end_of_combat.gui", "sha256": GUI_SHA256},
            {"logical_path": "interface/general_stuff.gfx", "sha256": GFX_SHA256},
        ],
    }
