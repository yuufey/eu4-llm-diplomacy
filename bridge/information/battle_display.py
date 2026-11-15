"""Present copied native values with their fixed-build GUI input bindings."""
from __future__ import annotations

from copy import deepcopy

from .battle_display_bindings import BINDINGS, PROVENANCE
from .battle_display_sides import control_side_binding, project_side_identity
from .battle_control_frames import project_native_frame_requests
from .battle_control_frame_assets import declared_frame_asset
from .battle_text import project_template
from .battle_flag_inputs import project_flag_inputs


def project_display(decoded: dict, template: dict | None = None, *,
                    mapping=None, observer_ref=None, native_line1=None,
                    include_uncaptured_bindings: bool = False) -> dict:
    """Describe control inputs without claiming a window was displayed.

    Direct text controls receive the copied native string. Supported numeric
    and icon inputs also retain fixed-build virtual setter requests; these
    calculated requests do not establish an actual widget state.
    All duplicate occurrences survive; no last-wins rule is invented here.
    """
    template = project_template(decoded) if template is None else template
    template_captured = template.get("status") == "known"
    if not template_captured and include_uncaptured_bindings is not True:
        return {"status": template.get("status", "unknown"),
                "reason": "DISPLAY_TEMPLATE_NOT_CAPTURED"}
    kind = {1: "land", 2: "naval"}.get((decoded.get("context") or {}).get("kind"))
    if kind is None:
        return {"status": "unsupported", "reason": "DISPLAY_BATTLE_TYPE_UNRESOLVED"}

    pairs = template["value"]["pairs"] if template_captured else []
    line1_sections = []
    if isinstance(native_line1, dict) and native_line1.get("status") == "known":
        value = native_line1.get("value")
        if isinstance(value, dict) and isinstance(value.get("sections"), list):
            line1_sections = [section for section in value["sections"]
                              if isinstance(section, dict)
                              and section.get("section") == "Line1"
                              and section.get("source") == "native_line1"
                              and isinstance(section.get("text"), str)
                              and isinstance(section.get("raw_hex"), str)]
    by_key: dict[str, list] = {}
    for pair in pairs:
        by_key.setdefault(pair["key_raw_hex"], []).append(pair)

    flags = project_flag_inputs(decoded)
    flag_requests = {item['template_key']: item for item in flags.get('controls', [])}
    controls, bound_indexes = [], set()
    for binding in BINDINGS[kind]:
        occurrences = by_key.get(binding["template_key"].encode("ascii").hex(), [])
        inputs = [{"pair_index": pair["index"],
                   "value_raw_hex": pair["value_raw_hex"],
                   "decoded": deepcopy(pair["value"])} for pair in occurrences]
        bound_indexes.update(pair["index"] for pair in occurrences)
        if not occurrences:
            display_text = {"status": "unknown", "reason": "TEMPLATE_KEY_NOT_CAPTURED"}
        elif binding["value_kind"] == "formatted_text":
            display_text = {"status": "unsupported", "reason": "CONTROL_FORMAT_OUTPUT_NOT_CAPTURED"}
        elif binding["value_kind"] != "text":
            display_text = {"status": "unsupported", "reason": "CONTROL_INPUT_IS_NOT_FINAL_TEXT"}
        elif len(occurrences) != 1:
            display_text = {"status": "unknown", "reason": "DUPLICATE_TEMPLATE_KEY_EFFECT_UNRESOLVED"}
        else:
            display_text = deepcopy(occurrences[0]["value"])
        control = {**deepcopy(binding), "inputs": inputs, "display_text": display_text,
                   "side_binding": control_side_binding(binding["template_key"], kind)}
        if binding["template_key"] == "WINORLOSE":
            control["text_view_scope"] = "physical_client"
        frame_requests = project_native_frame_requests(kind, binding, inputs)
        if binding['value_kind'] == 'flag_icon_frame':
            frame_requests = flag_requests.get(binding['template_key'])
        if frame_requests is not None:
            control["native_frame_requests"] = frame_requests
            control["declared_frame_asset"] = declared_frame_asset(binding)
        controls.append(control)

    missing_sections = ["title"]
    if not line1_sections:
        missing_sections.append("Line1")
    missing_sections.extend(("button_text", "actual_layout_and_visibility"))

    value = {
        "basis": ("copied_native_values_with_static_gui_input_bindings" if template_captured
                  else "static_gui_input_bindings_with_uncaptured_template"),
        "battle_type": kind,
        "binding_provenance": dict(PROVENANCE),
        "order_basis": "binding_declaration_order_not_screen_order",
        "layout_candidates": ["land_compact", "land_detailed"] if kind == "land" else ["naval"],
        "selected_layout": {"status": "unknown", "reason": "RUNTIME_LAYOUT_NOT_CAPTURED"},
        "controls": controls,
        "unbound_pair_indexes": [pair["index"] for pair in pairs if pair["index"] not in bound_indexes],
        "side_identity": project_side_identity(decoded, mapping, observer_ref),
        "missing_sections": missing_sections,
        "full_display_complete": False,
        "runtime_popup_verified": False,
    }
    if not template_captured:
        value["template_capture"] = {
            "status": template.get("status", "unknown"),
            "reason": template.get("reason", "DISPLAY_TEMPLATE_NOT_CAPTURED"),
        }
    return {"status": "known", "value": value}
