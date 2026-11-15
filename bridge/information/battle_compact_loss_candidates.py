"""Derive compact-loss text from same-event templates and loss operands.

The fixed land consumer passes OURLOST/ENEMYLOST String32 values to the
0x97fb0 wrapper as NUMBER (type 1). Plain type-1 and type-2 replacements copy
the supplied bytes literally. Missing copied inputs can use the separately
qualified summary aggregate model supplied by the composition layer.
"""
from collections.abc import Mapping

from .battle_body_candidate import _decode_output, _parts, _raw, _render_parts
from .battle_display_context import project_display_context
from .battle_text import project_template

_FLAGS = {
    "semantics": "derived_plain_type1_compact_losses",
    "representation": "candidate_for_compact_variant",
    "not_raw_text": True,
    "native_formatter_invoked": False,
    "native_widget_text_verified": False,
    "runtime_popup_verified": False,
    "complete": False,
    "full_display_complete": False,
    "visibility_verified": False,
}
_CONTROLS = (("OURLOST", "OurLost", 0), ("ENEMYLOST", "EnemyLost", 1))


def _unknown(reason):
    return {**_FLAGS, "status": "unknown", "reason": reason}


def project_compact_loss_candidates(decoded, *, quantity_candidates=None):
    if not isinstance(decoded, Mapping):
        return _unknown("COMPACT_LOSS_CANDIDATE_INPUT_INVALID")
    display = project_display_context(decoded)
    if display.get("status") != "known":
        return _unknown("COMPACT_LOSS_CANDIDATE_SAME_EVENT_CONTEXT_UNKNOWN")
    if display.get("battle_kind") != 1:
        return {**_FLAGS, "status": "unavailable", "reason": "COMPACT_LOSS_CANDIDATE_LAND_ONLY"}
    fields = display.get("text_fields", {})
    field = fields.get("compact_losses_template", {})
    if (field.get("status") != "known" or fields.get("language", {}).get("status") != "known"
            or fields.get("definition_key", {}).get("raw_hex") != b"LANDBATTLEOVER".hex()):
        return _unknown("COMPACT_LOSS_CANDIDATE_TEMPLATE_NOT_CAPTURED")
    try:
        template = _raw(field.get("raw_hex"))
        _decode_output(template)
        parts, count = _parts(template, b"NUMBER")
    except (ValueError, UnicodeError):
        return _unknown("COMPACT_LOSS_CANDIDATE_TEMPLATE_UNSUPPORTED")
    copied = project_template(decoded)
    if copied.get("status") != "known" and (quantity_candidates is None
                                            or decoded.get('message_template') is not None):
        return _unknown("COMPACT_LOSS_CANDIDATE_ARGUMENTS_NOT_CAPTURED")
    pairs = copied.get("value", {}).get("pairs", [])
    controls = []
    for key, widget, side in _CONTROLS:
        matches = [pair for pair in pairs if pair.get("key_raw_hex") == key.encode("ascii").hex()]
        control = {**_FLAGS, "template_key": key, "widget": widget, "combat_side_index": side,
                   "configured_layout_condition": display["layout_raw"] == 0}
        numeric = (quantity_candidates or {}).get(key, {})
        use_numeric = not matches and numeric.get('status') == 'known'
        if len(matches) != 1 and not use_numeric:
            control.update(status="unknown", reason=("COMPACT_LOSS_CANDIDATE_ARGUMENT_NOT_CAPTURED"
                           if not matches else "COMPACT_LOSS_CANDIDATE_DUPLICATE_ARGUMENT"))
        else:
            try:
                value = _raw(numeric['raw_hex'] if use_numeric else matches[0].get("value_raw_hex"))
                if count:
                    _decode_output(value)
                output = _render_parts(parts, value)
                text = _decode_output(output)
                control.update(status="known", reason=None, raw_hex=output.hex(),
                               codec="eu4_escape", decoded={"status": "known", "value": text},
                               replacement_count=count,
                               input_basis=('same_event_summary_aggregate_loss_count_model' if use_numeric
                                            else 'same_event_copied_String32_not_recomputed_loss_total'))
                control.update(input_pair_index=None if use_numeric else matches[0]["index"],
                               input_raw_hex=value.hex())
            except (ValueError, UnicodeError):
                control.update(status="unknown", reason="COMPACT_LOSS_CANDIDATE_INPUT_OR_OUTPUT_INVALID")
        controls.append(control)
    return {**_FLAGS, "status": "known", "controls": controls,
            "sequence": display["sequence"], "raw_date": display["raw_date"],
            "battle_kind": 1, "configured_layout_raw": display["layout_raw"],
            "localization_key": "COMPACT_BATTLE_RESULT_LOSSES",
            "configured_layout_condition": display["layout_raw"] == 0}
