"""Pure contract tests for the bounded selectable-mission text derivation."""
from copy import deepcopy

import pytest

from bridge.information.mission_custom_texts import (
    WHOLE_TEMPLATES,
    apply_single_template,
    match_single_template,
    normalize_methods,
)
from bridge.information.model import InformationError


CONTEXT = {
    "mode": "live",
    "status": "ready",
    "observer": "FRA",
    "session_id": "custom-session",
    "game_date": 56553384,
    "game_sha256": "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77",
}


def _selection(*, weight=1000, **changes):
    value = {
        "status": "observed",
        "kind": "single_unconditional_positive_weight",
        "option_count": 1,
        "predicate_count": 0,
        "weight": weight,
        "modifiers_empty": True,
        "random_flag": 1,
        "builtin_name_absent": True,
        "root_promotion_enum": 3,
        "derived_for_query_country_root": True,
        "ui_root_scope_verified": False,
    }
    value.update(changes)
    return value


def _method(name, *, key=None, status="observed", selection=None, reason=None):
    if status == "unknown":
        return {"name": name, "status": "unknown", "text_key": None,
                "selection": {"status": "unknown", "unknown_reason": reason or "unresolved"},
                "unknown_reason": reason or "unresolved"}
    if key is None:
        key = "SELECTABLE_MISSION_TITLE" if name.endswith("Title") else "SELECTABLE_MISSION_DESCRIPTION"
    text_key = {"status": "observed", "complete": True, "text": key,
                "raw_hex": key.encode("ascii").hex()}
    return {"name": name, "status": "observed", "text_key": text_key,
            "selection": _selection() if selection is None else selection}


def _report(methods=None, *, context=CONTEXT):
    methods = methods or {
        "GetSelectableMissionTitle": _method("GetSelectableMissionTitle"),
        "GetSelectableMissionDescription": _method("GetSelectableMissionDescription"),
    }
    date = context["game_date"]
    return {
        "status": "observed",
        "read_only": True,
        "profile": {"sha256": "profile-sha"},
        "probe_script_sha256": "probe-sha",
        "identity": {
            "binding_verified": True,
            "installation_session_id": context["session_id"],
            "process_path_sha256": context["game_sha256"],
        },
        "request": {"country": context["observer"], "methods": list(methods)},
        "query_scope": {
            "country": context["observer"],
            "root_kind": "country",
            "binding": "explicit_query_observer",
            "ui_root_scope_verified": False,
        },
        "static_contract_guard": {"status": "observed"},
        "file_code_guard": {"status": "observed"},
        "runtime_code_guard": {"status": "observed"},
        "doublepass": {"performed": True, "consistent": True},
        "before": {"status": "observed", "game_date": {"raw": date}},
        "after": {"status": "observed", "game_date": {"raw": date}},
        "cleanup": {"handle_close": {"closed": True}},
        "methods": methods,
    }


def test_custom_texts_bind_the_request_and_root_to_the_configured_observer():
    context = {**CONTEXT, "observer": "TUR"}
    report = _report(context=context)
    methods = report["request"]["methods"]
    result = normalize_methods(report, context, methods)
    assert result["provenance"]["country"] == "TUR"
    with pytest.raises(InformationError) as mismatch:
        normalize_methods(report, CONTEXT, methods)
    assert mismatch.value.code == "custom_localization_request_invalid"


def _dynamic_entry(method):
    template = WHOLE_TEMPLATES[method]
    return {
        "status": "unknown",
        "reason": "DYNAMIC_LOCALIZATION_UNRESOLVED",
        "raw_template_hex": template.encode("ascii").hex(),
        "codec": "utf8",
        "template": template,
        "unresolved_tokens": [template],
        "unresolved_markers": ["[", "]"],
        "dynamic_substitution_evaluated": False,
    }


def _literal(text="Resolved title"):
    return {
        "status": "known",
        "raw_template_hex": text.encode("utf-8").hex(),
        "codec": "utf8",
        "text": text,
        "dynamic_substitution_evaluated": False,
    }


def test_normalize_methods_exposes_only_proven_singletons():
    result = normalize_methods(_report(), CONTEXT,
                               ["GetSelectableMissionTitle", "GetSelectableMissionDescription"])

    assert result["status"] == "known"
    assert result["methods"]["GetSelectableMissionTitle"]["status"] == "known"
    assert result["methods"]["GetSelectableMissionTitle"]["text_key"] == "SELECTABLE_MISSION_TITLE"
    selection = result["methods"]["GetSelectableMissionTitle"]["selection"]
    assert selection["kind"] == "single_unconditional_positive_weight"
    assert selection["weight"] == 1000
    assert selection["root_promotion_enum"] == 3
    assert result["provenance"]["root_binding"] == "explicit_query_observer_country"
    assert result["provenance"]["ui_root_scope_verified"] is False
    assert result["provenance"]["native_function_invoked"] is False


@pytest.mark.parametrize("field,value", [("status", "recorded"), ("mode", "recorded")])
def test_normalize_requires_ready_live_context(field, value):
    context = deepcopy(CONTEXT)
    context[field] = value
    with pytest.raises(InformationError) as caught:
        normalize_methods(_report(context=context), context, ["GetSelectableMissionTitle"])
    assert caught.value.code == "custom_localization_context_invalid"


def test_explicit_unknown_method_does_not_leak_a_key_or_selection():
    methods = {
        "GetSelectableMissionTitle": _method("GetSelectableMissionTitle"),
        "GetSelectableMissionDescription": _method(
            "GetSelectableMissionDescription", status="unknown", reason="predicate_unknown"),
    }
    result = normalize_methods(_report(methods), CONTEXT, list(methods))

    unknown = result["methods"]["GetSelectableMissionDescription"]
    assert unknown == {
        "status": "unknown",
        "reason": "predicate_unknown",
    }
    assert result["methods"]["GetSelectableMissionTitle"]["status"] == "known"


def test_text_key_longer_than_cache_lookup_limit_is_not_known():
    methods = {"GetSelectableMissionTitle": _method(
        "GetSelectableMissionTitle", key="A" * 161)}
    with pytest.raises(InformationError) as caught:
        normalize_methods(_report(methods), CONTEXT, ["GetSelectableMissionTitle"])
    assert caught.value.code == "custom_localization_method_invalid"


@pytest.mark.parametrize("mutation,code", [
    (lambda r: r.update(status="unknown"), "custom_localization_snapshot_incomplete"),
    (lambda r: r.update(read_only=False), "custom_localization_snapshot_incomplete"),
    (lambda r: r["identity"].update(binding_verified=False), "custom_localization_snapshot_incomplete"),
    (lambda r: r["identity"].update(installation_session_id="other"), "custom_localization_snapshot_incomplete"),
    (lambda r: r["query_scope"].update(binding="implicit_ui_root"), "custom_localization_root_scope_unverified"),
    (lambda r: r["doublepass"].update(consistent=False), "custom_localization_snapshot_incomplete"),
    (lambda r: r["after"]["game_date"].update(raw=56553385), "custom_localization_context_changed"),
    (lambda r: r["cleanup"]["handle_close"].update(closed=False), "custom_localization_snapshot_incomplete"),
])
def test_identity_guard_date_and_cleanup_fail_closed(mutation, code):
    report = _report()
    mutation(report)
    with pytest.raises(InformationError) as caught:
        normalize_methods(report, CONTEXT,
                          ["GetSelectableMissionTitle", "GetSelectableMissionDescription"])
    assert caught.value.code == code


@pytest.mark.parametrize("field,value", [
    ("option_count", True),
    ("predicate_count", False),
    ("weight", True),
    ("random_flag", 2),
    ("root_promotion_enum", True),
])
def test_selection_numeric_domain_rejects_bool_or_out_of_range(field, value):
    methods = {"GetSelectableMissionTitle": _method(
        "GetSelectableMissionTitle", selection=_selection(**{field: value}))}
    with pytest.raises(InformationError) as caught:
        normalize_methods(_report(methods), CONTEXT, ["GetSelectableMissionTitle"])
    assert caught.value.code.startswith("custom_localization_")


@pytest.mark.parametrize("bad_requested", [None, ["GetSelectableMissionTitle", {}], [], ["GetSelectableMissionTitle"] * 2])
def test_malformed_requested_methods_never_leak_python_type_errors(bad_requested):
    with pytest.raises(InformationError) as caught:
        normalize_methods(_report(), CONTEXT, bad_requested)
    assert caught.value.code == "custom_localization_request_invalid"


def test_apply_single_template_preserves_source_template_and_marks_derivation():
    original = _dynamic_entry("GetSelectableMissionTitle")
    original_copy = deepcopy(original)
    normalized = normalize_methods(
        _report({"GetSelectableMissionTitle": _method("GetSelectableMissionTitle")}),
        CONTEXT, ["GetSelectableMissionTitle"],
    )["methods"]["GetSelectableMissionTitle"]

    result = apply_single_template(original, "GetSelectableMissionTitle", normalized,
                                    _literal("解放诺曼底"))

    assert result["status"] == "known"
    assert result["text"] == "解放诺曼底"
    assert result["raw_template_hex"] == original_copy["raw_template_hex"]
    assert result["codec"] == "utf8"
    assert result["template"] == original_copy["template"]
    assert result["dynamic_substitution_evaluated"] is False
    assert "unresolved_tokens" not in result and "unresolved_markers" not in result
    assert result["custom_text_derivation"] == {
        "method": "GetSelectableMissionTitle",
        "text_key": "SELECTABLE_MISSION_TITLE",
        "rule": "single_unconditional_positive_weight",
        "root_binding": "explicit_query_observer_country",
        "ui_root_scope_verified": False,
        "selected_text_raw_hex": "解放诺曼底".encode("utf-8").hex(),
        "literal_prefix": "",
        "literal_suffix": "",
        "selection": normalized["selection"],
        "native_function_invoked": False,
    }
    assert original == original_copy


@pytest.mark.parametrize("selected", [
    {"status": "unknown", "reason": "cache_missing"},
    {"status": "known", "text": "[still_dynamic]", "raw_template_hex": "5b7374696c6c5f64796e616d69635d"},
    {"status": "known", "text": "literal", "template": "literal", "raw_template_hex": "6c69746572616c"},
    {"status": "known", "text": "literal", "unresolved_tokens": ["$x$"], "raw_template_hex": "6c69746572616c"},
    {"status": "known", "text": "literal", "raw_template_hex": "not-hex"},
    {"status": "known", "text": "lit\x00eral", "codec": "utf8", "raw_template_hex": "6c69746572616c"},
    {"status": "known", "text": "\ud800", "codec": "utf8", "raw_template_hex": "6c69746572616c"},
    {"status": "known", "text": "literal", "codec": "cp1252", "raw_template_hex": "6c69746572616c"},
    {"status": "known", "text": "literal", "raw_template_hex": "6c69746572616c"},
])
def test_apply_keeps_dynamic_unknown_when_cache_is_not_a_literal(selected):
    original = _dynamic_entry("GetSelectableMissionDescription")
    normalized = normalize_methods(
        _report({"GetSelectableMissionDescription": _method("GetSelectableMissionDescription")}),
        CONTEXT, ["GetSelectableMissionDescription"],
    )["methods"]["GetSelectableMissionDescription"]

    result = apply_single_template(original, "GetSelectableMissionDescription", normalized, selected)
    assert result == original


def test_apply_requires_the_original_dynamic_reason_and_explicit_codec():
    normalized = normalize_methods(
        _report({"GetSelectableMissionTitle": _method("GetSelectableMissionTitle")}),
        CONTEXT, ["GetSelectableMissionTitle"],
    )["methods"]["GetSelectableMissionTitle"]
    selected = _literal("literal")

    wrong_reason = _dynamic_entry("GetSelectableMissionTitle")
    wrong_reason["reason"] = "OTHER_UNKNOWN_REASON"
    assert apply_single_template(wrong_reason, "GetSelectableMissionTitle", normalized, selected) == wrong_reason

    missing_original_codec = _dynamic_entry("GetSelectableMissionTitle")
    missing_original_codec.pop("codec")
    assert apply_single_template(missing_original_codec, "GetSelectableMissionTitle", normalized, selected) == missing_original_codec

    missing_selected_codec = _literal("literal")
    missing_selected_codec.pop("codec")
    original = _dynamic_entry("GetSelectableMissionTitle")
    assert apply_single_template(original, "GetSelectableMissionTitle", normalized, missing_selected_codec) == original


def test_apply_accepts_one_token_with_literal_prefix_and_suffix():
    original = _dynamic_entry("GetSelectableMissionTitle")
    original["template"] = "prefix [Root.GetSelectableMissionTitle] suffix"
    normalized = normalize_methods(
        _report({"GetSelectableMissionTitle": _method("GetSelectableMissionTitle")}),
        CONTEXT, ["GetSelectableMissionTitle"],
    )["methods"]["GetSelectableMissionTitle"]

    result = apply_single_template(original, "GetSelectableMissionTitle", normalized,
                                   _literal())
    assert result["status"] == "known"
    assert result["text"] == "prefix Resolved title suffix"
    assert result["custom_text_derivation"]["literal_prefix"] == "prefix "
    assert result["custom_text_derivation"]["literal_suffix"] == " suffix"


def test_match_single_template_preserves_leading_space_and_formatting_literals():
    original = _dynamic_entry("GetSelectableMissionDescription")
    original["template"] = " § [Root.GetSelectableMissionDescription] §"

    assert match_single_template(original) == {
        "method": "GetSelectableMissionDescription",
        "prefix": " § ",
        "suffix": " §",
    }


@pytest.mark.parametrize("template", [
    "[Other.GetText] [Root.GetSelectableMissionTitle]",
    "[Root.GetSelectableMissionTitle] [Root.GetSelectableMissionTitle]",
    "[Root.GetSelectableMissionTitle] [Root.GetSelectableMissionDescription]",
    "[Root.GetSelectableMissionTitle",
    "Root.GetSelectableMissionTitle]",
    "[Root.GetSelectableMissionTitle] $other$",
])
def test_match_single_template_rejects_other_duplicate_or_unbalanced_markers(template):
    original = _dynamic_entry("GetSelectableMissionTitle")
    original["template"] = template
    assert match_single_template(original) is None


def test_apply_rejects_derived_output_over_32768_utf8_bytes():
    original = _dynamic_entry("GetSelectableMissionTitle")
    original["template"] = "𐀀" * 8150 + WHOLE_TEMPLATES["GetSelectableMissionTitle"]
    normalized = normalize_methods(
        _report({"GetSelectableMissionTitle": _method("GetSelectableMissionTitle")}),
        CONTEXT, ["GetSelectableMissionTitle"],
    )["methods"]["GetSelectableMissionTitle"]
    selected = _literal("x" * 8192)

    assert match_single_template(original) is not None
    assert apply_single_template(original, "GetSelectableMissionTitle", normalized, selected) == original


def test_apply_invalid_original_entry_and_method_raise_information_errors():
    with pytest.raises(InformationError) as caught:
        apply_single_template(None, "GetSelectableMissionTitle", {}, _literal())
    assert caught.value.code == "custom_localization_entry_invalid"
    with pytest.raises(InformationError) as caught:
        apply_single_template(_dynamic_entry("GetSelectableMissionTitle"), "GetName", {}, _literal())
    assert caught.value.code == "custom_localization_method_invalid"
