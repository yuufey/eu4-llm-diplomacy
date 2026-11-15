"""Keep the pinned metadata consistent with the native option's number base."""
import hashlib
import json

from bridge.information import foreign_economy_capture as capture
from bridge.information import foreign_economy_visibility_memory as visibility
from bridge.information import native_ai_choice_mapping_memory as choice_mapping
from bridge.information import target_debt_principal_memory as principal


def test_active_profile_identifies_option_0x17_as_decimal_23():
    profile = capture._load_profile()
    predicate = profile["page_gates"]["income_page_local_predicate"]
    assert profile["profile_version"] == 6
    assert profile["semantics"]["capture_schema"] == capture.SCHEMA
    assert capture.SCHEMA == "information.foreign_economy_capture.v4"
    assert capture.PROFILE_SHA256 == (
        "3fbb65eadc9301765896bdde35d84e19f9e93e4b28f54a9820b30d5c2f213626")
    assert capture.PUBLIC_FIELDS == (
        "F03.income", "F03.debt", "F03.bankruptcy_risk", "F03.reparations", "F03.subsidies")
    assert capture.REPARATIONS_FIELD == "F03.observer_reparations"
    assert capture.REPARATIONS_FIELD in capture.FIELDS
    assert capture.SUBSIDIES_FIELD == "F03.observer_subsidies"
    assert capture.SUBSIDIES_FIELD in capture.FIELDS
    assert profile["observer_subsidies"]["scope"] == "observer_fiscal_bilateral_subsidies"
    assert capture.DEBT_TOTAL_FIELD == principal.FIELD
    assert capture.DEBT_TOTAL_FIELD in capture.FIELDS
    assert profile["target_debt_principal"]["private_field"] == principal.FIELD
    assert profile["target_debt_principal"]["basis"] == principal.BASIS
    assert profile["target_debt_principal"]["scope"] == principal.SCOPE
    assert set(visibility.PAGES) == {"income_comparison", "observer_lent_loans"}
    assert type(predicate["or_world_option_index"]) is int
    assert predicate["or_world_option_index"] == 23
    assert predicate["or_world_option_index_hex"] == "0x17"
    assert predicate["option_byte_offset_from_options_pointer"] == "0x5c"
    assert visibility._common.OPTIONS_QUALITY_INDEX == predicate["or_world_option_index"]


def test_v6_principal_and_ai_accept_scope_guards_are_pinned_and_bounded():
    profile = capture._load_profile()
    section = profile["target_debt_principal"]
    native_scope = section["native_ai_accept_scope"]
    assert section["public_projection_basis"] == "native_debt_independent_scopes"
    assert section["principal_amount"] == {
        "source": "all_principal_words_in_the_bound_target_loan_list",
        "unit": "ducats",
        "scale": 1000,
        "signed_width_bits": 32,
        "arithmetic": "signed32_wrap_each_principal_times_1000_then_signed32_add",
        "includes_remaining_interest": False,
        "overflow_is_preserved_and_reported": True,
    }
    assert native_scope["scope"] == "native_ai_accept_principal_amount"
    assert native_scope["action_id"] == "trade_favors_for_gold"
    assert native_scope["native_selector_is_independent_of_action_execution_validity"] is True
    assert native_scope["native_executor_validity_is_not_a_read_gate"] is True
    assert native_scope["favors_balance_or_amount_is_not_a_read_gate"] is True
    assert native_scope["diplomats_or_cooldown_are_not_read_gates"] is True
    assert native_scope["excluded_token"] == 15310
    assert native_scope["mapping_helper_schema"] == choice_mapping.SCHEMA
    assert choice_mapping.SCHEMA == "information.native_ai_choice_mapping_memory.v1"
    assert native_scope["mapping_helper_path"] == (
        "bridge/information/native_ai_choice_mapping_memory.py")
    assert native_scope["accepted_mapping_modes"] == [
        "native_true", "installed_observer_gui_forwarding"]
    assert native_scope["hook_asset_path"] == (
        "bridge/information/profiles/native-ai-choice-hook-v33.json")
    assert native_scope["hook_asset_sha256"] == choice_mapping.ASSET_SHA256
    hooked = native_scope["installed_v33_gui_forwarding_subset"]
    assert hooked["dll_sha256"] == choice_mapping.HOOK_DLL_SHA256
    assert hooked["body_rva"] == "0x56850"
    assert hooked["body_end_rva_exclusive"] == "0x56cdf"
    assert hooked["body_bytes"] == 1167
    assert hooked["body_sha256"] == (
        "51c57947e41feb61d935cb04c2bd6cc007f326fc9dc94c3d9b78cd990c29f24d")
    assert hooked["game_module_base_global_rva"] == "0xd34560"
    assert hooked["saved_original_predicate_global_rva"] == "0x72c0b8"
    assert hooked["saved_original_predicate_rva"] == "0x8f440"
    assert hooked["whole_loaded_dll_hash_verified"] is False
    assert hooked["runtime_callback_execution_observed"] is False
    assert hooked["gui_caller_uses_saved_native_predicate"] is True
    assert "not a general claim" in hooked["proof_scope"]
    assert native_scope["vtable_mapping_cells_are_not_static_guarded"] is True

    code_guards = profile["code_guards"]
    assert len(code_guards) == 45
    assert sum(len(bytes.fromhex(row["bytes"])) for row in code_guards) == 16155
    new_names = {
        "debt.diplomatic_principal_reason_4f5e90",
        "debt.current_action_token_getter_4f5960",
        "debt.ai_accept_tooltip_entry_EF2050",
        "debt.ai_accept_refresh_entry_EF2B00",
        "debt.ai_accept_predicate_4EA210",
        "debt.required_diplomat_constant_true_8F440",
    }
    assert new_names <= {row["name"] for row in code_guards}
    for row in code_guards:
        body = bytes.fromhex(row["bytes"])
        assert row["sha256"] == hashlib.sha256(body).hexdigest()
        assert int(row["end_rva_exclusive"], 16) - int(row["rva"], 16) == len(body)
        assert row["relocation_sites"] == []

    data_guards = profile["data_guards"]
    assert len(data_guards) == 1
    table = data_guards[0]
    assert table["name"] == "debt.ai_accept_excluded_action_tokens_1c35460"
    assert table["rva"] == "0x1c35460" and table["section"] == ".rdata"
    assert table["bytes"] == (
        "28300000292a0000cc3b0000e02d0000da2d00003c29000007330000b9330000"
        "75330000cb3b0000cd3b000066380000")
    table_bytes = bytes.fromhex(table["bytes"])
    assert len(table_bytes) == 48
    assert table["sha256"] == hashlib.sha256(table_bytes).hexdigest()
    assert table["relocation_sites"] == []
    assert "debt.ai_accept_excluded_action_tokens_1c35460" in section["data_guard_names"]
    assert section["code_guard_names"] == [row["name"] for row in code_guards[-6:]]
    assert sum(len(bytes.fromhex(row["bytes"])) for row in code_guards) + len(table_bytes) == 16203
    v5 = capture.PROFILE_FILE.with_name("foreign-economy-memory-1374-v5.json")
    v5_profile = json.loads(v5.read_text(encoding="utf-8"))
    assert code_guards == v5_profile["code_guards"]
    assert profile["data_guards"] == v5_profile["data_guards"]
    assert profile["base_profile"] == {
        "path": "bridge/information/profiles/foreign-economy-memory-1374-v5.json",
        "bytes": 95502,
        "sha256": "10a5d98661148cf9ed03594f96cd06de38c12a8ae4ae25616423d4c73370c0ca",
    }
    assert profile["reviewed_dependency_changes"] == [{
        "path": "bridge/information/target_debt_principal_memory.py",
        "from_profile": "foreign-economy-memory-1374-v5.json",
        "from_bytes": 27388,
        "from_sha256": "fa7ceead5206795f7c5385c226342a1ccf675f88aef0ac21545869ffd7b838aa",
        "to_bytes": 27558,
        "to_sha256": "0633d94436015bd70e5ec447a8fd47c9ae9fb994d12a3b0fdbf677ca90e232df",
        "reason": "The v2 adapter replaces the static-only predicate mapping assertion with strict dynamic proof for the stock predicate or the pinned installed v33 GUI-forwarding subset.",
    }]

    dependency_paths = {row["path"] for row in profile["layout_dependencies"]}
    assert {
        "bridge/information/foreign_debt_principal_memory.py",
        "bridge/information/target_debt_principal_memory.py",
        "bridge/information/foreign_debt_projection.py",
        "bridge/information/foreign_debt_disclosure.py",
        "bridge/information/native_ai_choice_mapping_memory.py",
        "bridge/information/profiles/native-ai-choice-hook-v33.json",
        "work/runtime/information-foreign-debt-public-20261031-001/build_production_profile_002.py",
        "bridge/information/profiles/foreign-economy-memory-1374-v4.json",
    } <= dependency_paths
    adapter_pins = [row for row in profile["layout_dependencies"]
                    if row["path"] == "bridge/information/target_debt_principal_memory.py"]
    assert len(adapter_pins) == 1
    assert (adapter_pins[0]["bytes"], adapter_pins[0]["sha256"]) == (
        27558, "0633d94436015bd70e5ec447a8fd47c9ae9fb994d12a3b0fdbf677ca90e232df")
    assert not any(path.endswith(("foreign_economy_capture.py",
                                  "foreign_economy_projection.py",
                                  "test_foreign_economy_profile.py"))
                   for path in dependency_paths)
    source_paths = {row["path"] for row in profile["source_evidence"]}
    assert "work/runtime/information-foreign-debt-public-20261031-001/ordinary-native-ai-accept-guards-001/ordinary-native-ai-accept-guards-001.raw-002.json" in source_paths
    assert "work/runtime/information-foreign-debt-public-20261031-001/ordinary-ai-accept-predicate-seeds-001/ai-accept-seeds-001.json" in source_paths
    assert {
        "work/runtime/information-foreign-debt-public-20261031-001/stage95/native-ai-accept-hook-audit-001/source-hook-audit.json",
        "work/runtime/information-foreign-debt-public-20261031-001/stage95/native-ai-accept-hook-audit-001/ordinary-choice-hook-body-001/ordinary-hook-analysis.json",
        "work/runtime/information-foreign-debt-public-20261031-001/stage95/native-ai-accept-hook-audit-001/ordinary-choice-hook-body-001/ordinary-pe-report.json",
        "work/runtime/information-foreign-debt-public-20261031-001/stage95/native-ai-accept-hook-audit-001/ordinary-choice-hook-body-001/body-00056850-00056cdf.bin",
        "work/runtime/information-foreign-debt-public-20261031-001/stage95/native-ai-accept-hook-audit-001/ordinary-choice-hook-body-001/objdump-body-00056850-00056cdf.txt",
        "work/runtime/diplomacy-observer-20261031-r74-economic-readonly-001/eu4_bridge_diplomacy_observer_v33.dll",
        "work/runtime/diplomacy-observer-20261031-r74-economic-readonly-001/build-manifest.json",
        "work/runtime/diplomacy-observer-20261031-r74-economic-readonly-001/installation.json",
        "work/runtime/diplomacy-observer-20261031-r74-economic-readonly-001/loader-output.txt",
    } <= source_paths


def test_historical_v1_through_v5_profiles_remain_unchanged():
    root = capture.PROFILE_FILE.parent
    v1 = root / "foreign-economy-memory-1374.json"
    v2 = root / "foreign-economy-memory-1374-v2.json"
    v3 = root / "foreign-economy-memory-1374-v3.json"
    v4 = root / "foreign-economy-memory-1374-v4.json"
    assert hashlib.sha256(v1.read_bytes()).hexdigest() == (
        "835855b4040a4f32347cec78538a763fe399a5295db559d084aa509653ddf1fe")
    assert hashlib.sha256(v2.read_bytes()).hexdigest() == (
        "c2b5b9421e9d6ebfc7a8d258812d435e11827223c041aa1b95597b311e73f80c")
    assert hashlib.sha256(v3.read_bytes()).hexdigest() == (
        "88380120f354a1cde25850d1dcc435f160efb563ecad10dc8f4698ae4a1efa21")
    assert hashlib.sha256(v4.read_bytes()).hexdigest() == (
        "6c6d92a14f4db20931a31c0ff01305f7f04ce6721f600455b8d9908def386196")
    v5 = root / "foreign-economy-memory-1374-v5.json"
    assert hashlib.sha256(v5.read_bytes()).hexdigest() == (
        "10a5d98661148cf9ed03594f96cd06de38c12a8ae4ae25616423d4c73370c0ca")
