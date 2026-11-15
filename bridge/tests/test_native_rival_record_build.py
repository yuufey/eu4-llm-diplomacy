"""Pin the v61 native builder contract and preserve the v58-v60 flag chain."""
import json
from pathlib import Path
import re

from bridge.relation_observation import SUPPORT_SUBJECT_RECORD_SCOPE


ROOT = Path(__file__).resolve().parents[2]
BUILDER = ROOT / "work/native/build-diplomacy-observer.ps1"
V60_MANIFEST = ROOT / (
    "work/runtime/diplomacy-observer-20261110-support-subject-v60-354-001"
    "/build-manifest.json"
)


def _source() -> str:
    return BUILDER.read_text(encoding="utf-8")


def _rival_blocks(source: str) -> list[str]:
    return re.findall(
        r"if\s*\(\$RivalRecordObservation\)\s*\{([^{}]*)\}",
        source,
        re.DOTALL,
    )


def test_rival_switch_extends_the_complete_support_subject_parent_chain():
    source = _source()
    assert "[switch]$RivalRecordObservation" in source
    assert "if ($RivalRecordObservation) { $SupportSubjectRecordObservation = $true }" in source
    chain = [
        "$RivalRecordObservation) { $SupportSubjectRecordObservation = $true }",
        "$SupportSubjectRecordObservation) { $DirectedRecordObservation = $true }",
        "$DirectedRecordObservation) { $RoyalRecordObservation = $true }",
        "$RoyalRecordObservation) { $MissionProvinceConditionObservation = $true }",
        "$MissionProvinceConditionObservation) { $MissionConditionObservation = $true }",
        "$MissionConditionObservation) { $MacroSourceObservation = $true }",
        "$MacroSourceObservation) { $MacroEventObservation = $true }",
        "$MacroEventObservation) { $RivalObservation = $true }",
        "$RivalObservation) { $CountryModifierExpiry = $true }",
        "$CountryModifierExpiry) { $CountryModifierRemoval = $true }",
        "$CountryModifierRemoval) { $CountryModifierObservation = $true }",
        "$CountryModifierObservation) { $SupportRoleContext = $true }",
        "$SupportRoleContext) { $BattleFlagInputs = $true }",
        "$BattleFlagInputs) { $BattleIndependentLine = $true }",
        "$BattleIndependentLine) { $CallToArmsObservation = $true }",
        "$CallToArmsObservation) { $BattleOutcomeTail = $true }",
        "$BattleOutcomeTail) { $BattleOutcomeText = $true }",
        "$BattleOutcomeText) { $BattleNameSources = $true }",
        "$BattleNameSources) { $BattleRetreat = $true }",
        "$BattleRetreat) { $BattleEndState = $true }",
        "$BattleEndState) { $DebtQuoteQuery = $true }",
        "$DebtQuoteQuery) { $BattleDisplayContext = $true }",
    ]
    positions = [source.index(item) for item in chain]
    assert positions == sorted(positions)


def test_rival_flag_selects_version_61_after_the_unchanged_v60_selector():
    source = _source()
    v58 = "if ($RoyalRecordObservation) { $observerVersion = 58 }"
    v59 = "if ($DirectedRecordObservation) { $observerVersion = 59 }"
    v60 = "if ($SupportSubjectRecordObservation) { $observerVersion = 60 }"
    v61 = "if ($RivalRecordObservation) { $observerVersion = 61 }"
    assert all(source.count(item) == 1 for item in (v58, v59, v60, v61))
    assert source.index(v58) < source.index(v59) < source.index(v60) < source.index(v61)
    assert "'eu4_bridge_diplomacy_observer_v' + $observerVersion + '.dll'" in source


def test_rival_flag_adds_only_its_dedicated_compile_define():
    source = _source()
    blocks = _rival_blocks(source)
    assert len(blocks) == 5
    define_blocks = [block for block in blocks if "-DBRIDGE_RIVAL_RECORD_OBSERVATION=1" in block]
    assert define_blocks == [
        "\n    $arguments = @('-DBRIDGE_RIVAL_RECORD_OBSERVATION=1') + $arguments\n"
    ]
    assert source.count("-DBRIDGE_RIVAL_RECORD_OBSERVATION=1") == 1
    for old_define in (
        "-DBRIDGE_ROYAL_RECORD_OBSERVATION=1",
        "-DBRIDGE_DIRECTED_RECORD_OBSERVATION=1",
        "-DBRIDGE_SUPPORT_SUBJECT_RECORD_OBSERVATION=1",
    ):
        assert source.count(old_define) == 1


def test_rival_flag_adds_exactly_the_two_new_manifest_sources():
    blocks = _rival_blocks(_source())
    source_blocks = [block for block in blocks if "$sourceNames +=" in block]
    assert source_blocks == [
        "\n    $sourceNames += @('information-rival-record-entry-plan.h',\n"
        "        'information-rival-record-observer.inc')\n"
    ]
    names = re.findall(r"'([^']+)'", source_blocks[0])
    assert names == [
        "information-rival-record-entry-plan.h",
        "information-rival-record-observer.inc",
    ]
    assert all((ROOT / "work/native" / name).is_file() for name in names)
    assert len(json.loads(V60_MANIFEST.read_text(encoding="utf-8-sig"))["sources"]) + len(names) == 189


def test_rival_manifest_uses_wire2_exact_scope_count_basis_and_formal_flags():
    blocks = _rival_blocks(_source())
    manifest_blocks = [block for block in blocks if "$manifest.native_rival_change_wire" in block]
    assert manifest_blocks == [
        "\n    $manifest.native_rival_change_wire = 2\n"
        "    $manifest.native_rival_change_scope = 'FRA_actor_target_or_old_rival_at_command_or_country_rival_record_returns'\n"
        "    $manifest.native_rival_record_observation = $true\n"
        "    $manifest.native_rival_record_count_basis = 'active_nonretired_nodes'\n"
        "    $manifest.prototype_only = $false\n"
        "    $manifest.formal_installation_admitted = $true\n"
    ]
    assert "$manifest.native_relation_change_wire" not in manifest_blocks[0]
    assert "$manifest.native_relation_change_scope" not in manifest_blocks[0]


def test_rival_record_manifest_preserves_inherited_support_subject_relation_contract():
    source = _source()
    support_blocks = re.findall(
        r"if\s*\(\$SupportSubjectRecordObservation\)\s*\{([^{}]*)\}",
        source,
        re.DOTALL,
    )
    text = next((block for block in support_blocks
                 if "$manifest.native_relation_change_wire = 5" in block), None)
    assert text is not None
    assert "$manifest.native_relation_change_wire = 5" in text
    assert ("$manifest.native_relation_change_scope = "
            f"'{SUPPORT_SUBJECT_RECORD_SCOPE}'") in text
    rival_block = next(block for block in _rival_blocks(source)
                       if "$manifest.native_rival_change_wire" in block)
    assert "$manifest.native_relation_change_wire" not in rival_block
    assert "$manifest.native_relation_change_scope" not in rival_block


def test_v58_v59_v60_contract_branches_remain_unchanged():
    source = _source()
    expected = (
        "if ($RoyalRecordObservation) {\n"
        "    $sourceNames += @('information-royal-record-entry-plan.h', 'information-royal-record-observer.inc')\n"
        "}",
        "if ($DirectedRecordObservation) {\n"
        "    $sourceNames += @('information-directed-record-entry-plan.h', 'information-directed-record-observer.inc')\n"
        "}",
        "if ($SupportSubjectRecordObservation) {\n"
        "    $sourceNames += @('information-support-subject-record-entry-plan.h',\n"
        "        'information-support-subject-record-observer.inc')\n"
        "}",
        "$manifest.native_relation_change_wire = 3\n"
        "    $manifest.native_relation_change_scope = 'FRA_pair_at_six_relation_command_or_alliance_or_royal_record_returns'\n"
        "    $manifest.native_royal_record_observation = $true",
        "$manifest.native_relation_change_wire = 4\n"
        "    $manifest.native_relation_change_scope = 'FRA_pair_at_six_relation_command_or_alliance_or_royal_or_directed_record_returns'\n"
        "    $manifest.native_directed_record_observation = $true",
        "$manifest.native_relation_change_wire = 5\n"
        "    $manifest.native_relation_change_scope = 'FRA_pair_at_six_relation_command_or_six_family_record_returns'\n"
        "    $manifest.native_support_subject_record_observation = $true\n"
        "    $manifest.prototype_only = $false\n"
        "    $manifest.formal_installation_admitted = $true",
    )
    for block in expected:
        assert block in source


def test_historical_v60_manifest_remains_187_source_formal_wire5_baseline():
    manifest = json.loads(V60_MANIFEST.read_text(encoding="utf-8-sig"))
    assert manifest["version"] == 60
    assert len(manifest["sources"]) == 187
    assert manifest["native_relation_change_wire"] == 5
    assert manifest["native_relation_change_scope"] == (
        "FRA_pair_at_six_relation_command_or_six_family_record_returns"
    )
    assert manifest["native_support_subject_record_observation"] is True
    assert manifest["prototype_only"] is False
    assert manifest["formal_installation_admitted"] is True
    assert "-DBRIDGE_RIVAL_RECORD_OBSERVATION=1" not in manifest["compiler_arguments"]
    assert not {
        "information-rival-record-entry-plan.h",
        "information-rival-record-observer.inc",
    } & {row["name"] for row in manifest["sources"]}
