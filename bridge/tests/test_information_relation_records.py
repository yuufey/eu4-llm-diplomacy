"""Pure tests for the selected-pair R01 relation projection."""
from __future__ import annotations

from copy import deepcopy
import ast
import json
from pathlib import Path

from bridge.diplomacy import ObserverSession
from bridge.information.relation_records import ACTION_MAPPING, project


ROOT = Path(__file__).parents[2]
SOURCE = ROOT / "work/runtime/information-relations-20261027-001/relation-source-001.json"
RIVAL = ROOT / "bridge/tests/fixtures/rival_r34b_real_native_inspections.json"


def _pins() -> dict[str, dict]:
    report = json.loads(SOURCE.read_text(encoding="utf-8"))
    return {pin["json_pointer"]: pin for pin in report["archived_example_pins"]}


def _pointer(path: Path, pointer: str):
    value = json.loads(path.read_text(encoding="utf-8"))
    if not pointer.startswith("/"):
        raise AssertionError(pointer)
    for part in pointer[1:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        value = value[int(part)] if isinstance(value, list) else value[part]
    return value


def _archived(pointer: str) -> tuple[dict, dict]:
    pin = _pins()[pointer]
    return deepcopy(_pointer(ROOT / pin["path"], pointer)), {
        "path": pin["path"],
        "json_pointer": pin["json_pointer"],
        "sha256": pin["sha256"],
    }


def _row(result: dict) -> dict:
    assert len(result["records"]) == 1
    return result["records"][0]


def test_real_archived_family_states_project_without_using_legality() -> None:
    cases = (
        ("/queries/ORL/offer_vassalization", "FRA", "ORL", "vassalization", "active"),
        ("/queries/SAV/proclaim_guarantee", "FRA", "SAV", "guarantee", "inactive"),
        ("/queries/SWE/support_independence", "FRA", "SWE", "support_independence", "inactive"),
        ("/queries/ARA/ask_military_access", "FRA", "ARA", "military_access", "inactive"),
    )
    for pointer, actor, recipient, family, status in cases:
        inspection, source_ref = _archived(pointer)
        result = project(inspection["action_id"], inspection, actor, recipient,
                         source_ref=source_ref)
        row = _row(result)
        assert row["relation_type"] == {"status": "known", "value": family}
        assert row["status"] == {"status": "known", "value": status}
        assert row["raw_sourcepath"] == source_ref["path"]
        assert row["raw_json_pointer"] == pointer
        assert row["expires_at"] == {"status": "unknown", "reason": "RELATION_EXPIRY_UNREAD"}
        assert "acceptance" not in row
        assert "legality" not in row
        assert "RELATION_EXPIRY_UNREAD" in result["missing"]

    inspection, source_ref = _archived("/queries/ORL/offer_vassalization")
    row = _row(project(inspection["action_id"], inspection, "FRA", "ORL",
                       source_ref=source_ref))
    assert row["grantor"] == {"status": "known", "value": "FRA"}
    assert row["recipient"] == {"status": "known", "value": "ORL"}


def test_real_rival_semantic_projection_supports_active_and_inactive() -> None:
    payload = json.loads(RIVAL.read_text(encoding="utf-8"))
    active_event = deepcopy(payload["events"][0]["event"])
    inactive_event = deepcopy(payload["events"][4]["event"])
    active = ObserverSession._semantic_rival_inspection(active_event)
    inactive = ObserverSession._semantic_rival_inspection(inactive_event)

    active_row = _row(project("set_rival", active, "FRA", "BUR",
                               source_ref={"path": str(RIVAL), "json_pointer": "/events/0/event"}))
    inactive_row = _row(project("set_rival", inactive, "FRA", "HAB"))
    assert active_row["relation_type"] == {"status": "known", "value": "rival"}
    assert active_row["status"] == {"status": "known", "value": "active"}
    assert active_row["grantor"]["status"] == "not_applicable"
    assert active_row["recipient"]["status"] == "not_applicable"
    assert inactive_row["status"] == {"status": "known", "value": "inactive"}


def test_incomplete_state_is_unknown_and_pending_acceptance_is_ignored() -> None:
    inspection, source_ref = _archived("/queries/SAV/proclaim_guarantee")
    broken = deepcopy(inspection)
    broken["relationship_state"]["complete"] = False
    broken["acceptance"] = {"predicted_response": "accept"}
    result = project(broken["action_id"], broken, "FRA", "SAV", source_ref=source_ref)
    row = _row(result)
    assert row["relation_type"] == {"status": "unknown", "reason": "RELATION_TYPE_UNVERIFIED"}
    assert row["status"] == {"status": "unknown", "reason": "RELATION_STATUS_UNVERIFIED"}
    assert "RELATIONSHIP_STATE_INCOMPLETE" in result["missing"]
    assert row["grantor"]["status"] == "unknown"

    royal, royal_ref = _archived("/queries/offer_royal_marriage:LAN")
    royal_result = project(royal["action_id"], royal, "FRA", "LAN", source_ref=royal_ref)
    royal_row = _row(royal_result)
    assert royal_row["relation_type"]["status"] == "unknown"
    assert royal_row["status"]["status"] == "unknown"
    assert "RELATIONSHIP_STATE_UNREAD" in royal_result["missing"]
    assert "NATIVE_WOULD_ACCEPT" not in royal_result["missing"]


def test_active_non_vassal_direction_is_not_invented_and_roles_are_not_mirrored() -> None:
    inspection, _ = _archived("/queries/SAV/proclaim_guarantee")
    active = deepcopy(inspection)
    active["relationship_state"]["guarantee_active"] = True
    result = project(active["action_id"], active, "FRA", "SAV")
    row = _row(result)
    assert row["status"] == {"status": "known", "value": "active"}
    assert row["grantor"] == {"status": "unknown", "reason": "RELATION_ROLE_DIRECTION_UNPROVEN"}
    assert row["recipient"] == {"status": "unknown", "reason": "RELATION_ROLE_DIRECTION_UNPROVEN"}
    assert "RELATION_ROLE_DIRECTION_UNPROVEN" in result["missing"]

    original = deepcopy(inspection)
    project(active["action_id"], active, "FRA", "SAV")
    assert inspection == original


def test_family_and_endpoint_guards_prevent_action_only_or_wrong_pair_projection() -> None:
    inspection, _ = _archived("/queries/ARA/ask_military_access")
    wrong_family = deepcopy(inspection)
    wrong_family["family"] = "guarantee"
    result = project(wrong_family["action_id"], wrong_family, "FRA", "ARA")
    assert result["records"][0]["status"]["status"] == "unknown"
    assert "ACTION_FAMILY_MISMATCH" in result["missing"]

    invalid_duplicate = deepcopy(inspection)
    invalid_duplicate["military_access_active"] = None
    invalid_duplicate_result = project(
        invalid_duplicate["action_id"], invalid_duplicate, "FRA", "ARA")
    assert "TOP_LEVEL_RELATIONSHIP_ACTIVE_INVALID" in invalid_duplicate_result["missing"]

    wrong_pair = project(inspection["action_id"], inspection, "FRA", "SAV")
    assert wrong_pair["records"] == []
    assert wrong_pair["missing"] == ["INSPECTION_ENDPOINT_MISMATCH"]

    invalid = project("proclaim_guarantee", inspection, "FR", "SAV")
    assert invalid["records"] == []
    assert invalid["missing"] == ["COUNTRY_PAIR_INVALID"]


def test_action_mapping_is_explicit_and_module_has_no_reader_import() -> None:
    assert set(ACTION_MAPPING.values()) == {
        "vassalization", "guarantee", "support_independence", "military_access", "rival",
    }
    tree = ast.parse((ROOT / "bridge/information/relation_records.py").read_text(encoding="utf-8"))
    imports = [node for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))]
    imported = {alias.name for node in imports for alias in node.names}
    assert "bridge.diplomacy" not in imported
    assert "bridge.information.sources" not in imported
