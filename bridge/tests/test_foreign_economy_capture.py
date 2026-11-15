"""Offline integration checks for the read-only F03 economy capture."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from typing import Any

import pytest

from bridge.information import foreign_economy_capture as capture
from bridge.information import foreign_economy_visibility_memory as permission
from bridge.information import foreign_income_memory as income
from bridge.information import foreign_loans_memory as loans
from bridge.information import country_ledger_membership_memory as membership
from bridge.information import country_view_admission_memory as admission
from bridge.information import foreign_technology_capture as owner
from bridge.information import bilateral_reparations_memory as reparations_leaf
from bridge.information import observer_reparations_memory as observer_reparations
from bridge.information import bilateral_subsidies_memory as subsidies_leaf
from bridge.information import observer_subsidies_memory as observer_subsidies
from bridge.information import target_debt_principal_memory as target_debt
from bridge.tests import test_foreign_quality_capture as quality_fixture
from bridge.tests import test_information_foreign_technology_capture as tech_fixture
from bridge.tests import test_observer_reparations_memory as reparations_fixture


MODULE_BASE = quality_fixture.MODULE_BASE
CREATION = 123456789012345678
SESSION_ID = "foreign-economy-capture-session"
GAME_DATE = quality_fixture.GAME_DATE
WORLD = quality_fixture.WORLD
SETTINGS = quality_fixture.SETTINGS
GUARD_RVA = 0x2200
GUARD_BYTES = b"\xCC\x90\xC3"
LOAN_NODE_BASE = 0x6B10000000
LOAN_RECORD_BASE = 0x6B20000000
LOAN_STRIDE = 0x100
SUBSIDY_OBJECT = 0x6C30000000
SUBSIDY_OBSERVER_ITEMS = 0x6C10000000
SUBSIDY_TARGET_ITEMS = 0x6C20000000
TARGET_DEBT_HEAD_OFFSET = 0xDE8
TARGET_DEBT_COUNT_OFFSET = 0xDF8
ACTION_GETTER_CELL_RVA = 0x1C80A18
PRINCIPAL_REASON_CELL_RVA = 0x1C80AA0
VALIDITY_HELPER_CELL_RVA = 0x1C80A50
ACTION_EXCLUSION_TABLE_RVA = 0x1C35460
ACTION_EXCLUSION_TABLE_BYTES = bytes.fromhex(
    "28300000292a0000cc3b0000e02d0000da2d00003c29000007330000b9330000"
    "75330000cb3b0000cd3b000066380000"
)
CURRENT_ACTION_TOKEN = 15310


class TraceReader:
    """Retain the owner's raw read format, including any fixture failures."""

    def __init__(self, image: Any) -> None:
        self.image = image
        self.read_log: list[dict[str, Any]] = []
        self.calls = 0
        self.bytes_requested = 0

    def read(self, address: int, size: int, label: str) -> bytes:
        self.calls += 1
        self.bytes_requested += size
        try:
            raw = self.image.read(address, size, label)
            if not isinstance(raw, bytes) or len(raw) != size:
                raise OSError("synthetic short read")
        except Exception as exc:
            self.read_log.append({
                "address": hex(address), "size": size, "label": label,
                "status": "error", "error": f"{type(exc).__name__}:{exc}",
            })
            raise
        self.read_log.append({
            "address": hex(address), "size": size, "label": label,
            "status": "observed", "raw_hex": raw.hex(),
        })
        return raw


@pytest.fixture
def fixture_profile(monkeypatch):
    """Use a fixture-only profile so this suite never depends on a pending production pin."""
    profile = {
        "profile_id": capture.PROFILE_ID,
        "game_version": "1.37.4",
        "executable": {"sha256": capture.EXE_SHA256},
        "code_guards": [{
            "name": "economy_capture_test_guard",
            "rva": hex(GUARD_RVA),
            "end_rva_exclusive": hex(GUARD_RVA + len(GUARD_BYTES)),
            "bytes": GUARD_BYTES.hex(),
            "sha256": hashlib.sha256(GUARD_BYTES).hexdigest(),
        }],
        "target_debt_principal": {
            "private_field": target_debt.FIELD,
            "scope": target_debt.SCOPE,
        },
    }
    monkeypatch.setattr(capture, "_load_profile", lambda: profile)
    return profile


def _pack_i32(values: list[int] | tuple[int, ...]) -> bytes:
    return b"".join(int(value).to_bytes(4, "little", signed=True) for value in values)


def _put_loans(image: Any, target_pointer: int, lenders: list[int],
               financials: list[tuple[int, int, int] | None]) -> dict[str, list[int]]:
    assert len(lenders) == len(financials)
    nodes: list[int] = []
    records: list[int] = []
    for index, (lender, values) in enumerate(zip(lenders, financials)):
        node = LOAN_NODE_BASE + index * LOAN_STRIDE
        record = LOAN_RECORD_BASE + index * LOAN_STRIDE
        next_node = LOAN_NODE_BASE + (index + 1) * LOAN_STRIDE if index + 1 < len(lenders) else 0
        nodes.append(node)
        records.append(record)
        image.put_u64(node, record)
        image.put_u64(node + 8, 0xA5A5A5A5A5A5A5A5)
        image.put_u64(node + 0x10, next_node)
        image.put_u64(record + 0x20, lender)
        if values is not None:
            image.put(record + 0x28, _pack_i32(values))
    image.put_u64(target_pointer + TARGET_DEBT_HEAD_OFFSET, nodes[0] if nodes else 0)
    image.put_i32(target_pointer + TARGET_DEBT_COUNT_OFFSET, len(nodes))
    return {"nodes": nodes, "records": records}


def _put_target_debt_candidate_context(image: Any, bindings: dict[str, Any],
                                      refs: dict[str, Any], *,
                                      observer_controller: int = 0,
                                      target_controller: int = 0) -> None:
    """Seed the fixed B23 candidate map, exclusion table, and stable world role."""
    image.put_u64(MODULE_BASE + ACTION_GETTER_CELL_RVA, MODULE_BASE + 0x4F5960)
    image.put_u64(MODULE_BASE + PRINCIPAL_REASON_CELL_RVA, MODULE_BASE + 0x4F5E90)
    image.put_u64(MODULE_BASE + VALIDITY_HELPER_CELL_RVA, MODULE_BASE + 0x8F440)
    image.put(MODULE_BASE + 0x8F440, bytes.fromhex("b001c3"))
    image.put(MODULE_BASE + ACTION_EXCLUSION_TABLE_RVA, ACTION_EXCLUSION_TABLE_BYTES)

    image.put_u64(MODULE_BASE + 0x233FE58, WORLD)
    image.put_i32(WORLD + 0x1DD0, GAME_DATE)
    image.put_i32(WORLD + 0x0A60, 1)
    controllers = refs["controller_types_pointer"]
    image.put_u64(WORLD + 0x1D48, controllers)
    image.put_i32(controllers + bindings["FRA"]["slot"] * 4, observer_controller)
    image.put_i32(controllers + bindings["ENG"]["slot"] * 4, target_controller)


def _put_observer_reparations(image: Any, bindings: dict[str, Any], refs: dict[str, Any],
                              *, present: bool = True, view_admitted: bool = True) -> None:
    """Add the FRA/target relation graph to the real parent fake image."""
    observer_slot = bindings["FRA"]["slot"]
    target_slot = bindings["ENG"]["slot"]
    observer_pointer = bindings["FRA"]["country_pointer"]
    target_pointer = refs["target_pointer"]
    observer_owner = observer_pointer + 0x14F8
    target_owner = target_pointer + 0x14F8
    observer_ref = refs["observer_fullref"]
    target_ref = refs["target_fullref"]
    f = reparations_fixture
    observer_row = f.OBSERVER_ROWS + target_slot * reparations_leaf.PAIR_ROW_STRIDE
    target_row = f.TARGET_ROWS + observer_slot * reparations_leaf.PAIR_ROW_STRIDE

    image.put_u64(observer_pointer + reparations_leaf.COUNTRY_RELATION_ROWS_OFFSET,
                  f.OBSERVER_ROWS)
    image.put_u64(target_pointer + reparations_leaf.COUNTRY_RELATION_ROWS_OFFSET,
                  f.TARGET_ROWS)
    image.put_u64(observer_row + reparations_leaf.PAIR_OWNER_OFFSET, observer_owner)
    image.put_u64(observer_row + reparations_leaf.PAIR_SELF_FULLREF_OFFSET, observer_ref)
    image.put_u64(observer_row + reparations_leaf.PAIR_OTHER_FULLREF_OFFSET, target_ref)
    image.put_u64(target_row + reparations_leaf.PAIR_OWNER_OFFSET, target_owner)
    image.put_u64(target_row + reparations_leaf.PAIR_SELF_FULLREF_OFFSET, target_ref)
    image.put_u64(target_row + reparations_leaf.PAIR_OTHER_FULLREF_OFFSET, observer_ref)
    # The country-view admission row uses this same observer row owner and
    # expects a positive observer->target counter at owner+0x38.
    counters = f.OBSERVER_ITEMS + 0x10000
    image.put_u64(observer_owner + admission.RELATION_OWNER_COUNTERS_OFFSET, counters)
    image.put_i32(counters + admission.RELATION_COUNTER_FIRST_OFFSET
                  + target_slot * admission.RELATION_COUNTER_STRIDE,
                  1 if view_admitted else 0)
    f._put_vector(image, observer_owner, f.OBSERVER_ITEMS,
                  [(target_slot, f.TREATY)] if present else [])
    f._put_vector(image, target_owner, f.TARGET_ITEMS,
                  [(observer_slot, f.TREATY)] if present else [])
    if present:
        image.put_u64(f.TREATY, MODULE_BASE + reparations_leaf.RELATION_TABLE_RVA)
        image.put(f.TREATY + 8,
                  reparations_leaf.RELATION_MARKER.to_bytes(4, "little")
                  + b"\x00" * 4)
        image.put_u64(f.TREATY + reparations_leaf.RELATION_PAYER_OFFSET, observer_ref)
        image.put_u64(f.TREATY + reparations_leaf.RELATION_CLAIMANT_OFFSET, target_ref)
        image.put_i32(f.TREATY + reparations_leaf.RELATION_START_DATE_OFFSET,
                      reparations_fixture.START_DATE)
        image.put_i32(f.TREATY + reparations_leaf.RELATION_END_DATE_OFFSET,
                      reparations_fixture.END_DATE)


def _put_observer_subsidies(image: Any, bindings: dict[str, Any], refs: dict[str, Any],
                            *, present: bool) -> None:
    """Use literal native offsets independently of the subsidy implementation."""
    for owner_pointer, items_pointer, slot in (
        (bindings["FRA"]["country_pointer"] + 0x14F8, SUBSIDY_OBSERVER_ITEMS, bindings["ENG"]["slot"]),
        (refs["target_pointer"] + 0x14F8, SUBSIDY_TARGET_ITEMS, bindings["FRA"]["slot"]),
    ):
        # Native owner+0x108 vector: +8 data, +0x10 capacity, +0x14 count.
        image.put_u64(owner_pointer + 0x110, items_pointer if present else 0)
        image.put_i32(owner_pointer + 0x118, 1 if present else 0)
        image.put_i32(owner_pointer + 0x11C, 1 if present else 0)
        if present:
            image.put(items_pointer, slot.to_bytes(4, "little") + b"\x00" * 4
                      + SUBSIDY_OBJECT.to_bytes(8, "little"))
    if present:
        raw = bytearray(0x48)
        raw[0:8] = (MODULE_BASE + 0x1C815D8).to_bytes(8, "little")
        raw[8:12] = (0x165).to_bytes(4, "little")
        raw[0x10:0x18] = refs["observer_fullref"].to_bytes(8, "little")
        raw[0x18:0x20] = refs["target_fullref"].to_bytes(8, "little")
        raw[0x20:0x24] = (GAME_DATE - 12 * 24).to_bytes(4, "little", signed=True)
        raw[0x40:0x44] = (1250).to_bytes(4, "little", signed=True)
        raw[0x44:0x48] = (3).to_bytes(4, "little", signed=True)
        image.put(SUBSIDY_OBJECT, bytes(raw))


def _make_image(profile: dict[str, Any], *, country_view_admitted: bool = True,
                income_option_blocked: bool = False, human_fra: bool = False,
                target_active: bool = True, income_values: list[int] | None = None,
                loan_rows: list[tuple[int, tuple[int, int, int] | None]] | None = None,
                reparations_present: bool = True, subsidies_present: bool = True):
    image, bindings, refs = quality_fixture._make_image(
        profile,
        country_view_admitted=country_view_admitted,
        quality_allowed=not income_option_blocked,
        human_fra=human_fra,
        target_in_ledger=target_active,
    )
    target_pointer = refs["target_pointer"]
    values = income_values if income_values is not None else [100 + 7 * i for i in range(19)]
    assert len(values) == income.INCOME_CATEGORY_COUNT
    income_address = target_pointer + income.COUNTRY_INCOME_CACHE_OFFSET
    image.put(income_address, _pack_i32(values))

    rows = loan_rows if loan_rows is not None else [
        (refs["observer_fullref"], (4000, 125000, GAME_DATE + 100)),
    ]
    graph = _put_loans(image, target_pointer,
                       [lender for lender, _financials in rows],
                       [financials for _lender, financials in rows])
    _put_observer_reparations(image, bindings, refs, present=reparations_present,
                              view_admitted=country_view_admitted)
    _put_observer_subsidies(image, bindings, refs, present=subsidies_present)
    _put_target_debt_candidate_context(image, bindings, refs,
                                       observer_controller=1 if human_fra else 0)
    image.put(MODULE_BASE + GUARD_RVA, GUARD_BYTES)
    return image, bindings, refs, {"income_address": income_address, "income_values": list(values), **graph}


def _make_capture(profile: dict[str, Any], *, country_view_admitted: bool = True,
                  income_option_blocked: bool = False, human_fra: bool = False,
                  target_active: bool = True, income_values: list[int] | None = None,
                  loan_rows: list[tuple[int, tuple[int, int, int] | None]] | None = None,
                  reparations_present: bool = True,
                  subsidies_present: bool = True,
                  image: Any | None = None, bindings: dict[str, Any] | None = None,
                  refs: dict[str, Any] | None = None, data: dict[str, Any] | None = None):
    if image is None:
        image, bindings, refs, data = _make_image(
            profile, country_view_admitted=country_view_admitted,
            income_option_blocked=income_option_blocked, human_fra=human_fra,
            target_active=target_active, income_values=income_values, loan_rows=loan_rows,
            reparations_present=reparations_present, subsidies_present=subsidies_present)
    assert bindings is not None and refs is not None and data is not None
    source = TraceReader(image)
    wrapped = owner._FailureReplayReader(source)
    observation_error = None
    try:
        observation = capture._observe(wrapped, MODULE_BASE, "ENG", profile)
    except Exception as exc:
        observation = None
        observation_error = f"{type(exc).__name__}:{exc}"
    completed = observation_error is None and observation.get("stable") is True
    identity = {
        "binding_verified": True,
        "process_creation_filetime": CREATION,
        "process_path": "synthetic-eu4.exe",
        "process_path_sha256": capture.EXE_SHA256,
    }
    report = {
        "schema": capture.SCHEMA,
        "status": "observed" if completed else "unknown",
        "completed": completed,
        "request": {"country": "ENG", "observer": "FRA",
                    "creation_filetime": CREATION, "session_id": SESSION_ID},
        "profile_sha256": capture.PROFILE_SHA256,
        "identity": deepcopy(identity),
        "identity_after": deepcopy(identity),
        "module_base": hex(MODULE_BASE),
        "observation": observation,
        "raw_reads": deepcopy(source.read_log),
        "cleanup": {"status": "closed", "closed": True, "success": True},
        "errors": [] if observation_error is None else [{"reason": observation_error}],
        "access": {
            "read_only": True, "native_function_invoked": False, "writes": False,
            "UI_control": False, "date_advance": False, "save_or_reload": False,
            "limit_bytes": owner.MAX_READ_BYTES, "calls": source.calls,
            "bytes_requested": source.bytes_requested,
        },
    }
    context = {
        "observer": "FRA", "session_id": SESSION_ID,
        "game_version": "1.37.4", "game_sha256": capture.EXE_SHA256,
        "game_date": GAME_DATE,
    }
    return report, context, CREATION, {
        "image": image, "source": source, "bindings": bindings,
        "target_pointer": refs["target_pointer"],
        "observer_fullref": refs["observer_fullref"],
        "physical_fullref": refs["physical_fullref"],
        "target_fullref": refs["target_fullref"],
        "controller_types_pointer": refs["controller_types_pointer"],
        "fra_controller_type": refs["fra_controller_type"],
        "income_address": data["income_address"],
        "income_values": data["income_values"],
        "nodes": data["nodes"], "records": data["records"],
    }


def _target(report: dict[str, Any]) -> dict[str, Any]:
    return report["observation"]["backend"]["targets"][0]


def _labels(report: dict[str, Any]) -> list[str]:
    return [row["label"] for row in report["raw_reads"]]


def _assert_valid(report: dict[str, Any], context: dict[str, Any], creation: int) -> None:
    assert report["observation"]["stable"] is True
    assert capture.validate_capture(report, context, creation, "ENG")


def test_two_pass_capture_projects_real_income_and_observer_lent_loan_with_role_and_replay(
        fixture_profile):
    report, context, creation, fixture = _make_capture(fixture_profile)
    _assert_valid(report, context, creation)
    backend = report["observation"]["backend"]
    target = _target(report)
    assert backend["consistency"] == {"status": "stable", "shared_mismatch_paths": []}
    assert backend["status"] == "observed"
    assert target["binding_status"] == "observed"
    assert target["fullref"] == hex(fixture["target_fullref"])
    assert target["fields"]["F03.income"]["status"] == "known"
    assert target["fields"]["F03.income"]["complete"] is False
    assert target["fields"]["F03.income"]["partial"] is True
    assert target["fields"]["F03.income"]["unit"] == "ducats"
    assert target["fields"]["F03.income"]["scale"] == 1000
    assert target["fields"]["F03.debt"]["status"] == "known"
    loan_subset = target["fields"]["F03.debt"]["value"]["loans_to_observer"]
    assert loan_subset["record_count"] == 1
    assert loan_subset["records"][0]["lender"] == "FRA"
    assert loan_subset["records"][0]["borrower"] == "ENG"
    assert loan_subset["records"][0]["principal"]["raw"] == 125000
    assert target["fields"]["F03.bankruptcy_risk"]["status"] == "unknown"
    assert "value" not in target["fields"]["F03.bankruptcy_risk"]
    pair = target["fields"][observer_reparations.FIELD]
    assert pair["status"] == "known" and pair["complete"] is False
    assert pair["value"]["status"] == "known"
    assert pair["value"]["payer"]["tag"] == "FRA"
    assert pair["value"]["claimant"]["tag"] == "ENG"
    assert pair["value"]["active_payment_obligation"]["status"] == "unknown"
    assert pair["value"]["payment_amount"]["status"] == "unknown"
    pair_permission = pair["raw_inputs"]["permission"]
    assert observer_reparations.validate_permission(pair_permission)
    assert pair_permission["raw_inputs"]["world"]["date_raw_i32"] == GAME_DATE
    backend = report["observation"]["backend"]
    assert backend["budget"]["bytes_requested"] <= capture._backend.MAX_TOTAL_READ_BYTES
    assert report["access"]["bytes_requested"] <= owner.MAX_READ_BYTES
    pair_budget = pair["raw_inputs"]["state"]["raw_inputs"]["read_budget"]
    assert pair_budget["bytes_requested"] <= reparations_leaf.MAX_TOTAL_READ_BYTES
    assert pair_budget["calls"] <= reparations_leaf.MAX_READ_CALLS
    assert pair_budget["max_single_read_bytes"] == reparations_leaf.MAX_SINGLE_READ_BYTES
    assert target["fields"][capture.VISIBILITY_FIELD]["status"] == "known"
    pages = target["fields"][capture.VISIBILITY_FIELD]["value"]
    assert pages[permission.INCOME_PAGE]["admitted"] is True
    assert pages[permission.LOANS_PAGE]["admitted"] is True
    assert target["field_consistency"]["F03.income"]["status"] == "stable"
    assert target["field_consistency"]["F03.debt"]["status"] == "stable"
    assert target["field_consistency"][observer_reparations.FIELD]["status"] == "stable"
    for phase in ("pass1", "pass2"):
        assert target["admission_by_pass"][phase]["observer_nonplayer_role"]["verified"] is True
        assert target["admission_by_pass"][phase]["observer_nonplayer_role"]["human_count"] == 1
        assert target["admission_by_pass"][phase]["observer_nonplayer_role"]["controller_type"] == 0
        scan = backend["pass_evidence"][phase]["country_scan"]
        assert scan["status"] == "observed"
        assert scan["requested"]["FRA"]["fullref"] == hex(fixture["observer_fullref"])
        assert scan["requested"]["ENG"]["fullref"] == hex(fixture["target_fullref"])
    assert fixture["physical_fullref"] != fixture["observer_fullref"]
    assert report["access"]["calls"] == len(report["raw_reads"])
    assert report["access"]["bytes_requested"] == sum(row["size"] for row in report["raw_reads"])
    assert any(label.startswith("country_reference.slot[") for label in _labels(report))


def test_target_debt_candidate_captures_all_target_principals_with_strict_replay(fixture_profile):
    image, bindings, refs, data = _make_image(fixture_profile)
    principals = [172, 173, 173, 179, 179, 179]
    graph = _put_loans(
        image, refs["target_pointer"],
        [refs["observer_fullref"]] * len(principals),
        [(0, value, 0) for value in principals],
    )
    data.update(graph)
    report, context, creation, _fixture = _make_capture(
        fixture_profile, image=image, bindings=bindings, refs=refs, data=data)
    _assert_valid(report, context, creation)

    target = _target(report)
    field = target["fields"][target_debt.FIELD]
    assert field["status"] == "known"
    assert field["basis"] == target_debt.BASIS
    assert field["value"]["principal_total"]["raw"] == 1055
    assert field["value"]["diplomatic_principal_total"]["raw"] == 1_055_000
    assert field["raw_inputs"]["state"]["raw_inputs"]["verified_loan_count"] == 6
    candidate_permission = field["raw_inputs"]["permission"]
    assert target_debt.validate_permission(candidate_permission)
    assert candidate_permission["admitted"] is True
    assert candidate_permission["raw_inputs"]["world"]["date_raw_i32"] == GAME_DATE
    assert target["fields"]["F03.income"]["status"] == "known"
    assert target["fields"]["F03.debt"]["status"] == "known"
    assert capture.PUBLIC_FIELDS == (
        "F03.income", "F03.debt", "F03.bankruptcy_risk",
        "F03.reparations", "F03.subsidies")
    assert target_debt.FIELD not in capture.PUBLIC_FIELDS


@pytest.mark.parametrize(("case", "expected_reason"), [
    ("target_role", "TARGET_CONTROLLER_NOT_ZERO"),
    ("mapping", "CURRENT_ACTION_GETTER_MAPPING_MISMATCH"),
    ("exclusion_table", "CURRENT_ACTION_TOKEN_EXCLUDED"),
])
def test_target_debt_candidate_denials_skip_principal_leaf(
        fixture_profile, case, expected_reason):
    image, bindings, refs, data = _make_image(fixture_profile)
    if case == "target_role":
        image.put_i32(refs["controller_types_pointer"] + bindings["ENG"]["slot"] * 4, 1)
    elif case == "mapping":
        image.put_u64(MODULE_BASE + ACTION_GETTER_CELL_RVA, MODULE_BASE + 0x4F5961)
    else:
        excluded = CURRENT_ACTION_TOKEN.to_bytes(4, "little") + ACTION_EXCLUSION_TABLE_BYTES[4:]
        image.put(MODULE_BASE + ACTION_EXCLUSION_TABLE_RVA, excluded)

    report, context, creation, _fixture = _make_capture(
        fixture_profile, image=image, bindings=bindings, refs=refs, data=data)
    _assert_valid(report, context, creation)
    target = _target(report)
    field = target["fields"][target_debt.FIELD]
    assert field["status"] == "unknown"
    candidate_permission = field["raw_inputs"]["permission"]
    assert candidate_permission["reason"] == expected_reason
    labels = _labels(report)
    assert not any(label.startswith("loan.node[") for label in labels)
    assert not any(label.startswith("loan.record_principal[") for label in labels)
    assert target["fields"]["F03.income"]["status"] == "known"
    assert target["fields"]["F03.debt"]["status"] == "known"


def test_target_debt_candidate_capture_date_mismatch_retracts_only_private_field(
        fixture_profile, monkeypatch):
    image, bindings, refs, data = _make_image(fixture_profile)
    original_permission = target_debt.read_permission

    def offset_only_candidate_permission(reader, base, observer, target):
        image.put_i32(WORLD + 0x1DD0, GAME_DATE + 1)
        try:
            return original_permission(reader, base, observer, target)
        finally:
            image.put_i32(WORLD + 0x1DD0, GAME_DATE)

    monkeypatch.setattr(target_debt, "read_permission", offset_only_candidate_permission)
    report, context, creation, _fixture = _make_capture(
        fixture_profile, image=image, bindings=bindings, refs=refs, data=data)
    _assert_valid(report, context, creation)
    target = _target(report)
    field = target["fields"][target_debt.FIELD]
    assert field["status"] == "unknown"
    assert field["reason"] == "TARGET_DEBT_CAPTURE_CONTEXT_DATE_MISMATCH"
    assert "value" not in field
    assert target["fields"]["F03.income"]["status"] == "known"
    assert target["fields"]["F03.debt"]["status"] == "known"


def test_saved_capture_rejects_target_debt_permission_trace_tampering(fixture_profile):
    report, context, creation, _fixture = _make_capture(fixture_profile)
    saved_report = json.loads(json.dumps(report, ensure_ascii=False))
    saved_context = json.loads(json.dumps(context, ensure_ascii=False))
    assert capture.validate_capture(saved_report, saved_context, creation, "ENG")

    field = _target(saved_report)["fields"][target_debt.FIELD]
    assert field["status"] == "known"
    trace = field["raw_inputs"]["permission"]["raw_inputs"]["ordered_read_trace"]
    date_read = next(row for row in trace if row["label"] == "world.date_i32")
    date_read["raw_hex"] = ("00" * date_read["size"])
    assert not capture.validate_capture(saved_report, saved_context, creation, "ENG")


def test_income_option_block_does_not_block_observer_lent_loan_records(fixture_profile):
    image, bindings, refs, data = _make_image(fixture_profile, income_option_blocked=True)
    target_pointer = refs["target_pointer"]
    observer_ref = refs["observer_fullref"]
    physical_ref = refs["physical_fullref"]
    graph = _put_loans(image, target_pointer, [physical_ref, observer_ref],
                       [None, (2500, 90000, GAME_DATE + 80)])
    data.update(graph)
    report, context, creation, fixture = _make_capture(
        fixture_profile, image=image, bindings=bindings, refs=refs, data=data)
    _assert_valid(report, context, creation)
    target = _target(report)
    pages = target["fields"][capture.VISIBILITY_FIELD]["value"]
    assert pages[permission.INCOME_PAGE]["admitted"] is False
    assert pages[permission.INCOME_PAGE]["mode"] == "denied"
    assert pages[permission.LOANS_PAGE]["admitted"] is True
    assert target["fields"]["F03.income"]["status"] == "unknown"
    assert target["fields"]["F03.debt"]["status"] == "known"
    assert target["fields"][observer_reparations.FIELD]["status"] == "known"
    assert target["fields"][observer_subsidies.FIELD]["status"] == "known"
    records = target["fields"]["F03.debt"]["value"]["loans_to_observer"]["records"]
    assert len(records) == 1 and records[0]["principal"]["raw"] == 90000
    labels = _labels(report)
    assert "economy.income_option_index17" in labels
    assert not any(label.startswith("income.previous_month_i32_categories") for label in labels)
    assert "foreign_loans.financials[0]" not in labels
    assert "foreign_loans.financials[1]" in labels


def test_country_view_denial_stops_all_financial_permission_and_value_reads(fixture_profile):
    report, context, creation, _fixture = _make_capture(
        fixture_profile, country_view_admitted=False)
    assert capture.validate_capture(report, context, creation, "ENG")
    target = _target(report)
    assert report["observation"]["stable"] is True
    assert all(target["fields"][field]["status"] == "invisible" for field in capture.FIELDS)
    labels = _labels(report)
    assert not any(label.startswith(("economy.", "income.", "foreign_loans.")) for label in labels)


def test_inactive_country_target_is_denied_without_income_or_loan_amount_reads(fixture_profile):
    report, context, creation, _fixture = _make_capture(fixture_profile, target_active=False)
    _assert_valid(report, context, creation)
    target = _target(report)
    permissions = target["fields"][capture.VISIBILITY_FIELD]["raw_inputs"]["permissions"]
    for page in permission.PAGES:
        assert permissions[page]["status"] == "known"
        assert permissions[page]["admitted"] is False
        assert permissions[page]["reason"] == "TARGET_NOT_LEDGER_CANDIDATE"
    assert target["fields"]["F03.income"]["status"] == "unknown"
    assert target["fields"]["F03.debt"]["status"] == "unknown"
    labels = _labels(report)
    assert not any(label.startswith("income.previous_month") or label.startswith("foreign_loans.financials")
                   for label in labels)


def test_human_fra_role_rejects_finance_reads(fixture_profile):
    report, _context, _creation, _fixture = _make_capture(fixture_profile, human_fra=True)
    target = _target(report)
    assert report["observation"]["stable"] is False
    assert all(target["admission_by_pass"][phase]["observer_nonplayer_role"]["verified"] is False
               for phase in ("pass1", "pass2"))
    assert not any(label.startswith(("economy.", "income.", "foreign_loans."))
                   for label in _labels(report))


def test_role_change_between_passes_withdraws_fields_and_does_not_read_second_pass_finance(
        fixture_profile):
    image, bindings, refs, data = _make_image(fixture_profile)
    controller_address = (refs["controller_types_pointer"]
                          + bindings["FRA"]["slot"] * 4)

    def change_role(memory, _address, _size, label, count):
        if label == "foreign_tech.role.observer_controller" and count == 2:
            memory.put_i32(controller_address, 1)

    image.on_read = change_role
    report, _context, _creation, _fixture = _make_capture(
        fixture_profile, image=image, bindings=bindings, refs=refs, data=data)
    backend = report["observation"]["backend"]
    assert backend["consistency"]["status"] == "changed"
    target = _target(report)
    assert target["admission_by_pass"]["pass1"]["observer_nonplayer_role"]["verified"] is True
    assert target["admission_by_pass"]["pass2"]["observer_nonplayer_role"]["verified"] is False
    assert all(target["fields"][field]["status"] == "unknown" for field in capture.FIELDS)
    labels = _labels(report)
    assert labels.count("income.previous_month_i32_categories_0_18") == 1
    assert labels.count("foreign_loans.financials[0]") == 1


def test_income_cache_change_withdraws_income_family_but_preserves_loan_field(fixture_profile):
    image, bindings, refs, data = _make_image(fixture_profile)

    def change_income(memory, _address, _size, label, count):
        if label == "income.previous_month_i32_categories_0_18" and count == 2:
            address = refs["target_pointer"] + income.COUNTRY_INCOME_CACHE_OFFSET
            values = list(data["income_values"])
            values[0] += 1
            memory.put(address, _pack_i32(values))

    image.on_read = change_income
    report, context, creation, _fixture = _make_capture(
        fixture_profile, image=image, bindings=bindings, refs=refs, data=data)
    _assert_valid(report, context, creation)
    target = _target(report)
    for field in ("F03.income", "F03.reparations", "F03.subsidies"):
        assert target["fields"][field]["status"] == "unknown"
        assert target["field_consistency"][field]["status"] == "changed"
    assert target["fields"][observer_reparations.FIELD]["status"] == "known"
    assert target["field_consistency"][observer_reparations.FIELD]["status"] == "stable"
    assert target["fields"][observer_subsidies.FIELD]["status"] == "known"
    assert target["field_consistency"][observer_subsidies.FIELD]["status"] == "stable"
    assert target["fields"]["F03.debt"]["status"] == "known"
    assert target["field_consistency"]["F03.debt"]["status"] == "stable"
    assert target["fields"][capture.VISIBILITY_FIELD]["status"] == "known"


@pytest.mark.parametrize("present, expected", [(True, "known"), (False, "absent")])
def test_observer_reparations_child_captures_only_fra_target_pair(fixture_profile,
                                                                  present, expected):
    report, context, creation, _fixture = _make_capture(
        fixture_profile, reparations_present=present)
    _assert_valid(report, context, creation)
    target = _target(report)
    field = target["fields"][observer_reparations.FIELD]
    assert field["status"] == "known"
    assert field["complete"] is False and field["partial"] is True
    assert field["value"]["status"] == expected
    assert field["raw_inputs"]["state"]["complete_country_contracts"] is False
    if expected == "absent":
        assert field["value"]["scope"] == "explicit_observer_target_pair_only"


def test_observer_reparations_leaf_unknown_is_local_to_its_private_field(fixture_profile):
    image, bindings, refs, data = _make_image(fixture_profile)
    image.put(reparations_fixture.TREATY + 8,
              (reparations_leaf.RELATION_MARKER + 1).to_bytes(4, "little"))
    report, context, creation, _fixture = _make_capture(
        fixture_profile, image=image, bindings=bindings, refs=refs, data=data)
    _assert_valid(report, context, creation)
    target = _target(report)
    assert target["fields"][observer_reparations.FIELD]["status"] == "unknown"
    assert target["fields"]["F03.income"]["status"] == "known"
    assert target["fields"]["F03.reparations"]["status"] == "known"


def test_observer_reparations_change_between_passes_retracts_only_child(fixture_profile):
    image, bindings, refs, data = _make_image(fixture_profile)

    def change_pair(memory, _address, _size, label, count):
        if label == "contract.relation_object" and count == 2:
            memory.put_i32(reparations_fixture.TREATY
                           + reparations_leaf.RELATION_END_DATE_OFFSET,
                           reparations_fixture.END_DATE + 1)

    image.on_read = change_pair
    report, context, creation, _fixture = _make_capture(
        fixture_profile, image=image, bindings=bindings, refs=refs, data=data)
    _assert_valid(report, context, creation)
    target = _target(report)
    assert target["field_consistency"][observer_reparations.FIELD]["status"] == "changed"
    assert target["fields"][observer_reparations.FIELD]["status"] == "unknown"
    assert target["fields"]["F03.income"]["status"] == "known"
    assert target["field_consistency"]["F03.income"]["status"] == "stable"


def test_observer_reparations_unstable_private_permission_date_skips_leaf(fixture_profile):
    image, bindings, refs, data = _make_image(fixture_profile)

    def change_permission_date(memory, _address, _size, label, _count):
        if label == "foreign_tech.date":
            memory.put_i32(WORLD + 0x1DD0, GAME_DATE)
        elif label == "world.date_i32":
            memory.put_i32(WORLD + 0x1DD0, GAME_DATE + 1)
        elif label == "world.fresh_date_i32":
            memory.put_i32(WORLD + 0x1DD0, GAME_DATE + 2)

    image.on_read = change_permission_date
    report, context, creation, _fixture = _make_capture(
        fixture_profile, image=image, bindings=bindings, refs=refs, data=data)
    _assert_valid(report, context, creation)
    target = _target(report)
    assert target["fields"][observer_reparations.FIELD]["status"] == "unknown"
    assert target["fields"]["F03.income"]["status"] == "known"
    assert not any(label.startswith("pair.") or label == "contract.relation_object"
                   for label in _labels(report))


def test_observer_reparations_context_date_mismatch_retracts_only_child(fixture_profile):
    image, bindings, refs, data = _make_image(fixture_profile)

    def offset_permission_date(memory, _address, _size, label, _count):
        if label == "foreign_tech.date":
            memory.put_i32(WORLD + 0x1DD0, GAME_DATE)
        elif label in {"world.date_i32", "world.fresh_date_i32"}:
            memory.put_i32(WORLD + 0x1DD0, GAME_DATE + 1)

    image.on_read = offset_permission_date
    report, context, creation, _fixture = _make_capture(
        fixture_profile, image=image, bindings=bindings, refs=refs, data=data)
    _assert_valid(report, context, creation)
    observation = report["observation"]
    target = _target(report)
    assert observation["context_before"]["game_date"] == GAME_DATE
    assert observation["context_after"]["game_date"] == GAME_DATE
    assert observation["stable"] is True
    child = target["fields"][observer_reparations.FIELD]
    assert child["status"] == "unknown"
    assert child["reason"] == "OBSERVER_REPARATIONS_CAPTURE_CONTEXT_DATE_MISMATCH"
    assert target["fields"]["F03.income"]["status"] == "known"
    assert any(label == "contract.relation_object" for label in _labels(report))


@pytest.mark.parametrize("present", [True, False])
def test_subsidy_pair_is_strictly_replayed_with_its_independent_permission(fixture_profile, present):
    report, context, creation, _fixture = _make_capture(fixture_profile, subsidies_present=present)
    _assert_valid(report, context, creation)
    target = _target(report)
    field = target["fields"][capture.SUBSIDIES_FIELD]
    assert field["status"] == "known"
    assert field["basis"] == observer_subsidies.BASIS
    assert field["value"]["present"] is present
    assert field["raw_inputs"]["state"]["complete_country_contracts"] is False
    assert observer_subsidies.validate_permission(field["raw_inputs"]["permission"])
    assert target["field_consistency"][capture.SUBSIDIES_FIELD]["status"] == "stable"
    if present:
        value = field["value"]
        assert value["payer"]["tag"] == "FRA" and value["recipient"]["tag"] == "ENG"
        assert value["monthly_nominal_amount"]["raw"] == 1250
        assert value["monthly_nominal_amount"]["value"] == 1.25
        assert value["duration_years"]["raw"] == 3
        assert value["displayed_end_date"]["raw"] == GAME_DATE - 12 * 24 + 3 * 8760
        assert value["active_payment_obligation"]["status"] == "unknown"


def test_subsidy_amount_drift_withdraws_only_its_private_child(fixture_profile):
    image, bindings, refs, data = _make_image(fixture_profile)
    subsidy_reads = 0

    def change_subsidy(memory, address, _size, label, _count):
        nonlocal subsidy_reads
        if address == SUBSIDY_OBJECT and label == "contract.relation_object":
            subsidy_reads += 1
            if subsidy_reads == 2:
                memory.put_i32(SUBSIDY_OBJECT + 0x40, 1251)

    image.on_read = change_subsidy
    report, context, creation, _fixture = _make_capture(
        fixture_profile, image=image, bindings=bindings, refs=refs, data=data)
    _assert_valid(report, context, creation)
    target = _target(report)
    assert target["fields"][capture.SUBSIDIES_FIELD]["status"] == "unknown"
    assert target["field_consistency"][capture.SUBSIDIES_FIELD]["status"] == "changed"
    for field in ("F03.income", "F03.subsidies", "F03.debt", capture.REPARATIONS_FIELD):
        assert target["fields"][field]["status"] == "known"


def test_subsidy_permission_date_mismatch_withdraws_subsidy_child_independently(
        fixture_profile, monkeypatch):
    image, bindings, refs, data = _make_image(fixture_profile)
    original_permission = observer_subsidies.read_permission

    def offset_only_subsidy_permission(reader, base, observer, target):
        image.put_i32(WORLD + 0x1DD0, GAME_DATE + 1)
        try:
            return original_permission(reader, base, observer, target)
        finally:
            image.put_i32(WORLD + 0x1DD0, GAME_DATE)

    monkeypatch.setattr(observer_subsidies, "read_permission", offset_only_subsidy_permission)
    report, context, creation, _fixture = _make_capture(
        fixture_profile, image=image, bindings=bindings, refs=refs, data=data)
    _assert_valid(report, context, creation)
    target = _target(report)
    child = target["fields"][capture.SUBSIDIES_FIELD]
    assert child["status"] == "unknown"
    assert child["reason"] == "OBSERVER_SUBSIDIES_CAPTURE_CONTEXT_DATE_MISMATCH"
    assert "value" not in child
    assert target["fields"][capture.REPARATIONS_FIELD]["status"] == "known"
    assert target["fields"]["F03.subsidies"]["status"] == "known"


def test_shared_target_fullref_change_withdraws_all_finance_fields(fixture_profile):
    image, bindings, refs, data = _make_image(fixture_profile)
    target_ref_address = refs["target_pointer"] + 0x20
    changed_ref = tech_fixture._fullref("ENG", bindings["ENG"]["slot"], 0x4501)

    def change_generation(memory, _address, _size, label, count):
        if label == f"country_reference.slot[{bindings['ENG']['slot']}].fullref" and count == 2:
            memory.put_u64(target_ref_address, changed_ref)

    image.on_read = change_generation
    report, _context, _creation, _fixture = _make_capture(
        fixture_profile, image=image, bindings=bindings, refs=refs, data=data)
    backend = report["observation"]["backend"]
    assert backend["consistency"]["status"] == "changed"
    assert "country_scan" in backend["consistency"]["shared_mismatch_paths"]
    target = _target(report)
    assert all(target["fields"][field]["status"] == "unknown" for field in capture.FIELDS)
    assert report["observation"]["stable"] is False


def test_trace_identity_profile_access_and_cleanup_tampering_are_rejected(fixture_profile):
    report, context, creation, _fixture = _make_capture(fixture_profile)
    assert capture.validate_capture(report, context, creation, "ENG")

    variants = []
    bad = deepcopy(report)
    bad["profile_sha256"] = "0" * 64
    variants.append((bad, deepcopy(context), creation, "ENG"))
    bad = deepcopy(report)
    bad["schema"] = "information.foreign_economy_capture.v1"
    variants.append((bad, deepcopy(context), creation, "ENG"))
    bad = deepcopy(report)
    bad["profile_sha256"] = "c2b5b9421e9d6ebfc7a8d258812d435e11827223c041aa1b95597b311e73f80c"
    variants.append((bad, deepcopy(context), creation, "ENG"))
    bad = deepcopy(report)
    bad["request"]["session_id"] = "other-session"
    variants.append((bad, deepcopy(context), creation, "ENG"))
    bad_context = deepcopy(context)
    bad_context["game_date"] += 1
    variants.append((deepcopy(report), bad_context, creation, "ENG"))
    bad = deepcopy(report)
    bad["cleanup"]["closed"] = False
    variants.append((bad, deepcopy(context), creation, "ENG"))
    bad = deepcopy(report)
    bad["access"]["writes"] = True
    variants.append((bad, deepcopy(context), creation, "ENG"))
    bad = deepcopy(report)
    bad["raw_reads"][0]["raw_hex"] = "00" * bad["raw_reads"][0]["size"]
    variants.append((bad, deepcopy(context), creation, "ENG"))
    bad = deepcopy(report)
    bad["raw_reads"][0], bad["raw_reads"][1] = bad["raw_reads"][1], bad["raw_reads"][0]
    variants.append((bad, deepcopy(context), creation, "ENG"))
    variants.append((deepcopy(report), deepcopy(context), creation + 1, "ENG"))
    variants.append((deepcopy(report), deepcopy(context), creation, "POR"))

    assert all(not capture.validate_capture(candidate, candidate_context, candidate_creation, country)
               for candidate, candidate_context, candidate_creation, country in variants)


def test_saved_json_roundtrip_keeps_strict_raw_trace_validation(fixture_profile):
    report, context, creation, _fixture = _make_capture(fixture_profile)
    saved_report = json.loads(json.dumps(report, ensure_ascii=False))
    saved_context = json.loads(json.dumps(context, ensure_ascii=False))
    assert capture.validate_capture(saved_report, saved_context, creation, "ENG")

