"""Synthetic public F03 adapter tests; captures are not native observations."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from bridge.information import foreign_economy as source_module
from bridge.information import foreign_economy_projection as projection
from bridge.information import foreign_economy_visibility_memory as permission_memory
from bridge.information import foreign_income_memory as income_memory
from bridge.information import foreign_loans_memory as loans_memory
from bridge.information import bilateral_reparations_memory as reparations_leaf
from bridge.information import observer_reparations_memory as reparations_memory
from bridge.information import bilateral_subsidies_memory as subsidies_leaf
from bridge.information import observer_subsidies_memory as subsidies_memory
from bridge.information import foreign_debt_disclosure as debt_disclosure
from bridge.information import target_debt_principal_memory as principal_memory
from bridge.information import foreign_technology_capture
from bridge.information import InformationService
from bridge.information.catalog import list_topics
from bridge.information.composite import CompositeSource
from bridge.information.model import InformationError
from bridge.information.tools import InformationTools
from bridge.tests import test_foreign_income_memory as income_fixture
from bridge.tests import test_foreign_debt_principal_memory as principal_leaf_fixture
from bridge.tests import test_target_debt_principal_memory as principal_permission_fixture
from bridge.tests import test_foreign_debt_disclosure as disclosure_fixture


TARGET = "ENG"
OBSERVER = "FRA"
BASE = income_fixture.BASE
CREATION = 123456789012345678
SESSION = "foreign-economy-public-test"
GAME_DATE = 56_564_448
PROFILE_SHA = "a" * 64
LOAN_NODE = 0x6700000000
LOAN_RECORD = 0x6710000000
REPARATIONS_OBSERVER_ROWS = 0x6800000000
REPARATIONS_TARGET_ROWS = 0x6810000000
REPARATIONS_OBSERVER_ITEMS = 0x6820000000
REPARATIONS_TARGET_ITEMS = 0x6830000000
REPARATIONS_TREATY = 0x6840000000
SUBSIDIES_OBSERVER_ROWS = 0x6850000000
SUBSIDIES_TARGET_ROWS = 0x6860000000
SUBSIDIES_OBSERVER_ITEMS = 0x6870000000
SUBSIDIES_TARGET_ITEMS = 0x6880000000
SUBSIDY_OBJECT = 0x6890000000


class BaseSource:
    event_types = ()

    def __init__(self, directory: Path):
        self.current = {
            "status": "ready", "mode": "live", "complete": True,
            "observer": OBSERVER, "session_id": SESSION,
            "game_version": "1.37.4", "game_sha256": foreign_technology_capture.EXE_SHA256,
            "game_date": GAME_DATE,
        }
        self.session = SimpleNamespace(directory=directory, creation_filetime=CREATION,
            session_id=SESSION,
            record={"session_id": SESSION, "creation_filetime": CREATION,
                    "game_sha256": foreign_technology_capture.EXE_SHA256,
                    "controlled_countries": [OBSERVER]})

    def context(self):
        return deepcopy(self.current)

    def catalog(self):
        return list_topics()

    def read(self, query, context):
        return {"fields": {field: {"status": "unsupported", "reason": "PRIMARY_UNUSED"}
                           for field in query["fields"]},
                "complete": False,
                "source": {"name": "fixture_primary", "mode": "live"}}


class FakeCaptureModule:
    SCHEMA = "information.foreign_economy_capture.v4"
    PROFILE_SHA256 = PROFILE_SHA
    EXE_SHA256 = foreign_technology_capture.EXE_SHA256

    def __init__(self, report):
        self.report = report
        self.validator_calls = 0
        self.validator_result = True

    def validate_capture(self, report, context, creation, country):
        self.validator_calls += 1
        request = report.get("request") if isinstance(report, dict) else None
        return (self.validator_result is True and isinstance(request, dict)
                and report.get("schema") == self.SCHEMA
                and report.get("profile_sha256") == self.PROFILE_SHA256
                and request.get("country") == country and request.get("observer") == OBSERVER
                and request.get("session_id") == context.get("session_id")
                and request.get("creation_filetime") == creation
                and context.get("observer") == OBSERVER)


class FakeDisclosureTools:
    """One-call read-only native inspection stub using the real helper validator."""

    def __init__(self, session, response, *, before_return=None):
        self.session = session
        self.response = deepcopy(response)
        self.before_return = before_return
        self.calls = []

    def inspect_diplomatic_action(self, *args):
        self.calls.append(args)
        result = deepcopy(self.response)
        if self.before_return is not None:
            self.before_return()
        return result


def _attach_disclosure_tools(base, *, date=GAME_DATE, native_visibility=True,
                             visibility_status=None, before_return=None,
                             recipient=TARGET):
    response = disclosure_fixture.inspection_shape(
        recipient=recipient, date_raw=date, native_visibility=native_visibility,
        visibility_status=visibility_status)
    tools = FakeDisclosureTools(base.session, response, before_return=before_return)
    base.diplomacy_tools = tools
    return tools


def query(fields):
    return {"topic": "F03", "object": {"type": "country", "country": TARGET},
            "fields": list(fields), "parameters": {}}


def _public_amount(raw, *, scale=1000, unit="ducats", period="month", reference="previous_month"):
    return {"value": raw / scale, "raw": raw, "unit": unit, "scale": scale,
            "period": period, "reference": reference}


def _admission(admitted=True, *, verified=True):
    return {"status": "known", "admitted": admitted,
            "observer_nonplayer_role": {"verified": verified,
                "basis": "synthetic_capture_test_only"}}


def _loan_bytes(image, observer, target, *, rows=None):
    rows = rows or []
    target_pointer = int(target["country_pointer"], 16)
    observer_ref = int(observer["fullref"], 16)
    if not rows:
        image.put_u64(target_pointer + 0xDE8, 0)
        return
    image.put_u64(target_pointer + 0xDE8, LOAN_NODE)
    for index, row in enumerate(rows):
        node = LOAN_NODE + index * 0x100
        record = LOAN_RECORD + index * 0x100
        next_node = LOAN_NODE + (index + 1) * 0x100 if index + 1 < len(rows) else 0
        image.put_u64(node, record)
        image.put_u64(node + 8, 0)
        image.put_u64(node + 16, next_node)
        image.put_u64(record + 0x20, observer_ref)
        financials = b"".join(int(value).to_bytes(4, "little", signed=True)
                               for value in (row["interest"], row["principal"], row["due"]))
        image.put(record + 0x28, financials)


def _reparations_bytes(image, observer, target, *, present=True, payer="FRA"):
    observer_pointer = int(observer["country_pointer"], 16)
    target_pointer = int(target["country_pointer"], 16)
    observer_ref = int(observer["fullref"], 16)
    target_ref = int(target["fullref"], 16)
    observer_owner = observer_pointer + 0x14F8
    target_owner = target_pointer + 0x14F8

    image.put_i32(income_fixture.WORLD + reparations_memory.WORLD_DATE_OFFSET, GAME_DATE)
    image.put_u64(observer_pointer + reparations_leaf.COUNTRY_RELATION_ROWS_OFFSET,
                  REPARATIONS_OBSERVER_ROWS)
    image.put_u64(target_pointer + reparations_leaf.COUNTRY_RELATION_ROWS_OFFSET,
                  REPARATIONS_TARGET_ROWS)
    observer_row = REPARATIONS_OBSERVER_ROWS + target["slot"] * reparations_leaf.PAIR_ROW_STRIDE
    target_row = REPARATIONS_TARGET_ROWS + observer["slot"] * reparations_leaf.PAIR_ROW_STRIDE
    for address, owner, self_ref, other_ref in (
            (observer_row, observer_owner, observer_ref, target_ref),
            (target_row, target_owner, target_ref, observer_ref)):
        image.put_u64(address + reparations_leaf.PAIR_OWNER_OFFSET, owner)
        image.put_u64(address + reparations_leaf.PAIR_SELF_FULLREF_OFFSET, self_ref)
        image.put_u64(address + reparations_leaf.PAIR_OTHER_FULLREF_OFFSET, other_ref)

    def put_vector(owner, data_pointer, slot, treaty_pointer):
        vector = owner + reparations_leaf.OWNER_PAIR_VECTOR_OFFSET
        if present:
            item = (slot.to_bytes(4, "little", signed=True) + b"\x00" * 4
                    + treaty_pointer.to_bytes(8, "little"))
            image.put_u64(vector + reparations_leaf.VECTOR_DATA_OFFSET, data_pointer)
            image.put_i32(vector + reparations_leaf.VECTOR_CAPACITY_OFFSET, 1)
            image.put_i32(vector + reparations_leaf.VECTOR_COUNT_OFFSET, 1)
            image.put(data_pointer, item)
        else:
            image.put_u64(vector + reparations_leaf.VECTOR_DATA_OFFSET, 0)
            image.put_i32(vector + reparations_leaf.VECTOR_CAPACITY_OFFSET, 0)
            image.put_i32(vector + reparations_leaf.VECTOR_COUNT_OFFSET, 0)

    put_vector(observer_owner, REPARATIONS_OBSERVER_ITEMS, target["slot"], REPARATIONS_TREATY)
    put_vector(target_owner, REPARATIONS_TARGET_ITEMS, observer["slot"], REPARATIONS_TREATY)
    if present:
        claimant = target_ref if payer == "FRA" else observer_ref
        payer_ref = observer_ref if payer == "FRA" else target_ref
        image.put_u64(REPARATIONS_TREATY, BASE + reparations_leaf.RELATION_TABLE_RVA)
        image.put_u32(REPARATIONS_TREATY + 8, reparations_leaf.RELATION_MARKER)
        image.put_u32(REPARATIONS_TREATY + 12, 0)
        image.put_u64(REPARATIONS_TREATY + reparations_leaf.RELATION_PAYER_OFFSET,
                      payer_ref)
        image.put_u64(REPARATIONS_TREATY + reparations_leaf.RELATION_CLAIMANT_OFFSET,
                      claimant)
        image.put_i32(REPARATIONS_TREATY + reparations_leaf.RELATION_START_DATE_OFFSET,
                      GAME_DATE - 24 * 100)
        image.put_i32(REPARATIONS_TREATY + reparations_leaf.RELATION_END_DATE_OFFSET,
                      GAME_DATE + 24 * 100)


def _subsidies_bytes(image, observer, target, *, present=True, payer="FRA",
                     amount=-2_500, start=GAME_DATE - 24 * 100, duration=2):
    observer_pointer = int(observer["country_pointer"], 16)
    target_pointer = int(target["country_pointer"], 16)
    observer_ref = int(observer["fullref"], 16)
    target_ref = int(target["fullref"], 16)
    observer_owner = observer_pointer + 0x14F8
    target_owner = target_pointer + 0x14F8

    image.put_i32(income_fixture.WORLD + subsidies_memory.WORLD_DATE_OFFSET, GAME_DATE)
    image.put_u64(observer_pointer + subsidies_leaf.SUBSIDY_RELATION_ROWS_OFFSET,
                  SUBSIDIES_OBSERVER_ROWS)
    image.put_u64(target_pointer + subsidies_leaf.SUBSIDY_RELATION_ROWS_OFFSET,
                  SUBSIDIES_TARGET_ROWS)
    # Literal native row stride keeps this fixture independent of the leaf constant.
    observer_row = SUBSIDIES_OBSERVER_ROWS + target["slot"] * 0x48
    target_row = SUBSIDIES_TARGET_ROWS + observer["slot"] * 0x48
    for address, owner, self_ref, other_ref in (
            (observer_row, observer_owner, observer_ref, target_ref),
            (target_row, target_owner, target_ref, observer_ref)):
        image.put_u64(address, owner)
        image.put_u64(address + 8, self_ref)
        image.put_u64(address + 0x10, other_ref)

    def put_vector(owner, data_pointer, slot, relation_pointer):
        vector = owner + subsidies_leaf.OWNER_SUBSIDY_VECTOR_OFFSET
        if present:
            image.put_u64(vector + subsidies_leaf.VECTOR_DATA_OFFSET, data_pointer)
            image.put_i32(vector + subsidies_leaf.VECTOR_CAPACITY_OFFSET, 1)
            image.put_i32(vector + subsidies_leaf.VECTOR_COUNT_OFFSET, 1)
            entry = (slot.to_bytes(4, "little", signed=True) + b"\x00" * 4
                     + relation_pointer.to_bytes(8, "little"))
            image.put(data_pointer, entry)
        else:
            image.put_u64(vector + subsidies_leaf.VECTOR_DATA_OFFSET, 0)
            image.put_i32(vector + subsidies_leaf.VECTOR_CAPACITY_OFFSET, 0)
            image.put_i32(vector + subsidies_leaf.VECTOR_COUNT_OFFSET, 0)

    put_vector(observer_owner, SUBSIDIES_OBSERVER_ITEMS, target["slot"], SUBSIDY_OBJECT)
    put_vector(target_owner, SUBSIDIES_TARGET_ITEMS, observer["slot"], SUBSIDY_OBJECT)
    if present:
        payer_ref = observer_ref if payer == "FRA" else target_ref
        recipient_ref = target_ref if payer == "FRA" else observer_ref
        image.put(SUBSIDY_OBJECT, bytes(subsidies_leaf.SUBSIDY_OBJECT_SIZE))
        image.put_u64(SUBSIDY_OBJECT, BASE + subsidies_leaf.SUBSIDY_VTABLE_RVA)
        image.put_u32(SUBSIDY_OBJECT + 8, subsidies_leaf.SUBSIDY_MARKER)
        image.put_u64(SUBSIDY_OBJECT + subsidies_leaf.SUBSIDY_PAYER_OFFSET, payer_ref)
        image.put_u64(SUBSIDY_OBJECT + subsidies_leaf.SUBSIDY_RECIPIENT_OFFSET,
                      recipient_ref)
        image.put_i32(SUBSIDY_OBJECT + subsidies_leaf.SUBSIDY_START_DATE_OFFSET, start)
        image.put_u32(SUBSIDY_OBJECT + subsidies_leaf.SUBSIDY_FLAG_0X28_OFFSET, 0)
        image.put_i32(SUBSIDY_OBJECT + subsidies_leaf.SUBSIDY_MONTHLY_AMOUNT_OFFSET, amount)
        image.put_i32(SUBSIDY_OBJECT + subsidies_leaf.SUBSIDY_DURATION_YEARS_OFFSET, duration)


def _target_debt_candidate_field(*, date=GAME_DATE):
    """Build a real candidate permission and loan-state record from test fixtures."""
    image, observer, target = principal_permission_fixture._environment(date=date)
    leaf_image, _leaf_observer, _leaf_target, _nodes, _records = principal_leaf_fixture._environment(
        (100, -25))
    image.data.update(leaf_image.data)
    permission = principal_permission_fixture._permission(image, observer, target)
    return principal_memory.read_fields(
        image, principal_permission_fixture.BASE, observer, target,
        principal_memory.FIELD, permission=permission)[principal_memory.FIELD]


def make_capture(*, values=None, option=0, candidate=True, view_admitted=True,
                 role_verified=True, page_override=None, income_consistency="stable",
                 loan_rows=None, debt_override=None, income_override=None,
                 target_debt_candidate=False, target_debt_override=None,
                 reparations_present=True, reparations_payer="FRA",
                 reparations_consistency="stable", reparations_override=None,
                 subsidies_present=True, subsidies_payer="FRA", subsidies_amount=-2_500,
                 subsidies_start=GAME_DATE - 24 * 100, subsidies_duration=2,
                 subsidies_consistency="stable", subsidies_override=None):
    values = list(values if values is not None else [100 + i for i in range(19)])
    image, observer, target, _cache, _values = income_fixture._make_image(
        values, option=option, target_in_candidates=candidate)
    _loan_bytes(image, observer, target, rows=loan_rows)
    _reparations_bytes(image, observer, target, present=reparations_present,
                       payer=reparations_payer)
    _subsidies_bytes(image, observer, target, present=subsidies_present,
                     payer=subsidies_payer, amount=subsidies_amount,
                     start=subsidies_start, duration=subsidies_duration)
    income_permission = permission_memory.read_permission(
        image, BASE, observer, target, page=permission_memory.INCOME_PAGE)
    loan_permission = permission_memory.read_permission(
        image, BASE, observer, target, page=permission_memory.LOANS_PAGE)
    private_fields = income_memory.read_fields(
        image, BASE, target, income_memory.FIELDS, permission=income_permission)
    private_fields.update(loans_memory.read_fields(
        image, BASE, observer, target, loans_memory.FIELDS, permission=loan_permission))
    reparations_permission = reparations_memory.read_permission(
        image, BASE, observer, target)
    private_fields.update(reparations_memory.read_fields(
        image, BASE, observer, target, reparations_memory.FIELDS,
        permission=reparations_permission))
    subsidies_permission = subsidies_memory.read_permission(
        image, BASE, observer, target)
    private_fields.update(subsidies_memory.read_fields(
        image, BASE, observer, target, subsidies_memory.FIELDS,
        permission=subsidies_permission))
    if income_override is not None:
        private_fields[income_memory.FIELD_INCOME] = deepcopy(income_override)
    if debt_override is not None:
        private_fields[loans_memory.FIELD] = deepcopy(debt_override)
    if target_debt_candidate:
        private_fields[principal_memory.FIELD] = _target_debt_candidate_field()
    if target_debt_override is not None:
        private_fields[principal_memory.FIELD] = deepcopy(target_debt_override)
    if reparations_override is not None:
        private_fields[reparations_memory.FIELD] = deepcopy(reparations_override)
    if subsidies_override is not None:
        private_fields[subsidies_memory.FIELD] = deepcopy(subsidies_override)
    permissions = {permission_memory.INCOME_PAGE: income_permission,
                   permission_memory.LOANS_PAGE: loan_permission}
    visibility_value = {
        page: ({"status": "known", "admitted": record["admitted"], "mode": record["mode"]}
               if record.get("status") == "known" else
               {"status": "unknown", "reason": record.get("reason", "PERMISSION_UNKNOWN")})
        for page, record in permissions.items()
    }
    if page_override:
        visibility_value.update(deepcopy(page_override))
    private_fields[projection.PRIVATE_VISIBILITY_FIELD] = {
        "status": "known", "value": visibility_value,
        "partial": True, "complete": False,
        "basis": permission_memory.BASIS,
        "raw_inputs": {"permissions": deepcopy(permissions), "synthetic": True},
    }
    _, context, _creation, _fixture = income_fixture_context()
    gate = _admission(view_admitted, verified=role_verified)
    item = {
        "tag": TARGET,
        "admission_by_pass": {"pass1": deepcopy(gate), "pass2": deepcopy(gate)},
        "fields": private_fields,
        "field_consistency": {field: {"status": "stable"} for field in private_fields},
    }
    item["field_consistency"][income_memory.FIELD_INCOME] = {"status": income_consistency}
    item["field_consistency"][reparations_memory.FIELD] = {"status": reparations_consistency}
    item["field_consistency"][subsidies_memory.FIELD] = {"status": subsidies_consistency}
    identity = {
        "binding_verified": True, "installation_session_id": SESSION,
        "installation_creation_filetime": CREATION,
        "process_creation_filetime": CREATION,
        "process_path_sha256": foreign_technology_capture.EXE_SHA256,
    }
    report = {
        "schema": FakeCaptureModule.SCHEMA, "status": "observed", "completed": True,
        "profile_sha256": PROFILE_SHA,
        "request": {"country": TARGET, "observer": OBSERVER,
                    "session_id": SESSION, "creation_filetime": CREATION},
        "identity": deepcopy(identity), "identity_after": deepcopy(identity),
        "observation": {"backend": {"targets": [item]}},
    }
    return report, context


def income_fixture_context():
    context = {
        "status": "ready", "mode": "live", "complete": True,
        "observer": OBSERVER, "session_id": SESSION,
        "game_version": "1.37.4", "game_sha256": foreign_technology_capture.EXE_SHA256,
        "game_date": GAME_DATE,
    }
    return None, context, CREATION, None


def setup(tmp_path, monkeypatch, **kwargs):
    report, context = make_capture(**kwargs)
    base = BaseSource(tmp_path)
    base.current = deepcopy(context)
    module = FakeCaptureModule(report)
    calls = []

    def capture(installation, *, country, observer):
        calls.append((Path(installation), country, observer))
        return deepcopy(module.report)

    original_import = source_module.import_module
    monkeypatch.setattr(source_module, "import_module", lambda name, package:
        module if name == ".foreign_economy_capture_v7" else original_import(name, package))
    source = source_module.NativeForeignEconomySource(base, capture=capture)
    return source, base, module, calls


def _public_read(source, base, fields):
    return source.read(query(fields), base.context())


def _assert_visibility(field, *, page, country_view, page_permission):
    visibility = field["visibility"]
    assert set(visibility) == {"country_view", "page", "page_permission", "basis"}
    assert visibility["page"] == page
    assert visibility["country_view"] == country_view
    assert visibility["page_permission"] == page_permission
    assert visibility["basis"] == permission_memory.BASIS
    assert "raw_inputs" not in repr(visibility)
    assert "mode" not in visibility and "country_pointer" not in repr(visibility)


def _assert_debt_visibility(field, *, country_view, total_permission, page_permission):
    visibility = field["visibility"]
    assert visibility["country_view"] == country_view
    if country_view == {"status": "known", "admitted": False}:
        assert visibility == {"country_view": country_view}
        return
    assert set(visibility) == {"country_view", "components", "basis"}
    assert visibility["basis"] == "native_debt_independent_scopes"
    assert visibility["components"] == {
        "total_debt": {"scope": debt_disclosure.SCOPE,
                        "permission": total_permission},
        "loans_to_observer": {"page": permission_memory.LOANS_PAGE,
                              "permission": page_permission},
    }
    assert "raw_inputs" not in repr(visibility)
    assert "country_pointer" not in repr(visibility) and "fullref" not in repr(visibility)


def _assert_reparations_visibility(field, *, country_view, received_page_permission):
    visibility = field["visibility"]
    assert set(visibility) == {
        "country_view", "received_previous_month", "observer_involved_contracts"}
    assert visibility["country_view"] == country_view
    assert visibility["received_previous_month"] == {
        "page": permission_memory.INCOME_PAGE,
        "page_permission": received_page_permission,
        "basis": permission_memory.BASIS,
    }
    assert visibility["observer_involved_contracts"] == {
        "scope": reparations_memory.SCOPE,
        "basis": reparations_memory.BASIS,
        "actual_UI_observed": False,
    }
    assert "raw_inputs" not in repr(visibility)
    assert "country_pointer" not in repr(visibility) and "mode" not in repr(visibility)


def _assert_subsidies_visibility(field, *, country_view, received_page_permission):
    visibility = field["visibility"]
    assert set(visibility) == {
        "country_view", "received_previous_month", "observer_involved_contracts"}
    assert visibility["country_view"] == country_view
    assert visibility["received_previous_month"] == {
        "page": permission_memory.INCOME_PAGE,
        "page_permission": received_page_permission,
        "basis": permission_memory.BASIS,
    }
    assert visibility["observer_involved_contracts"] == {
        "scope": subsidies_memory.SCOPE,
        "basis": subsidies_memory.BASIS,
        "actual_UI_observed": False,
    }
    assert "raw_inputs" not in repr(visibility)
    assert "country_pointer" not in repr(visibility) and "mode" not in repr(visibility)


def test_catalog_has_exactly_five_public_fields_and_never_exposes_private_visibility(tmp_path):
    source = source_module.NativeForeignEconomySource(BaseSource(tmp_path))
    topic = source.catalog()[0]
    assert topic["topic_id"] == "F03" and topic["status"] == "available"
    assert set(topic["fields"]) == set(projection.PUBLIC_FIELDS)
    assert "economy_visibility" not in topic["fields"]
    assert topic["fields"]["bankruptcy_risk"]["coverage"] == "planned"
    assert all(topic["fields"][name]["coverage"] == "partial"
               for name in set(projection.PUBLIC_FIELDS) - {"bankruptcy_risk"})
    assert topic["parameters"]["additionalProperties"] is False
    assert topic["fields"]["income"]["runtime_validation"] == "pinned_native_cache_and_page_conditions"
    debt_catalog = topic["fields"]["debt"]
    assert debt_catalog["basis"] == "native_debt_independent_scopes"
    assert debt_catalog["runtime_validation"] == "pinned_native_principal_and_independent_disclosure_scopes"
    assert debt_catalog["components"]["total_debt"]["scope"] == debt_disclosure.SCOPE
    assert debt_catalog["components"]["loans_to_observer"]["scope"] == "observer_lent_loans_only"
    reparations = topic["fields"]["reparations"]
    assert reparations["unit"] == "reparations_information"
    assert reparations["period"] == "mixed"
    assert reparations["basis"] == "native_reparations_independent_scopes"
    assert reparations["runtime_validation"] == "pinned_native_cache_and_independent_pair_scope"
    assert any(path.endswith("observer_involved_contracts") for path in reparations["paths"])
    subsidies = topic["fields"]["subsidies"]
    assert subsidies["unit"] == "subsidies_information"
    assert subsidies["scale"] == 1 and subsidies["raw"] is False
    assert subsidies["period"] == "mixed"
    assert subsidies["basis"] == "native_subsidies_independent_scopes"
    assert subsidies["runtime_validation"] == "pinned_native_cache_and_independent_pair_scope"
    assert any(path.endswith("observer_involved_contracts") for path in subsidies["paths"])
    assert subsidies["components"]["received_previous_month"] == {
        "unit": "ducats", "scale": 1000, "period": "month",
        "reference": "previous_month", "scope": "income_page"}
    assert subsidies["components"]["observer_involved_contracts"]["scope"] == subsidies_memory.SCOPE
    assert "不保证等于可见类别之和" in topic["fields"]["income"]["description"]


def test_income_projection_preserves_native_total_and_exact_visible_categories(tmp_path, monkeypatch):
    source, base, module, calls = setup(tmp_path, monkeypatch)
    result = _public_read(source, base, ["income"])
    field = result["fields"]["income"]
    expected_total = sum((100 + index) for index in income_memory.NATIVE_TOTAL_INDICES)
    assert field["status"] == "known" and field["partial"] is True and field["complete"] is False
    assert field["unit"] == "ducats" and field["scale"] == 1000
    assert field["value"]["native_ledger_total"] == _public_amount(expected_total)
    cats = field["value"]["visible_categories"]
    assert [(item["index"], item["localization_key"]) for item in cats] == list(income_memory.VISIBLE_CATEGORY_KEYS)
    assert cats[0]["amount"] == _public_amount(100)
    assert 14 not in [item["index"] for item in cats]
    assert field["value"]["total_includes_additional_native_terms"] is True
    _assert_visibility(field, page=permission_memory.INCOME_PAGE,
        country_view={"status": "known", "admitted": True},
        page_permission={"status": "known", "admitted": True})
    assert set(result["source"]["provenance"]["capture_report_sha256_by_source"]) == {"economy"}
    digest = result["source"]["provenance"]["capture_report_sha256_by_source"]["economy"]
    assert result["source"]["provenance"]["capture_report_sha256"] == digest
    assert result["source"]["projection_version"] == 4
    assert calls == [(tmp_path / "installation.json", TARGET, OBSERVER)]
    assert module.validator_calls == 1
    rendered = repr(result)
    for private in ("raw_inputs", "country_pointer", "table_entry_address", "cache_slice", "raw_reads"):
        assert private not in rendered


def test_debt_only_exports_observer_lent_subset_and_recomputes_safe_date(tmp_path, monkeypatch):
    source, base, _module, _calls = setup(tmp_path, monkeypatch,
        loan_rows=[{"interest": 250, "principal": 5000, "due": GAME_DATE}])
    field = _public_read(source, base, ["debt"])["fields"]["debt"]
    assert field["status"] == "known" and field["unit"] == "debt_information"
    assert field["basis"] == "native_debt_independent_scopes"
    assert field["scale"] == 1 and field["period"] == "current"
    value = field["value"]
    assert value["total_debt"] == {
        "status": "unknown", "reason": "DEBT_PRINCIPAL_FIELD_NOT_STABLE",
        "partial": True, "complete": False}
    subset = value["loans_to_observer"]
    assert subset["coverage"] == "observer_lent_loans_only" and subset["complete_country_debt"] is False
    assert subset["record_count"] == 1 and subset["observed_principal_sum"]["value"] == 5000
    record = subset["records"][0]
    assert (record["lender"], record["borrower"]) == (OBSERVER, TARGET)
    assert record["principal"] == {"value": 5000, "raw": 5000, "unit": "ducats", "scale": 1}
    assert record["interest"] == {"value": 0.25, "raw": 250, "unit": "percent", "scale": 1000}
    assert record["due"]["raw"] == GAME_DATE
    assert record["due"]["calendar"]["date"] == "1457.2.17"
    _assert_debt_visibility(field, country_view={"status": "known", "admitted": True},
        total_permission={"status": "unknown", "reason": "DEBT_PRINCIPAL_FIELD_NOT_STABLE"},
        page_permission={"status": "known", "admitted": True})
    assert "calendar_source" not in repr(field)
    assert "raw_inputs" not in repr(field) and "0x" not in repr(field)


def test_zero_observer_lent_records_does_not_claim_zero_total_country_debt(tmp_path, monkeypatch):
    source, base, _module, _calls = setup(tmp_path, monkeypatch)
    debt = _public_read(source, base, ["debt"])["fields"]["debt"]
    value = debt["value"]
    assert value["total_debt"]["status"] == "unknown"
    assert value["loans_to_observer"]["record_count"] == 0
    assert value["loans_to_observer"]["observed_principal_sum"]["value"] == 0
    assert value["loans_to_observer"]["complete_country_debt"] is False
    _assert_debt_visibility(debt, country_view={"status": "known", "admitted": True},
        total_permission={"status": "unknown", "reason": "DEBT_PRINCIPAL_FIELD_NOT_STABLE"},
        page_permission={"status": "known", "admitted": True})


def test_candidate_with_fresh_real_disclosure_helper_publishes_native_principal_total(
        tmp_path, monkeypatch):
    source, base, module, capture_calls = setup(
        tmp_path, monkeypatch, target_debt_candidate=True,
        loan_rows=[{"interest": 250, "principal": 50, "due": GAME_DATE}])
    tools = _attach_disclosure_tools(base)

    result = _public_read(source, base, ["debt"])
    debt = result["fields"]["debt"]
    total = debt["value"]["total_debt"]
    provenance = result["source"]["provenance"]

    assert debt["status"] == "known"
    assert total["status"] == "known"
    assert total["raw"] == 75_000 and total["value"] == 75.0
    assert total["basis"] == "native_diplomatic_loan_principal_sum"
    assert total["includes_remaining_interest"] is False
    assert debt["value"]["loans_to_observer"]["record_count"] == 1
    assert tools.calls == [("trade_favors_for_gold", OBSERVER, TARGET, "initiate", {})]
    assert provenance["read_only"] is True
    assert provenance["native_function_invoked"] is True
    assert provenance["native_debt_visibility_queries"] == 1
    assert provenance["debt_disclosure"]["status"] == "known"
    assert provenance["debt_disclosure"]["admitted"] is True
    assert module.validator_calls == 1 and len(capture_calls) == 1
    assert result["source"]["projection_version"] == 4
    assert "raw_inputs" not in repr(result)
    assert "country_pointer" not in repr(result)


@pytest.mark.parametrize("mismatch", ["session", "date"])
def test_disclosure_identity_or_date_mismatch_retracts_total_but_preserves_lent_subset(
        tmp_path, monkeypatch, mismatch):
    source, base, _module, _capture_calls = setup(
        tmp_path, monkeypatch, target_debt_candidate=True,
        loan_rows=[{"interest": 100, "principal": 50, "due": GAME_DATE}])
    main_tools = _attach_disclosure_tools(base)
    real_read_scope = debt_disclosure.read_scope
    foreign_tools = None

    def mismatched_read_scope(base_source, context, target):
        nonlocal foreign_tools
        if mismatch == "date":
            altered_context = deepcopy(context)
            altered_context["game_date"] += 24
            main_tools.response["session"]["date_raw"] = altered_context["game_date"]
            scope = real_read_scope(base_source, altered_context, target)
            main_tools.response["session"]["date_raw"] = GAME_DATE
        else:
            foreign_base = BaseSource(tmp_path / "other-session")
            foreign_base.current = deepcopy(context)
            foreign_base.current["session_id"] = SESSION + "-other"
            foreign_base.session.session_id = SESSION + "-other"
            foreign_base.session.creation_filetime = CREATION + 1
            foreign_base.session.record["session_id"] = SESSION + "-other"
            foreign_base.session.record["creation_filetime"] = CREATION + 1
            foreign_tools = _attach_disclosure_tools(foreign_base)
            scope = real_read_scope(foreign_base, foreign_base.context(), target)
        assert debt_disclosure.validate_scope(scope)
        return scope

    monkeypatch.setattr(debt_disclosure, "read_scope", mismatched_read_scope)
    result = _public_read(source, base, ["debt"])
    debt = result["fields"]["debt"]
    provenance = result["source"]["provenance"]

    assert debt["status"] == "known"
    assert debt["value"]["total_debt"]["status"] == "unknown"
    assert debt["value"]["loans_to_observer"]["status"] == "known"
    assert debt["value"]["loans_to_observer"]["record_count"] == 1
    assert provenance["debt_disclosure"]["status"] == "unknown"
    assert provenance["debt_disclosure"]["reason"] == "DEBT_DISCLOSURE_BINDING_INVALID"
    assert "admitted" not in provenance["debt_disclosure"]
    assert "proof_sha256" not in provenance["debt_disclosure"]
    assert provenance["read_only"] is True
    assert provenance["native_function_invoked"] is True
    assert provenance["native_debt_visibility_queries"] == 1
    assert len(main_tools.calls) == (1 if mismatch == "date" else 0)
    if mismatch == "session":
        assert foreign_tools is not None and len(foreign_tools.calls) == 1
    assert "raw_inputs" not in repr(result)


def test_unknown_disclosure_scope_does_not_erase_observer_lent_subset(tmp_path, monkeypatch):
    source, base, _module, _capture_calls = setup(
        tmp_path, monkeypatch, target_debt_candidate=True,
        loan_rows=[{"interest": 100, "principal": 50, "due": GAME_DATE}])
    tools = _attach_disclosure_tools(
        base, native_visibility=True, visibility_status="hidden")

    result = _public_read(source, base, ["debt"])
    debt = result["fields"]["debt"]
    provenance = result["source"]["provenance"]

    assert debt["status"] == "known"
    assert debt["value"]["total_debt"]["status"] == "unknown"
    assert debt["value"]["loans_to_observer"]["status"] == "known"
    assert debt["value"]["loans_to_observer"]["record_count"] == 1
    assert provenance["debt_disclosure"]["status"] == "unknown"
    assert provenance["debt_disclosure"]["reason"] == "VISIBILITY_PROJECTION_MISMATCH"
    assert provenance["debt_disclosure"]["admitted"] is None
    assert len(provenance["debt_disclosure"]["proof_sha256"]) == 64
    assert provenance["native_function_invoked"] is True
    assert provenance["native_debt_visibility_queries"] == 1
    assert tools.calls == [("trade_favors_for_gold", OBSERVER, TARGET, "initiate", {})]
    assert "raw_inputs" not in repr(result)


def test_candidate_unknown_income_and_risk_paths_never_call_disclosure_helper(
        tmp_path, monkeypatch):
    unknown_candidate = _target_debt_candidate_field()
    unknown_candidate["status"] = "unknown"
    unknown_candidate.pop("value", None)
    unknown_candidate["reason"] = "TARGET_DEBT_PRINCIPAL_STATE_UNKNOWN"
    source, base, module, capture_calls = setup(
        tmp_path, monkeypatch, target_debt_candidate=True,
        target_debt_override=unknown_candidate,
        loan_rows=[{"interest": 100, "principal": 50, "due": GAME_DATE}])
    tools = _attach_disclosure_tools(base)

    debt = _public_read(source, base, ["debt"])
    assert debt["fields"]["debt"]["value"]["total_debt"]["status"] == "unknown"
    assert tools.calls == []
    debt_provenance = debt["source"]["provenance"]
    assert debt_provenance["read_only"] is True
    assert debt_provenance["native_function_invoked"] is False
    assert debt_provenance["native_debt_visibility_queries"] == 0

    income = _public_read(source, base, ["income"])
    assert income["fields"]["income"]["status"] == "known"
    assert tools.calls == []
    income_provenance = income["source"]["provenance"]
    assert income_provenance["native_function_invoked"] is False
    assert income_provenance["native_debt_visibility_queries"] == 0

    risk = _public_read(source, base, ["bankruptcy_risk"])
    assert risk["fields"]["bankruptcy_risk"]["status"] == "unknown"
    assert tools.calls == []
    risk_provenance = risk["source"]["provenance"]
    assert risk_provenance["read_only"] is True
    assert risk_provenance["native_function_invoked"] is False
    assert risk_provenance["native_debt_visibility_queries"] == 0
    assert len(capture_calls) == 2 and module.validator_calls == 2


def test_post_disclosure_context_drift_withdraws_entire_capture(tmp_path, monkeypatch):
    source, base, module, capture_calls = setup(
        tmp_path, monkeypatch, target_debt_candidate=True,
        loan_rows=[{"interest": 100, "principal": 50, "due": GAME_DATE}])
    tools = _attach_disclosure_tools(
        base, before_return=lambda: base.current.update(game_date=GAME_DATE + 24))

    result = _public_read(source, base, ["debt"])
    debt = result["fields"]["debt"]
    provenance = result["source"]["provenance"]

    assert debt["status"] == "unknown" and "value" not in debt
    assert provenance["capture_failures"]["economy"] == "FOREIGN_ECONOMY_CONTEXT_CHANGED_DURING_DISCLOSURE"
    assert provenance["read_only"] is True
    assert provenance["native_function_invoked"] is True
    assert provenance["native_debt_visibility_queries"] == 1
    assert tools.calls == [("trade_favors_for_gold", OBSERVER, TARGET, "initiate", {})]
    assert len(capture_calls) == 1 and module.validator_calls == 1


def test_income_and_loan_page_denials_are_independent_and_never_fallback(tmp_path, monkeypatch):
    source, base, _module, calls = setup(tmp_path, monkeypatch, option=1)
    result = _public_read(source, base, ["income", "debt"])
    assert result["fields"]["income"]["status"] == "invisible"
    assert "value" not in result["fields"]["income"]
    assert result["fields"]["debt"]["status"] == "known"
    _assert_visibility(result["fields"]["income"], page=permission_memory.INCOME_PAGE,
        country_view={"status": "known", "admitted": True},
        page_permission={"status": "known", "admitted": False})
    _assert_debt_visibility(result["fields"]["debt"],
        country_view={"status": "known", "admitted": True},
        total_permission={"status": "unknown", "reason": "DEBT_PRINCIPAL_FIELD_NOT_STABLE"},
        page_permission={"status": "known", "admitted": True})
    assert len(calls) == 1


def test_unknown_income_page_permission_does_not_poison_independent_debt_page(tmp_path, monkeypatch):
    unknown_income = {permission_memory.INCOME_PAGE: {"status": "unknown", "reason": "GATE_UNREADABLE"}}
    source, base, _module, _calls = setup(tmp_path, monkeypatch, page_override=unknown_income)
    fields = _public_read(source, base, ["income", "debt"])["fields"]
    assert fields["income"]["status"] == "unknown" and "value" not in fields["income"]
    assert fields["debt"]["status"] == "known"
    _assert_visibility(fields["income"], page=permission_memory.INCOME_PAGE,
        country_view={"status": "known", "admitted": True},
        page_permission={"status": "unknown", "reason": "GATE_UNREADABLE"})


def test_country_view_denial_or_unverified_nonplayer_role_never_exports_economy_values(tmp_path, monkeypatch):
    source, base, _module, _calls = setup(tmp_path, monkeypatch, view_admitted=False)
    result = _public_read(source, base, ["income", "debt"])
    assert all(result["fields"][name]["status"] == "invisible" for name in ("income", "debt"))
    assert all("value" not in result["fields"][name] for name in ("income", "debt"))
    _assert_visibility(result["fields"]["income"], page=permission_memory.INCOME_PAGE,
        country_view={"status": "known", "admitted": False},
        page_permission={"status": "unknown",
                         "reason": "NOT_EVALUATED_COUNTRY_VIEW_NOT_ADMITTED"})
    assert result["fields"]["debt"]["visibility"] == {
        "country_view": {"status": "known", "admitted": False}}
    source2, base2, _module2, _calls2 = setup(tmp_path, monkeypatch, role_verified=False)
    fields = _public_read(source2, base2, ["income", "debt"])["fields"]
    assert all(fields[name]["status"] == "unknown" for name in ("income", "debt"))
    assert all("value" not in fields[name] for name in ("income", "debt"))
    unknown_view = {"status": "unknown", "reason": "COUNTRY_VIEW_ADMISSION_UNKNOWN"}
    _assert_visibility(fields["income"], page=permission_memory.INCOME_PAGE,
        country_view=unknown_view,
        page_permission={"status": "unknown",
                         "reason": "NOT_EVALUATED_COUNTRY_VIEW_NOT_ADMITTED"})
    _assert_debt_visibility(fields["debt"], country_view=unknown_view,
        total_permission={"status": "unknown", "reason": "COUNTRY_VIEW_ADMISSION_UNKNOWN"},
        page_permission={"status": "unknown", "reason": "COUNTRY_VIEW_ADMISSION_UNKNOWN"})


def test_all_implemented_fields_have_only_sanitized_visibility_metadata(tmp_path, monkeypatch):
    source, base, _module, _calls = setup(tmp_path, monkeypatch)
    fields = _public_read(source, base, ["income", "debt", "reparations", "subsidies"])["fields"]
    _assert_visibility(fields["income"], page=permission_memory.INCOME_PAGE,
        country_view={"status": "known", "admitted": True},
        page_permission={"status": "known", "admitted": True})
    _assert_debt_visibility(fields["debt"],
        country_view={"status": "known", "admitted": True},
        total_permission={"status": "unknown", "reason": "DEBT_PRINCIPAL_FIELD_NOT_STABLE"},
        page_permission={"status": "known", "admitted": True})
    _assert_reparations_visibility(fields["reparations"],
        country_view={"status": "known", "admitted": True},
        received_page_permission={"status": "known", "admitted": True})
    _assert_subsidies_visibility(fields["subsidies"],
        country_view={"status": "known", "admitted": True},
        received_page_permission={"status": "known", "admitted": True})
    assert "economy_visibility" not in repr(fields)
    assert "raw_inputs" not in repr(fields) and "country_pointer" not in repr(fields)
    assert "fullref" not in repr(fields) and "0x" not in repr(fields)
    risk = _public_read(source, base, ["bankruptcy_risk"])["fields"]["bankruptcy_risk"]
    assert "visibility" not in risk


def test_nonstable_private_field_is_local_and_received_amounts_do_not_infer_obligations(tmp_path, monkeypatch):
    source, base, module, _calls = setup(tmp_path, monkeypatch, income_consistency="changed")
    fields = _public_read(source, base, ["income", "reparations", "subsidies"])["fields"]
    assert fields["income"]["status"] == "unknown"
    assert fields["reparations"]["status"] == "known"
    assert fields["subsidies"]["status"] == "known"
    assert fields["reparations"]["value"]["received_previous_month"]["value"] == 0.108
    for name in ("reparations", "subsidies"):
        value = fields[name]["value"]
        assert value["current_payment_obligations"]["status"] == "unknown"
        assert value["active_contracts"]["status"] == "unknown"
        assert "value" not in value["current_payment_obligations"]
        assert "value" not in value["active_contracts"]
    assert fields["reparations"]["value"]["observer_involved_contracts"]["status"] == "known"
    assert module.validator_calls == 1


def test_reparations_received_denial_does_not_block_own_pair_relation(tmp_path, monkeypatch):
    source, base, _module, _calls = setup(tmp_path, monkeypatch, option=1)
    field = _public_read(source, base, ["reparations"])["fields"]["reparations"]
    assert field["status"] == "known"
    value = field["value"]
    assert value["received_previous_month"]["status"] == "invisible"
    assert value["observer_involved_contracts"]["status"] == "known"
    assert value["observer_involved_contracts"]["contracts"][0]["payer"] == {"tag": "FRA"}
    assert value["current_payment_obligations"]["status"] == "unknown"
    assert value["active_contracts"]["status"] == "unknown"
    assert field["visibility"]["received_previous_month"]["page_permission"] == {
        "status": "known", "admitted": False}


def test_unknown_income_page_permission_does_not_block_own_pair_relation(tmp_path, monkeypatch):
    page_unknown = {permission_memory.INCOME_PAGE:
        {"status": "unknown", "reason": "GATE_UNREADABLE"}}
    source, base, _module, _calls = setup(tmp_path, monkeypatch,
                                          page_override=page_unknown)
    field = _public_read(source, base, ["reparations"])["fields"]["reparations"]
    assert field["status"] == "known"
    assert field["value"]["received_previous_month"]["status"] == "unknown"
    assert field["value"]["received_previous_month"]["reason"] == "GATE_UNREADABLE"
    assert field["value"]["observer_involved_contracts"]["status"] == "known"
    assert field["visibility"]["received_previous_month"]["page_permission"] == {
        "status": "unknown", "reason": "GATE_UNREADABLE"}


def test_received_amount_survives_unstable_contract_child_and_absent_pair_is_scoped(
        tmp_path, monkeypatch):
    source, base, _module, _calls = setup(tmp_path, monkeypatch,
                                           reparations_consistency="changed")
    field = _public_read(source, base, ["reparations"])["fields"]["reparations"]
    assert field["status"] == "known"
    assert field["unit"] == "reparations_information"
    assert field["scale"] == 1 and field["period"] == "mixed"
    assert field["basis"] == "native_reparations_independent_scopes"
    assert field["value"]["received_previous_month"]["status"] == "known"
    assert field["value"]["observer_involved_contracts"]["status"] == "unknown"

    absent_source, absent_base, _module2, _calls2 = setup(
        tmp_path, monkeypatch, reparations_present=False)
    absent = _public_read(absent_source, absent_base, ["reparations"])["fields"]["reparations"]
    child = absent["value"]["observer_involved_contracts"]
    assert absent["status"] == "known"
    assert child["status"] == "known"
    assert child["scope"] == "observer_target_pair_only"
    assert child["complete_country_contracts"] is False
    assert child["pair_relation"] == {"status": "known", "present": False}
    assert child["contracts"] == []
    assert "target_has_no_contracts" not in repr(child)


def test_subsidies_received_denial_and_unknown_page_do_not_block_own_pair(tmp_path, monkeypatch):
    denied_source, denied_base, _module, _calls = setup(tmp_path, monkeypatch, option=1)
    denied = _public_read(denied_source, denied_base, ["subsidies"])["fields"]["subsidies"]
    assert denied["status"] == "known"
    assert denied["unit"] == "subsidies_information"
    assert denied["scale"] == 1 and denied["period"] == "mixed"
    assert denied["basis"] == "native_subsidies_independent_scopes"
    assert denied["value"]["received_previous_month"]["status"] == "invisible"
    child = denied["value"]["observer_involved_contracts"]
    assert child["status"] == "known" and child["pair_relation"] == {
        "status": "known", "present": True}
    assert child["contracts"][0]["payer"] == {"tag": "FRA"}
    assert child["contracts"][0]["observer_role"] == "payer"
    assert denied["value"]["current_payment_obligations"]["status"] == "unknown"
    assert denied["value"]["active_contracts"]["status"] == "unknown"
    assert denied["visibility"]["received_previous_month"]["page_permission"] == {
        "status": "known", "admitted": False}

    page_unknown = {permission_memory.INCOME_PAGE:
        {"status": "unknown", "reason": "GATE_UNREADABLE"}}
    unknown_source, unknown_base, _module2, _calls2 = setup(
        tmp_path, monkeypatch, page_override=page_unknown)
    unknown = _public_read(unknown_source, unknown_base, ["subsidies"])["fields"]["subsidies"]
    assert unknown["status"] == "known"
    assert unknown["value"]["received_previous_month"]["status"] == "unknown"
    assert unknown["value"]["received_previous_month"]["reason"] == "GATE_UNREADABLE"
    assert unknown["value"]["observer_involved_contracts"]["status"] == "known"


def test_subsidy_relation_direction_signed_terms_and_dates_are_sanitized(tmp_path, monkeypatch):
    source, base, _module, _calls = setup(tmp_path, monkeypatch,
        subsidies_payer="ENG", subsidies_amount=-3_250, subsidies_duration=-2)
    field = _public_read(source, base, ["subsidies"])["fields"]["subsidies"]
    assert field["status"] == "known"
    child = field["value"]["observer_involved_contracts"]
    assert child["status"] == "known"
    assert child["scope"] == "observer_target_pair_only"
    assert child["complete_country_contracts"] is False
    contract = child["contracts"][0]
    assert contract["payer"] == {"tag": "ENG"}
    assert contract["recipient"] == {"tag": "FRA"}
    assert contract["observer_role"] == "recipient"
    assert contract["monthly_nominal_amount"] == {
        "raw": -3_250, "value": -3.25, "unit": "ducats", "scale": 1000,
        "period": "month"}
    assert contract["duration_years"] == {
        "raw": -2, "value": -2, "unit": "years", "scale": 1}
    assert contract["start_date"]["calendar"]["status"] == "derived"
    assert contract["displayed_end_date"]["calendar"]["status"] == "derived"
    assert contract["displayed_end_date"]["derivation"] == {
        "status": "derived",
        "formula": "signed32_wrap(start + signed32_wrap(years * 8760))",
        "ticks_per_subsidy_year": 8760,
    }
    assert contract["active_payment_obligation"] == {
        "status": "unknown", "reason": "SUBSIDY_PAYMENT_OBLIGATION_SEMANTICS_NOT_CAPTURED"}
    assert contract["relation_flag"] == {
        "status": "unknown", "reason": "SUBSIDY_RELATION_FLAG_SEMANTICS_UNCLOSED"}
    assert contract["term_legality"] == {
        "status": "unknown", "reason": "SUBSIDY_AMOUNT_OR_DURATION_LEGALITY_NOT_CAPTURED"}
    assert "active" not in contract["displayed_end_date"]["derivation"]["status"]
    rendered = repr(field)
    for private in ("fullref", "raw_inputs", "country_pointer", "0x", "static_evidence_id",
                    "ordered_read_trace", "source_path"):
        assert private not in rendered


def test_absent_subsidy_relation_is_known_only_for_observer_target_pair(tmp_path, monkeypatch):
    source, base, _module, _calls = setup(
        tmp_path, monkeypatch, subsidies_present=False)
    field = _public_read(source, base, ["subsidies"])["fields"]["subsidies"]
    child = field["value"]["observer_involved_contracts"]
    assert field["status"] == "known"
    assert child["status"] == "known"
    assert child["scope"] == "observer_target_pair_only"
    assert child["complete_country_contracts"] is False
    assert child["pair_relation"] == {"status": "known", "present": False}
    assert child["contracts"] == []
    assert "target_has_no_contracts" not in repr(child)
    assert "no_subsidies" not in repr(child)

    drift_source, drift_base, _module2, _calls2 = setup(
        tmp_path, monkeypatch, subsidies_consistency="changed")
    drift = _public_read(drift_source, drift_base, ["subsidies"])["fields"]["subsidies"]
    assert drift["status"] == "known"
    assert drift["value"]["received_previous_month"]["status"] == "known"
    assert drift["value"]["observer_involved_contracts"]["status"] == "unknown"


@pytest.mark.parametrize("mutation", ["payer", "amount_type", "end_date", "flag", "permission"])
def test_subsidy_contract_tampering_only_withdraws_pair_component(mutation):
    report, _context = make_capture()
    item = report["observation"]["backend"]["targets"][0]
    private = item["fields"][subsidies_memory.FIELD]
    if mutation == "permission":
        private["raw_inputs"]["permission"]["admitted"] = 1
    else:
        contracts = (private["value"], private["raw_inputs"]["state"]["contract"])
        for contract in contracts:
            if mutation == "payer":
                contract["payer"]["tag"] = "XXX"
            elif mutation == "amount_type":
                contract["monthly_nominal_amount"]["raw"] = True
            elif mutation == "end_date":
                contract["displayed_end_date"]["raw"] += 1
            else:
                contract["relation_flag_0x28"] = {"status": "known", "value": False}
    field = projection.project(item, TARGET, ["subsidies"])["subsidies"]
    assert field["status"] == "known"
    assert field["value"]["received_previous_month"]["status"] == "known"
    assert field["value"]["observer_involved_contracts"]["status"] == "unknown"
    assert "raw_inputs" not in repr(field)
    assert "country_pointer" not in repr(field) and "fullref" not in repr(field)


def test_subsidy_unknown_components_return_no_value_and_parent_gate_suppresses_both(
        tmp_path, monkeypatch):
    no_components, no_components_base, _module, _calls = setup(
        tmp_path, monkeypatch, option=1, subsidies_consistency="changed")
    unknown = _public_read(no_components, no_components_base, ["subsidies"])["fields"]["subsidies"]
    assert unknown["status"] == "unknown"
    assert unknown["reason"] == "NO_SUBSIDIES_COMPONENT_AVAILABLE"
    assert "value" not in unknown
    assert unknown["component_statuses"]["received_previous_month"]["status"] == "invisible"
    assert unknown["component_statuses"]["observer_involved_contracts"]["status"] == "unknown"

    denied_source, denied_base, _module2, _calls2 = setup(
        tmp_path, monkeypatch, view_admitted=False)
    denied = _public_read(denied_source, denied_base, ["subsidies"])["fields"]["subsidies"]
    assert denied["status"] == "invisible" and "value" not in denied
    assert "observer_involved_contracts" not in repr(denied)


def test_reparations_pair_direction_and_public_calendar_are_sanitized(tmp_path, monkeypatch):
    source, base, _module, _calls = setup(tmp_path, monkeypatch,
                                           reparations_payer="ENG")
    field = _public_read(source, base, ["reparations"])["fields"]["reparations"]
    assert field["status"] == "known"
    contract = field["value"]["observer_involved_contracts"]["contracts"][0]
    assert contract["payer"] == {"tag": "ENG"}
    assert contract["claimant"] == {"tag": "FRA"}
    assert contract["start_date"]["calendar"]["status"] == "derived"
    assert contract["end_date"]["calendar"]["status"] == "derived"
    assert type(contract["date_window_contains_observed_date"]) is bool
    rendered = repr(field)
    for private in ("raw_inputs", "fullref", "country_pointer", "0x", "calendar_source",
                    "raw_hex", "REPARATIONS_TREATY"):
        assert private not in rendered


def test_country_view_and_fra_ai_gate_suppress_both_reparations_components(tmp_path, monkeypatch):
    source, base, _module, _calls = setup(tmp_path, monkeypatch, view_admitted=False)
    denied = _public_read(source, base, ["reparations"])["fields"]["reparations"]
    assert denied["status"] == "invisible" and "value" not in denied
    assert "observer_involved_contracts" not in repr(denied)

    source2, base2, _module2, _calls2 = setup(tmp_path, monkeypatch, role_verified=False)
    unknown = _public_read(source2, base2, ["reparations"])["fields"]["reparations"]
    assert unknown["status"] == "unknown" and "value" not in unknown
    assert "observer_involved_contracts" not in repr(unknown)


def test_no_available_reparations_component_has_safe_unknown_without_value(tmp_path, monkeypatch):
    source, base, _module, _calls = setup(tmp_path, monkeypatch,
        option=1, reparations_consistency="changed")
    field = _public_read(source, base, ["reparations"])["fields"]["reparations"]
    assert field["status"] == "unknown"
    assert field["reason"] == "NO_REPARATIONS_COMPONENT_AVAILABLE"
    assert "value" not in field
    assert field["component_statuses"]["received_previous_month"]["status"] == "invisible"
    assert field["component_statuses"]["observer_involved_contracts"]["status"] == "unknown"


@pytest.mark.parametrize("mutation", [
    "basis", "unit", "scale_bool", "period", "payer", "date", "date_window_bool",
    "flag", "permission_bool", "permission_pair", "permission_row_owner",
])
def test_contract_component_tampering_is_local_and_never_exports_private_data(
        tmp_path, monkeypatch, mutation):
    source, base, module, _calls = setup(tmp_path, monkeypatch)
    item = module.report["observation"]["backend"]["targets"][0]
    record = item["fields"][reparations_memory.FIELD]
    if mutation == "basis":
        record["basis"] = "forged_basis"
    elif mutation == "unit":
        record["unit"] = "ducats"
    elif mutation == "scale_bool":
        record["scale"] = True
    elif mutation == "period":
        record["period"] = "previous_month"
    elif mutation in ("payer", "date", "date_window_bool", "flag"):
        contract = record["value"]
        if mutation == "payer":
            contract["payer"]["tag"] = "SCO"
        elif mutation == "date":
            contract["end_date"]["raw"] += 24
        elif mutation == "date_window_bool":
            contract["date_window_contains_observed_date"] = 1
        else:
            contract["relation_flag_0x28"] = {"status": "known", "value": 1}
        record["raw_inputs"]["state"]["contract"] = deepcopy(contract)
    elif mutation == "permission_bool":
        record["raw_inputs"]["permission"]["admitted"] = 1
    elif mutation == "permission_pair":
        record["raw_inputs"]["permission"]["target"]["tag"] = "SCO"
    else:
        record["raw_inputs"]["permission"]["raw_inputs"]["pair_row_bindings"][0]["owner"] = "0x70000000"

    field = _public_read(source, base, ["reparations"])["fields"]["reparations"]
    assert field["status"] == "known"
    assert field["value"]["received_previous_month"]["status"] == "known"
    assert field["value"]["observer_involved_contracts"]["status"] == "unknown"
    assert field["value"]["current_payment_obligations"]["status"] == "unknown"
    assert field["value"]["active_contracts"]["status"] == "unknown"
    rendered = repr(field)
    for private in ("raw_inputs", "fullref", "country_pointer", "0x", "calendar_source"):
        assert private not in rendered


def test_v1_capture_schema_is_rejected_without_retrying_capture(tmp_path, monkeypatch):
    source, base, module, calls = setup(tmp_path, monkeypatch)
    module.SCHEMA = "information.foreign_economy_capture.v1"
    field = _public_read(source, base, ["reparations"])["fields"]["reparations"]
    assert field["status"] == "unknown" and "value" not in field
    assert calls == [] and module.validator_calls == 0


def test_callers_cannot_inject_known_payment_obligations(tmp_path, monkeypatch):
    report, context = make_capture()
    item = report["observation"]["backend"]["targets"][0]
    item["fields"][income_memory.FIELD_REPARATIONS]["value"]["current_payment_obligations"] = {
        "status": "known", "value": 12345}
    base = BaseSource(tmp_path)
    base.current = context
    module = FakeCaptureModule(report)
    original_import = source_module.import_module
    monkeypatch.setattr(source_module, "import_module", lambda name, package:
        module if name == ".foreign_economy_capture_v7" else original_import(name, package))
    source = source_module.NativeForeignEconomySource(base,
        capture=lambda installation, *, country, observer: deepcopy(module.report))
    field = _public_read(source, base, ["reparations"])["fields"]["reparations"]
    assert field["status"] == "known"
    assert field["value"]["received_previous_month"]["status"] == "unknown"
    assert field["value"]["observer_involved_contracts"]["status"] == "known"


def test_planned_risk_only_does_not_import_or_capture_and_mixed_query_captures_once(tmp_path, monkeypatch):
    source, base, module, calls = setup(tmp_path, monkeypatch)
    def forbidden_import(name, package):
        raise AssertionError("risk-only query must not load a capture module")
    monkeypatch.setattr(source_module, "import_module", forbidden_import)
    risk = _public_read(source, base, ["bankruptcy_risk"])["fields"]["bankruptcy_risk"]
    assert risk == {"status": "unknown", "reason": projection._public_risk()["reason"],
                    "partial": True, "complete": False}
    assert calls == [] and module.validator_calls == 0
    monkeypatch.undo()
    source2, base2, module2, calls2 = setup(tmp_path, monkeypatch)
    result = _public_read(source2, base2, list(projection.PUBLIC_FIELDS))
    assert len(calls2) == 1 and module2.validator_calls == 1
    assert result["fields"]["bankruptcy_risk"]["status"] == "unknown"
    assert all(result["fields"][name]["status"] == "known"
               for name in ("income", "debt", "reparations", "subsidies"))


@pytest.mark.parametrize("mutation", ["bad_key", "insert_hidden_index", "changed_amount"])
def test_forged_income_dto_is_rejected_without_exporting_private_raws(tmp_path, monkeypatch, mutation):
    report, context = make_capture()
    record = report["observation"]["backend"]["targets"][0]["fields"][income_memory.FIELD_INCOME]
    if mutation == "bad_key":
        record["value"]["visible_categories"][0]["localization_key"] = "PRIVATE_POINTER_LABEL"
    elif mutation == "insert_hidden_index":
        record["value"]["visible_categories"][0]["index"] = 14
    else:
        record["value"]["visible_categories"][0]["amount"]["value"] += 1
    base = BaseSource(tmp_path); base.current = context
    module = FakeCaptureModule(report)
    original_import = source_module.import_module
    monkeypatch.setattr(source_module, "import_module", lambda name, package:
        module if name == ".foreign_economy_capture_v7" else original_import(name, package))
    source = source_module.NativeForeignEconomySource(base,
        capture=lambda installation, *, country, observer: deepcopy(module.report))
    field = _public_read(source, base, ["income"])["fields"]["income"]
    assert field["status"] == "unknown" and "value" not in field
    assert "raw_inputs" not in repr(field) and "PRIVATE_POINTER_LABEL" not in repr(field)


def test_debt_count_sum_and_total_are_validated_without_widening_scope(tmp_path, monkeypatch):
    report, context = make_capture(loan_rows=[{"interest": 100, "principal": 50, "due": GAME_DATE}])
    debt = report["observation"]["backend"]["targets"][0]["fields"][loans_memory.FIELD]
    debt["value"]["loans_to_observer"]["record_count"] = 2
    base = BaseSource(tmp_path); base.current = context
    module = FakeCaptureModule(report)
    original_import = source_module.import_module
    monkeypatch.setattr(source_module, "import_module", lambda name, package:
        module if name == ".foreign_economy_capture_v7" else original_import(name, package))
    source = source_module.NativeForeignEconomySource(base,
        capture=lambda installation, *, country, observer: deepcopy(module.report))
    field = _public_read(source, base, ["debt"])["fields"]["debt"]
    assert field["status"] == "unknown" and "value" not in field


@pytest.mark.parametrize("mode", ["stale_before", "change_during", "capture_exception", "validator_false", "wrong_profile"])
def test_context_capture_and_validator_failures_fail_closed(tmp_path, monkeypatch, mode):
    source, base, module, calls = setup(tmp_path, monkeypatch)
    passed_context = base.context()
    if mode == "stale_before":
        base.current["game_date"] += 1
        result = source.read(query(["income"]), passed_context)
        assert calls == []
    elif mode == "change_during":
        def mutate(installation, *, country, observer):
            calls.append((installation, country, observer))
            base.current["game_date"] += 1
            return deepcopy(module.report)
        source.capture = mutate
        result = _public_read(source, base, ["income"])
        assert module.validator_calls == 0
    elif mode == "capture_exception":
        def fail(*_args, **_kwargs):
            calls.append("attempted")
            raise OSError("synthetic")
        source.capture = fail
        result = _public_read(source, base, ["income"])
        assert module.validator_calls == 0 and calls == ["attempted"]
    else:
        if mode == "validator_false":
            module.validator_result = False
        else:
            module.report["profile_sha256"] = "b" * 64
        result = _public_read(source, base, ["income"])
    field = result["fields"]["income"]
    assert field["status"] == "unknown" and "value" not in field
    assert "raw_inputs" not in repr(field)


@pytest.mark.parametrize("obj,fields,parameters", [
    ({"type": "country", "country": "FRA"}, ["income"], {}),
    ({"type": "country", "country": "eng"}, ["income"], {}),
    ({"type": "country", "country": "ENG", "pointer": "0x1"}, ["income"], {}),
    ({"type": "country", "country": "ENG"}, ["private_visibility"], {}),
    ({"type": "country", "country": "ENG"}, ["income", "income"], {}),
    ({"type": "country", "country": "ENG"}, ["income"], {"page": "income_comparison"}),
])
def test_strict_query_scope_rejects_invalid_selector_before_capture(tmp_path, monkeypatch,
                                                                   obj, fields, parameters):
    source, base, _module, calls = setup(tmp_path, monkeypatch)
    bad = {"topic": "F03", "object": obj, "fields": fields, "parameters": parameters}
    with pytest.raises(InformationError):
        source.read(bad, base.context())
    assert calls == []


def test_capture_query_and_saved_report_share_public_projection(tmp_path, monkeypatch):
    source, base, _module, calls = setup(tmp_path, monkeypatch)
    composite = CompositeSource(base, [source])
    service = InformationService(composite, tmp_path / "information.sqlite3")
    tools = InformationTools(service)
    selected = query(["income", "debt", "bankruptcy_risk"])
    try:
        topic = next(item for item in composite.catalog() if item["topic_id"] == "F03")
        assert set(topic["fields"]) == set(projection.PUBLIC_FIELDS)
        direct = tools.call("information_query", {"view": "full", "request_id": "economy-query", "queries": [selected]})
        report = tools.call("information_manage_report", {"request_id": "economy-report",
            "operation": "create", "config": {"name": "foreign economy", "detail": "raw",
                                                  "queries": [selected]}})["report"]
        rendered = tools.call("information_query", {"view": "full", "request_id": "economy-render",
                                                       "report_id": report["id"]})
        assert direct["items"][0]["fields"] == rendered["items"][0]["fields"]
        assert direct["items"][0]["fields"]["bankruptcy_risk"]["status"] == "unknown"
        assert len(calls) == 2
    finally:
        service.close()
