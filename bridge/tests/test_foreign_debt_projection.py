"""Literal proof-replay tests for the independent foreign-debt projection."""
from __future__ import annotations

from copy import deepcopy

import pytest

from bridge.information import engine_dates
from bridge.information import foreign_debt_disclosure as disclosure
from bridge.information import foreign_debt_principal_memory as principal_leaf
from bridge.information import foreign_debt_projection as projection
from bridge.information import foreign_economy_projection as economy_projection
from bridge.information import foreign_economy_visibility_memory as visibility
from bridge.information import foreign_loans_memory as loans
from bridge.information import target_debt_principal_memory as principal_adapter
from bridge.tests import test_foreign_debt_disclosure as scope_fixture
from bridge.tests import test_target_debt_principal_memory as memory_fixture


TARGET = "ENG"
GAME_DATE = scope_fixture.GAME_DATE
NODE = 0x64000000
RECORD = 0x64001000
PRINCIPAL_WRAP_INPUT = 2_147_484
WRAPPED_SCALED_PRINCIPAL = -2_147_483_296


def _debt_subset_record(target: str = TARGET) -> dict:
    due_calendar = engine_dates.project_engine_date(GAME_DATE)
    return {
        "status": "known",
        "basis": loans.BASIS,
        "partial": True,
        "complete": False,
        "unit": "observed_loan_records",
        "scale": 1,
        "period": "current",
        "raw_inputs": {"fixture": "literal projected observer-lent subset"},
        "value": {
            "total_debt": {
                "status": "unknown",
                "reason": "TOTAL_FOREIGN_DEBT_NOT_ESTABLISHED",
            },
            "loans_to_observer": {
                "status": "known",
                "records": [{
                    "lender": "FRA",
                    "borrower": target,
                    "principal": {"status": "known", "raw": 50, "value": 50,
                                  "unit": "ducats", "scale": 1},
                    "interest": {"status": "known", "raw": 250, "value": 250,
                                 "unit": "percent", "scale": 1000},
                    "due": {
                        "status": "known",
                        "raw": GAME_DATE,
                        "raw_hex": GAME_DATE.to_bytes(4, "little", signed=True).hex(),
                        "unit": "eu4_hour_tick",
                        "scale": 1,
                        "calendar": {
                            "status": "derived",
                            "year_index": due_calendar["year_index"],
                            "month": due_calendar["month"],
                            "day": due_calendar["day"],
                            "date": due_calendar["date"],
                        },
                    },
                    "source_list_ordinal": 0,
                }],
                "record_count": 1,
                "coverage": "observer_lent_loans_only",
                "observed_principal_sum": {
                    "status": "known", "raw": 50, "value": 50,
                    "unit": "ducats", "scale": 1,
                },
                "complete_country_debt": False,
            },
        },
    }


def _scope_record(*, target: str = TARGET, game_date: int = GAME_DATE,
                  controlled_countries=None) -> dict:
    response = scope_fixture.inspection_shape(
        recipient=target, date_raw=game_date, native_visibility=True)
    _session, tools, source = scope_fixture.make_source(
        controlled_countries=controlled_countries, response=response)
    context = scope_fixture.valid_context()
    context["game_date"] = game_date
    result = disclosure.read_scope(source, context, target)
    assert disclosure.validate_scope(result) is True
    assert tools.calls in ([], [("trade_favors_for_gold", "FRA", target, "initiate", {})])
    return result


def _item(*, principal: int = PRINCIPAL_WRAP_INPUT,
          page_admitted: bool = True,
          include_principal_field: bool = True,
          include_subset_field: bool = True) -> tuple[dict, dict, dict]:
    image, observer, target = memory_fixture._environment()
    target_pointer = int(target["country_pointer"], 0)
    image.put_u64(target_pointer + 0xDE8, NODE)
    image.put_i32(target_pointer + 0xDF8, 1)
    node_header = (RECORD.to_bytes(8, "little") + bytes(8)
                   + bytes(8))
    image.put(NODE, node_header)
    # Literal native i32 principal at record+2c, independent of leaf constants.
    image.put(RECORD + 0x2C, principal.to_bytes(4, "little", signed=True))

    private_permission = principal_adapter.read_permission(
        image, memory_fixture.BASE, observer, target)
    assert private_permission["status"] == "known"
    assert private_permission["admitted"] is True
    private_record = principal_adapter.read_fields(
        image, memory_fixture.BASE, observer, target, principal_adapter.FIELD,
        permission=private_permission)[principal_adapter.FIELD]
    assert private_record["status"] == "known"
    assert private_record["raw_inputs"]["state"]["status"] == "known"
    assert private_record["raw_inputs"]["state"]["value"]["loan_count"] == 1

    page_permission = {
        "status": "known",
        "admitted": page_admitted,
        "mode": "observer_lent_loans_candidate" if page_admitted else "denied",
    }
    fields = {
        economy_projection.PRIVATE_VISIBILITY_FIELD: {
            "status": "known",
            "basis": visibility.BASIS,
            "partial": True,
            "complete": False,
            "raw_inputs": {"fixture": "public page permission DTO"},
            "value": {
                visibility.INCOME_PAGE: {
                    "status": "known", "admitted": True,
                    "mode": "observer_high32_byte3",
                },
                visibility.LOANS_PAGE: page_permission,
            },
        },
    }
    if include_subset_field:
        fields[loans.FIELD] = _debt_subset_record()
    if include_principal_field:
        fields[principal_adapter.FIELD] = private_record
    item = {
        "fields": fields,
        "field_consistency": {
            economy_projection.PRIVATE_VISIBILITY_FIELD: {"status": "stable"},
            loans.FIELD: {"status": "stable"},
            principal_adapter.FIELD: {"status": "stable"},
        },
    }
    bindings = (observer, target)
    return item, bindings, image


def _project(item: dict, scope_record=None, *, country_view=None) -> dict:
    if country_view is None:
        country_view = {"status": "known", "admitted": True}
    return projection.project(item, TARGET, country_view,
                              scope_record=scope_record)


def test_both_debt_scopes_project_independently_and_keep_scaled_wrap_private():
    item, _bindings, _image = _item()
    scope = _scope_record()
    field = _project(item, scope)

    assert field["status"] == "known"
    assert field["partial"] is True and field["complete"] is False
    assert field["unit"] == "debt_information"
    assert field["scale"] == 1 and field["period"] == "current"
    assert field["basis"] == "native_debt_independent_scopes"
    assert set(field["value"]) == {"total_debt", "loans_to_observer"}
    assert field["value"]["total_debt"] == {
        "status": "known",
        "raw": WRAPPED_SCALED_PRINCIPAL,
        "value": WRAPPED_SCALED_PRINCIPAL / 1000.0,
        "unit": "ducats",
        "scale": 1000,
        "signed_bits": 32,
        "overflowed": True,
        "basis": "native_diplomatic_loan_principal_sum",
        "includes_remaining_interest": False,
    }
    subset = field["value"]["loans_to_observer"]
    assert subset["status"] == "known"
    assert subset["coverage"] == "observer_lent_loans_only"
    assert subset["record_count"] == 1
    assert subset["records"][0]["principal"]["raw"] == 50
    assert subset["complete_country_debt"] is False
    assert field["component_statuses"] == {
        "total_debt": {"status": "known"},
        "loans_to_observer": {"status": "known"},
    }
    assert field["visibility"]["country_view"] == {"status": "known", "admitted": True}
    assert field["visibility"]["components"]["total_debt"] == {
        "scope": disclosure.SCOPE,
        "permission": {"status": "known", "admitted": True},
    }
    assert field["visibility"]["components"]["loans_to_observer"] == {
        "page": visibility.LOANS_PAGE,
        "permission": {"status": "known", "admitted": True},
    }
    rendered = repr(field)
    for private in ("raw_inputs", "ordered_read_trace", "fullref", "country_pointer",
                    "session_id", "creation_filetime", "inspection", "favor_trade",
                    hex(memory_fixture.TARGET_POINTER), hex(memory_fixture.BASE)):
        assert private not in rendered
    assert "loan_count" not in rendered
    assert "principal_total" not in rendered

    # Native selection is visible even when action legality is unavailable and
    # the tooltip reports no reasons; that evidence alone never widens scope.
    inspection = scope["raw_inputs"]["inspection"]
    assert inspection["legality"]["status"] == "unavailable"
    assert inspection["native_rule_components"]["executor_validity"] is False
    assert inspection["acceptance"]["reason_count"] == 0


def test_each_component_retains_its_own_unknown_or_denied_state():
    item, _bindings, _image = _item()
    scope = _scope_record()

    no_scope = _project(item, None)
    assert no_scope["status"] == "known"
    assert no_scope["value"]["total_debt"]["status"] == "unknown"
    assert no_scope["value"]["loans_to_observer"]["status"] == "known"

    page_denied_item, _bindings, _image = _item(page_admitted=False)
    page_denied = _project(page_denied_item, scope)
    assert page_denied["status"] == "known"
    assert page_denied["value"]["total_debt"]["status"] == "known"
    assert page_denied["value"]["loans_to_observer"]["status"] == "invisible"
    assert page_denied["visibility"]["components"]["loans_to_observer"]["permission"] == {
        "status": "known", "admitted": False}

    scope_denied = _scope_record(controlled_countries=["FRA", TARGET])
    denied_total = _project(item, scope_denied)
    assert denied_total["status"] == "known"
    assert denied_total["value"]["total_debt"]["status"] == "invisible"
    assert denied_total["value"]["loans_to_observer"]["status"] == "known"

    no_subset_item, _bindings, _image = _item(include_subset_field=False)
    no_subset = _project(no_subset_item, scope)
    assert no_subset["status"] == "known"
    assert no_subset["value"]["total_debt"]["status"] == "known"
    assert no_subset["value"]["loans_to_observer"]["status"] == "unknown"


def test_two_unknown_components_have_no_top_level_value():
    item, _bindings, _image = _item(
        include_principal_field=False, include_subset_field=False)
    field = _project(item, None)
    assert field["status"] == "unknown"
    assert "value" not in field
    assert field["component_statuses"]["total_debt"]["status"] == "unknown"
    assert field["component_statuses"]["loans_to_observer"]["status"] == "unknown"


@pytest.mark.parametrize("tamper", [
    "total_amount", "record_value", "raw_trace", "permission", "scope_date", "target", "date_bool",
])
def test_invalid_total_proof_is_removed_without_revoking_known_subset(tamper: str):
    item, _bindings, _image = _item()
    scope = _scope_record()
    private_record = item["fields"][principal_adapter.FIELD]
    if tamper == "total_amount":
        private_record["raw_inputs"]["state"]["value"]["diplomatic_principal_total"]["raw"] += 1
    elif tamper == "record_value":
        private_record["value"]["diplomatic_principal_total"]["raw"] += 1
    elif tamper == "raw_trace":
        row = private_record["raw_inputs"]["state"]["raw_inputs"]["ordered_read_trace"][0]
        row["raw_hex"] = "00" * row["size"]
    elif tamper == "permission":
        private_record["raw_inputs"]["permission"]["raw_inputs"]["ordered_read_trace"][0]["raw_hex"] = "00" * 8
    elif tamper == "scope_date":
        scope = _scope_record(game_date=GAME_DATE + 1)
    elif tamper == "target":
        private_record["raw_inputs"]["permission"]["target"]["tag"] = "SWE"
    else:
        private_record["raw_inputs"]["permission"]["raw_inputs"]["world"]["date_raw_i32"] = True

    field = _project(item, scope)
    assert field["status"] == "known"
    assert field["value"]["total_debt"]["status"] == "unknown"
    assert field["value"]["loans_to_observer"]["status"] == "known"
    assert "raw" not in field["value"]["total_debt"]


def test_failure_field_is_public_unknown_without_value_or_private_scope_data():
    failed = projection.failure_field("bad reason / pointer", {"status": "known", "admitted": True})
    assert failed["status"] == "unknown"
    assert "value" not in failed
    assert failed["component_statuses"]["total_debt"]["status"] == "unknown"
    assert failed["component_statuses"]["loans_to_observer"]["status"] == "unknown"
    assert failed["visibility"]["components"]["total_debt"]["scope"] == disclosure.SCOPE
    assert "raw_inputs" not in repr(failed)
    assert "pointer" not in repr(failed)
