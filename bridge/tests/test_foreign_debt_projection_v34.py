"""Integration fixtures for the schema-routed v7 public debt projection."""
from __future__ import annotations

from copy import deepcopy
import struct

from bridge.information import foreign_economy as source_module
from bridge.information import foreign_economy_projection_v7 as economy_projection
from bridge.information import foreign_debt_disclosure as disclosure
from bridge.information import target_debt_principal_memory_v34 as principal_adapter
from bridge.tests import test_foreign_debt_disclosure as disclosure_fixture
from bridge.tests import test_foreign_debt_projection as v2_projection_fixture
from bridge.tests import test_information_foreign_economy as country_view_fixture
from bridge.tests import test_target_debt_principal_memory_v34 as v34_memory_fixture


TARGET = "ENG"
PRINCIPAL = 1055
NODE = 0x51000000
RECORD = 0x51001000


def _v34_item(*, observer_tag='FRA', observer_controller=0) -> dict:
    image, observer, target = v34_memory_fixture._environment(
        observer_tag=observer_tag, observer_controller=observer_controller)
    target_pointer = int(target["country_pointer"], 0)
    observer_ref = int(observer["fullref"], 0)
    target_ref = int(target["fullref"], 0)

    # This is the literal linked-list layout consumed by the production leaf:
    # target+DE8 head, target+DF8 count, then record@node+0/next@node+10.
    image.put_u64(target_pointer + 0xDE8, NODE)
    image.put_i32(target_pointer + 0xDF8, 1)
    image.put(NODE, struct.pack("<QQQ", RECORD, 0xA5A5A5A5A5A5A5A5, 0))
    row = bytearray(0x40)
    row[0x10:0x18] = observer_ref.to_bytes(8, "little")
    row[0x20:0x28] = target_ref.to_bytes(8, "little")
    row[0x2C:0x30] = PRINCIPAL.to_bytes(4, "little", signed=True)
    image.put(RECORD, bytes(row))

    permission = principal_adapter.read_permission(
        image, v34_memory_fixture.BASE, observer, target)
    assert principal_adapter.validate_permission(permission) is True
    assert permission["schema"] == "information.target_debt_principal_memory.v3"
    assert permission["status"] == "known" and permission["admitted"] is True
    private_field = principal_adapter.read_fields(
        image, v34_memory_fixture.BASE, observer, target,
        principal_adapter.FIELD, permission=permission)[principal_adapter.FIELD]
    assert private_field["status"] == "known"
    assert private_field["raw_inputs"]["permission"] == permission
    assert private_field["raw_inputs"]["state"]["status"] == "known"

    # Match the capture contract: public field consistency is checked before
    # the v7 projection revalidates permission and replays the complete leaf.
    return {
        "tag": TARGET,
        "admission_by_pass": _country_view_evidence(),
        "fields": {principal_adapter.FIELD: private_field},
        "field_consistency": {principal_adapter.FIELD: {"status": "stable"}},
    }


def _country_view_evidence() -> dict:
    gate = country_view_fixture._admission(admitted=True, verified=True)
    return {"pass1": deepcopy(gate), "pass2": deepcopy(gate)}


def _disclosure_scope() -> dict:
    return v2_projection_fixture._scope_record(target=TARGET)


def test_non_fra_player_observer_requires_matching_real_scope_and_principal():
    item = _v34_item(observer_tag='POR', observer_controller=1)
    inspection = disclosure_fixture.inspection_shape(recipient=TARGET)
    inspection['actor'] = 'POR'
    _session, tools, source = disclosure_fixture.make_source(
        controlled_countries=['POR'], response=inspection)
    scope = disclosure.read_scope(source, disclosure_fixture.valid_context() | {'observer': 'POR'}, TARGET)
    assert disclosure.validate_scope(scope) and scope['admitted'] is True
    assert tools.calls == [('trade_favors_for_gold', 'POR', TARGET, 'initiate', {})]
    field = economy_projection.project(item, TARGET, ['debt'], debt_scope=scope, observer='POR')['debt']
    assert field['value']['total_debt']['status'] == 'known'
    assert field['value']['total_debt']['raw'] == PRINCIPAL * 1000

    wrong_scope = economy_projection.project(
        item, TARGET, ['debt'], debt_scope=_disclosure_scope(), observer='POR')['debt']
    assert wrong_scope['status'] == 'unknown' and 'value' not in wrong_scope
    assert wrong_scope['reason'] == 'DEBT_DISCLOSURE_SCOPE_BINDING_OR_DATE_MISMATCH'


def test_real_v34_private_permission_and_leaf_reach_v7_public_f03_total():
    assert source_module._projection is economy_projection
    item = _v34_item()
    assert item["fields"][principal_adapter.FIELD]["raw_inputs"]["permission"]["schema"] == (
        "information.target_debt_principal_memory.v3")

    field = source_module._projection.project(
        item, TARGET, ["debt"], debt_scope=_disclosure_scope())["debt"]

    assert field["status"] == "known"
    assert field["basis"] == "native_debt_independent_scopes"
    assert field["partial"] is True and field["complete"] is False
    assert field["value"]["total_debt"] == {
        "status": "known",
        "raw": PRINCIPAL * 1000,
        "value": float(PRINCIPAL),
        "unit": "ducats",
        "scale": 1000,
        "signed_bits": 32,
        "overflowed": False,
        "basis": "native_diplomatic_loan_principal_sum",
        "includes_remaining_interest": False,
    }
    assert field["value"]["loans_to_observer"]["status"] == "unknown"

    public_text = repr(field)
    for private in ("raw_inputs", "ordered_read_trace", "fullref", "country_pointer",
                    hex(v34_memory_fixture.BASE),
                    hex(v34_memory_fixture.OBSERVER_POINTER),
                    hex(v34_memory_fixture.TARGET_POINTER),
                    hex(NODE), hex(RECORD)):
        assert private not in public_text


def test_v7_projection_preserves_explicit_v2_permission_route():
    item, _bindings, _image = v2_projection_fixture._item()
    item["tag"] = TARGET
    item["admission_by_pass"] = _country_view_evidence()
    permission = item["fields"]["F03.target_debt_principal"]["raw_inputs"]["permission"]
    assert permission["schema"] == "information.target_debt_principal_memory.v2"

    field = economy_projection.project(
        item, TARGET, ["debt"], debt_scope=_disclosure_scope())["debt"]

    assert field["status"] == "known"
    assert field["value"]["total_debt"]["status"] == "known"
    assert field["value"]["total_debt"]["raw"] == v2_projection_fixture.WRAPPED_SCALED_PRINCIPAL


def test_v7_projection_does_not_coerce_an_unrecognized_permission_schema():
    item, _bindings, _image = v2_projection_fixture._item()
    item = deepcopy(item)
    item["tag"] = TARGET
    item["admission_by_pass"] = _country_view_evidence()
    permission = item["fields"]["F03.target_debt_principal"]["raw_inputs"]["permission"]
    permission["schema"] = "information.target_debt_principal_memory.v999"

    field = economy_projection.project(
        item, TARGET, ["debt"], debt_scope=_disclosure_scope())["debt"]

    assert field["status"] == "known"
    assert field["value"]["total_debt"]["status"] == "unknown"
    assert field["value"]["total_debt"]["reason"] == "DEBT_PRINCIPAL_PERMISSION_INVALID"
    assert field["value"]["loans_to_observer"]["status"] == "known"
