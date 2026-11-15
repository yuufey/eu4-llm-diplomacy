"""Derive trade-income expectations from independent raw graph bytes only."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path

STAGE = Path(__file__).resolve().parent / "runtime/information-budget-collectors-20261027-001"


def main():
    path = STAGE / "native-trade-income-inputs-005.json"
    raw = path.read_bytes()
    document = json.loads(raw)
    assert document["completed"] and document["doublepass"]["consistent"]
    first, second = document["trade_income_inputs"]
    assert first == second and document["cleanup"]["handle_close"]["closed"]
    slot = int.from_bytes(bytes.fromhex(first["country_reference_raw_hex"])[4:6], "little", signed=True)
    special = int.from_bytes(bytes.fromhex(first["filter_special_country_slot_raw_hex"]), "little", signed=True)
    nodes = {}
    total = 0
    for node in first["nodes"]:
        predicate = int(node["predicate_rva"], 16)
        assert predicate in (0x8F440, 0x8F450)
        if predicate == 0x8F450:
            continue
        key = bytes.fromhex(node["key_payload_hex"])[:-1].decode("ascii")
        assert key == node["node_id"] and key not in nodes
        assert int(node["definition_pointer"], 16) == int.from_bytes(bytes.fromhex(node["native_definition_pointer_raw_hex"]), "little")
        ac, ad, ae = bytes.fromhex(node["flags_ac_ad_ae_hex"])
        eligible = slot == special or (ae != 0 and ac == 0) or (ad != 0 and not (ae != 0 and ac != 0))
        cache = int.from_bytes(bytes.fromhex(node["income_raw_hex"]), "little", signed=True)
        assert cache == node["income_raw"]
        contribution = cache if eligible else 0
        nodes[key] = {"cache_income_raw": cache, "eligible": eligible, "income_raw": contribution,
                      "center": node["center"], "flags_ac_ad_ae_hex": node["flags_ac_ad_ae_hex"]}
        total = (total + contribution) & 0xFFFFFFFF
    if total >= 0x80000000:
        total -= 0x100000000
    result = {"schema": "information_trade_income_independent_expected.v1",
              "basis": "independent_raw_RPM_and_bounded_PE_filter_not_public_values",
              "reference_path": str(path), "reference_sha256": hashlib.sha256(raw).hexdigest(),
              "session_id": document["identity"]["installation_session_id"],
              "game_date": first["date"]["value"], "country": "FRA", "country_slot": slot,
              "special_slot": special, "definition_count": len(first["nodes"]), "node_count": len(nodes),
              "total_raw": total, "unit": "ducats", "scale": 1000, "period": "month", "nodes": nodes,
              "semantics": "Per-node income is the contribution selected by B58C70; excluded node caches contribute zero.",
              "layers": "Raw RPM is independent of the production reader. Predicate/filter/unit interpretation is ordinary PE static evidence, not an observed game call or GUI screenshot."}
    with (STAGE / "expected-trade-income-001.json").open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({"total_raw": total, "nodes": len(nodes), "eligible": [key for key, value in nodes.items() if value["eligible"]]}))


if __name__ == "__main__":
    main()
