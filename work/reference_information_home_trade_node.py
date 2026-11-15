"""Select the home key from independently copied native AD flags."""
import hashlib
import json
from pathlib import Path

STAGE = Path(__file__).resolve().parent / "runtime/information-trade-state-20261027-001"


def main():
    path = STAGE / "native-trade-state-inputs-001.json"
    raw = path.read_bytes()
    data = json.loads(raw)
    assert data["completed"] and data["identity"]["binding_verified"]
    assert data["doublepass"]["consistent"] and data["cleanup"]["handle_close"]["closed"]
    first, second = data["trade_income_inputs"]
    assert first == second
    flags = {}
    for node in first["nodes"]:
        predicate = int(node["predicate_rva"], 16)
        assert predicate in (0x8F440, 0x8F450)
        if predicate == 0x8F450:
            continue
        key = bytes.fromhex(node["key_payload_hex"])[:-1].decode("ascii")
        assert key == node["node_id"] and key not in flags
        values = bytes.fromhex(node["flags_ac_ad_ae_hex"])
        assert len(values) == 3
        flags[key] = values[1]
    candidates = [key for key, flag in flags.items() if flag != 0]
    assert len(candidates) == 1
    expected = {"schema": "information_home_trade_node_independent_expected.v1",
                "basis": "independent_raw_RPM_and_static_home_flag_not_public_values",
                "reference": str(path), "reference_sha256": hashlib.sha256(raw).hexdigest(),
                "session_id": data["identity"]["installation_session_id"], "game_date": first["date"]["value"],
                "country": "FRA", "fullref_raw_hex": first["country_reference_raw_hex"],
                "country_slot": first["country_slot"], "definition_count": len(first["nodes"]),
                "node_count": len(flags), "home_candidates": candidates, "home_node": candidates[0], "home_flags": flags,
                "evidence_layers": "Raw bytes and selected-country identity are observations. The AD-home interpretation is separately pinned ordinary PE plus localization evidence."}
    with (STAGE / "expected-home-node-001.json").open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(expected, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({"home_node": expected["home_node"], "nodes": len(flags), "country_slot": first["country_slot"]}))


if __name__ == "__main__":
    main()
