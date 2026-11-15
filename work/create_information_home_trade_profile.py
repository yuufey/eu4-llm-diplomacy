"""Pin the native home-node flag contract without accessing the game process."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.discover_diplomacy import PE
from work.local_config import game_exe

STAGE = ROOT / "work/runtime/information-trade-state-20261027-001"
SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
TRADE_PROFILE_SHA = "1375800668ed0ddec29d2e5f8efe8e1369d1e4da8b0aa6916b5b970078b137cd"
PROFILE_ID = "home-trade-node-memory-1374"
SOURCE_ID = "information-home-trade-node-source-index-001"


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024*1024), b""):
            value.update(block)
    return value.hexdigest()


def pin(path):
    return {"path": path.relative_to(ROOT).as_posix(), "sha256": digest(path), "bytes": path.stat().st_size}


def write(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def main():
    pe = PE(game_exe())
    assert hashlib.sha256(pe.data).hexdigest() == SHA and pe.base == 0x140000000
    windows = [("country_selected_fullref_getter", 0x763840, 0x76386E),
               ("home_node_flag_getter", 0xB58C40, 0xB58C61),
               ("country_and_home_label_binding", 0x13D40CC, 0x13D416A),
               ("transit_node_literal", 0x1D4FC78, 0x1D4FC78+len(b"TRADE_TRANSIT_NODE\0")),
               ("home_transit_node_literal", 0x1D4FD10, 0x1D4FD10+len(b"TRADE_TRANSIT_NODE_CAPITAL\0"))]
    guards = [{"name": name, "rva": hex(begin), "rva_end_exclusive": hex(end),
               "hex": pe.bytes_at(begin, end-begin).hex(),
               "sha256": hashlib.sha256(pe.bytes_at(begin, end-begin)).hexdigest()}
              for name, begin, end in windows]
    assert pe.bytes_at(0xB58C40, 33).hex() == "48c1ea20480fbfc2488d144048c1e2064803511874080fb682ad000000c332c0c3"
    layout = {"entry_home_flag_offset": "0xad", "required_home_count": 1,
              "source_trade_profile_sha256": TRADE_PROFILE_SHA}
    source = {"schema": "information_home_trade_node_source.v1", "source_index_id": SOURCE_ID, "profile_id": PROFILE_ID,
              "target": {"game_version": "1.37.4", "exe_sha256": SHA, "image_base_va": hex(pe.base),
                         "address_rule": "RVA; VA=image_base+RVA; all ranges end exclusive"},
              "behavior": "Select the unique verified trade node whose FRA country-entry home flag AD is nonzero.",
              "basis": "native_trade_node_home_flag", "value_origin": "derived_from_copied_native_flags",
              "layout": layout,
              "ordinary_bounded_PE": [pin(STAGE/"home-node-source-001.json")],
              "reused_graph_contract": pin(ROOT/"bridge/information/profiles/trade-income-memory-1374.json"),
              "reused_source_index": pin(ROOT/"work/runtime/information-budget-collectors-20261027-001/trade-income-source-index-001.json"),
              "derivation": {"input": "A complete validated trade_income_memory record with all real node entries, FRA fullref and dynamically derived slot.",
                             "flag": "B58C40 returns byte table[slot*0xC0+0xAD]; zero entry returns0.",
                             "meaning": "Selected-country fullref is passed to B58C40. Nonzero AL selects TRADE_TRANSIT_NODE_CAPITAL; base localization explicitly describes the home node.",
                             "key": "Return the verified definition ASCII node_id, not localized display text.",
                             "uniqueness": "Exactly one nonzero AD is required. Zero/multiple candidates produce explicit unknown without arbitrary selection.",
                             "source_binding": "The derived record includes a canonical SHA256 of the complete validated input trade record. Existing graph reads are reused."},
              "evidence_layers": {"static": "Ordinary bounded PE plus pinned on-disk English localization; no new REA function Evidence.",
                                  "runtime": "Fresh raw graph observations and public MCP acceptance remain separate artifacts; this source index itself makes no execution claim."},
              "unresolved_conditions": ["The runtime source supports the verified FRA observer and fixed1.37.4 executable only.",
                                        "Home selection uses existing native flags. No cache refresh or game function is invoked, so freshness remains partial.",
                                        "This does not establish merchant_task, collection, transfer relationships or steering_direction semantics.",
                                        "Double-pass snapshots are not atomic and same-date reload generations are not independently established."],
              "runtime_guards": guards}
    path = STAGE / "home-trade-node-source-index-001.json"
    write(path, source)
    profile = {"profile_id": PROFILE_ID, "game_version": "1.37.4", "executable": {"sha256": SHA},
               "source_index": {"source_index_id": SOURCE_ID, "path": path.relative_to(ROOT).as_posix(), "sha256": digest(path)},
               "layout": layout, "semantics": {key: source[key] for key in ("basis", "value_origin")}, "code_guards": guards}
    profile_path = ROOT / "bridge/information/profiles/home-trade-node-memory-1374.json"
    write(profile_path, profile)
    print(json.dumps({"source": pin(path), "profile": pin(profile_path), "guards": len(guards),
                      "guard_bytes": sum(len(bytes.fromhex(x["hex"])) for x in guards)}))


if __name__ == "__main__":
    main()
