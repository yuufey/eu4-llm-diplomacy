"""Compare selected-language native bytes with explicit current static inputs.

This reads files only. It does not prove general engine merge precedence,
dynamic evaluation, current UI visibility, or a world-generation boundary.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from bridge.information.localization import LocalizationIndex, _cp1252_bytes
from bridge.information.mission_texts import decode_template


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError("Crosscheck output must be new")
    raw = args.capture.read_bytes()
    native = json.loads(raw)
    assert native["status"] == "observed" and native["doublepass"]["consistent"]
    assert native["cleanup"]["handle_close"]["closed"]
    keys = native["request"]["keys"]
    index = LocalizationIndex()
    static = index.lookup(keys,language=native["language"]["text"],encoding="eu4_escape_cp1252")
    comparisons = {}
    for key in keys:
        disk = static["entries"][key]
        runtime = native["entries"][key]
        assert disk["status"] in {"known","template"} and runtime["status"] == "observed"
        reconstructed = _cp1252_bytes(disk["raw_text"])
        decoded = decode_template(runtime["value_hex"],"eu4_escape")
        comparisons[key] = {"bytes_equal":reconstructed.hex() == runtime["value_hex"],
            "decoded_equal":decoded.get("text",decoded.get("template")) == disk["decoded_text"],
            "static_status":disk["status"],"runtime_decoded_status":decoded["status"],
            "runtime_value_hex":runtime["value_hex"], "static_raw_text":disk["raw_text"],
            "static_source":disk["source"],"static_line":disk["line"],
            "dynamic_tokens":disk["dynamic_tokens"]}
        assert comparisons[key]["bytes_equal"] and comparisons[key]["decoded_equal"],key
    context = index.context()
    assert context["status"] == "ready"
    report = {"status":"passed","evidence_kind":"static_file_to_retained_runtime_crosscheck",
        "new_runtime_read":False,"native_capture_sha256":hashlib.sha256(raw).hexdigest(),
        "language":native["language"]["text"],"static_encoding":"eu4_escape_cp1252",
        "native_codec":"eu4_escape","key_count":len(keys),"all_bytes_equal":True,
        "all_decoded_values_equal":True,"comparisons":comparisons,
        "configuration_sha256":context["configuration_sha256"],
        "localization_index_sha256":hashlib.sha256((ROOT / "bridge/information/localization.py").read_bytes()).hexdigest(),
        "general_engine_merge_semantics_verified":False,"dynamic_substitution_evaluated":False}
    args.output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({key:value for key,value in report.items() if key != "comparisons"}))


if __name__ == "__main__":
    main()
