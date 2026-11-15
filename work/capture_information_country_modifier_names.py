"""Retain literal-cache bytes for the two already archived country modifiers.

Uses the existing read-only cache capture and text decoder, independently of
the new country-record localization projection.  It does not invoke game
functions, save, advance the date, or submit a diplomatic action.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bridge.information.localization_memory import capture
from bridge.information.mission_texts import decode_template


def write(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def run(installation, output):
    output.mkdir(parents=True, exist_ok=False)
    binding = json.loads(installation.read_bytes())
    reference = ROOT / "work/runtime/information-country-records-20261027-001/expected-country-modifiers-001.json"
    data = reference.read_bytes()
    assert hashlib.sha256(data).hexdigest() == "f2ddec02933ff2ffa0b3176da1b3d9fa430655682575f4b69c706d16426de3f9"
    previous = json.loads(data)
    header = previous["header"]
    assert binding["session_id"] == header["session_id"]
    ids = previous["queries"]["N07"]["modifier_id"]["value"]
    keys = list(dict.fromkeys(k for key in ids for k in (key, "desc_" + key)))
    raw = capture(installation, "FRA", keys)
    write(output / "native-cache.json", raw)
    assert raw["status"] == "observed" and raw["doublepass"]["consistent"] is True
    assert raw["cleanup"]["handle_close"]["closed"] is True
    assert raw["identity"]["installation_session_id"] == header["session_id"]
    assert raw["identity"]["process_creation_filetime"] == header["creation_filetime"]
    assert raw["before"]["game_date"]["raw"] == raw["after"]["game_date"]["raw"] == header["game_date"]
    entries = {
        key: decode_template(item["value_hex"], binding["native_text_codec"])
        if item["status"] == "observed" else {"status": "unknown", "reason": item.get("unknown_reason")}
        for key, item in raw["entries"].items()
    }
    expected = {"session_id": header["session_id"], "game_date": header["game_date"],
                "modifier_ids": ids, "language": raw["language"]["text"],
                "codec": binding["native_text_codec"], "entries": entries,
                "raw_sha256": hashlib.sha256((output / "native-cache.json").read_bytes()).hexdigest(),
                "basis": "decoded_original_cache_bytes_without_new_country_record_projector",
                "atomic_with_modifier_list": False}
    write(output / "expected-literals.json", expected)
    print(json.dumps({"status": "passed", "keys": len(keys),
                      "known": sum(v["status"] == "known" for v in entries.values()),
                      "language": expected["language"], "native_functions_invoked": False,
                      "handle_closed": True}, ensure_ascii=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run(args.installation, args.output)
