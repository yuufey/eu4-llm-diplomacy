"""Update only configured F03 metadata; this is not live acceptance evidence."""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from bridge.information.foreign_economy import NativeForeignEconomySource


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", required=True)
    parser.parse_args()
    stage = ROOT / "work/runtime/information-foreign-debt-public-20261031-001"
    path = ROOT / "docs/信息字段覆盖.json"
    previous = path.read_bytes()
    data = json.loads(previous)
    counts = deepcopy(data["counts"])
    topic = object.__new__(NativeForeignEconomySource).catalog()[0]
    matches = [index for index, row in enumerate(data["topics"]) if row["topic_id"] == "F03"]
    assert len(matches) == 1 and len(topic["fields"]) == 5
    old = data["topics"][matches[0]]
    assert {name: row["coverage"] for name, row in old["fields"].items()} == {
        name: row["coverage"] for name, row in topic["fields"].items()}
    data["topics"][matches[0]] = deepcopy(topic)
    data["F03"] = {"context_scope": "visible_scope", "source": "NativeForeignEconomySource",
                   "fields": deepcopy(topic["fields"])}
    assert data["counts"] == counts and len(data["topics"]) == 74
    with (stage / "coverage-before-001.json").open("xb") as stream:
        stream.write(previous)
    current = (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    path.write_bytes(current)
    receipt = {"schema": "information.debt_public.configured_coverage_update.v1",
               "before_sha256": hashlib.sha256(previous).hexdigest(),
               "after_sha256": hashlib.sha256(current).hexdigest(),
               "counts": counts, "changed_topic": "F03", "field_set_unchanged": True,
               "live_session_opened": False, "catalog_is_not_live_acceptance": True}
    with (stage / "coverage-update-001.json").open("x", encoding="utf-8") as stream:
        json.dump(receipt, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps(receipt, ensure_ascii=False))


if __name__ == "__main__":
    main()
