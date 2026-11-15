"""Replay field bytes from the independent RPM report without opening EU4."""
import json
from pathlib import Path

from bridge.information import military_effective_memory as memory
from bridge.tests.test_information_military_effective_memory import BoundedReader

ROOT = Path(__file__).resolve().parents[2]
RAW_REPORT = ROOT / "work/runtime/information-military-effective-20261027-001/native-effective-inputs-003.json"


def test_archived_dense_inputs_use_the_embedded_modifier_object():
    report = json.loads(RAW_REPORT.read_bytes())
    assert report["status"] == "observed" and report["doublepass"]["consistent"] is True
    assert report["cleanup"]["handle_close"]["closed"] is True
    raw = report["military_effective_inputs"][0]["military_effective"]
    module_base = int(raw["module_base"], 16)
    country = int(raw["country_pointer"], 16)
    reader = BoundedReader()
    # The diagnostic RPM report retained the helper guard and processor prefix,
    # not every complete production guard.  Fill the remaining guard bytes from
    # the pinned static profile; only field/layout inputs below are runtime data.
    profile = memory._load_profile()
    for _name, rva, _end, guard in memory._profile_code_guards(profile):
        reader.put(module_base + rva, guard)
    for item in raw["reads"]:
        value = bytes.fromhex(item["raw_hex"])
        assert len(value) == item["bytes"]
        reader.put(int(item["va"], 16), value)
    result = memory.read_fields(reader, module_base, country)
    assert result["status"] == "observed", result.get("reason")
    assert result["fields"]["discipline"]["value"] == 1000
    assert result["fields"]["discipline"]["complete"] is False
    assert result["observation"]["modifier"]["modifier_object"] == hex(country + 0x28D0)
    assert result["observation"]["modifier"]["values_pointer"] == raw["values_pointer"]
    assert memory.validate_record(result) is True
