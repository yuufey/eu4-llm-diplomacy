"""Use archived independent field bytes, with static-only guards labelled."""
import json
from pathlib import Path

from bridge.information import military_professionalism_memory as memory
from bridge.tests.test_information_military_quality_memory import BoundedReader

ROOT = Path(__file__).resolve().parents[2]
RAW_REPORT = ROOT / "work/runtime/information-military-effective-20261027-001/native-effective-inputs-003.json"


def test_archived_professionalism_qword_is_copied_without_pointer_dereference():
    report = json.loads(RAW_REPORT.read_bytes())
    assert report["status"] == "observed" and report["doublepass"]["consistent"] is True
    assert report["cleanup"]["handle_close"]["closed"] is True
    data = report["military_effective_inputs"][0]["military_effective"]
    module, country = int(data["module_base"], 16), int(data["country_pointer"], 16)
    raw = next(item for item in data["reads"] if item["label"] == "professionalism_raw_unit_unresolved")
    assert int(raw["va"], 16) == country + 0x50 and raw["bytes"] == 8
    reader = BoundedReader()
    # Batch50 captured the field bytes before the professionalism profile was
    # built. These guards are static profile bytes, not archived RPM guards.
    for _name, rva, _end, guard in memory._profile_code_guards(memory._load_profile()):
        reader.put(module + rva, guard)
    reader.put(country + 0x50, bytes.fromhex(raw["raw_hex"]))
    result = memory.read_fields(reader, module, country)
    assert result["status"] == "observed", result.get("reason")
    assert result["fields"]["professionalism"]["value"] == 655
    assert result["fields"]["professionalism"]["raw_hex"] == "8f02000000000000"
    assert result["fields"]["professionalism"]["scale"] == 32768
    assert memory.validate_record(result) is True
