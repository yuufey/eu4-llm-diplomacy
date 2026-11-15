"""Unrelated mission features must not silently disable shared live sources."""
import json
import hashlib
from pathlib import Path

import pytest

from bridge.information import country_resources_memory, domestic_pressure_memory


@pytest.mark.parametrize('module,old_name,keys', [
    (country_resources_memory, 'country-resources-memory-1374.json',
     ('globals', 'country', 'code_guards')),
    (domestic_pressure_memory, 'domestic-pressure-memory-1374-v6.json',
     ('globals', 'country', 'scalars', 'save_tokens', 'limits', 'code_guards')),
])
def test_active_shared_parent_dependencies_are_closed_without_native_layout_changes(module, old_name, keys):
    guard = module._static_contract_guard()
    assert guard['status'] == 'observed', guard.get('unknown_conditions')
    current = module._load_profile()
    old = json.loads((module.PROFILE_FILE.parent/old_name).read_text(encoding='utf-8'))
    for key in keys:
        assert current[key] == old[key]


def test_domestic_pressure_retains_python_references_and_hashes_fixed_evidence(tmp_path):
    root = Path(domestic_pressure_memory.__file__).resolve().parents[2]
    source = tmp_path / "reader.py"
    source.write_text("current implementation\n", encoding="utf-8")
    evidence = tmp_path / "native-proof.json"
    raw = b'{"native_layout":1}'
    evidence.write_bytes(raw)
    source_path = source.relative_to(root).as_posix()
    evidence_path = evidence.relative_to(root).as_posix()
    dependencies = [{"path": source_path, "sha256": "0" * 64},
                    {"path": evidence_path, "sha256": hashlib.sha256(raw).hexdigest()}]

    assert domestic_pressure_memory._dependency_hash_checks(dependencies) == (
        True, {evidence_path: True}, [])
    evidence.write_bytes(raw.replace(b"1", b"2"))
    valid, checks, unknown = domestic_pressure_memory._dependency_hash_checks(dependencies)
    assert valid is False and checks == {evidence_path: False}
    assert unknown == [f"dependency_sha256_mismatch:{evidence_path}"]
    valid, _, unknown = domestic_pressure_memory._dependency_hash_checks([
        {"path": "../reader.py", "sha256": "0" * 64}])
    assert valid is False and "dependency_outside_workspace" in unknown[0]
