from copy import deepcopy

import pytest

from bridge.information import mission_trigger_country_state as country_state
from bridge.information import religious_unity_memory


MODULE_BASE = 0x140000000
COUNTRY_POINTER = 0x2000000


class DictBackend:
    """Small byte-addressed fake backend with separate aligned/code paths."""

    def __init__(self, memory=None, *, code_error=None):
        self.memory = dict(memory or {})
        self.code_error = code_error
        self.code_reads = []
        self.aligned_reads = []

    def load(self, address, payload):
        for offset, value in enumerate(payload):
            self.memory[address + offset] = value

    def read_code(self, address, size, label):
        self.code_reads.append((address, size, label))
        if self.code_error is not None:
            raise self.code_error
        try:
            return bytes(self.memory[address + offset] for offset in range(size))
        except KeyError as exc:
            raise OSError("fake_memory_missing") from exc

    def read(self, address, size, label):
        self.aligned_reads.append((address, size, label))
        if address & 7:
            raise AssertionError("unaligned read used the aligned backend path")
        return self.read_code(address, size, label)


def _known_unity_record(*, raw_override=None):
    profile = religious_unity_memory._load_profile()
    expected = {
        item["name"]: item["sha256"] for item in profile["code_guards"]
    }
    inputs = {
        "cache_state": 0,
        "special_rule": {
            "processor": 0,
            "resolved_type": 0,
            "type_flags": 0,
            "base_raw": 0,
        },
        "province_component_raw": 523,
        "unity_modifier": {
            "processor": 0,
            "resolved_type": 0,
            "base_raw": 0,
        },
    }
    derived = religious_unity_memory._derive(inputs)
    raw = derived if raw_override is None else raw_override
    return {
        "status": "known",
        "raw": raw,
        "raw_hex": raw.to_bytes(4, "little", signed=True).hex(),
        "unit": "fraction",
        "scale": 1000,
        "calculation": {
            "basis": "native_getter_equivalent_from_copied_inputs",
            "upper_clamp": False,
            "profile_sha256": religious_unity_memory.EXPECTED_PROFILE_SHA256,
            "inputs": inputs,
            "code_guard": {
                "status": "observed",
                "checks": dict.fromkeys(expected, True),
                "actual_sha256": expected,
            },
        },
    }


def _compact(key):
    return {
        "key": key,
        "start_date_raw": 1,
        "date_raw": 2,
        "flags": {
            "ruler_modifier": 0,
            "parliament_modifier": 0,
            "permanent": 0,
            "hidden": 0,
        },
        "effects": [],
    }


def _modifier_record(definitions):
    compact = [_compact(key) for _, key in definitions]
    nodes = [
        {
            "definition_address": hex(pointer),
            "definition": {"key": key},
        }
        for pointer, key in definitions
    ]
    return {
        "status": "observed",
        "profile_id": "country-modifiers-memory-1374-v2",
        "module_base": hex(MODULE_BASE),
        "country_pointer": hex(COUNTRY_POINTER),
        "fields": {
            "modifiers": {
                "status": "known",
                "complete": True,
                "value": deepcopy(compact),
            }
        },
        "values": {"modifiers": deepcopy(compact)},
        "observation": {
            "module_base": hex(MODULE_BASE),
            "country_pointer": hex(COUNTRY_POINTER),
            "terminated": True,
            "count_observed": len(nodes),
            "nodes": nodes,
        },
    }


def test_unity_known_requires_real_record_validation(monkeypatch):
    backend = DictBackend()
    record = _known_unity_record()
    seen = {}

    def fake_capture(reader, module_base, country_pointer):
        seen["reader"] = reader
        seen["args"] = (module_base, country_pointer)
        return deepcopy(record)

    monkeypatch.setattr(
        country_state.religious_unity_memory, "capture", fake_capture
    )
    result = country_state.read_country_state(
        backend, MODULE_BASE, COUNTRY_POINTER, "religious_unity"
    )

    assert result == {
        "status": "known",
        "raw_fixed_milli": 523,
        "source": "religious_unity_memory.capture",
    }
    assert seen["args"] == (MODULE_BASE, COUNTRY_POINTER)
    assert seen["reader"].module_base == MODULE_BASE


@pytest.mark.parametrize(
    "reason",
    [
        "RELIGIOUS_UNITY_CACHE_CALCULATING",
        "RELIGIOUS_UNITY_SPECIAL_PROCESSOR_UNSUPPORTED",
        "RELIGIOUS_UNITY_VALUE_PROCESSOR_UNSUPPORTED",
    ],
)
def test_unity_preserves_child_unknown_reason_without_validation(
    monkeypatch, reason
):
    monkeypatch.setattr(
        country_state.religious_unity_memory,
        "capture",
        lambda *args: {
            "status": "unknown",
            "reason": reason,
            "calculation": {"inputs": {"unity_modifier": {"processor": 99}}},
        },
    )
    monkeypatch.setattr(
        country_state.religious_unity_memory,
        "validate_record",
        lambda record: pytest.fail("unknown child record must not be validated"),
    )

    assert country_state.read_country_state(
        DictBackend(), MODULE_BASE, COUNTRY_POINTER, "religious_unity"
    ) == {
        "status": "unknown",
        "reason": reason,
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("raw", True),
        ("raw", 2**31),
        ("raw", -(2**31) - 1),
        ("scale", True),
        ("scale", 1001),
        ("unit", "percent"),
    ],
)
def test_unity_rejects_malformed_scalar_before_validation(
    monkeypatch, field, value
):
    record = _known_unity_record()
    record[field] = value
    monkeypatch.setattr(
        country_state.religious_unity_memory,
        "capture",
        lambda *args: deepcopy(record),
    )
    monkeypatch.setattr(
        country_state.religious_unity_memory,
        "validate_record",
        lambda record: pytest.fail("malformed scalar must not be validated"),
    )

    result = country_state.read_country_state(
        DictBackend(), MODULE_BASE, COUNTRY_POINTER, "religious_unity"
    )
    assert result["status"] == "unknown"


def test_unity_rejects_record_when_pinned_validator_fails(monkeypatch):
    # The child record's claimed value disagrees with its copied inputs.
    record = _known_unity_record(raw_override=524)
    monkeypatch.setattr(
        country_state.religious_unity_memory,
        "capture",
        lambda *args: deepcopy(record),
    )

    result = country_state.read_country_state(
        DictBackend(), MODULE_BASE, COUNTRY_POINTER, "religious_unity"
    )

    assert result == {
        "status": "unknown",
        "reason": "RELIGIOUS_UNITY_RECORD_VALIDATION_FAILED",
    }


def test_child_reads_use_unaligned_path_and_exceptions_stay_unknown(monkeypatch):
    backend = DictBackend(code_error=OSError("read_denied"))

    def capture_and_read(reader, module_base, country_pointer):
        reader.read(0x200001, 2, "fixture.unaligned")

    monkeypatch.setattr(
        country_state.religious_unity_memory, "capture", capture_and_read
    )
    result = country_state.read_country_state(
        backend, MODULE_BASE, COUNTRY_POINTER, "religious_unity"
    )

    assert result == {
        "status": "unknown",
        "reason": "RELIGIOUS_UNITY_CAPTURE_FAILED:OSError",
    }
    assert backend.code_reads == [(0x200001, 2, "fixture.unaligned")]
    assert backend.aligned_reads == []


def test_modifier_empty_list_is_known_only_when_complete(monkeypatch):
    snapshot = _modifier_record([])
    monkeypatch.setattr(
        country_state.country_modifiers_memory,
        "read_fields",
        lambda *args: deepcopy(snapshot),
    )

    assert country_state.read_country_state(
        DictBackend(), MODULE_BASE, COUNTRY_POINTER, "modifiers"
    ) == {
        "status": "known",
        "definitions": [],
        "source": "country_modifiers_memory.read_fields",
    }


def test_modifier_reuses_canonical_definition_references_and_allows_duplicates(
    monkeypatch,
):
    definitions = [
        (0x3000000, "advisor_cost"),
        (0x3000000, "advisor_cost"),
        (0x3001000, "advisor_cost"),
    ]
    snapshot = _modifier_record(definitions)
    seen = {}

    def fake_read_fields(reader, module_base, country_pointer):
        seen["reader"] = reader
        seen["args"] = (module_base, country_pointer)
        return deepcopy(snapshot)

    monkeypatch.setattr(
        country_state.country_modifiers_memory, "read_fields", fake_read_fields
    )
    result = country_state.read_country_state(
        DictBackend(), MODULE_BASE, COUNTRY_POINTER, "modifiers"
    )

    assert result == {
        "status": "known",
        "definitions": [
            {"pointer": 0x3000000, "key": "advisor_cost"},
            {"pointer": 0x3001000, "key": "advisor_cost"},
        ],
        "source": "country_modifiers_memory.read_fields",
    }
    assert seen["args"] == (MODULE_BASE, COUNTRY_POINTER)
    assert seen["reader"].module_base == MODULE_BASE


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        (
            lambda record: record["fields"]["modifiers"].update(complete=False),
            "COUNTRY_MODIFIERS_FIELD_INCOMPLETE",
        ),
        (
            lambda record: record["observation"].update(terminated=False),
            "COUNTRY_MODIFIERS_LIST_NOT_TERMINATED",
        ),
        (
            lambda record: record["observation"].update(count_observed=0),
            "COUNTRY_MODIFIERS_NODE_COUNT_MISMATCH",
        ),
        (
            lambda record: record["observation"].update(country_pointer=hex(0x2001000)),
            "COUNTRY_MODIFIERS_OBSERVATION_IDENTITY_MISMATCH",
        ),
        (
            lambda record: record["values"].update(modifiers=[]),
            "COUNTRY_MODIFIERS_COMPACT_VALUE_MISMATCH",
        ),
        (
            lambda record: record["observation"]["nodes"][0].update(
                definition_address="bad"
            ),
            "COUNTRY_MODIFIERS_DEFINITION_INVALID",
        ),
        (
            lambda record: (
                record["fields"]["modifiers"]["value"][0].update(
                    key="other_key"
                ),
                record["values"]["modifiers"][0].update(key="other_key"),
            ),
            "COUNTRY_MODIFIERS_NODE_PAIR_MISMATCH",
        ),
    ],
)
def test_modifier_incomplete_or_malformed_node_pairs_fail_closed(
    monkeypatch, mutation, reason
):
    snapshot = _modifier_record([(0x3000000, "advisor_cost")])
    mutation(snapshot)
    monkeypatch.setattr(
        country_state.country_modifiers_memory,
        "read_fields",
        lambda *args: deepcopy(snapshot),
    )

    assert country_state.read_country_state(
        DictBackend(), MODULE_BASE, COUNTRY_POINTER, "modifiers"
    ) == {"status": "unknown", "reason": reason}


def test_modifier_top_level_identity_must_match(monkeypatch):
    snapshot = _modifier_record([])
    snapshot["module_base"] = hex(MODULE_BASE + 0x1000)
    monkeypatch.setattr(
        country_state.country_modifiers_memory,
        "read_fields",
        lambda *args: deepcopy(snapshot),
    )

    assert country_state.read_country_state(
        DictBackend(), MODULE_BASE, COUNTRY_POINTER, "modifiers"
    ) == {
        "status": "unknown",
        "reason": "COUNTRY_MODIFIERS_IDENTITY_MISMATCH",
    }


def test_modifier_duplicate_pointer_with_conflicting_key_fails_closed(monkeypatch):
    snapshot = _modifier_record(
        [(0x3000000, "advisor_cost"), (0x3000000, "tax_income")]
    )
    monkeypatch.setattr(
        country_state.country_modifiers_memory,
        "read_fields",
        lambda *args: deepcopy(snapshot),
    )

    assert country_state.read_country_state(
        DictBackend(), MODULE_BASE, COUNTRY_POINTER, "modifiers"
    ) == {
        "status": "unknown",
        "reason": "COUNTRY_MODIFIERS_POINTER_KEY_CONFLICT",
    }


def test_unsupported_kind_makes_no_reader_calls(monkeypatch):
    monkeypatch.setattr(
        country_state.religious_unity_memory,
        "capture",
        lambda *args: pytest.fail("unsupported kind called unity reader"),
    )
    monkeypatch.setattr(
        country_state.country_modifiers_memory,
        "read_fields",
        lambda *args: pytest.fail("unsupported kind called modifier reader"),
    )
    backend = DictBackend()

    result = country_state.read_country_state(
        backend, MODULE_BASE, COUNTRY_POINTER, "capital_scope"
    )

    assert result == {
        "status": "unknown",
        "reason": "COUNTRY_STATE_KIND_UNSUPPORTED",
    }
    assert backend.code_reads == []
    assert backend.aligned_reads == []
