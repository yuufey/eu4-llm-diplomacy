"""N09 delegation of the three existing native scalar sources."""
from __future__ import annotations

from copy import deepcopy
import re

import pytest

from bridge.information.diplomats_total import NativeDiplomatsTotalSource
from bridge.information.diplomats_total_capture import PROFILE_SHA256 as DIPLOMATS_PROFILE
from bridge.information.diplomatic_reputation import NativeDiplomaticReputationSource
from bridge.information.diplomatic_reputation_capture import PROFILE_SHA256 as REPUTATION_PROFILE
from bridge.information.final_attributes import NativeFinalAttributesSource
from bridge.information.relations_capacity import NativeRelationsCapacitySource
from bridge.information.relations_capacity_capture import PROFILE_SHA256 as RELATIONS_PROFILE
from bridge.information.sources import _result, _source_info
from bridge.tests.test_information_final_attributes import Upstream, query
from bridge.tests.test_information_war_exhaustion import _context


SPECS = {
    "diplomatic_reputation": {
        "topic": "N06", "field": "diplomatic_reputation",
        "name": "NativeDiplomaticReputationSource", "unit": "diplomatic_reputation",
        "scale": 1000, "basis": "native_diplomatic_reputation_aggregate_cache",
        "origin": "copied_native_aggregate_modifier", "profile": REPUTATION_PROFILE,
        "value": 1250,
    },
    "diplomats_total": {
        "topic": "N05", "field": "diplomats_total",
        "name": "NativeDiplomatsTotalSource", "unit": "diplomats",
        "scale": 1000, "basis": "native_diplomats_total_aggregate_cache",
        "origin": "copied_native_aggregate_modifier", "profile": DIPLOMATS_PROFILE,
        "value": -1750,
    },
    "relations_limit": {
        "topic": "N05", "field": "relations_limit",
        "name": "NativeRelationsCapacitySource", "unit": "diplomatic_relation",
        "scale": 1, "basis": "native_diplomatic_relation_trigger_arithmetic",
        "origin": "derived_from_copied_native_modifier_and_relation_caches",
        "profile": RELATIONS_PROFILE, "value": 8,
    },
}
SOURCE_TYPES = {
    "diplomatic_reputation": NativeDiplomaticReputationSource,
    "diplomats_total": NativeDiplomatsTotalSource,
    "relations_limit": NativeRelationsCapacitySource,
}


def _known_item(key, value=None, **extra):
    spec = SPECS[key]
    value = spec["value"] if value is None else value
    item = {
        "status": "known", "value": value, "raw": value,
        "raw_hex": int(value).to_bytes(4, "little", signed=True).hex(),
        "unit": spec["unit"], "scale": spec["scale"], "period": "current",
        "partial": True, "complete": False, "basis": spec["basis"],
        "value_origin": spec["origin"],
    }
    item.update(extra)
    return item


class ScalarProbe:
    """A controlled source result that keeps the real source class identity."""

    def __init__(self, key):
        self.key = key
        self.spec = SPECS[key]
        self.ctx = _context()
        self.calls = []
        self.context_calls = 0
        self.before_context_mismatch = False
        self.change_context_after_read = False
        self.read_error = False
        self.identity_fault = None
        self.report_hash = "ab" * 32
        self.profile_hash = self.spec["profile"]
        self.item = _known_item(key)

    def context(self):
        self.context_calls += 1
        context = deepcopy(self.ctx)
        if self.before_context_mismatch:
            context["game_date"] += 1
        return context

    def read(self, selected_query, context):
        self.calls.append((deepcopy(selected_query), deepcopy(context)))
        if self.read_error:
            raise RuntimeError("fixture read failure")
        source = _source_info(
            self.spec["name"], context, complete=False,
            provenance={"capture_report_sha256": self.report_hash,
                        "profile_sha256": self.profile_hash},
        )
        result = _result(selected_query, context,
                         {self.spec["field"]: deepcopy(self.item)}, False, source)
        if self.identity_fault == "name":
            result["source"]["name"] = "UnexpectedScalarSource"
        elif self.identity_fault in {"mode", "observer", "session_id"}:
            result["source"][self.identity_fault] = "mismatch"
        elif self.identity_fault == "game_date":
            result["game_date"] += 1
        elif self.identity_fault == "objects":
            result["objects"] = [{"type": "country", "country": "ENG"}]
        if self.change_context_after_read:
            self.ctx["game_date"] += 1
        return result


def _make_scalar_source(key, base, probe=None):
    probe = probe or ScalarProbe(key)
    source = SOURCE_TYPES[key](base)
    # The real class is retained so constructor validation sees the production type.
    source.context = probe.context
    source.read = probe.read
    return source, probe


def _configured(*, keys=tuple(SPECS), military=None, probes=None, **probe_options):
    military = military or Upstream()
    probes = probes or {}
    sources = {}
    used_probes = {}
    for key in keys:
        probe = probes.get(key) or ScalarProbe(key)
        for name, value in probe_options.get(key, {}).items():
            setattr(probe, name, value)
        sources[key], used_probes[key] = _make_scalar_source(key, military, probe)
    return NativeFinalAttributesSource(military, scalar_sources=sources), military, used_probes


def _expected_scalar_query(key):
    spec = SPECS[key]
    return {"topic": spec["topic"], "object": {"type": "country", "country": "FRA"},
            "fields": [spec["field"]], "parameters": {}}


def _hash(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


@pytest.mark.parametrize("key", tuple(SPECS))
def test_final_value_reads_each_configured_scalar_with_the_same_bound_context(key):
    source, military, probes = _configured()
    before = military.context()

    result = source.read(query())

    field = result["fields"]["final_value"]
    assert field["status"] == "known"
    assert set(field["value"]) == {"discipline", "morale", *SPECS}
    assert field["value"]["discipline"]["status"] == "known"
    assert field["value"]["morale"]["status"] == "known"
    for scalar_key, probe in probes.items():
        assert len(probe.calls) == 1
        selected_query, selected_context = probe.calls[0]
        assert selected_query == _expected_scalar_query(scalar_key)
        assert selected_context == before
        assert probe.context_calls >= 2
        assert field["value"][scalar_key] == _known_item(scalar_key)


def test_scalar_projection_is_whitelisted_and_success_has_delegation_hashes():
    source, _, _ = _configured()

    result = source.read(query())

    projected = result["fields"]["final_value"]["value"]["diplomatic_reputation"]
    assert projected == _known_item("diplomatic_reputation")
    provenance = result["source"]["provenance"]
    delegations = provenance["delegations"]
    for key, spec in SPECS.items():
        delegation = delegations[f"{spec['topic']}.{spec['field']}"]
        for hash_name in ("capture_report_sha256", "profile_sha256", "result_sha256"):
            assert _hash(delegation[hash_name])
        assert delegation["profile_sha256"] == spec["profile"]
        fields = delegation.get("fields", [])
        assert (spec["field"] in fields or delegation.get("field") == spec["field"]
                or delegation.get("source_field") == spec["field"])


def test_private_scalar_dto_keys_make_only_that_attribute_unknown_without_leaking_values():
    probe = ScalarProbe("diplomatic_reputation")
    probe.item.update({"country_pointer": "0x60000000", "processor_pointer": "0x70000000",
                       "native_handle": "opaque", "debug": {"address": "0xdeadbeef"}})
    source, _, _ = _configured(probes={"diplomatic_reputation": probe})

    result = source.read(query())

    field = result["fields"]["final_value"]
    rejected = field["value"]["diplomatic_reputation"]
    assert field["status"] == "known"
    assert rejected["status"] == "unknown"
    assert "value" not in rejected
    assert all(field["value"][key]["status"] == "known"
               for key in ("diplomats_total", "relations_limit"))
    rendered = repr(rejected)
    for private_value in ("country_pointer", "processor_pointer", "native_handle", "debug",
                          "0x60000000", "0x70000000", "0xdeadbeef", "opaque"):
        assert private_value not in rendered


@pytest.mark.parametrize("selected_field", ("source_breakdown", "modifier_effects"))
def test_scalar_sources_are_not_called_for_other_fields(selected_field):
    source, _, probes = _configured()
    if selected_field == "modifier_effects":
        source.country_records_source = _CountryRecordsStub()

    source.read(query((selected_field,)))

    assert all(probe.calls == [] for probe in probes.values())


class _CountryRecordsStub:
    def __init__(self):
        self.ctx = _context()

    def context(self):
        return deepcopy(self.ctx)

    def read(self, selected_query, context):
        source = _source_info("NativeCountryRecordsSource", context, complete=False,
                              provenance={"capture_report_sha256": "cd" * 32})
        return _result(selected_query, context,
                       {"effects": {"status": "unknown", "reason": "NO_RECORDS"}},
                       False, source)


@pytest.mark.parametrize("key", tuple(SPECS))
@pytest.mark.parametrize("phase", ("before", "after"))
def test_scalar_context_mismatch_with_base_withdraws_all_selected_attributes(key, phase):
    probe = ScalarProbe(key)
    if phase == "before":
        probe.before_context_mismatch = True
    else:
        probe.change_context_after_read = True
    source, _, _ = _configured(probes={key: probe})

    field = source.read(query())["fields"]["final_value"]

    assert field["status"] == "unavailable"
    assert field["reason"] == "FINAL_ATTRIBUTES_CONTEXT_CHANGED"


@pytest.mark.parametrize("fault", ("name", "mode", "observer", "session_id", "game_date", "objects"))
def test_scalar_identity_mismatch_invalidates_only_its_attribute(fault):
    probe = ScalarProbe("relations_limit")
    probe.identity_fault = fault
    source, _, _ = _configured(probes={"relations_limit": probe})

    field = source.read(query())["fields"]["final_value"]

    assert field["status"] == "known"
    assert field["value"]["relations_limit"]["status"] == "unknown"
    assert field["value"]["diplomatic_reputation"]["status"] == "known"
    assert field["value"]["diplomats_total"]["status"] == "known"


@pytest.mark.parametrize("fault", ("bad_report", "bad_profile_format", "wrong_profile", "read_error"))
def test_bad_scalar_evidence_or_read_failure_withdraws_only_its_attribute(fault):
    probe = ScalarProbe("diplomats_total")
    if fault == "bad_report":
        probe.report_hash = "not-a-sha256"
    elif fault == "bad_profile_format":
        probe.profile_hash = "g" * 64
    elif fault == "wrong_profile":
        probe.profile_hash = "ff" * 32
    else:
        probe.read_error = True
    source, _, _ = _configured(probes={"diplomats_total": probe})

    field = source.read(query())["fields"]["final_value"]

    assert field["status"] == "known"
    assert field["value"]["diplomats_total"]["status"] == "unknown"
    assert field["value"]["diplomatic_reputation"]["status"] == "known"
    assert field["value"]["relations_limit"]["status"] == "known"


@pytest.mark.parametrize("fault", ("boolean", "raw_mismatch", "bad_hex", "bad_unit", "bad_scale",
                                    "bad_period", "bad_partial", "bad_complete", "bad_basis", "bad_origin"))
def test_invalid_known_scalar_projection_is_unknown(fault):
    probe = ScalarProbe("diplomatic_reputation")
    item = probe.item
    if fault == "boolean":
        item["value"] = True
    elif fault == "raw_mismatch":
        item["raw"] += 1
    elif fault == "bad_hex":
        item["raw_hex"] = "00000000"
    elif fault == "bad_unit":
        item["unit"] = "ratio"
    elif fault == "bad_scale":
        item["scale"] = 1
    elif fault == "bad_period":
        item["period"] = "monthly"
    elif fault == "bad_partial":
        item["partial"] = False
    elif fault == "bad_complete":
        item["complete"] = True
    elif fault == "bad_basis":
        item["basis"] = "other"
    else:
        item["value_origin"] = "other"
    source, _, _ = _configured(probes={"diplomatic_reputation": probe})

    field = source.read(query())["fields"]["final_value"]

    assert field["status"] == "known"
    assert field["value"]["diplomatic_reputation"]["status"] == "unknown"
    assert field["value"]["diplomats_total"]["status"] == "known"


def test_nonknown_scalar_projection_keeps_only_status_and_bounded_reason():
    probe = ScalarProbe("relations_limit")
    probe.item = {"status": "unknown", "reason": "CACHE_MISSING",
                  "country_pointer": "0x60000000", "raw_inputs": {"address": "0xdeadbeef"}}
    source, _, _ = _configured(probes={"relations_limit": probe})

    field = source.read(query())["fields"]["final_value"]

    assert field["status"] == "known"
    assert field["value"]["relations_limit"] == {"status": "unknown", "reason": "CACHE_MISSING"}
    assert field["value"]["diplomatic_reputation"]["status"] == "known"


def test_n03_failure_does_not_hide_known_scalar_values():
    military = Upstream()
    military.fields = {
        "discipline": {"status": "unknown", "reason": "CACHE_MISSING"},
        "morale": {"status": "unavailable", "reason": "QUALITY_UNAVAILABLE"},
    }
    source, _, _ = _configured(military=military)

    field = source.read(query())["fields"]["final_value"]

    assert field["status"] == "known"
    assert field["value"]["discipline"]["status"] == "unknown"
    assert field["value"]["morale"]["status"] == "unavailable"
    assert all(field["value"][key]["status"] == "known" for key in SPECS)


def test_unconfigured_sources_preserve_old_value_and_catalogue_scope():
    source = NativeFinalAttributesSource(Upstream())

    field = source.read(query())["fields"]["final_value"]
    catalogue = source.catalog()[0]["fields"]

    assert field["status"] == "known"
    assert set(field["value"]) == {"discipline", "morale"}
    assert catalogue["final_value"]["supported_attributes"] == [
        "discipline", "morale.army", "morale.navy"]
    assert catalogue["source_breakdown"]["supported_attributes"] == ["discipline"]


def test_catalogue_lists_only_configured_scalar_attributes():
    source, _, _ = _configured(keys=("diplomats_total",))

    catalogue = source.catalog()[0]["fields"]

    supported = catalogue["final_value"]["supported_attributes"]
    assert "diplomats_total" in supported
    assert "diplomatic_reputation" not in supported
    assert "relations_limit" not in supported
    assert catalogue["source_breakdown"]["supported_attributes"] == ["discipline"]


def test_constructor_rejects_unknown_scalar_keys_and_wrong_source_types():
    military = Upstream()
    valid_source, _ = _make_scalar_source("diplomatic_reputation", military)

    with pytest.raises(ValueError):
        NativeFinalAttributesSource(military, scalar_sources={"not_a_scalar": valid_source})
    with pytest.raises(ValueError):
        NativeFinalAttributesSource(military, scalar_sources={"relations_limit": object()})
