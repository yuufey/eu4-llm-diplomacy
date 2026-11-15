from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from typing import Any

import pytest

from bridge.information import country_scale_capture as capture
from bridge.information import country_scale_development_memory as development
from bridge.information import country_scale_flag_memory as flag
from bridge.information import country_wars_memory as wars
from bridge.information import country_territory_memory as territory
from bridge.information import country_view_admission_memory as admission
from bridge.information import observer_registry_memory as registry_memory
from bridge.tests import test_information_country_faith_capture as faith_fixture
from bridge.tests import test_information_foreign_technology_capture as parent_fixture


MODULE_BASE = parent_fixture.MODULE_BASE
CREATION = parent_fixture.CREATION
SESSION_ID = "country-scale-capture-session"
GAME_DATE = parent_fixture.GAME_DATE
WORLD = parent_fixture.WORLD
WEIGHT_RVA = development.WEIGHT_GLOBAL_RVA


def _promote_fixture_refs(image: Any, fixture: dict[str, Any]) -> None:
    """Use current-shaped fullrefs with a nonzero top byte in this fake image."""
    for tag, old_ref in list(fixture["refs"].items()):
        ref = old_ref | 0x0100000000000000
        fixture["refs"][tag] = ref
        pointer = fixture["bindings"][tag]["country_pointer"]
        image.put_u64(pointer + 0x20, ref)
    target_tag = next(tag for tag, row in fixture["bindings"].items()
                      if row["slot"] == fixture["target_slot"])
    fixture["target_fullref"] = fixture["refs"][target_tag]
    fixture["physical_fullref"] = fixture["refs"]["POR"]
    image.put_u64(WORLD + 0x1E60, fixture["physical_fullref"])
    row_address = (parent_fixture.RELATION_TABLE
                   + fixture["target_slot"] * admission.RELATION_ROW_STRIDE)
    image.put_u64(row_address + admission.RELATION_ROW_RECIPIENT_FULLREF_OFFSET,
                  fixture["target_fullref"])


def _make_profile() -> dict[str, Any]:
    """Use the real immutable profile after its loader has verified all pins."""
    return capture._load_profile()


def test_python_evidence_version_does_not_reject_runtime_profile(monkeypatch):
    original_sha = capture._owner._sha

    def checked_sha(path):
        assert Path(path).suffix != ".py"
        return original_sha(path)

    monkeypatch.setattr(capture._owner, "_sha", checked_sha)
    assert capture._load_profile()["profile_id"] == capture.PROFILE_ID


def test_runtime_layout_evidence_hash_remains_required(monkeypatch):
    profile = json.loads(capture.PROFILE_FILE.read_text(encoding="utf-8"))
    dependency = next(item for item in profile["source_evidence"] + profile["layout_dependencies"]
                      if Path(item["path"]).suffix != ".py")
    target = (capture.ROOT / dependency["path"]).resolve()
    original_sha = capture._owner._sha

    def changed_sha(path):
        return "0" * 64 if Path(path).resolve() == target else original_sha(path)

    monkeypatch.setattr(capture._owner, "_sha", changed_sha)
    with pytest.raises(ValueError, match="COUNTRY_SCALE_PROFILE_DEPENDENCY"):
        capture._load_profile()


def _bound_module(profile: dict[str, Any], base: int | None = None) -> dict[str, Any]:
    descriptor = profile["observer_registry"]
    file_pin = descriptor["module_file"]
    path = (capture.ROOT / file_pin["path"]).resolve()
    if base is None:
        base = int(descriptor["preferred_image_base"], 0)
    return {"status": "bound", "module_base": hex(base),
            "observed_path": str(path), "file": deepcopy(file_pin)}


def _install_observer_registry(image: Any, profile: dict[str, Any],
                              creation: int, pointer: int = 0x40000000) -> str:
    descriptor = profile["observer_registry"]
    base = int(descriptor["preferred_image_base"], 0)
    image.put(base, bytes.fromhex(descriptor["header_raw_hex"]))
    for guard in descriptor["code_guards"]:
        image.put(base + int(guard["rva"], 0), bytes.fromhex(guard["bytes"]))
    image.put_u64(base + descriptor["creation_rva"], creation)
    image.put(base + descriptor["count_rva"], (1).to_bytes(4, "little"))
    identifier = f"war_{registry_memory.epoch(creation):016x}_00000001"
    encoded = identifier.encode("ascii")
    assert len(encoded) == 29
    record = pointer.to_bytes(8, "little") + encoded + b"\0\0\0"
    assert len(record) == 40
    image.put(base + descriptor["entries_rva"], record)
    return identifier


def _prepare_image(country: str, profile: dict[str, Any], *, admitted: bool = True,
                   own_development: int = 123,
                   weight: int = 750,
                   city_count: int = 27):
    image, fixture = faith_fixture._make_image(country, profile, admitted=admitted)
    _promote_fixture_refs(image, fixture)
    for tag, row in fixture["bindings"].items():
        if tag != country:
            image.put(parent_fixture.RELATION_TABLE
                      + row["slot"] * admission.RELATION_ROW_STRIDE,
                      b"\0" * admission.RELATION_ROW_STRIDE)
    target = fixture["target_pointer"]
    image.put_i32(target + development.OWN_DEVELOPMENT_OFFSET, own_development)
    image.put_i32(target + territory.CITY_COUNT_CACHE_OFFSET, city_count)
    image.put_u64(target + development.SUBJECT_VECTOR_BEGIN_OFFSET, 0)
    image.put_u64(target + development.SUBJECT_VECTOR_END_OFFSET, 0)
    image.put_i32(MODULE_BASE + WEIGHT_RVA, weight)

    # The feature reader is deliberately wired through a positive ordinary
    # predicate, while visibility remains owned by the parent admission gate.
    image.put(target + flag.COUNTRY_GREAT_POWER_FLAG_OFFSET, b"\x01")
    image.put_i32(target + flag.COUNTRY_FEATURE_QUALIFIER_OFFSET, 1)
    image.put_u64(target + flag.COUNTRY_OVERLORD_FULLREF_OFFSET, 0)
    image.put(MODULE_BASE + flag.FEATURE_GLOBAL_A_RVA, b"\x01")
    image.put(MODULE_BASE + flag.FEATURE_GLOBAL_B_RVA, b"\x00")
    image.put(MODULE_BASE + flag.FEATURE_GLOBAL_C_RVA, b"\x00")
    _install_war_index(image, country, fixture)
    return image, fixture


def _install_war_index(image: Any, country: str, fixture: dict[str, Any]) -> None:
    """Add one current-scope war graph using the parent's canonical bindings."""
    from bridge.tests import test_information_country_wars_memory as war_fixture

    other = "FRA" if country != "FRA" else "POR"
    graph = war_fixture.WarFixture.__new__(war_fixture.WarFixture)
    graph.memory = image
    if not callable(getattr(image, "put_u32", None)):
        image.put_u32 = lambda address, value, signed=False: image.put(
            address, int(value).to_bytes(4, "little", signed=signed))
    graph.target = country
    graph.tags = {tag: row["slot"] for tag, row in fixture["bindings"].items()}
    graph.country_pointers = {
        tag: row["country_pointer"] for tag, row in fixture["bindings"].items()
    }
    graph.fullrefs = dict(fixture["refs"])
    graph.war_specs = [{"side_a": [other], "side_b": [country]}]
    graph.war_pointers = [0x40000000]
    graph._make_wars()


def _bundle(country: str = "ENG", *, admitted: bool = True,
            profile: dict[str, Any] | None = None,
            reader_type: type | None = None,
            own_development: int = 123,
            weight: int = 750,
            city_count: int = 27,
            module_bindings: dict[str, Any] | None = None,
            registry_id: bool = False):
    profile = _make_profile() if profile is None else profile
    image, fixture = _prepare_image(country, profile, admitted=admitted,
                                    own_development=own_development, weight=weight,
                                    city_count=city_count)
    if registry_id:
        fixture["registry_id"] = _install_observer_registry(image, profile, CREATION)
        bound = _bound_module(profile)
        module_bindings = {"before": bound, "after": deepcopy(bound)}
    reader_cls = reader_type or parent_fixture.RecordingReader
    reader = reader_cls(image)
    observation = capture._observe(
        capture._owner._FailureReplayReader(reader), MODULE_BASE, country, profile,
        module_bindings=module_bindings, expected_creation=CREATION)
    identity = {
        "binding_verified": True,
        "process_creation_filetime": CREATION,
        "process_path": "synthetic-eu4.exe",
        "process_path_sha256": capture._owner.EXE_SHA256,
    }
    report = {
        "schema": capture.SCHEMA,
        "status": "observed" if observation.get("stable") is True else "unknown",
        "completed": observation.get("stable") is True,
        "request": {"country": country, "observer": "FRA", "creation_filetime": CREATION,
                    "session_id": SESSION_ID},
        "profile_sha256": capture.PROFILE_SHA256,
        "identity": deepcopy(identity),
        "identity_after": deepcopy(identity),
        "module_base": hex(MODULE_BASE),
        "observation": observation,
        "raw_reads": deepcopy(reader.read_log),
        "access": {"read_only": True, "native_function_invoked": False, "writes": False,
                   "UI_control": False, "date_advance": False, "save_or_reload": False,
                   "limit_bytes": capture._owner.MAX_READ_BYTES,
                   "bytes_requested": reader.bytes_requested, "calls": reader.calls},
        "cleanup": {"status": "closed", "closed": True, "success": True},
        "errors": [],
    }
    context = {
        "observer": "FRA", "session_id": SESSION_ID,
        "game_version": "1.37.4", "game_sha256": capture._owner.EXE_SHA256,
        "game_date": GAME_DATE,
    }
    return report, context, CREATION, {"image": image, "reader": reader, **fixture}


@pytest.fixture(scope="module")
def pinned_profile():
    return _make_profile()


@pytest.fixture(scope="module")
def positive_capture(pinned_profile):
    return _bundle(profile=pinned_profile)


def _valid(report: dict[str, Any], context: dict[str, Any], creation: int,
           country: str | None = None) -> bool:
    return capture.validate_capture(report, context, creation,
                                    country if country is not None else report["request"]["country"])


def test_two_pass_capture_replays_five_independent_fields_and_fra_role(positive_capture):
    report, context, creation, fixture = positive_capture
    assert _valid(report, context, creation)
    observation = report["observation"]
    assert observation["stable"] is True
    assert observation["context_before"]["game_date"] == GAME_DATE
    assert observation["context_before"]["physical_client_reference_raw_hex"] == (
        fixture["physical_fullref"].to_bytes(8, "little").hex())

    backend = observation["backend"]
    assert backend["observer"]["tag"] == "FRA"
    assert backend["targets"][0]["tag"] == "ENG"
    target = backend["targets"][0]
    assert target["bindings_by_pass"]["pass2"]["slot"] == 300
    assert target["fields"][development.FIELD_DEVELOPMENT]["status"] == "known"
    assert target["fields"][development.FIELD_DEVELOPMENT]["value"] == 123
    assert target["fields"][development.FIELD_DEVELOPMENT]["scale"] == 1000
    assert target["fields"][development.FIELD_SUBJECT_SCALE]["status"] == "known"
    assert target["fields"][development.FIELD_SUBJECT_SCALE]["value"] == {
        "reference_count": 0, "included_count": 0, "excluded_count": 0,
        "weighted_development_raw": 0, "development_scale": 1000,
        "weight_raw": 750, "weight_scale": 1000,
    }
    assert target["fields"][flag.FIELD_ID]["status"] == "known"
    assert target["fields"][flag.FIELD_ID]["value"] is True
    assert target["fields"][territory.FIELD_ID]["status"] == "known"
    assert target["fields"][territory.FIELD_ID]["value"] == {"city_count": 27}
    assert target["fields"][wars.FIELD_WARS]["status"] == "known"
    assert target["fields"][wars.FIELD_WARS]["value"]["at_war"] is True
    assert target["fields"][wars.FIELD_WARS]["value"]["war_count"] == 1
    assert target["fields"][wars.FIELD_WARS]["value"]["wars"][0]["war_id"]["status"] == "unknown"
    module_binding = observation["observer_module_binding"]
    assert module_binding["consistency"] == "stable"
    assert module_binding["before"] == module_binding["after"] == {
        "status": "unknown", "reason": "OBSERVER_MODULE_BINDING_UNAVAILABLE",
    }
    for phase in ("pass1", "pass2"):
        gate = target["admission_by_pass"][phase]
        assert gate["admitted"] is True
        assert gate["observer_nonplayer_role"]["verified"] is True
    assert backend["visibility"]["status"] == "unknown"
    assert backend["public_export_ready"] is False
    assert backend["complete"] is False


def test_self_target_fra_is_allowed_without_replacing_physical_por(pinned_profile):
    report, context, creation, fixture = _bundle("FRA", profile=pinned_profile)
    assert _valid(report, context, creation, "FRA")
    observation = report["observation"]
    target = observation["backend"]["targets"][0]
    assert target["tag"] == "FRA"
    assert target["fullref"] == observation["backend"]["observer"]["fullref"]
    assert observation["context_before"]["physical_client_reference_raw_hex"] == (
        fixture["physical_fullref"].to_bytes(8, "little").hex())
    assert fixture["physical_fullref"] != fixture["target_fullref"]


def test_denied_admission_does_not_read_any_scale_leaf(pinned_profile):
    report, context, creation, _fixture = _bundle(admitted=False, profile=pinned_profile)
    assert report["observation"]["stable"] is True
    assert _valid(report, context, creation)
    target = report["observation"]["backend"]["targets"][0]
    assert target["admission_by_pass"]["pass1"]["admitted"] is False
    assert all(target["fields"][field]["status"] == "invisible" for field in capture.FIELDS)
    leaf_labels = {
        "country_great_power_flag", "country_feature_qualifier", "country_overlord_fullref",
        "feature_global_A", "feature_global_B", "feature_global_C",
        "country_territory.city_count.cache_i32",
    }
    assert not any(row["label"].startswith("country_scale.") or row["label"] in leaf_labels
                   or row["label"].startswith("country_territory.")
                   or row["label"].startswith("country_wars.")
                   for row in report["raw_reads"])


class _MutateDevelopmentOnSecondRead(parent_fixture.RecordingReader):
    def __init__(self, source: Any, address: int):
        super().__init__(source)
        self.address = address
        self.count = 0

    def read(self, address: int, size: int, label: str) -> bytes:
        if label == "country_scale.development.own_i32":
            self.count += 1
            if self.count == 2:
                self.source.put_i32(self.address, 124)
        return super().read(address, size, label)


def test_one_field_change_retracts_only_that_field_and_replays_exactly(pinned_profile):
    image, fixture = _prepare_image("ENG", pinned_profile, own_development=123)
    reader = _MutateDevelopmentOnSecondRead(
        image, fixture["target_pointer"] + development.OWN_DEVELOPMENT_OFFSET)
    observation = capture._observe(reader, MODULE_BASE, "ENG", pinned_profile,
                                   expected_creation=CREATION)
    assert observation["stable"] is True
    target = observation["backend"]["targets"][0]
    assert target["fields"][development.FIELD_DEVELOPMENT]["status"] == "unknown"
    assert target["field_consistency"][development.FIELD_DEVELOPMENT]["status"] == "changed"
    assert target["fields"][development.FIELD_SUBJECT_SCALE]["status"] == "known"
    assert target["fields"][flag.FIELD_ID]["status"] == "known"
    assert target["fields"][territory.FIELD_ID]["status"] == "known"
    assert target["fields"][wars.FIELD_WARS]["status"] == "known"

    report, context, creation, _fixture = _bundle(profile=pinned_profile)
    report["observation"] = observation
    report["raw_reads"] = deepcopy(reader.read_log)
    report["access"]["calls"] = reader.calls
    report["access"]["bytes_requested"] = reader.bytes_requested
    assert _valid(report, context, creation)


class _MutateTerritoryOnSecondRead(parent_fixture.RecordingReader):
    def __init__(self, source: Any, address: int):
        super().__init__(source)
        self.address = address
        self.count = 0

    def read(self, address: int, size: int, label: str) -> bytes:
        if label == "country_territory.city_count.cache_i32":
            self.count += 1
            if self.count == 2:
                self.source.put_i32(self.address, 28)
        return super().read(address, size, label)


def test_territory_change_retracts_only_territory_and_replays_exactly(pinned_profile):
    image, fixture = _prepare_image("ENG", pinned_profile, city_count=27)
    reader = _MutateTerritoryOnSecondRead(
        image, fixture["target_pointer"] + territory.CITY_COUNT_CACHE_OFFSET)
    observation = capture._observe(reader, MODULE_BASE, "ENG", pinned_profile,
                                   expected_creation=CREATION)
    assert observation["stable"] is True
    target = observation["backend"]["targets"][0]
    assert target["fields"][territory.FIELD_ID]["status"] == "unknown"
    assert target["field_consistency"][territory.FIELD_ID]["status"] == "changed"
    assert target["fields"][development.FIELD_DEVELOPMENT]["status"] == "known"
    assert target["fields"][development.FIELD_SUBJECT_SCALE]["status"] == "known"
    assert target["fields"][flag.FIELD_ID]["status"] == "known"
    assert target["fields"][wars.FIELD_WARS]["status"] == "known"

    report, context, creation, _fixture = _bundle(profile=pinned_profile)
    report["observation"] = observation
    report["raw_reads"] = deepcopy(reader.read_log)
    report["access"]["calls"] = reader.calls
    report["access"]["bytes_requested"] = reader.bytes_requested
    assert _valid(report, context, creation)


class _FailTerritoryReadOnce(parent_fixture.RecordingReader):
    def __init__(self, source: Any):
        super().__init__(source)
        self.failed = False

    def read(self, address: int, size: int, label: str) -> bytes:
        if label == "country_territory.city_count.cache_i32" and not self.failed:
            self.failed = True
            self.read_log.append({
                "address": hex(address), "size": size, "label": label,
                "status": "error", "error": "synthetic_territory_read_failure",
            })
            self.bytes_requested += size
            self.calls += 1
            raise OSError("synthetic source read failure")
        return super().read(address, size, label)


def test_territory_read_failure_is_replayed_without_losing_other_fields(pinned_profile):
    report, context, creation, _fixture = _bundle(
        profile=pinned_profile, reader_type=_FailTerritoryReadOnce)
    observation = report["observation"]
    target = observation["backend"]["targets"][0]
    assert observation["stable"] is True
    assert observation["read_failures"] == [{
        "address": next(row["address"] for row in report["raw_reads"]
                        if row["label"] == "country_territory.city_count.cache_i32"
                        and row["status"] == "error"),
        "size": 4, "label": "country_territory.city_count.cache_i32",
        "status": "error", "error": "synthetic_territory_read_failure",
    }]
    assert target["fields"][territory.FIELD_ID]["status"] == "unknown"
    assert target["fields"][development.FIELD_DEVELOPMENT]["status"] == "known"
    assert target["fields"][development.FIELD_SUBJECT_SCALE]["status"] == "known"
    assert target["fields"][flag.FIELD_ID]["status"] == "known"
    assert target["fields"][wars.FIELD_WARS]["status"] == "known"
    assert _valid(report, context, creation)


class _MutateWarsOnSecondRead(parent_fixture.RecordingReader):
    def __init__(self, source: Any):
        super().__init__(source)
        self.count = 0

    def read(self, address: int, size: int, label: str) -> bytes:
        if label == "country_wars.target.at_war":
            self.count += 1
            if self.count == 2:
                self.source.put(address, b"\x00")
        return super().read(address, size, label)


def test_war_field_change_retracts_only_wars_and_replays(pinned_profile):
    report, context, creation, _fixture = _bundle(
        profile=pinned_profile, reader_type=_MutateWarsOnSecondRead)
    target = report["observation"]["backend"]["targets"][0]
    assert report["observation"]["stable"] is True
    assert target["fields"][wars.FIELD_WARS]["status"] == "unknown"
    assert target["field_consistency"][wars.FIELD_WARS]["status"] == "changed"
    assert target["fields"][development.FIELD_DEVELOPMENT]["status"] == "known"
    assert target["fields"][development.FIELD_SUBJECT_SCALE]["status"] == "known"
    assert target["fields"][flag.FIELD_ID]["status"] == "known"
    assert target["fields"][territory.FIELD_ID]["status"] == "known"
    assert _valid(report, context, creation)


def test_held_module_binding_change_retracts_only_wars(pinned_profile):
    unknown = {"status": "unknown", "reason": "OBSERVER_MODULE_BINDING_UNAVAILABLE"}
    changed = {"before": unknown, "after": _bound_module(pinned_profile)}
    report, context, creation, _fixture = _bundle(
        profile=pinned_profile, module_bindings=changed)
    observation = report["observation"]
    target = observation["backend"]["targets"][0]
    assert observation["observer_module_binding"]["consistency"] == "changed"
    assert target["fields"][wars.FIELD_WARS]["status"] == "unknown"
    assert target["fields"][wars.FIELD_WARS]["reason"] == "observer_module_binding_changed"
    for field in (development.FIELD_DEVELOPMENT, development.FIELD_SUBJECT_SCALE,
                  flag.FIELD_ID, territory.FIELD_ID):
        assert target["fields"][field]["status"] == "known"
    assert _valid(report, context, creation)


def test_validator_replays_recorded_metadata_without_os_enumeration(monkeypatch,
                                                                   positive_capture):
    report, context, creation, _fixture = positive_capture

    def forbidden(*_args, **_kwargs):
        raise AssertionError("validate_capture must not enumerate process modules")

    monkeypatch.setattr(capture._module_binding, "from_held_reader", forbidden)
    assert _valid(report, context, creation)


def test_registry_reader_receives_installation_creation_for_both_passes(
        monkeypatch, pinned_profile):
    seen: list[int] = []

    def registry(_reader: Any, _base: int, *, binding: Any,
                 layout: Any, expected_creation: int) -> dict[str, Any]:
        assert binding == {"status": "unknown",
                           "reason": "OBSERVER_MODULE_BINDING_UNAVAILABLE"}
        assert layout == pinned_profile["observer_registry"]
        seen.append(expected_creation)
        return {"status": "unknown", "reason": "SYNTHETIC_REGISTRY_UNAVAILABLE"}

    monkeypatch.setattr(capture._registry, "read_registry", registry)
    report, context, creation, _fixture = _bundle(profile=pinned_profile)
    assert seen == [CREATION, CREATION]
    assert _valid(report, context, creation)
    assert seen == [CREATION, CREATION, CREATION, CREATION]


def test_positive_registry_id_survives_json_roundtrip_and_binds_creation_epoch(
        pinned_profile):
    report, context, creation, fixture = _bundle(
        profile=pinned_profile, registry_id=True)
    target = report["observation"]["backend"]["targets"][0]
    war_field = target["fields"][wars.FIELD_WARS]
    assert war_field["status"] == "known"
    assert war_field["value"]["wars"][0]["war_id"] == {
        "status": "known", "value": fixture["registry_id"],
        "identity_scope": "observer_session", "lifetime_verified": False,
    }

    roundtripped = json.loads(json.dumps(report, ensure_ascii=False))
    assert _valid(roundtripped, context, creation)

    changed_epoch = deepcopy(roundtripped)
    changed_epoch["request"]["creation_filetime"] = creation + 1
    changed_epoch["identity"]["process_creation_filetime"] = creation + 1
    changed_epoch["identity_after"]["process_creation_filetime"] = creation + 1
    assert not _valid(changed_epoch, context, creation + 1)


def test_validator_rejects_module_binding_path_base_and_creation_tampering(
        pinned_profile, positive_capture):
    report, context, creation, _fixture = positive_capture

    invalid_path = deepcopy(report)
    invalid_path["observation"]["observer_module_binding"]["after"] = _bound_module(
        pinned_profile)
    invalid_path["observation"]["observer_module_binding"]["after"]["observed_path"] = (
        "C:/wrong/observer.dll")
    invalid_path["observation"]["observer_module_binding"]["consistency"] = "changed"
    assert not _valid(invalid_path, context, creation)

    changed_replay_base = deepcopy(report)
    bound = _bound_module(pinned_profile)
    metadata = changed_replay_base["observation"]["observer_module_binding"]
    metadata["before"] = deepcopy(bound)
    metadata["after"] = deepcopy(bound)
    metadata["consistency"] = "stable"
    assert not _valid(changed_replay_base, context, creation)
    assert not _valid(report, context, creation + 1)


def test_module_metadata_consistency_enum_is_exact(positive_capture):
    report, context, creation, _fixture = positive_capture
    altered = deepcopy(report)
    altered["observation"]["observer_module_binding"]["consistency"] = True
    assert not _valid(altered, context, creation)


@pytest.mark.parametrize("tamper", ["field_value", "trace_raw", "role", "date", "session", "wrong_country"])
def test_validator_rejects_trace_projection_identity_and_context_tampering(
        positive_capture, tamper):
    report, context, creation, _fixture = positive_capture
    report = deepcopy(report)
    context = deepcopy(context)
    if tamper == "field_value":
        report["observation"]["backend"]["targets"][0]["fields"][
            development.FIELD_DEVELOPMENT]["value"] = 124
    elif tamper == "trace_raw":
        row = next(item for item in report["raw_reads"]
                   if item["label"] == "country_scale.development.own_i32")
        row["raw_hex"] = "00000000"
    elif tamper == "role":
        report["observation"]["backend"]["targets"][0]["admission_by_pass"][
            "pass1"]["observer_nonplayer_role"]["verified"] = False
    elif tamper == "date":
        context["game_date"] += 1
    elif tamper == "session":
        context["session_id"] = "different-session"
    else:
        assert not _valid(report, context, creation, "POR")
        return
    assert not _valid(report, context, creation)


def test_access_and_cleanup_metadata_are_strictly_validated(positive_capture):
    report, context, creation, _fixture = positive_capture
    for section, key, value in (("access", "calls", report["access"]["calls"] + 1),
                                ("access", "read_only", False),
                                ("cleanup", "success", False),
                                ("cleanup", "closed", False)):
        altered = deepcopy(report)
        altered[section][key] = value
        assert not _valid(altered, context, creation)


def _capture_with_fake_process(monkeypatch, profile, image, *, close_ok: bool):
    class FakeKernel:
        def __init__(self):
            self.open_calls = self.close_calls = 0

        def OpenProcess(self, _access, _inherit, _pid):
            self.open_calls += 1
            return object()

        def CloseHandle(self, _handle):
            self.close_calls += 1
            return close_ok

    kernel = FakeKernel()
    document = {"pid": 777, "creation_filetime": CREATION,
                "session_id": SESSION_ID, "game_sha256": capture._owner.EXE_SHA256}
    monkeypatch.setattr(capture, "_load_profile", lambda: deepcopy(profile))
    monkeypatch.setattr(capture._owner._identity, "_load_installation", lambda _path: dict(document))
    monkeypatch.setattr(capture._owner._identity, "_configure_kernel", lambda: kernel)

    def fake_identity(target_report, _document, _kernel, _handle):
        target_report["identity"].update({
            "binding_verified": True,
            "process_creation_filetime": CREATION,
            "process_path": "synthetic-eu4.exe",
            "process_path_sha256": capture._owner.EXE_SHA256,
        })
        return MODULE_BASE

    monkeypatch.setattr(capture._owner._identity, "_capture_identity", fake_identity)
    expected = {int(item["rva"], 0): bytes.fromhex(item["bytes"])
                for item in profile["code_guards"]}
    monkeypatch.setattr(capture._owner._mm, "_read_pe_rva_bytes",
                        lambda _path, rva, size: expected[rva][:size])
    readers = []

    def fake_rpm(_kernel, _handle, _base):
        reader = parent_fixture.RecordingReader(image)
        readers.append(reader)
        return reader

    monkeypatch.setattr(capture._owner._parent, "AddressBoundedRPM", fake_rpm)
    report = capture.capture(Path("synthetic-installation.json"), "ENG")
    return report, kernel, readers


def test_capture_closes_fake_readonly_handle_and_validates_ordered_trace(monkeypatch,
                                                                        pinned_profile):
    image, _fixture = _prepare_image("ENG", pinned_profile)
    module_observations: list[Any] = []

    def record_held_reader(reader: Any, _descriptor: dict[str, Any]) -> dict[str, str]:
        module_observations.append(reader)
        return {"status": "unknown", "reason": "OBSERVER_MODULE_BINDING_UNAVAILABLE"}

    monkeypatch.setattr(capture._module_binding, "from_held_reader", record_held_reader)
    report, kernel, readers = _capture_with_fake_process(
        monkeypatch, pinned_profile, image, close_ok=True)
    assert kernel.open_calls == 1 and kernel.close_calls == 1
    assert report["status"] == "observed" and report["completed"] is True
    assert len(module_observations) == 2
    assert all(isinstance(item, capture._owner._FailureReplayReader)
               and item.reader is readers[0] for item in module_observations)
    context = {"observer": "FRA", "session_id": SESSION_ID,
               "game_version": "1.37.4", "game_sha256": capture._owner.EXE_SHA256,
               "game_date": GAME_DATE}
    assert capture.validate_capture(report, context, CREATION, "ENG")
    assert readers and readers[0].read_log == report["raw_reads"]


def test_pinned_registry_record_replays_with_a_new_current_selector(monkeypatch, pinned_profile):
    report, context, creation, _fixture = _bundle(profile=pinned_profile, registry_id=True)
    current = deepcopy(pinned_profile['observer_registry'])
    current['module_file']['path'] = 'work/runtime/current-observer/observer.dll'
    monkeypatch.setattr(capture._registry_layout, 'descriptor_for_installation',
                        lambda _installation: current)
    assert capture.validate_capture(report, context, creation, 'ENG')


def test_current_descriptor_reaches_capture_registry_and_trace_replay(monkeypatch, pinned_profile):
    image, _fixture = _prepare_image('ENG', pinned_profile)
    descriptor = deepcopy(pinned_profile['observer_registry'])
    descriptor['module_file'] = {
        'path': 'work/runtime/current-observer/observer.dll',
        'bytes': 1234, 'sha256': 'a' * 64,
    }
    current_profile = dict(pinned_profile, observer_registry=descriptor)
    identifier = _install_observer_registry(image, current_profile, CREATION)
    observed_descriptors = []

    def held_binding(_reader, selected):
        observed_descriptors.append(deepcopy(selected))
        return _bound_module(current_profile)

    monkeypatch.setattr(capture._registry_layout, 'descriptor_for_installation',
                        lambda _installation: deepcopy(descriptor))
    monkeypatch.setattr(capture._module_binding, 'from_held_reader', held_binding)
    report, kernel, _readers = _capture_with_fake_process(
        monkeypatch, pinned_profile, image, close_ok=True)
    assert report['completed'] and kernel.close_calls == 1
    assert observed_descriptors == [descriptor, descriptor]
    observed_wars = report['observation']['backend']['targets'][0]['fields'][wars.FIELD_WARS]
    assert observed_wars['value']['wars'][0]['war_id']['value'] == identifier
    context = {'observer': 'FRA', 'session_id': SESSION_ID,
               'game_version': '1.37.4', 'game_sha256': capture._owner.EXE_SHA256,
               'game_date': GAME_DATE}
    assert capture.validate_capture(report, context, CREATION, 'ENG')


def test_invalid_request_does_not_enumerate_observer_module(monkeypatch, pinned_profile):
    module_calls: list[Any] = []
    monkeypatch.setattr(capture, "_load_profile", lambda: deepcopy(pinned_profile))
    monkeypatch.setattr(capture._owner._identity, "_load_installation",
                        lambda _path: {"pid": 777, "creation_filetime": CREATION,
                                       "session_id": SESSION_ID})
    monkeypatch.setattr(capture._module_binding, "from_held_reader",
                        lambda reader, descriptor: module_calls.append((reader, descriptor)))
    report = capture.capture(Path("synthetic-installation.json"), "not-a-tag")
    assert report["status"] == "unknown"
    assert module_calls == []


def test_closehandle_failure_retracts_capture(monkeypatch, pinned_profile):
    image, _fixture = _prepare_image("ENG", pinned_profile)
    report, kernel, _readers = _capture_with_fake_process(
        monkeypatch, pinned_profile, image, close_ok=False)
    assert kernel.open_calls == 1 and kernel.close_calls == 1
    assert report["status"] == "unknown" and report["completed"] is False
    assert report["cleanup"]["status"] != "closed"

