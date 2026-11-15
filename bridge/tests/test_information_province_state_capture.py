"""Synthetic identity and trace replay tests for province-state capture.

All memory reads use a byte-addressed fake image. These tests exercise the
parent capture and validator contracts without opening a process or touching a
game installation.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from bridge.information import province_state_capture as capture
from bridge.information import province_state_memory as backend
from bridge.information import localization_memory as localization
from bridge.tests import test_information_foreign_technology_capture as owner_fixture
from bridge.tests import test_information_province_state_memory as state_fixture


MODULE_BASE = state_fixture.BASES[0]
WORLD = state_fixture.WORLD
GAME_DATE = 56_564_448
CREATION = 134376782534496994
SESSION_ID = "province-state-capture-session"
PROVINCE_ID = state_fixture.PROVINCE_ID
LOCALIZATION_OUTER = 0x6200000000
LOCALIZATION_INNER = 0x6200010000
LOCALIZATION_TABLE = 0x6200020000
LOCALIZATION_POOL = 0x6200030000


def test_python_evidence_version_does_not_reject_runtime_profile(monkeypatch):
    original_sha = capture._owner._sha

    def checked_sha(path):
        assert Path(path).suffix != ".py"
        return original_sha(path)

    monkeypatch.setattr(capture._owner, "_sha", checked_sha)
    assert capture._load_profile()["profile_id"] == "province-state-memory-1374"


def test_runtime_layout_evidence_hash_remains_required(monkeypatch):
    profile = json.loads(capture.PROFILE_FILE.read_text(encoding="utf-8"))
    dependency = next(item for item in profile["source_evidence"] + profile["layout_dependencies"]
                      if Path(item["path"]).suffix != ".py")
    target = (capture.ROOT / dependency["path"]).resolve()
    original_sha = capture._owner._sha

    def changed_sha(path):
        return "0" * 64 if Path(path).resolve() == target else original_sha(path)

    monkeypatch.setattr(capture._owner, "_sha", changed_sha)
    with pytest.raises(ValueError, match="PROVINCE_PROFILE_DEPENDENCY"):
        capture._load_profile()


@pytest.mark.parametrize('proof', ['valid', 'tampered_frozen', 'no_frozen'])
def test_native_source_revision_uses_its_pinned_build_copy(monkeypatch, tmp_path, proof):
    profile = json.loads(capture.PROFILE_FILE.read_bytes())
    live = capture.ROOT / 'work/native/peace-context-query.inc'
    frozen = next(item for item in profile['layout_dependencies']
                  if item['path'].startswith('work/runtime/')
                  and Path(item['path']).name == live.name)
    frozen_path = (capture.ROOT / frozen['path']).resolve()
    if proof == 'no_frozen':
        profile['layout_dependencies'].remove(frozen)
        raw = json.dumps(profile).encode()
        profile_path = tmp_path / 'profile.json'
        profile_path.write_bytes(raw)
        monkeypatch.setattr(capture, 'PROFILE_FILE', profile_path)
        monkeypatch.setattr(capture, 'PROFILE_SHA256', hashlib.sha256(raw).hexdigest())
    original_sha = capture._owner._sha
    hashed = []

    def checked_sha(path):
        path = Path(path).resolve()
        hashed.append(path)
        if path == live.resolve() or (proof == 'tampered_frozen' and path == frozen_path):
            return '0' * 64
        return original_sha(path)

    monkeypatch.setattr(capture._owner, '_sha', checked_sha)
    if proof == 'valid':
        assert capture._load_profile()['profile_id'] == 'province-state-memory-1374'
        assert frozen_path in hashed and live.resolve() not in hashed
    else:
        with pytest.raises(ValueError, match='PROVINCE_PROFILE_DEPENDENCY'):
            capture._load_profile()


class MutatingReader(owner_fixture.RecordingReader):
    """Return a different value for one ordered read without editing the image."""
    def __init__(self, source: Any, *, label: str, occurrence: int,
                 replacement: bytes):
        super().__init__(source)
        self.label = label
        self.occurrence = occurrence
        self.replacement = replacement
        self.seen = 0

    def read(self, address: int, size: int, label: str) -> bytes:
        raw = self.source.read(address, size, label)
        if label == self.label:
            self.seen += 1
            if self.seen == self.occurrence:
                raw = self.replacement
        self.read_log.append({
            "address": hex(address), "size": size, "label": label,
            "status": "observed", "raw_hex": raw.hex(),
        })
        self.bytes_requested += size
        self.calls += 1
        return raw


class ErrorRecordingReader(owner_fixture.RecordingReader):
    """Record an AddressBoundedRPM-shaped error row and raise for that read."""
    def __init__(self, source: Any, fail_label: str):
        super().__init__(source)
        self.fail_label = fail_label

    def read(self, address: int, size: int, label: str) -> bytes:
        if label == self.fail_label:
            self.read_log.append({
                "address": hex(address), "size": size, "label": label,
                "status": "error", "error": "synthetic read failure",
            })
            self.bytes_requested += size
            self.calls += 1
            raise OSError("synthetic read failure")
        return super().read(address, size, label)


def _fullref(tag: str, slot: int, generation: int = 0x5500) -> int:
    low = int.from_bytes(tag.encode("ascii") + b"\x00", "little")
    return ((generation & 0xFFFF) << 48) | (slot << 32) | low


def _write_context(image: Any) -> dict[str, int]:
    physical_ref = _fullref("POR", 189)
    image.put_i32(WORLD + 0x1DD0, GAME_DATE)
    image.put_u64(WORLD + 0x1E60, physical_ref)
    # Current context is default-reference mode; its alternate cell is zero.
    image.put_u64(WORLD + 0x1E68, 0)
    return {"physical_fullref": physical_ref}


def _install_localization_cache(image: Any, values: dict[str, bytes] | None = None,
                                *, language: str = "l_english") -> None:
    values = {"cloth": b"Cloth"} if values is None else values
    offsets: dict[str, int] = {}
    cursor = 0
    for key, value in values.items():
        offsets[key] = cursor
        image.put(LOCALIZATION_POOL + cursor, value + b"\x00")
        cursor += len(value) + 1

    image.put_u64(MODULE_BASE + localization.LOCALIZATION_GLOBAL_CELL_RVA,
                  LOCALIZATION_OUTER)
    image.put_u64(LOCALIZATION_OUTER + localization.OUTER_INNER_OFFSET,
                  LOCALIZATION_INNER)
    image.put_u64(LOCALIZATION_OUTER + localization.POOL_BEGIN_OFFSET,
                  LOCALIZATION_POOL)
    image.put_u64(LOCALIZATION_OUTER + localization.POOL_END_OFFSET,
                  LOCALIZATION_POOL + cursor)
    image.put_u64(LOCALIZATION_OUTER + localization.POOL_CAPACITY_END_OFFSET,
                  LOCALIZATION_POOL + cursor + 0x100)

    language_raw = language.encode("ascii") + b"\x00"
    language_header = bytearray(32)
    language_header[:len(language_raw)] = language_raw
    image.put(LOCALIZATION_INNER + localization.INNER_LANGUAGE_OFFSET,
              bytes(language_header))
    image.put_u64(LOCALIZATION_INNER + localization.INNER_LANGUAGE_OFFSET + 0x10,
                  len(language))
    image.put_u64(LOCALIZATION_INNER + localization.INNER_LANGUAGE_OFFSET + 0x18,
                  max(1, len(language)))

    entries = sorted((localization._fnv1_ascii(key), offsets[key])
                     for key in values)
    table_end = LOCALIZATION_TABLE + len(entries) * localization.TABLE_ENTRY_STRIDE
    image.put_u64(LOCALIZATION_INNER + localization.INNER_TABLE_BEGIN_OFFSET,
                  LOCALIZATION_TABLE if entries else 0)
    image.put_u64(LOCALIZATION_INNER + localization.INNER_TABLE_END_OFFSET,
                  table_end if entries else 0)
    image.put_u64(LOCALIZATION_INNER + localization.INNER_TABLE_CAPACITY_OFFSET,
                  table_end + 2 * localization.TABLE_ENTRY_STRIDE if entries else 0)
    for index, (hash_value, offset) in enumerate(entries):
        entry = LOCALIZATION_TABLE + index * localization.TABLE_ENTRY_STRIDE
        image.put_u64(entry + localization.TABLE_ENTRY_HASH_OFFSET, hash_value)
        image.put_u64(entry + localization.TABLE_ENTRY_OFFSET_OFFSET, offset)


def _make_image(profile: dict[str, Any], *, discovered: bool = True,
                localized_values: dict[str, bytes] | None = None):
    image = state_fixture.make_image(base=MODULE_BASE, discovered=discovered)
    record=state_fixture.RECORDS + PROVINCE_ID*0x2e10
    culture,religion=0x5D00000000,0x5E00000000
    image.put_u64(record+0x440,culture)
    image.put_u64(record+0x448,religion)
    for address,text in ((culture+0x68,b'francien'),(religion+0xb0,b'catholic')):
        image.put(address,text+b'\0'+bytes(15-len(text)))
        image.put_u64(address+0x10,len(text));image.put_u64(address+0x18,15)
    image.put_i32(religion+0x570,1)
    image.put_i32(record+0x428,25000)
    image.put_i32(record+0x2df0,10000)
    image.put_i32(record+0x2df4,100000)
    image.put_i32(record+0x3e4,2000)
    image.put_i32(record+0x3e8,3000)
    image.put_i32(record+0x3e0,4000)
    resource,center,definition=0x5F00000000,0x6000000000,0x6100000000
    image.put_u64(record+0x458,resource)
    image.put(resource+0x18,b'cloth\0'+bytes(10))
    image.put_u64(resource+0x28,5);image.put_u64(resource+0x30,15)
    image.put_i32(resource+0x78,4)
    image.put_u64(record+0x960,center);image.put_u64(center+8,definition)
    image.put_i32(definition+0x10,1);image.put_i32(definition+0x14,2)
    refs = _write_context(image)
    _install_localization_cache(image, localized_values)
    for guard in profile["code_guards"]:
        image.put(MODULE_BASE + int(guard["rva"], 0), bytes.fromhex(guard["bytes"]))
    return image, refs


def _context() -> dict[str, Any]:
    return {
        "observer": "FRA",
        "session_id": SESSION_ID,
        "game_version": "1.37.4",
        "game_sha256": capture._owner.EXE_SHA256,
        "game_date": GAME_DATE,
    }


def _bundle(profile: dict[str, Any], *, province_id: int = PROVINCE_ID,
            discovered: bool = True, reader_factory=None,
            localized_values: dict[str, bytes] | None = None):
    image, refs = _make_image(profile, discovered=discovered,
                              localized_values=localized_values)
    reader = (owner_fixture.RecordingReader(image) if reader_factory is None
              else reader_factory(image))
    failure_reader = capture._owner._FailureReplayReader(reader)
    observation = capture._observe_for(province_id)(
        failure_reader, MODULE_BASE, "FRA", profile)
    identity = {
        "binding_verified": True,
        "process_creation_filetime": CREATION,
        "process_path": "synthetic-eu4.exe",
        "process_path_sha256": capture._owner.EXE_SHA256,
    }
    inner = {
        "schema": capture.INNER_SCHEMA,
        "status": "observed" if observation.get("stable") is True else "unknown",
        "completed": observation.get("stable") is True,
        "request": {
            "country": "FRA",
            "observer": "FRA",
            "installation": "synthetic-installation.json",
            "creation_filetime": CREATION,
            "session_id": SESSION_ID,
        },
        "profile_sha256": capture.PROFILE_SHA256,
        "identity": deepcopy(identity),
        "identity_after": deepcopy(identity),
        "module_base": hex(MODULE_BASE),
        "observation": observation,
        "raw_reads": deepcopy(reader.read_log),
        "access": {
            "read_only": True,
            "native_function_invoked": False,
            "writes": False,
            "UI_control": False,
            "date_advance": False,
            "save_or_reload": False,
            "limit_bytes": capture._owner.MAX_READ_BYTES,
            "bytes_requested": reader.bytes_requested,
            "calls": reader.calls,
        },
        "cleanup": {"status": "closed", "closed": True, "success": True},
        "errors": [],
    }
    packet = {
        "schema": capture.SCHEMA,
        "observer": "FRA",
        "object": {"type": "province", "province_id": province_id},
        "capture": inner,
    }
    return packet, _context(), CREATION, {"image": image, "reader": reader, **refs}


@pytest.fixture(scope="module")
def pinned_profile():
    return capture._load_profile()


@pytest.fixture(scope="module")
def positive_capture(pinned_profile):
    return _bundle(pinned_profile)


def _valid(packet: dict[str, Any], context: dict[str, Any], creation: int,
           province_id: int = PROVINCE_ID) -> bool:
    return capture.validate_capture(packet, context, creation, province_id)


def _fields(packet: dict[str, Any]) -> dict[str, Any]:
    return packet["capture"]["observation"]["backend"]["targets"][0]["fields"]


def test_capture_replays_discovered_owner_and_controller_with_por_physical_context(
        positive_capture):
    packet, context, creation, fixture = positive_capture

    assert _valid(packet, context, creation)
    assert packet["schema"] == capture.SCHEMA
    assert packet["object"] == {"type": "province", "province_id": PROVINCE_ID}
    inner = packet["capture"]
    assert inner["status"] == "observed" and inner["completed"] is True
    observation = inner["observation"]
    assert observation["stable"] is True
    assert observation["context_before"]["game_date"] == GAME_DATE
    assert observation["context_before"]["physical_client_reference_raw_hex"] == (
        fixture["physical_fullref"].to_bytes(8, "little").hex())
    assert observation["context_before"]["client_mode"] == 0
    assert observation["context_before"]["client_override"] == 0
    backend_result = observation["backend"]
    assert backend_result["observer"]["tag"] == "FRA"
    assert backend_result["targets"][0]["province_id"] == PROVINCE_ID
    assert _fields(packet)["G02.owner"]["status"] == "known"
    assert _fields(packet)["G02.owner"]["value"] == "ENG"
    assert _fields(packet)["G02.controller"]["status"] == "known"
    assert _fields(packet)["G02.controller"]["value"] == "SWE"
    assert _fields(packet)["G02.culture"]["value"]["name"]["text"] == "francien"
    assert _fields(packet)["G02.religion"]["value"]["name"]["text"] == "catholic"
    assert _fields(packet)["G02.religion"]["value"]["icon_frame_request"] == 1
    assert _fields(packet)["G02.autonomy"]["value"] == 25000
    assert _fields(packet)['G02.development']['value']==9000
    assert _fields(packet)['G02.resource']['value']=={
        'localization_key':'cloth','icon_index':4,
        'name':{'status':'known','raw_hex':b'Cloth'.hex(),'language':'l_english'}}
    assert _fields(packet)['G02.center_of_trade']['value']=={'present':True,'level':2,'kind':'coastal',
        'sprite_key':'GFX_center_of_trade_coastal_2'}
    assert backend_result["visibility"]["status"] == "unknown"
    assert backend_result["complete"] is False
    assert backend_result["public_export_ready"] is False
    assert all(row["status"] == "observed" for row in inner["raw_reads"])
    id_rows = [row for row in inner["raw_reads"]
               if row["label"] == f"province_reference.id[{PROVINCE_ID}]"]
    assert len(id_rows) == 2
    assert all(row["raw_hex"] == "01000000" for row in id_rows)


def test_clear_discovery_bit_is_a_valid_unknown_capture_and_short_circuits_fields(
        pinned_profile):
    packet, context, creation, _fixture = _bundle(
        pinned_profile, discovered=False)

    assert _valid(packet, context, creation)
    assert packet["capture"]["observation"]["stable"] is True
    fields = _fields(packet)
    assert fields["G02.owner"]["status"] == "unknown"
    assert fields["G02.owner"]["reason"] == "PROVINCE_DISCOVERY_NOT_ESTABLISHED"
    assert fields["G02.controller"]["reason"] == "PROVINCE_DISCOVERY_NOT_ESTABLISHED"
    assert set(fields)==set(capture._details.FIELDS)
    assert all(item['status']=='unknown' and 'value' not in item for item in fields.values())
    assert not any(row["label"].startswith("province_state.G02.")
                   for row in packet["capture"]["raw_reads"])
    assert not any(row['label'].startswith(('province_identity.','province_scalar.',
                    'province_development.','province_resource.','province_cot.','province_state.development_owner.'))
                   for row in packet['capture']['raw_reads'])
    assert not any(row['label'].startswith('localization.')
                   for row in packet['capture']['raw_reads'])


@pytest.mark.parametrize("case", ["outer_bool", "outer_wrong_id", "inner_id_raw", "inner_binding"])
def test_outer_object_and_inner_trace_bind_the_same_integer_province_id(
        positive_capture, case: str):
    packet, context, creation, _fixture = positive_capture
    packet = deepcopy(packet)
    if case == "outer_bool":
        packet["object"]["province_id"] = True
        assert not _valid(packet, context, creation, PROVINCE_ID)
    elif case == "outer_wrong_id":
        packet["object"]["province_id"] = PROVINCE_ID + 1
        assert not _valid(packet, context, creation, PROVINCE_ID + 1)
    elif case == "inner_id_raw":
        row = next(row for row in packet["capture"]["raw_reads"]
                   if row["label"] == f"province_reference.id[{PROVINCE_ID}]")
        row["raw_hex"] = "02000000"
        assert not _valid(packet, context, creation)
    else:
        packet["capture"]["observation"]["backend"]["targets"][0][
            "bindings_by_pass"]["pass1"]["province"]["record_id"] = PROVINCE_ID + 1
        assert not _valid(packet, context, creation)


@pytest.mark.parametrize("province_id", [True, 0, 65536])
def test_capture_entrypoint_rejects_noncanonical_or_out_of_range_ids(province_id):
    with pytest.raises(ValueError, match="PROVINCE_REQUEST_SCOPE"):
        capture.capture(Path("synthetic-installation.json"), province_id)


@pytest.mark.parametrize("field", backend.FIELDS)
def test_field_change_is_replayed_as_field_local_unknown(field: str, pinned_profile):
    label = f"province_state.{field}.province_fullref"
    changed_ref = state_fixture._fullref("DEN", state_fixture.DEN_SLOT)
    reader_factory = lambda image: MutatingReader(
        image, label=label, occurrence=2,
        replacement=changed_ref.to_bytes(8, "little"))
    packet, context, creation, _fixture = _bundle(
        pinned_profile, reader_factory=reader_factory)

    assert _valid(packet, context, creation)
    changed = _fields(packet)[field]
    other = "G02.controller" if field == "G02.owner" else "G02.owner"
    assert changed["status"] == "unknown"
    assert changed["reason"] == "FIELD_RAW_DATA_CHANGED"
    assert _fields(packet)[other]["status"] == "known"


@pytest.mark.parametrize("tamper", [
    "profile", "runtime_guard", "field_value", "role", "date", "session",
    "creation", "physical_ref", "cleanup_status", "cleanup_closed", "access_calls",
    "access_bytes", "access_limit",
])
def test_capture_validator_rejects_identity_metadata_and_projection_tampering(
        positive_capture, tamper: str):
    packet, context, creation, _fixture = positive_capture
    packet = deepcopy(packet)
    context = deepcopy(context)
    inner = packet["capture"]
    if tamper == "profile":
        inner["profile_sha256"] = "0" * 64
    elif tamper == "runtime_guard":
        row = next(row for row in inner["raw_reads"]
                   if row["label"].startswith("foreign_tech.code."))
        raw = bytearray.fromhex(row["raw_hex"])
        raw[0] ^= 1
        row["raw_hex"] = raw.hex()
    elif tamper == "field_value":
        inner["observation"]["backend"]["targets"][0]["fields"][
            "G02.owner"]["value"] = "FRA"
    elif tamper == "role":
        inner["observation"]["backend"]["targets"][0]["admission_by_pass"][
            "pass1"]["observer_nonplayer_role"]["verified"] = False
    elif tamper == "date":
        context["game_date"] += 1
    elif tamper == "session":
        context["session_id"] = "different-session"
    elif tamper == "creation":
        creation += 1
    elif tamper == "physical_ref":
        inner["observation"]["context_before"][
            "physical_client_reference_raw_hex"] = _fullref("FRA", 3, 0x1200).to_bytes(
                8, "little").hex()
    elif tamper == "cleanup_status":
        inner["cleanup"]["status"] = "open"
    elif tamper == "cleanup_closed":
        inner["cleanup"]["closed"] = False
    elif tamper == "access_calls":
        inner["access"]["calls"] += 1
    elif tamper == "access_bytes":
        inner["access"]["bytes_requested"] += 1
    elif tamper == "access_limit":
        inner["access"]["bytes_requested"] = capture._owner.MAX_READ_BYTES + 1

    assert not _valid(packet, context, creation)


def test_validator_rejects_profile_with_changed_source_guard(positive_capture,
                                                             pinned_profile,
                                                             monkeypatch):
    packet, context, creation, _fixture = positive_capture
    changed_profile = deepcopy(pinned_profile)
    first = changed_profile["code_guards"][0]
    raw = bytearray.fromhex(first["bytes"])
    raw[0] ^= 1
    first["bytes"] = raw.hex()
    monkeypatch.setattr(capture, "_load_profile", lambda: changed_profile)
    assert not _valid(packet, context, creation)


def test_failed_field_reads_are_trace_normalized_and_leave_other_field_known(
        pinned_profile):
    fail_label = "province_state.G02.owner.province_fullref"
    packet, context, creation, _fixture = _bundle(
        pinned_profile,
        reader_factory=lambda image: ErrorRecordingReader(image, fail_label))

    assert packet["capture"]["observation"]["stable"] is True
    assert _valid(packet, context, creation)
    assert _fields(packet)["G02.owner"]["status"] == "unknown"
    assert _fields(packet)["G02.controller"]["status"] == "known"
    failures = [row for row in packet["capture"]["raw_reads"]
                if row.get("status") == "error"]
    assert len(failures) == 2
    assert all(row["label"] == fail_label and "raw_hex" not in row for row in failures)

    altered = deepcopy(packet)
    altered_failure = next(row for row in altered["capture"]["raw_reads"]
                           if row.get("status") == "error")
    altered_failure["error"] = "different failure reason"
    assert not _valid(altered, context, creation)


@pytest.mark.parametrize('field',('G02.culture','G02.religion','G02.autonomy'))
def test_validator_rebuilds_all_three_new_field_values(positive_capture,field):
    packet,context,creation,_=positive_capture
    packet=deepcopy(packet)
    item=_fields(packet)[field]
    if field=='G02.autonomy':item['value']+=1
    else:item['value']['name']['text']='forged'
    assert not _valid(packet,context,creation)


@pytest.mark.parametrize('field,label',(
    ('G02.culture','province_identity.culture.String32_header'),
    ('G02.religion','province_identity.religion.icon_frame_request'),
    ('G02.autonomy',f'province_scalar.autonomy.current[{PROVINCE_ID}]')))
def test_failed_new_leaf_read_replays_without_withdrawing_other_fields(pinned_profile,field,label):
    packet,context,creation,_=_bundle(pinned_profile,
        reader_factory=lambda image:ErrorRecordingReader(image,label))
    assert _valid(packet,context,creation)
    assert _fields(packet)[field]['status']=='unknown'
    assert all(value['status']=='known' for key,value in _fields(packet).items() if key!=field)


@pytest.mark.parametrize('field,label,replacement',(
    ('G02.culture','province_identity.culture.String32_header',
        b'occitan\0'+bytes(8)+(7).to_bytes(8,'little')+(15).to_bytes(8,'little')),
    ('G02.religion','province_identity.religion.icon_frame_request',(2).to_bytes(4,'little')),
    ('G02.autonomy',f'province_scalar.autonomy.current[{PROVINCE_ID}]',(35000).to_bytes(4,'little'))))
def test_new_leaf_raw_change_only_withdraws_the_changed_field(pinned_profile,field,label,replacement):
    packet,context,creation,_=_bundle(pinned_profile,reader_factory=lambda image:
        MutatingReader(image,label=label,occurrence=2,replacement=replacement))
    assert _valid(packet,context,creation)
    assert _fields(packet)[field]['status']=='unknown'
    assert _fields(packet)[field]['reason']=='FIELD_RAW_DATA_CHANGED'
    assert all(value['status']=='known' for key,value in _fields(packet).items() if key!=field)


@pytest.mark.parametrize('field',('G02.development','G02.resource','G02.center_of_trade'))
def test_production_fields_are_rebuilt_from_trace(positive_capture,field):
    packet,context,creation,_=positive_capture;packet=deepcopy(packet)
    value=_fields(packet)[field]['value']
    if field=='G02.development':_fields(packet)[field]['value']+=1
    elif field=='G02.resource':value['localization_key']='forged'
    else:value['level']+=1
    assert not _valid(packet,context,creation)


@pytest.mark.parametrize('field,label',(
    ('G02.development',f'province_development.base.tax[{PROVINCE_ID}]'),
    ('G02.resource','province_resource.String32_header'),
    ('G02.center_of_trade','province_cot.definition_level')))
def test_production_read_failure_only_withdraws_its_field(pinned_profile,field,label):
    packet,context,creation,_=_bundle(pinned_profile,
        reader_factory=lambda image:ErrorRecordingReader(image,label))
    assert _valid(packet,context,creation)
    assert _fields(packet)[field]['status']=='unknown'
    assert all(value['status']=='known' for key,value in _fields(packet).items() if key!=field)


@pytest.mark.parametrize('field,label,replacement',(
    ('G02.development',f'province_development.base.tax[{PROVINCE_ID}]',(5000).to_bytes(4,'little')),
    ('G02.resource','province_resource.icon_index',(5).to_bytes(4,'little')),
    ('G02.center_of_trade','province_cot.definition_level',(3).to_bytes(4,'little'))))
def test_production_field_change_preserves_other_fields(pinned_profile,field,label,replacement):
    packet,context,creation,_=_bundle(pinned_profile,reader_factory=lambda image:
        MutatingReader(image,label=label,occurrence=2,replacement=replacement))
    assert _valid(packet,context,creation)
    assert _fields(packet)[field]['reason']=='FIELD_RAW_DATA_CHANGED'
    assert all(value['status']=='known' for key,value in _fields(packet).items() if key!=field)


def test_null_center_is_known_zero_and_does_not_read_definition(pinned_profile):
    def factory(image):
        image.put_u64(state_fixture.RECORDS+PROVINCE_ID*0x2e10+0x960,0)
        return owner_fixture.RecordingReader(image)
    packet,context,creation,_=_bundle(pinned_profile,reader_factory=factory)
    assert _valid(packet,context,creation)
    assert _fields(packet)['G02.center_of_trade']['value']=={'present':False,'level':0}
    labels=[row['label'] for row in packet['capture']['raw_reads']]
    assert not any(label.startswith('province_cot.definition') for label in labels)


def test_resource_cached_name_is_raw_and_survives_json_capture_roundtrip(pinned_profile):
    packet, context, creation, _fixture = _bundle(pinned_profile)
    restored = json.loads(json.dumps(packet, ensure_ascii=False))

    assert _valid(restored, context, creation)
    item = _fields(restored)['G02.resource']
    assert item['status'] == 'known'
    assert item['value'] == {
        'localization_key': 'cloth', 'icon_index': 4,
        'name': {'status': 'known', 'raw_hex': b'Cloth'.hex(),
                 'language': 'l_english'},
    }
    assert 'text' not in item['value']['name']
    helper = item['raw_inputs']['resource_name_capture']
    assert helper['status'] == 'known'
    assert helper['raw_hex'] == b'Cloth'.hex()
    assert helper['raw_inputs']['snapshot']['entries']['cloth']['native_cached_template'] is True


@pytest.mark.parametrize('payload', [b'$NAME$ [Root.GetName]', b''])
def test_dynamic_or_empty_cached_name_is_preserved_without_decoding(payload, pinned_profile):
    packet, context, creation, _fixture = _bundle(
        pinned_profile, localized_values={'cloth': payload})

    assert _valid(packet, context, creation)
    name = _fields(packet)['G02.resource']['value']['name']
    assert name == {
        'status': 'known', 'raw_hex': payload.hex(), 'language': 'l_english'}
    assert 'text' not in name


def test_missing_localization_key_keeps_resource_key_and_icon_known(pinned_profile):
    packet, context, creation, _fixture = _bundle(
        pinned_profile, localized_values={'grain': b'Grain'})

    assert _valid(packet, context, creation)
    item = _fields(packet)['G02.resource']
    assert item['status'] == 'known'
    assert item['value'] == {
        'localization_key': 'cloth', 'icon_index': 4,
        'name': {'status': 'unknown', 'reason': 'LOCALIZATION_KEY_NOT_FOUND'},
    }
    assert item['raw_inputs']['resource_name_capture']['status'] == 'unknown'


def test_localization_read_failure_only_makes_nested_name_unknown(pinned_profile):
    packet, context, creation, _fixture = _bundle(
        pinned_profile,
        reader_factory=lambda image: ErrorRecordingReader(image, 'localization.outer_header'))

    assert _valid(packet, context, creation)
    item = _fields(packet)['G02.resource']
    assert item['status'] == 'known'
    assert item['value']['localization_key'] == 'cloth'
    assert item['value']['icon_index'] == 4
    assert item['value']['name'] == {
        'status': 'unknown', 'reason': 'LOCALIZATION_SNAPSHOT_INCOMPLETE'}
    assert len([row for row in packet['capture']['raw_reads']
                if row.get('status') == 'error'
                and row['label'] == 'localization.outer_header']) == 2


def test_name_only_change_preserves_stable_key_and_icon_as_partial(pinned_profile):
    packet, context, creation, _fixture = _bundle(
        pinned_profile,
        reader_factory=lambda image: MutatingReader(
            image, label='localization.value[cloth]', occurrence=2,
            replacement=b'Goods\x00'))

    assert _valid(packet, context, creation)
    backend_result = packet['capture']['observation']['backend']
    assert backend_result['consistency'] == {
        'status': 'stable', 'shared_mismatch_paths': []}
    item = _fields(packet)['G02.resource']
    assert item['status'] == 'known'
    assert item['value']['localization_key'] == 'cloth'
    assert item['value']['icon_index'] == 4
    assert item['value']['name'] == {
        'status': 'unknown', 'reason': 'RESOURCE_NAME_CHANGED'}
    assert backend_result['targets'][0]['field_consistency']['G02.resource'] == {
        'status': 'partial', 'base': 'stable', 'name': 'changed',
        'reason': 'RESOURCE_NAME_CHANGED'}


def test_base_resource_change_is_not_reconciled_as_a_name_change(pinned_profile):
    packet, context, creation, _fixture = _bundle(
        pinned_profile,
        reader_factory=lambda image: MutatingReader(
            image, label='province_resource.icon_index', occurrence=2,
            replacement=(5).to_bytes(4, 'little', signed=True)))

    assert _valid(packet, context, creation)
    item = _fields(packet)['G02.resource']
    assert item['status'] == 'unknown'
    assert item['reason'] == 'FIELD_RAW_DATA_CHANGED'
    assert 'value' not in item


def test_shared_discovery_change_cannot_be_reconciled_as_a_name_change(pinned_profile):
    packet, context, creation, _fixture = _bundle(
        pinned_profile,
        reader_factory=lambda image: MutatingReader(
            image, label='province_state.discovery.word_u32', occurrence=2,
            replacement=bytes(4)))

    backend_result = packet['capture']['observation']['backend']
    assert backend_result['consistency']['status'] == 'changed'
    item = _fields(packet)['G02.resource']
    assert item['status'] == 'unknown'
    assert item['reason'] == 'SHARED_EVIDENCE_CHANGED'
    assert 'value' not in item
    assert backend_result['targets'][0]['field_consistency']['G02.resource'] == {
        'status': 'unknown', 'reason': 'SHARED_EVIDENCE_CHANGED'}
    assert not _valid(packet, context, creation)


def test_unknown_resource_pointer_does_not_read_localization_cache(pinned_profile):
    def factory(image):
        record = state_fixture.RECORDS + PROVINCE_ID * 0x2e10
        image.put_u64(record + 0x458, 0)
        return owner_fixture.RecordingReader(image)

    packet, context, creation, _fixture = _bundle(
        pinned_profile, reader_factory=factory)

    assert _valid(packet, context, creation)
    assert _fields(packet)['G02.resource']['status'] == 'unknown'
    assert not any(row['label'].startswith('localization.')
                   for row in packet['capture']['raw_reads'])


def test_unrequested_resource_field_does_not_read_localization_cache(positive_capture):
    packet, _context_value, _creation, fixture = positive_capture
    reader = owner_fixture.RecordingReader(fixture['image'])
    binding = packet['capture']['observation']['backend']['pass_evidence'][
        'pass1']['province_binding']

    result = capture._details.read_fields(
        reader, MODULE_BASE, binding, ('G02.autonomy',))

    assert set(result) == {'G02.autonomy'}
    assert result['G02.autonomy']['status'] == 'known'
    assert not any(row['label'].startswith('localization.')
                   for row in reader.read_log)


@pytest.mark.parametrize('tamper', ['value_address', 'snapshot_address', 'raw_name'])
def test_resource_name_projection_and_cache_trace_tampering_is_rejected(
        positive_capture, tamper):
    packet, context, creation, _fixture = positive_capture
    packet = deepcopy(packet)
    if tamper == 'value_address':
        row = next(row for row in packet['capture']['raw_reads']
                   if row['label'] == 'localization.value[cloth]')
        row['address'] = hex(int(row['address'], 0) + 1)
    elif tamper == 'snapshot_address':
        snapshot = (packet['capture']['observation']['backend']['pass_evidence']
                    ['pass1']['fields_raw']['G02.resource']['raw_inputs']
                    ['resource_name_capture']['raw_inputs']['snapshot'])
        row = snapshot['entries']['cloth']
        row['value_address']['va'] = hex(int(row['value_address']['va'], 0) + 1)
    else:
        _fields(packet)['G02.resource']['value']['name']['raw_hex'] = b'Forged'.hex()

    assert not _valid(packet, context, creation)
