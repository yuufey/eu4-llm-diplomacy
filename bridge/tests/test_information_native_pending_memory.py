"""Synthetic-memory tests only; these do not collect from a real game process."""

from copy import deepcopy
import json
import struct

import pytest

from bridge.information import native_pending_memory as native
from bridge.information.native_pending_memory import (
    load_contract,
    read_queue,
    validate_value,
)


_COUNTRY_POINTER = 0x100000
_MODULE_BASE = 0x140000000
_SESSION_ID = "synthetic-session-pending-001"
_FRA = (1 << 32) | int.from_bytes(b"FRA", "little")
_TUR = (5 << 32) | int.from_bytes(b"TUR", "little")
_SAV = (2 << 32) | int.from_bytes(b"SAV", "little")
_GEN = (3 << 32) | int.from_bytes(b"GEN", "little")
_ENG_OLD = (4 << 32) | int.from_bytes(b"ENG", "little")
_PRIVATE_KEYS = {
    "node", "clone", "vtable", "token", "native_proposal_id",
    "response_authority", "response_authorized",
}


def test_snapshot_reads_player_controlled_observer_queue(monkeypatch):
    game, country, table = 0x200000, 0x300000, 0x400000
    layout = {'game_global_rva': 0x100, 'game_date_offset': 0x10, 'country_fullref_offset': 0x20}
    memory_bytes = {
        (_MODULE_BASE + 0x100, 8): game.to_bytes(8, 'little'),
        (game + 0x10, 4): (56553384).to_bytes(4, 'little', signed=True),
        (game + 0x1e60, 8): _TUR.to_bytes(8, 'little'),
        (table + 5 * 8, 8): country.to_bytes(8, 'little'),
        (country + 0x20, 8): _TUR.to_bytes(8, 'little'),
    }
    monkeypatch.setattr(native.memory, '_profile_layout', lambda _: layout)
    monkeypatch.setattr(native.memory, '_reader_read',
                        lambda _reader, address, size, *_args: memory_bytes[(address, size)])
    monkeypatch.setattr(native.memory, '_find_country', lambda *_args: (
        country, {'country_handle': hex(_TUR), 'table_pointer': hex(table), 'country_count': 6}))
    seen = {}
    def read_queue(_read, pointer, recipient, _base, _session, resolver, _contract, **_options):
        seen.update(pointer=pointer, recipient=recipient, tag=resolver(recipient))
        return {'value': {'entries': []}}
    monkeypatch.setattr(native, 'read_queue', read_queue)
    result = native._snapshot(None, _MODULE_BASE, {}, {'code_guards': []}, _SESSION_ID, None, 'TUR')
    assert seen == {'pointer': country, 'recipient': _TUR, 'tag': 'TUR'}
    assert result['player_country'] == 'TUR'


@pytest.fixture(scope="module")
def contract():
    return load_contract()


def _clone_header(contract, spec):
    action = spec.get("action", "offer_alliance")
    vtable = spec.get(
        "vtable", _MODULE_BASE + contract["action_vtable_rvas"][action])
    actor = spec.get("actor", _SAV)
    mirror = spec.get("mirror", actor)
    recipient = spec.get("recipient", _FRA)
    header = bytearray(0x40)
    struct.pack_into("<Qi", header, 0, vtable, spec.get("discriminator", 0x165))
    struct.pack_into("<QQQ", header, 0x10, actor, mirror, recipient)
    struct.pack_into("<i", header, 0x34, spec.get("state", 0))
    header[0x38] = spec.get("variant", 1)
    struct.pack_into("<i", header, 0x3C, spec.get("token", 7))
    return bytes(header)


def _synthetic_memory(contract, specs=(), *, root_head=None, root_tail=None,
                      root_count=None, stale_refs=(), fail_reads=False, deferred_removal=0):
    """Build dictionary-backed memory regions for the production read callback."""
    specs = list(specs)
    nodes = [0x200000 + index * 0x100 for index in range(len(specs))]
    clones = [0x300000 + index * 0x100 for index in range(len(specs))]
    blocks = {}
    country_tags = {_FRA: "FRA", _SAV: "SAV", _GEN: "GEN", _TUR: "TUR"}
    stale_refs = set(stale_refs)

    for index, spec in enumerate(specs):
        node, clone = nodes[index], clones[index]
        previous = spec.get("previous", nodes[index - 1] if index else 0)
        following = spec.get("following", nodes[index + 1] if index + 1 < len(nodes) else 0)
        blocks[node] = struct.pack("<QQQB", clone, previous, following, spec.get("retired", 0))
        blocks[clone] = _clone_header(contract, spec)
        if spec.get("action", "offer_alliance") == "offer_royal_marriage":
            blocks[clone + 0x60] = bytes([spec.get("royal_flag", 0)])

    head = (nodes[0] if nodes else 0) if root_head is None else root_head
    tail = (nodes[-1] if nodes else 0) if root_tail is None else root_tail
    count = len(nodes) if root_count is None else root_count
    queue_offsets = contract["queue_offsets"]
    blocks[_COUNTRY_POINTER + queue_offsets["head"]] = struct.pack(
        "<QQIB", head, tail, count, deferred_removal)

    def read(address, size):
        if fail_reads:
            raise OSError("synthetic memory read failure")
        for start, data in blocks.items():
            if start <= address and address + size <= start + len(data):
                offset = address - start
                return data[offset:offset + size]
        raise OSError("unmapped synthetic memory region")

    def resolve_country(reference):
        if reference in stale_refs:
            raise ValueError("synthetic stale country reference")
        try:
            return country_tags[reference]
        except KeyError as exc:
            raise ValueError("synthetic unresolved country reference") from exc

    return {
        "blocks": blocks,
        "read": read,
        "resolve_country": resolve_country,
        "country_pointer": _COUNTRY_POINTER,
        "recipient_ref": _FRA,
        "module_base": _MODULE_BASE,
        "session_id": _SESSION_ID,
    }


def _capture(memory, contract):
    return read_queue(
        memory["read"], memory["country_pointer"], memory["recipient_ref"],
        memory["module_base"], memory["session_id"],
        memory["resolve_country"], contract)


def test_queue_inventory_requires_the_same_canonical_recipient(contract):
    memory = _synthetic_memory(contract, [{"recipient": _TUR}, {"recipient": _FRA}])
    memory["recipient_ref"] = _TUR
    result = _capture(memory, contract)["value"]
    assert result["recognized_entry_count"] == 1
    assert result["entries"][0]["recipient"] == "TUR"
    assert result["entries"][1]["recognition"] == "unresolved"
    assert validate_value(result, contract, observer="TUR") == result
    with pytest.raises(ValueError, match="NATIVE_PENDING_PUBLIC_ACTION_INVALID"):
        validate_value(result, contract, observer="FRA")


def test_empty_queue_has_zero_counts(contract):
    memory = _synthetic_memory(contract)
    result = _capture(memory, contract)

    assert result["value"]["native_queue_count"] == 0
    assert result["value"]["recognized_entry_count"] == 0
    assert result["value"]["unresolved_entry_count"] == 0
    assert result["value"]["entries"] == []
    assert result["private"]["nodes"] == []


@pytest.mark.parametrize('flag', [1, 2, 255])
def test_deferred_queue_removal_rejects_even_empty_snapshot(contract, flag):
    memory = _synthetic_memory(contract, deferred_removal=flag)
    with pytest.raises(ValueError, match='NATIVE_PENDING_QUEUE_MUTATING'):
        _capture(memory, contract)


@pytest.mark.parametrize('flag', [1, 2, 255])
@pytest.mark.parametrize('payload_present', [False, True])
def test_retired_node_is_rejected_before_reading_destroyed_action(contract, flag, payload_present):
    memory = _synthetic_memory(contract, [
        {'action': 'offer_alliance'},
        {'action': 'ask_military_access', 'retired': flag},
    ])
    if not payload_present:
        del memory['blocks'][0x300100]
    with pytest.raises(ValueError, match='NATIVE_PENDING_NODE_RETIRED'):
        _capture(memory, contract)


def test_valid_multinode_queue_recognizes_alliance_and_military_access(contract):
    memory = _synthetic_memory(contract, [
        {"action": "offer_alliance", "actor": _SAV},
        {"action": "ask_military_access", "actor": _GEN},
    ])
    result = _capture(memory, contract)
    value = result["value"]

    assert value["native_queue_count"] == 2
    assert value["recognized_entry_count"] == 2
    assert value["unresolved_entry_count"] == 0
    assert [entry["action_id"] for entry in value["entries"]] == [
        "offer_alliance", "ask_military_access"]
    assert [(entry["actor"], entry["recipient"], entry["phase"])
            for entry in value["entries"]] == [
                ("SAV", "FRA", "initiate"), ("GEN", "FRA", "initiate")]
    assert all(entry["recognition"] == "recognized" for entry in value["entries"])
    assert all(len(entry["entry_id"]) == len("pending-entry-") + 32
               for entry in value["entries"])
    assert [node["node"] for node in result["private"]["nodes"]] == [
        hex(0x200000), hex(0x200100)]


def test_unknown_vtable_and_wrong_discriminator_remain_unresolved(contract):
    unknown_vtable = _MODULE_BASE + 0x123456
    memory = _synthetic_memory(contract, [
        {"vtable": unknown_vtable},
        {"action": "offer_alliance", "discriminator": 0x166},
    ])
    entries = _capture(memory, contract)["value"]["entries"]

    assert [entry["recognition"] for entry in entries] == ["unresolved", "unresolved"]
    assert [entry["reason"] for entry in entries] == [
        "UNSUPPORTED_NATIVE_PENDING_ACTION", "UNSUPPORTED_NATIVE_PENDING_ACTION"]
    assert all(set(entry) == {"entry_id", "recognition", "reason"} for entry in entries)


def test_royal_marriage_with_nonzero_extra_flag_remains_unresolved(contract):
    memory = _synthetic_memory(contract, [{
        "action": "offer_royal_marriage", "royal_flag": 1,
    }])
    result = _capture(memory, contract)

    assert result["value"]["entries"][0]["recognition"] == "unresolved"
    assert result["value"]["entries"][0]["reason"] == "NATIVE_PENDING_ACTION_SHAPE_UNVERIFIED"
    assert result["private"]["nodes"][0]["royal_flag_hex"] == "01"


def test_known_action_shape_mismatches_remain_unresolved(contract):
    specs = [
        {"action": "offer_alliance", "recipient": _GEN},
        {"action": "offer_alliance", "mirror": _GEN},
        {"action": "offer_alliance", "state": 1},
        {"action": "offer_alliance", "variant": 0},
        {"action": "offer_alliance", "token": 0},
    ]
    for spec in specs:
        memory = _synthetic_memory(contract, [spec])
        entry = _capture(memory, contract)["value"]["entries"][0]
        assert entry["recognition"] == "unresolved"
        assert entry["reason"] == "NATIVE_PENDING_ACTION_SHAPE_UNVERIFIED"
        assert set(entry) == {"entry_id", "recognition", "reason"}


def test_stale_country_reference_remains_unresolved(contract):
    memory = _synthetic_memory(contract, [{"action": "offer_alliance", "actor": _ENG_OLD}],
                               stale_refs={_ENG_OLD})
    entry = _capture(memory, contract)["value"]["entries"][0]

    assert entry["recognition"] == "unresolved"
    assert entry["reason"] == "NATIVE_PENDING_PARTY_UNRESOLVED"


def test_invalid_queue_roots_are_rejected(contract):
    invalid_roots = [
        _synthetic_memory(contract, [], root_head=0x200000, root_count=0),
        _synthetic_memory(contract, [{"action": "offer_alliance"}], root_head=0),
        _synthetic_memory(contract, [{"action": "offer_alliance"}], root_tail=0),
    ]
    for memory in invalid_roots:
        with pytest.raises(ValueError, match="NATIVE_PENDING_ROOTS_INVALID"):
            _capture(memory, contract)


def test_bad_previous_link_is_rejected(contract):
    memory = _synthetic_memory(contract, [{
        "action": "offer_alliance", "previous": 0x210000,
    }])

    with pytest.raises(ValueError, match="NATIVE_PENDING_LINK_INVALID"):
        _capture(memory, contract)


def test_tail_mismatch_and_underreported_count_are_rejected(contract):
    tail_mismatch = _synthetic_memory(
        contract, [{"action": "offer_alliance"}], root_tail=0x210000)
    underreported_count = _synthetic_memory(contract, [
        {"action": "offer_alliance"}, {"action": "ask_military_access"},
    ], root_count=1)

    for memory in (tail_mismatch, underreported_count):
        with pytest.raises(ValueError, match="NATIVE_PENDING_TAIL_OR_COUNT_MISMATCH"):
            _capture(memory, contract)


def test_repeated_node_cycle_is_rejected(contract):
    node = 0x200000
    memory = _synthetic_memory(contract, [{
        "action": "offer_alliance", "following": node,
    }], root_tail=node, root_count=2)

    with pytest.raises(ValueError, match="NATIVE_PENDING_NODE_REPEATED"):
        _capture(memory, contract)


def test_more_than_256_entries_is_rejected(contract):
    memory = _synthetic_memory(
        contract, [{"action": "offer_alliance"}], root_count=257)

    with pytest.raises(ValueError, match="NATIVE_PENDING_ROOTS_INVALID"):
        _capture(memory, contract)


def test_read_exception_is_not_reported_as_empty_queue(contract):
    memory = _synthetic_memory(contract, fail_reads=True)

    with pytest.raises(OSError, match="synthetic memory read failure"):
        _capture(memory, contract)


def test_public_projection_omits_native_identity_and_response_authority(contract):
    memory = _synthetic_memory(contract, [
        {"action": "offer_alliance", "actor": _SAV},
        {"vtable": _MODULE_BASE + 0x123456},
    ])
    value = _capture(memory, contract)["value"]
    public_json = json.dumps(value, sort_keys=True)

    assert value["response_contexts_available"] is False
    assert "payload_details_complete" in value and value["payload_details_complete"] is False
    for key in _PRIVATE_KEYS:
        assert f'"{key}"' not in public_json
        assert all(key not in entry for entry in value["entries"])
    assert set(value["entries"][0]) == {
        "entry_id", "recognition", "action_id", "actor", "recipient", "phase", "deadline"}
    assert set(value["entries"][1]) == {"entry_id", "recognition", "reason"}


def test_validate_value_accepts_closed_public_projection(contract):
    memory = _synthetic_memory(contract, [{"action": "offer_alliance"}])
    value = _capture(memory, contract)["value"]

    validated = validate_value(value, contract)

    assert validated == value
    assert validated is not value


def test_validate_value_rejects_bad_counts_identity_and_private_fields(contract):
    memory = _synthetic_memory(contract, [{"action": "offer_alliance"}])
    value = _capture(memory, contract)["value"]
    invalid_values = []

    changed = deepcopy(value)
    changed["native_queue_count"] = True
    invalid_values.append(changed)
    changed = deepcopy(value)
    changed["recognized_entry_count"] = 0
    invalid_values.append(changed)
    changed = deepcopy(value)
    changed["identity_scope"] = "native_proposal_identity"
    invalid_values.append(changed)
    changed = deepcopy(value)
    changed["list_traversal_complete"] = False
    invalid_values.append(changed)
    changed = deepcopy(value)
    changed["node"] = "0x200000"
    invalid_values.append(changed)
    for key in _PRIVATE_KEYS:
        changed = deepcopy(value)
        changed["entries"][0][key] = "private"
        invalid_values.append(changed)

    for invalid in invalid_values:
        with pytest.raises(ValueError):
            validate_value(invalid, contract)
