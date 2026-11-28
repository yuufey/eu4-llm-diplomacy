from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

from bridge.information import InformationService, country_province_ids_capture
from bridge.information.composite import CompositeSource
from bridge.information.country_provinces import NativeCountryProvincesSource
from bridge.information.country_province_ids_capture import FIELD, _read_owned_ids
from bridge.information.sources import DiplomacySource
from bridge.information.tools import InformationTools


CONTEXT = {
    "status": "ready", "mode": "live", "complete": True,
    "observer": "TUR", "session_id": "session-1", "game_version": "1.37.4",
    "game_date": 123,
}


class Base:
    session = SimpleNamespace(directory="fixture", record={"creation_filetime": 1})

    def context(self):
        return dict(CONTEXT)


class OwnedIds:
    def capture(self, installation, country, *, observer):
        assert (country, observer) == ("SER", "TUR")
        return [1, 2, 3]

    def validate_capture(self, report, context, creation, country):
        return True

    def project_fields(self, report):
        return {FIELD: {"status": "known", "value": report}}


class ProvinceState:
    def __init__(self, values):
        self.values = values

    def read(self, query, context):
        value = self.values[query["object"]["province_id"]]
        return {"fields": {
            name: {"status": "known", "value": item}
            for name, item in value.items()
        }}


class StaticTrade:
    def __init__(self, nodes):
        self.nodes = nodes

    def read(self, query, context):
        if query["topic"] == "T01":
            wanted = query["object"]["node_id"]
            return {"fields": {"provinces": {"status": "known", "value": [
                province for province, node in self.nodes.items() if node == wanted
            ]}}}
        province_id = query["object"]["province_id"]
        node = self.nodes.get(province_id)
        return {"fields": {"trade_node": {
            "status": "known", "value": node,
        } if node is not None else {
            "status": "unknown", "reason": "PROVINCE_NOT_IN_STATIC_TRADE_NODE",
        }}}


def make_source(**kwargs):
    values = {
        1: {"owner": "SER", "controller": "SER",
            "resource": {"localization_key": "gold", "name": {"text": "Gold"}},
            "center_of_trade": {"present": True, "level": 2}},
        2: {"owner": "SER", "controller": "TUR",
            "resource": {"localization_key": "livestock", "name": {"text": "Livestock"}},
            "center_of_trade": {"present": False, "level": 0}},
        3: {"owner": "HUN", "controller": "HUN",
            "resource": {"localization_key": "gold", "name": {"text": "Gold"}},
            "center_of_trade": {"present": False, "level": 0}},
    }
    return NativeCountryProvincesSource(
        Base(), owned_ids_capture=OwnedIds(), province_state=ProvinceState(values),
        static_trade=StaticTrade({1: "constantinople", 2: "ragusa", 3: "ragusa"}), **kwargs,
    )


def query(**parameters):
    return {"topic": "G06", "object": {"type": "country", "country": "SER"},
            "fields": ["provinces"], "parameters": parameters}


def test_lists_owned_discovered_provinces_in_id_order_and_paginates():
    source = make_source()
    result = source.read(query(limit=1), CONTEXT)
    value = result["fields"]["provinces"]["value"]
    assert [row["province_id"] for row in value["rows"]] == [1]
    assert value["next_offset"] == 1
    result = source.read(query(limit=2, offset=1), CONTEXT)
    value = result["fields"]["provinces"]["value"]
    assert [row["province_id"] for row in value["rows"]] == [2]
    assert value["rows"][0]["controller"] == "TUR"


def test_filters_resource_trade_node_and_center_of_trade():
    source = make_source()
    result = source.read(query(resource="gold", center_of_trade=True,
                               trade_node="constantinople"), CONTEXT)
    rows = result["fields"]["provinces"]["value"]["rows"]
    assert [row["province_id"] for row in rows] == [1]
    assert rows[0]["trade_node"] == "constantinople"


def test_trade_node_filter_skips_unrelated_native_reads(monkeypatch):
    source = make_source()
    original = source.province_state.read
    read_ids = []

    def read(query, context):
        read_ids.append(query["object"]["province_id"])
        return original(query, context)

    monkeypatch.setattr(source.province_state, "read", read)
    source.read(query(trade_node="constantinople"), CONTEXT)
    assert read_ids == [1]


def test_river_estuary_filter_uses_existing_reader_only_for_eligible_candidates():
    calls = []

    def estuary(province_id, context):
        calls.append(province_id)
        return {"status": "known", "value": True}

    source = make_source(estuary_reader=SimpleNamespace(read=estuary))
    rows = source.read(query(resource="gold", river_estuary=True), CONTEXT)["fields"]["provinces"]["value"]["rows"]
    assert calls == [1]
    assert rows[0]["river_estuary"] is True


def test_changed_owner_is_filtered_and_owned_list_failure_is_unavailable():
    source = make_source()
    result = source.read(query(), CONTEXT)
    value = result["fields"]["provinces"]["value"]
    assert [row["province_id"] for row in value["rows"]] == [1, 2]
    assert value["unknown_candidates"] == 1
    source.owned_ids_capture = None
    result = source.read(query(), CONTEXT)
    assert result["fields"]["provinces"]["status"] == "unavailable"


def test_empty_filtered_page_can_advance_scan_and_includes_later_match():
    source = make_source(max_scan=1)
    page = source.read(query(resource="livestock"), CONTEXT)["fields"]["provinces"]["value"]
    assert page["rows"] == [] and page["next_offset"] == 1
    page = source.read(query(resource="livestock", offset=page["next_offset"]), CONTEXT)
    assert [row["province_id"] for row in page["fields"]["provinces"]["value"]["rows"]] == [2]


def test_owned_vector_reader_returns_sorted_ids_without_province_domain_scan():
    class Reader:
        def __init__(self):
            self.data = {
                0x1000 + 4920: (0x2000).to_bytes(8, "little"),
                0x1000 + 4932: (3).to_bytes(4, "little", signed=True),
                0x2000: b"".join(value.to_bytes(4, "little", signed=True)
                                 for value in (9, 2, 5)),
            }

        def read(self, address, size, label):
            return self.data[address]

    result = _read_owned_ids(
        Reader(), {"country_pointer": hex(0x1000)},
        {"owned_vector_offset": 4920, "owned_count_offset": 4932,
         "max_owned_provinces": 4096},
    )
    assert result["value"] == [2, 5, 9]


def test_country_provinces_normal_tool_query_and_discovery(tmp_path):
    adapter = make_source()
    primary = DiplomacySource()
    primary.context = adapter.context
    source = CompositeSource(primary, [adapter])
    service = InformationService(source, tmp_path / "information.sqlite3", owner="test")
    try:
        tools = InformationTools(service)
        result = tools.call("information_query", {"request_id": "g06-smoke", "queries": [query()]})
        assert [row["province_id"] for row in result["items"][0]["provinces"]["rows"]] == [1, 2]
        discover = tools.call("information_discover", {"topics": ["G06"]})
        assert discover["topics"][0]["fields"] == ["provinces"]
    finally:
        service.close()


def test_owned_vector_capture_replays_and_rejects_relabelled_ids():
    from bridge.tests.test_information_country_occupation_memory import put_provinces
    from bridge.tests.test_information_foreign_technology_capture import (
        MODULE_BASE, WORLD, RecordingReader, make_valid_capture,
    )

    module = country_province_ids_capture
    report, context, creation, fixture = make_valid_capture(admitted=True)
    profile = module._load_profile()
    image = fixture["image"]
    for guard in profile["code_guards"]:
        image.put(MODULE_BASE + int(guard["rva"], 0), bytes.fromhex(guard["bytes"]))
    put_provinces(image, fixture["target_fullref"],
                  [fixture["target_fullref"], fixture["observer_fullref"]],
                  country=fixture["target_pointer"], world=WORLD)
    reader = RecordingReader(image)
    report["schema"] = module.SCHEMA
    report["profile_sha256"] = module.PROFILE_SHA256
    report["observation"] = module._observe_for()(reader, MODULE_BASE, "ENG", profile)
    report["raw_reads"] = deepcopy(reader.read_log)
    report["access"] = {"read_only": True, "native_function_invoked": False,
        "writes": False, "UI_control": False, "date_advance": False, "save_or_reload": False,
        "limit_bytes": module._owner.MAX_READ_BYTES,
        "calls": reader.calls, "bytes_requested": reader.bytes_requested}
    assert module.validate_capture(report, context, creation, "ENG")
    assert module.project_fields(report)[FIELD]["value"] == [1, 2]
    report["observation"]["backend"]["targets"][0]["fields"][FIELD]["value"][0] = 3
    assert not module.validate_capture(report, context, creation, "ENG")
