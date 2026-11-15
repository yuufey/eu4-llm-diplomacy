"""Task text follows native membership and preserves unresolved substitutions."""
from copy import deepcopy

from bridge.information import InformationService
from bridge.information.composite import CompositeSource
from bridge.information.missions import MissionInformationSource
from bridge.tests.test_information_missions import Definitions, State, query


class Reader:
    def __init__(self, state):
        self.state = state
        self.calls = []
        self.fail = False
        self.omit = False

    def __call__(self, country):
        return self.state.capture(country)

    def localized_text(self, country, context, keys):
        self.calls.append(keys)
        if self.fail:
            raise RuntimeError("native cache unavailable")
        values = {key: {"status":"known", "text":"解放诺曼底" if key == "first_title" else "说明"} for key in keys}
        if "second_title" in values:
            values["second_title"] = {"status":"unknown", "reason":"DYNAMIC_LOCALIZATION_UNRESOLVED",
                                      "template":"[Root.GetSelectableMissionTitle]", "unresolved_tokens":["[Root.GetSelectableMissionTitle]"]}
        if self.omit:
            values.pop(keys[0])
        return {"status":"known", "entries":values, "language":"l_english",
                "provenance":{"reader":"bounded_ReadProcessMemory", "atomic_with_task_slots":False}}


def make_service(tmp_path):
    state, definitions = State(), Definitions()
    state.sample["loaded_tasks"] = {"status":"known", "roots":[{"root_id":"loaded", "task_ids":["first","second"]}]}
    reader = Reader(state)
    adapter = MissionInformationSource(state, definitions, reader)
    api = InformationService(CompositeSource(state,[adapter]),tmp_path / "information.db")
    return api, state, definitions, reader


def test_unresolved_title_keeps_literal_names_and_complete_sibling_description(tmp_path):
    api,state,definitions,reader=make_service(tmp_path)
    try:
        result=api.query("texts",queries=[query("M01",["task_id","name","description"])])
        assert result["status"] == "partial" and result["complete"] is False
        fields=result["items"][0]["fields"]
        names=fields["name"]["value"]
        assert fields["name"]["complete"] is False and names["resolution_complete"] is False
        assert (names["resolved_count"],names["unresolved_count"]) == (1,1)
        assert names["entries"][0]["text"] == "解放诺曼底"
        assert names["entries"][1]["status"] == "unknown" and "text" not in names["entries"][1]
        assert names["entries"][1]["template"] == "[Root.GetSelectableMissionTitle]"
        assert fields["description"]["complete"] is True
        assert fields["task_id"]["status"] == "known"
        assert len(reader.calls) == 1
    finally:
        api.close()


def test_selected_literal_texts_are_complete_without_current_definition_files(tmp_path):
    api,state,definitions,reader=make_service(tmp_path)
    definitions.ready=False
    try:
        result=api.query("one",queries=[query("M01",["name","description"],task_id="first")])
        assert result["complete"] is True
        assert result["items"][0]["fields"]["name"]["value"]["entries"][0]["localization_key"] == "first_title"
        assert reader.calls == [["first_title","first_desc"]]
    finally:
        api.close()


def test_no_text_request_does_not_read_the_localization_cache(tmp_path):
    api,state,definitions,reader=make_service(tmp_path)
    try:
        assert api.query("ids",queries=[query("M01",["task_id"])])["complete"] is True
        assert reader.calls == []
    finally:
        api.close()


def test_only_requested_field_and_loaded_task_can_select_cache_keys(tmp_path):
    api,state,definitions,reader=make_service(tmp_path)
    state.sample["loaded_tasks"]["roots"][0]["task_ids"]=["first"]
    try:
        result=api.query("name",queries=[query("M01",["name"])])
        assert result["complete"] is True and reader.calls == [["first_title"]]
        result=api.query("not-loaded",queries=[query("M01",["name"],task_id="second")])
        assert result["items"][0]["fields"]["name"]["reason"] == "TASK_NOT_IN_CAPTURED_LOADED_TASKS"
        assert len(reader.calls) == 1
    finally:
        api.close()


def test_unknown_membership_does_not_use_static_tasks_for_text(tmp_path):
    api,state,definitions,reader=make_service(tmp_path)
    state.sample["loaded_tasks"]={"status":"unknown","reason":"TASK_READ_FAILED"}
    try:
        result=api.query("unknown",queries=[query("M01",["name","branches"])])
        assert result["items"][0]["fields"]["name"]["reason"] == "LOADED_TASK_MEMBERSHIP_REQUIRED_FOR_LOCALIZATION"
        assert result["items"][0]["fields"]["branches"]["status"] == "known" and reader.calls == []
    finally:
        api.close()


def test_failed_or_incomplete_text_capture_preserves_native_ids(tmp_path):
    api,state,definitions,reader=make_service(tmp_path)
    try:
        for index,attribute in enumerate(("fail","omit")):
            setattr(reader,attribute,True)
            result=api.query(f"failure-{index}",queries=[query("M01",["task_id","name","branches"])])
            fields=result["items"][0]["fields"]
            assert fields["name"]["status"] == "unavailable"
            assert fields["task_id"]["status"] == fields["branches"]["status"] == "known"
            setattr(reader,attribute,False)
    finally:
        api.close()


def test_empty_loaded_task_list_has_empty_texts_without_extra_read(tmp_path):
    api,state,definitions,reader=make_service(tmp_path)
    state.sample["loaded_tasks"]["roots"][0]["task_ids"]=[]
    try:
        result=api.query("empty",queries=[query("M01",["name","description"])])
        assert result["complete"] is True and reader.calls == []
        assert result["items"][0]["fields"]["name"]["value"]["entries"] == []
    finally:
        api.close()


def test_definition_change_does_not_invalidate_independent_native_text(tmp_path):
    api,state,definitions,reader=make_service(tmp_path)
    original=definitions.roots
    def read_then_change(ids):
        result=original(ids)
        definitions.ready=False
        return result
    definitions.roots=read_then_change
    try:
        result=api.query("changed",queries=[query("M01",["name"],task_id="first")])
        assert result["complete"] is True
        assert result["items"][0]["fields"]["name"]["value"]["entries"][0]["text"] == "解放诺曼底"
    finally:
        api.close()
