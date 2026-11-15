"""Loaded trigger evaluation shares identity, double-pass and handle lifetime."""
from contextlib import ExitStack
import json
from pathlib import Path

import pytest

from bridge.information import mission_trigger_profile as trigger_profile
from bridge.information import mission_memory as mm
from bridge.information.mission_trigger_profile import load_profile
from bridge.tests.test_information_mission_trigger_memory import _fixture, _install_root, _write_leaf
from bridge.tests.test_information_mission_task_memory import FakeCaptureKernel, _capture_patches


def test_python_evidence_version_does_not_reject_runtime_profile(monkeypatch):
    original_sha = trigger_profile._sha

    def checked_sha(path):
        assert Path(path).suffix != ".py"
        return original_sha(path)

    monkeypatch.setattr(trigger_profile, "_sha", checked_sha)
    assert load_profile()["schema"] == "eu4.mission_trigger_memory.v14"


def test_non_python_profile_evidence_hash_remains_required(monkeypatch):
    profile = json.loads(trigger_profile.PROFILE_FILE.read_text(encoding="utf-8"))
    dependency = next(item for item in profile["source_evidence"]
                      if Path(item["path"]).suffix != ".py")
    target = (trigger_profile.ROOT / dependency["path"]).resolve()
    original_sha = trigger_profile._sha

    def changed_sha(path):
        return "0" * 64 if Path(path).resolve() == target else original_sha(path)

    monkeypatch.setattr(trigger_profile, "_sha", changed_sha)
    with pytest.raises(ValueError, match="MISSION_TRIGGER_EVIDENCE_PIN"):
        load_profile()


def fixture():
    reader,module,country,_loaded,_guards,_definitions,pointers=_fixture()
    for item in load_profile()['code_guards']:
        reader.put(module+item['rva'],bytes.fromhex(item['raw_hex']))
    leaf=0xa35000
    _write_leaf(reader,module,leaf,'sailors',0x33f0,800)
    _install_root(reader,module,pointers['task_a'],[leaf])
    reader.dword_put(country+0xdc0,900000,signed=True)
    reader.dword_put(country+0xdc4,1000000,signed=True)
    return reader,module,country

def capture(reader,module,*,close=True,snapshot=None):
    kernel=FakeCaptureKernel(module,close_result=close)
    with ExitStack() as stack:
        for item in _capture_patches(reader,kernel,snapshot=snapshot):
            stack.enter_context(item)
        report=mm.capture(Path('fake-installation.json'),'FRA',include_tasks=True,
            include_prerequisites=True,include_conditions=True,include_triggers=True)
    assert len(kernel.closed)==1
    return report

def test_owner_capture_reads_loaded_tree_and_derives_true_without_native_call():
    reader,module,_country=fixture();report=capture(reader,module)
    assert report['status']=='observed'
    assert report['doublepass']['trigger_consistent'] is True
    assert report['mission_triggers']['tasks'][0]['tree']['evaluation']=={'status':'known','satisfied':True}
    assert report['access']['native_game_calls'] is False

def test_same_boolean_with_changed_scalar_input_withdraws_trigger_tree():
    reader,module,country=fixture();original=mm._snapshot;calls=0
    def snapshot(*args,**kwargs):
        nonlocal calls
        calls+=1
        if calls==2:reader.dword_put(country+0xdc4,999999,signed=True)
        return original(*args,**kwargs)
    report=capture(reader,module,snapshot=snapshot)
    assert report['doublepass']['condition_consistent'] is True
    assert report['doublepass']['trigger_consistent'] is False
    assert report['mission_triggers']['status']=='unknown'

def test_close_failure_withdraws_triggers():
    reader,module,_country=fixture();report=capture(reader,module,close=False)
    assert report['status']=='cleanup_error'
    assert report['doublepass']['trigger_consistent'] is False
    assert report['mission_triggers']['status']=='unknown'

def test_trigger_option_requires_conditions_before_any_handle():
    with pytest.raises(ValueError,match='requires include_conditions'):
        mm.capture(Path('never-opened.json'),'FRA',include_triggers=True)
