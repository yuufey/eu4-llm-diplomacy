"""Condition membership must share the owner's double pass and cleanup."""
from contextlib import ExitStack
from pathlib import Path

import pytest

from bridge.information import mission_memory as mm
from bridge.information import mission_condition_memory as cm
from bridge.information.mission_condition_profile import load_profile
from bridge.tests.test_information_mission_condition_memory import synthetic_condition_fixture
from bridge.tests.test_information_mission_task_memory import FakeCaptureKernel, _capture_patches

def fixture():
    values=synthetic_condition_fixture(task_ids=('task_a',),required_by_task={'task_a':('required',)})
    reader,module=values[:2]
    for guard in load_profile()['code_guards']:
        reader.put(module+guard['rva'],bytes.fromhex(guard['raw_hex']))
    return reader,module

def capture(reader,module,*,close=True,snapshot=None):
    kernel=FakeCaptureKernel(module,close_result=close)
    with ExitStack() as stack:
        for item in _capture_patches(reader,kernel,snapshot=snapshot):
            stack.enter_context(item)
        report=mm.capture(Path('fake-installation.json'),'FRA',include_tasks=True,
                          include_prerequisites=True,include_conditions=True)
    assert len(kernel.closed)==1
    return report

def test_owner_captures_real_synthetic_pointer_lookup_without_completed_name_list():
    reader,module=fixture()
    report=capture(reader,module)
    assert report['status']=='observed'
    assert report['doublepass']['condition_consistent'] is True
    assert report['mission_conditions']['tasks'][0]['prerequisites_satisfied'] is False
    assert report['cleanup']['handle_close']['closed'] is True

def test_raw_map_header_drift_with_same_booleans_withdraws_conditions_only():
    reader,module=fixture();original=mm._snapshot;calls=0
    def snapshot(*args,**kwargs):
        nonlocal calls
        calls+=1
        if calls==2:
            registry=int.from_bytes(reader.read(module+cm.REGISTRY_SINGLETON_RVA,8,'test.registry'),'little')
            reader.qword_put(registry+cm.REGISTRY_MAP_OFFSET,0x3f800000)
        return original(*args,**kwargs)
    report=capture(reader,module,snapshot=snapshot)
    assert report['doublepass']['consistent'] is True
    assert report['doublepass']['prerequisite_consistent'] is True
    assert report['doublepass']['condition_consistent'] is False
    assert report['mission_conditions']['status']=='unknown'

def test_close_failure_withdraws_conditions():
    reader,module=fixture()
    report=capture(reader,module,close=False)
    assert report['status']=='cleanup_error'
    assert report['doublepass']['condition_consistent'] is False
    assert report['mission_conditions']['status']=='unknown'

def test_conditions_require_prerequisite_capture_before_open():
    with pytest.raises(ValueError,match='requires include_prerequisites'):
        mm.capture(Path('never-opened.json'),'FRA',include_conditions=True)
