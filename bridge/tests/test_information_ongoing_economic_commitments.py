"""Shared subsidy/reparations capture and partial-component preservation."""
from copy import deepcopy

import pytest

from bridge.information import ongoing_economic_commitments_capture as capture
from bridge.information import reparations_commitments as reparations
from bridge.tests import test_information_country_faith_capture as faith
from bridge.tests import test_information_foreign_technology_capture as parent
from bridge.tests import test_information_foreign_economy as economy
from bridge.tests import test_information_economic_commitments_capture as legacy


def make_capture(*, present=True, factor_changes=False, observer_patch=False, observer='FRA'):
    profile = capture._load_profile()
    image, state = faith._make_image('ENG', profile)
    image.put_u32 = lambda address, value: image.put(address, value.to_bytes(4, 'little'))
    bindings = {tag: {**row, 'country_pointer': hex(row['country_pointer']),
                       'fullref': hex(state['refs'][tag])} for tag, row in state['bindings'].items()}
    own = bindings['FRA']
    if observer != 'FRA':
        reference = faith._fullref(observer, own['slot'], state['refs']['FRA'] >> 48)
        image.put_u64(state['observer_pointer'] + 0x20, reference)
        own = dict(own, tag=observer, fullref=hex(reference))
    economy._subsidies_bytes(image, own, bindings['ENG'], present=present,
                             amount=12500, start=parent.GAME_DATE, duration=2)
    economy._reparations_bytes(image, own, bindings['ENG'], present=present)
    image.put_u64(state['observer_pointer'] + 0x14F8 + parent.admission.RELATION_OWNER_COUNTERS_OFFSET,
                  parent.RELATION_COUNTERS)
    for tag in ('FRA', 'ENG'):
        image.put_u64(state['bindings'][tag]['country_pointer'] + 0x18F0, 0)
    if present:
        image.put(economy.REPARATIONS_TREATY + 0x28, b'\0')
        image.put_i32(parent.MODULE_BASE + reparations.INCOME_FACTOR_RVA, 100)
    if factor_changes:
        def change(image, address, size, label, count):
            if label == 'reparations_commitments.income_factor' and count == 2:
                image.put_i32(address, 250)
        image.on_read = change
    binding = legacy.put_observer_patch(image, profile)[0] if observer_patch else None
    reader = parent.RecordingReader(image)
    observation = capture._observe(reader, parent.MODULE_BASE, 'ENG', profile,
                                   observer=observer, observer_binding=binding)
    identity = {'binding_verified': True, 'process_creation_filetime': parent.CREATION,
                'process_path': 'synthetic-eu4.exe', 'process_path_sha256': capture._owner.EXE_SHA256}
    report = {
        'schema': capture.SCHEMA, 'status': 'observed', 'completed': True,
        'profile_sha256': capture.PROFILE_SHA256,
        'request': {'country': 'ENG', 'observer': observer, 'creation_filetime': parent.CREATION,
                    'session_id': parent.SESSION_ID},
        'identity': identity, 'identity_after': deepcopy(identity), 'module_base': hex(parent.MODULE_BASE),
        'observation': observation, 'raw_reads': reader.read_log,
        'cleanup': {'status': 'closed', 'closed': True, 'success': True},
        'access': {'read_only': True, 'native_function_invoked': False, 'writes': False,
                   'UI_control': False, 'date_advance': False, 'save_or_reload': False,
                   'limit_bytes': capture._owner.MAX_READ_BYTES,
                   'calls': reader.calls, 'bytes_requested': reader.bytes_requested},
    }
    context = {'status': 'ready', 'mode': 'live', 'observer': observer, 'session_id': parent.SESSION_ID,
               'game_version': '1.37.4', 'game_sha256': capture._owner.EXE_SHA256,
               'game_date': parent.GAME_DATE}
    return report, context


def test_turkish_observer_binds_both_economic_contract_endpoints_and_dates():
    report, context = make_capture(observer='TUR')
    assert capture.validate_capture(report, context, parent.CREATION, 'ENG')
    fields = capture.project_fields(report)
    rows = fields['economic_support']['value']['active_payment_obligations']['value']
    assert [row['kind'] for row in rows] == ['subsidy', 'war_reparations']
    assert all({row['payer'], row['recipient']} == {'TUR', 'ENG'} for row in rows)
    assert not capture.validate_capture(report, dict(context, observer='FRA'), parent.CREATION, 'ENG')


@pytest.mark.parametrize('present', [True, False])
def test_both_contract_types_share_country_binding_and_exact_replay(present):
    report, context = make_capture(present=present)
    assert capture.validate_capture(report, context, parent.CREATION, 'ENG')
    fields = capture.project_fields(report)
    active = fields['economic_support']['value']['active_payment_obligations']
    assert active['status'] == 'known' and active['complete'] is True
    assert [row['kind'] for row in active['value']] == (['subsidy', 'war_reparations'] if present else [])
    assert len(fields['expiry']['value']) == (2 if present else 0)
    assert len(report['observation']['backend']['targets']) == 1
    guards = capture._load_profile()['code_guards']
    assert len({row['rva'] for row in guards}) == len(guards)


def test_both_contract_types_remain_readable_with_the_installed_subsidy_observer():
    report, context = make_capture(observer_patch=True)
    assert capture.validate_capture(report, context, parent.CREATION, 'ENG')
    obligations = capture.project_fields(report)['economic_support']['value']['active_payment_obligations']
    assert obligations['complete'] is True
    assert [row['kind'] for row in obligations['value']] == ['subsidy', 'war_reparations']


def test_changed_rate_preserves_stable_subsidy_and_both_deadlines():
    report, context = make_capture(factor_changes=True)
    assert capture.validate_capture(report, context, parent.CREATION, 'ENG')
    fields = capture.project_fields(report)
    active = fields['economic_support']['value']['active_payment_obligations']
    assert active['status'] == 'known' and active['complete'] is False
    assert [row['kind'] for row in active['value']] == ['subsidy']
    assert len(fields['expiry']['value']) == 2


def test_existing_subsidy_capture_keeps_its_original_projection():
    report, context = legacy.make_capture()
    assert capture.validate_capture(report, context, parent.CREATION, 'ENG')
    assert capture.project_fields(report) == legacy.capture.project_fields(report)


def test_altered_combined_capture_is_rejected():
    report, context = make_capture()
    fields = report['observation']['backend']['targets'][0]['fields']
    fields['reparations.expiry']['value'] = []
    assert not capture.validate_capture(report, context, parent.CREATION, 'ENG')
