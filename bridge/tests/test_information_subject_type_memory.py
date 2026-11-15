import pytest

from bridge.information import subject_pressure, subject_type_memory
from bridge.tests.test_information_ai_personality import (
    MODULE_BASE, SUBJECT_DEFINITION_BASE, _add_country, _share_ruler)
from bridge.tests.test_information_foreign_technology_memory import MemoryReader


def make_reader(*, annual=False):
    profile = subject_pressure._load_profile()
    relationship = profile['attitude']['personality']
    spec = profile['subject_obligations']
    reader, rows = MemoryReader(), {}
    child, _ = _add_country(reader, rows, relationship, 'NOR', 1, 0)
    parent, parent_ref = _add_country(reader, rows, relationship, 'DAN', 2, 0)
    _share_ruler(reader, relationship, child, 1, parent, parent_ref, 2, False)
    definition = SUBJECT_DEFINITION_BASE + 0x1000
    reader.put_u64(definition, MODULE_BASE + spec['vtable_rva'])
    name = bytearray(32)
    name[:6] = b'vassal'
    name[16:24] = (6).to_bytes(8, 'little')
    name[24:32] = (15).to_bytes(8, 'little')
    reader.put(definition + spec['name_offset'], bytes(name))
    for field, values in spec['fields'].items():
        for key, member in values.items():
            if member['kind'] == 'bool':
                reader.put(definition + member['offset'], bytes([annual]))
            else:
                value = {'vassal_tax_multiplier': 1000,
                         'land_force_limit_share_percent': 100,
                         'base_diplomatic_cost_per_development': 8000}.get(key, 0)
                reader.put_i32(definition + member['offset'], value)
    return reader, {'country_pointer': hex(child)}, relationship, spec


@pytest.mark.parametrize('annual', [False, True])
def test_reads_loaded_definition_and_keeps_contribution_scales(annual):
    reader, binding, relationship, spec = make_reader(annual=annual)
    name, fields = subject_type_memory.read_obligations(
        reader, MODULE_BASE, binding, relationship, spec, ['tribute', 'levy'])
    assert name == 'vassal'
    assert fields['tribute']['value']['annual_tribute'] is annual
    assert fields['tribute']['value']['vassal_tax_multiplier']['value'] == 1000
    assert fields['levy']['value']['land_force_limit_share_percent']['scale'] == 10
    assert fields['levy']['value']['manpower_factor']['value'] == 0


def test_tribute_only_skips_levy_members():
    reader, binding, relationship, spec = make_reader()
    _, fields = subject_type_memory.read_obligations(
        reader, MODULE_BASE, binding, relationship, spec, ['tribute'])
    assert set(fields) == {'tribute'}
    assert not any(label == 'subject_type.manpower_factor' for _, _, label in reader.reads)


def test_integration_base_cost_converts_fixed_point_to_diplomatic_power():
    from bridge.information.presentation import _concise_value

    reader, binding, relationship, spec = make_reader()
    _, fields = subject_type_memory.read_obligations(
        reader, MODULE_BASE, binding, relationship, spec, ['integration'])
    assert _concise_value(fields['integration'])['base_diplomatic_cost_per_development'] == 8.0


def test_unrelated_definition_class_is_rejected():
    reader, binding, relationship, spec = make_reader()
    reader.put_u64(SUBJECT_DEFINITION_BASE + 0x1000, MODULE_BASE)
    with pytest.raises(ValueError, match='SUBJECT_TYPE_CLASS_UNAVAILABLE'):
        subject_type_memory.read_obligations(
            reader, MODULE_BASE, binding, relationship, spec, ['tribute'])
