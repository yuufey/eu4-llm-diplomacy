"""Operand-reading boundaries; arithmetic also has an owned-code oracle."""
import pytest

from bridge.information.person_age_memory import MONTHS,project_age,read_age

BASE=0x140000000
PERSON=0x7000000000
WORLD=0x7100000000


class Memory:
    def __init__(self,birth=56269872,current=56564448):
        self.data={PERSON+0x70:birth.to_bytes(4,'little',signed=True),
            BASE+0x233fe58:WORLD.to_bytes(8,'little'),
            WORLD+0x1dd0:current.to_bytes(4,'little',signed=True),
            BASE+0x1c3a5c8:b''.join(x.to_bytes(4,'little') for x in MONTHS)}
        self.reads=[]

    def read(self,address,size,label):
        self.reads.append((address,size,label))
        return self.data[address]


def test_actual_retained_operands_read_as_33_years():
    result=read_age(Memory(),BASE,PERSON,require_known_birth=True)
    assert result['status']=='known' and result['value']==33 and result['unit']=='years'
    assert result['raw_inputs']['birth_date_raw_hex']=='309c5a03'


def test_future_birth_is_known_zero_instead_of_unknown():
    result=read_age(Memory(56564472),BASE,PERSON)
    assert result['status']=='known' and result['value']==0


def test_ruler_unknown_birthday_does_not_become_a_large_computed_age():
    memory=Memory(0)
    result=read_age(memory,BASE,PERSON,require_known_birth=True)
    assert result['status']=='unknown' and 'value' not in result
    assert result['reason']=='PERSON_BIRTH_DATE_NATIVE_UI_UNKNOWN'
    assert [address for address,_size,_label in memory.reads]==[PERSON+0x70]


def test_native_known_birth_threshold_is_inclusive():
    assert read_age(Memory(0x29c77f8),BASE,PERSON,require_known_birth=True)['status']=='unknown'
    assert read_age(Memory(0x29c77f9),BASE,PERSON,require_known_birth=True)['status']=='known'


def test_nonstandard_month_table_is_unknown_with_raw_operands_retained():
    memory=Memory();memory.data[BASE+0x1c3a5c8]=b'\x00'*48
    result=read_age(memory,BASE,PERSON)
    assert result['status']=='unknown' and 'value' not in result
    assert result['raw_inputs']['month_lengths_raw_hex']=='00'*48


def test_missing_date_read_preserves_partial_input_without_a_value():
    memory=Memory();del memory.data[WORLD+0x1dd0]
    result=read_age(memory,BASE,PERSON)
    assert result['status']=='unknown' and 'value' not in result
    assert result['raw_inputs']['birth_date_raw_hex']=='309c5a03'


@pytest.mark.parametrize('birth,current',[(True,1),(1,False),(-1,56564448),(1,-1),(2**31,1)])
def test_unsupported_raw_dates_are_rejected(birth,current):
    with pytest.raises(ValueError,match='DATE_RANGE_UNSUPPORTED'):
        project_age(birth,current)
