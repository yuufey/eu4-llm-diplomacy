"""Project the fixed B23 character-age helper from copied date operands."""
from __future__ import annotations

from .foreign_technology_capture import _read, _pointer

EPOCH_TICKS=0x29c55c0
MONTHS=(31,28,31,30,31,30,31,31,30,31,30,31)


def project_age(birth_raw:int,current_raw:int)->int:
    """Age follows a4e140's year and birthday comparisons, clamped to zero."""
    if (type(birth_raw) is not int or type(current_raw) is not int
            or not 0<=birth_raw<=0x7fffffff or not 0<=current_raw<=0x7fffffff):
        raise ValueError('PERSON_AGE_DATE_RANGE_UNSUPPORTED')
    birth_days=(birth_raw-EPOCH_TICKS)//24
    current_days=(current_raw-EPOCH_TICKS)//24
    birth_year,birth_ordinal=divmod(birth_days,365)
    current_year,current_ordinal=divmod(current_days,365)
    return max(0,current_year-birth_year-int(current_ordinal<birth_ordinal))


def read_age(reader,base,person,*,label='person',require_known_birth=False):
    raw_inputs={}
    try:
        _pointer(base);_pointer(person)
        raw=_read(reader,person+0x70,4,'person.age.'+label+'.birth_date')
        raw_inputs['birth_date_raw_hex']=raw.hex()
        birth=int.from_bytes(raw,'little',signed=True)
        if require_known_birth and birth<0x29c77f9:
            raise ValueError('PERSON_BIRTH_DATE_NATIVE_UI_UNKNOWN')
        world_raw=_read(reader,base+0x233fe58,8,'person.age.'+label+'.world_pointer')
        world=_pointer(int.from_bytes(world_raw,'little'))
        raw_inputs['world_pointer_raw_hex']=world_raw.hex()
        current_raw=_read(reader,world+0x1dd0,4,'person.age.'+label+'.current_date')
        raw_inputs['current_date_raw_hex']=current_raw.hex()
        current=int.from_bytes(current_raw,'little',signed=True)
        months_raw=_read(reader,base+0x1c3a5c8,48,'person.age.'+label+'.month_lengths')
        raw_inputs['month_lengths_raw_hex']=months_raw.hex()
        months=tuple(int.from_bytes(months_raw[n:n+4],'little',signed=True) for n in range(0,48,4))
        if months!=MONTHS:
            raise ValueError('PERSON_AGE_CALENDAR_TABLE_MISMATCH')
        value=project_age(birth,current)
        return {'status':'known','value':value,'unit':'years','raw_inputs':raw_inputs,
            'basis':'projected_native_a4e140_calendar_age','native_function_invoked':False}
    except Exception as exc:
        return {'status':'unknown','reason':str(exc)[:160],'raw_inputs':raw_inputs,
            'basis':'projected_native_a4e140_calendar_age','native_function_invoked':False}


__all__=['project_age','read_age']
