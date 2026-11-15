"""Reuse force records with the native galley-count branch and fixed units."""
from . import country_forces_memory as forces

def _s32(value):
    value &= 0xffffffff
    return value-0x100000000 if value & 0x80000000 else value

def count_galleys(reader,module_base,country_pointer):
    observed=forces.read_fields(reader,module_base,country_pointer,country='FRA')
    if observed.get('status')!='observed':
        raise ValueError('GALLEY_FORCE_RECORDS_UNAVAILABLE:'+str(observed.get('reason')))
    groups=observed['groups'];records=observed['records'];raw_total=0
    for index,group in enumerate(groups):
        selected=[row for row in records if row['group_index']==index and row['type_kind']==5]
        if not selected:
            continue  # Both native branches contribute zero for this group.
        pointer=int(group['group_object'],0)
        vtable=reader.qword(pointer,'mission_trigger.galley.group.vtable')[0]
        if not module_base<=vtable<module_base+0x2800000:
            raise ValueError('GALLEY_GROUP_VTABLE_OUTSIDE_MODULE')
        method=reader.qword(vtable+0x88,'mission_trigger.galley.group.kind_method')[0]
        if not module_base<=method<module_base+0x1c00000:
            raise ValueError('GALLEY_GROUP_KIND_METHOD_OUTSIDE_CODE')
        raw=reader.read_code(method,6,'mission_trigger.galley.group.kind_method_bytes')
        if not isinstance(raw,bytes) or len(raw)!=6:
            raise ValueError('GALLEY_GROUP_KIND_METHOD_SHORT_READ')
        if raw.startswith(b'\xb0\x01\xc3') or raw==b'\xb8\x01\0\0\0\xc3':
            count_units=True
        elif raw.startswith((b'\x32\xc0\xc3',b'\x33\xc0\xc3')):
            count_units=False
        else:
            raise ValueError('GALLEY_GROUP_KIND_METHOD_NOT_CONSTANT')
        addition=len(selected)*1000 if count_units else sum(row['strength_raw'] for row in selected)
        raw_total=_s32(raw_total+addition)
    return {'raw_fixed_milli':raw_total,
            'source':'native_kind5_group_gate_with_country_forces_memory.read_fields'}
