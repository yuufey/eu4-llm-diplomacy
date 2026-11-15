"""Pure bounded RPM projection of the pinned observer's shared war-ID registry.

IDs retain the native observer-session semantics. A pointer match is not proof
of war-object lifetime; this reader never creates, registers or retires an ID.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import re
import struct
from typing import Any, Mapping

from . import observer_module_binding as _binding

_ID=re.compile(r'war_([0-9a-f]{16})_([0-9a-f]{8})\Z')
MAX_ENTRIES=256
ENTRY_STRIDE=40
MAX_TOTAL_BYTES=65536
MAX_SINGLE_READ=16384
MAX_CALLS=32


def epoch(creation: int) -> int:
    value=(creation+0x9e3779b97f4a7c15)&0xffffffffffffffff
    value=((value^(value>>30))*0xbf58476d1ce4e5b9)&0xffffffffffffffff
    value=((value^(value>>27))*0x94d049bb133111eb)&0xffffffffffffffff
    return value^(value>>31)


def _unknown(reason,raw):
    return {'status':'unknown','reason':reason,'raw_inputs':raw,'lifetime_binding_verified':False}


class _Failure(ValueError):pass


def read_registry(reader: Any, main_base: int, *, binding: Any,
                  layout: Mapping[str,Any], expected_creation: int) -> dict:
    raw={'binding':deepcopy(binding),'reads':[]}
    try:
        if type(expected_creation) is not int or not 0<expected_creation<2**64:
            raise _Failure('OBSERVER_REGISTRY_CREATION_INVALID')
        try:normalized=_binding.validate_binding(binding,layout)
        except Exception as exc:raise _Failure('OBSERVER_REGISTRY_BINDING_INVALID') from exc
        if normalized['status']!='bound':return _unknown('OBSERVER_REGISTRY_BINDING_UNAVAILABLE',raw)
        base=int(normalized['module_base'],0);size=layout['image_size']
        header=bytes.fromhex(layout['header_raw_hex'])
        if not 128<=len(header)<=4096:raise _Failure('OBSERVER_REGISTRY_HEADER_PROFILE_INVALID')
        nt=struct.unpack_from('<I',header,0x3c)[0]
        if (header[:2]!=b'MZ' or nt+0x54>len(header) or header[nt:nt+4]!=b'PE\0\0'
                or struct.unpack_from('<H',header,nt+24)[0]!=0x20b
                or struct.unpack_from('<I',header,nt+0x50)[0]!=size):
            raise _Failure('OBSERVER_REGISTRY_HEADER_PROFILE_INVALID')
        image_at=nt+0x30;preferred=struct.unpack_from('<Q',header,image_at)[0]
        if image_at!=layout['header_image_base_offset'] or preferred!=int(layout['preferred_image_base'],0):
            raise _Failure('OBSERVER_REGISTRY_IMAGE_BASE_PROFILE_INVALID')
        ranges=[]
        for key,width,alignment in (('count_rva',4,4),('entries_rva',MAX_ENTRIES*ENTRY_STRIDE,8),('creation_rva',8,8)):
            rva=layout[key]
            if type(rva) is not int or rva<len(header) or rva%alignment or rva>size-width:
                raise _Failure('OBSERVER_REGISTRY_LAYOUT_INVALID')
            ranges.append((rva,rva+width))
        if any(a<c_end and c<a_end for index,(a,a_end) in enumerate(ranges) for c,c_end in ranges[index+1:]):
            raise _Failure('OBSERVER_REGISTRY_LAYOUT_ALIAS')
        registry_format=layout.get('registry_format')
        if registry_format not in (None,'reusable_slots_v1'):
            raise _Failure('OBSERVER_REGISTRY_FORMAT_INVALID')
        reusable=registry_format=='reusable_slots_v1'
        if reusable:
            revision_rva=layout.get('revision_rva')
            if (type(revision_rva) is not int or revision_rva<len(header)
                    or revision_rva%8 or revision_rva>size-8
                    or any(revision_rva<end and begin<revision_rva+8 for begin,end in ranges)):
                raise _Failure('OBSERVER_REGISTRY_REVISION_PROFILE_INVALID')
        calls=total=0
        def read(rva,width,label):
            nonlocal calls,total
            if (type(rva) is not int or type(width) is not int or width<=0 or width>MAX_SINGLE_READ
                    or rva<0 or rva>size-width or calls>=MAX_CALLS or total+width>MAX_TOTAL_BYTES):
                raise _Failure('OBSERVER_REGISTRY_READ_BUDGET')
            calls+=1;total+=width
            method=getattr(reader,'read',None)
            try:data=method(base+rva,width,'observer_registry.'+label) if callable(method) else reader(base+rva,width,'observer_registry.'+label)
            except Exception as exc:raise _Failure('OBSERVER_REGISTRY_READ_FAILED') from exc
            if not isinstance(data,(bytes,bytearray,memoryview)) or len(data)!=width:
                raise _Failure('OBSERVER_REGISTRY_SHORT_READ')
            data=bytes(data);raw['reads'].append({'rva':hex(rva),'size':width,'label':label,'sha256':hashlib.sha256(data).hexdigest()})
            return data
        actual=read(0,len(header),'header')
        observed_image=struct.unpack_from('<Q',actual,image_at)[0]
        if observed_image not in (preferred,base):raise _Failure('OBSERVER_REGISTRY_IMAGE_BASE_VARIANT_INVALID')
        expected=bytearray(header);expected[image_at:image_at+8]=actual[image_at:image_at+8]
        if actual!=bytes(expected):raise _Failure('OBSERVER_REGISTRY_HEADER_MISMATCH')
        raw['image_base_variant']='preferred' if observed_image==preferred else 'loaded_base'
        for index,code in enumerate(layout.get('code_guards',[])):
            rva=int(code['rva'],0);expected=bytearray.fromhex(code['bytes'])
            if (not expected or hashlib.sha256(expected).hexdigest()!=code['sha256']
                    or int(code['end_rva_exclusive'],0)!=rva+len(expected)):
                raise _Failure('OBSERVER_REGISTRY_CODE_PROFILE_INVALID')
            used=set()
            for offset in code.get('relocation_offsets',[]):
                if type(offset) is not int or not 0<=offset<=len(expected)-8 or any(x in used for x in range(offset,offset+8)):
                    raise _Failure('OBSERVER_REGISTRY_RELOCATION_PROFILE_INVALID')
                used.update(range(offset,offset+8));value=struct.unpack_from('<Q',expected,offset)[0]
                if not preferred<=value<preferred+size:raise _Failure('OBSERVER_REGISTRY_RELOCATION_TARGET_INVALID')
                struct.pack_into('<Q',expected,offset,value-preferred+base)
            if read(rva,len(expected),f'code[{index}]')!=bytes(expected):
                raise _Failure('OBSERVER_REGISTRY_CODE_MISMATCH')
        creation_raw=read(layout['creation_rva'],8,'creation');creation=int.from_bytes(creation_raw,'little')
        raw['creation_raw_hex']=creation_raw.hex()
        if creation!=expected_creation:raise _Failure('OBSERVER_REGISTRY_CREATION_MISMATCH')
        revision_before=read(revision_rva,8,'revision_before') if reusable else None
        if reusable and int.from_bytes(revision_before,'little')&1:
            raise _Failure('OBSERVER_REGISTRY_MUTATING')
        count_raw=read(layout['count_rva'],4,'count');count=int.from_bytes(count_raw,'little')
        raw['count_raw_hex']=count_raw.hex()
        if count>MAX_ENTRIES:raise _Failure('OBSERVER_REGISTRY_COUNT_OUT_OF_RANGE')
        records=read(layout['entries_rva'],count*ENTRY_STRIDE,'entries') if count else b''
        if reusable:
            revision_after=read(revision_rva,8,'revision_after')
            raw.update(revision_before_raw_hex=revision_before.hex(),revision_after_raw_hex=revision_after.hex())
            if revision_before!=revision_after:
                raise _Failure('OBSERVER_REGISTRY_CHANGED_DURING_READ')
        raw['entries_raw_hex']=records.hex();entries=[];references=set();serials=set()
        for index in range(count):
            record=records[index*ENTRY_STRIDE:(index+1)*ENTRY_STRIDE];reference=int.from_bytes(record[:8],'little')
            name=record[8:38]
            if name.find(b'\0')!=29:raise _Failure('OBSERVER_REGISTRY_ID_WIDTH_INVALID')
            try:identifier=name[:29].decode('ascii')
            except UnicodeDecodeError as exc:raise _Failure('OBSERVER_REGISTRY_ID_ENCODING_INVALID') from exc
            match=_ID.fullmatch(identifier)
            serial=int(match.group(2),16) if match else 0
            if (not match or int(match.group(1),16)!=epoch(creation) or not serial
                    or serial in serials or (not reusable and serial!=index+1)):
                raise _Failure('OBSERVER_REGISTRY_ID_BINDING_INVALID')
            serials.add(serial)
            if reference==0:
                continue
            if not 0x10000<=reference<0x800000000000 or reference&7 or reference in references:
                raise _Failure('OBSERVER_REGISTRY_REFERENCE_INVALID')
            references.add(reference)
            entries.append({'native_reference':hex(reference),'war_id':identifier,'serial':serial})
        entries.sort(key=lambda entry:entry['serial'])
        raw.update(calls=calls,bytes_requested=total)
        result={'status':'known','entries':entries,'count':len(entries),'allocated_count':count,'raw_inputs':raw,
                'creation_matches':True,'lifetime_binding_verified':False}
        if reusable:result['serial_scope']='observer_lifetime'
        return result
    except _Failure as exc:return _unknown(str(exc),raw)
    except Exception:return _unknown('OBSERVER_REGISTRY_PROFILE_OR_READER_INVALID',raw)


__all__=['read_registry','epoch']
