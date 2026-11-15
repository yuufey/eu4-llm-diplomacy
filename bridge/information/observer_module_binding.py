"""Locate the pinned observer DLL using an already authenticated read-only handle."""
from __future__ import annotations

import ctypes as C
from ctypes import wintypes as W
from pathlib import Path
import re
from typing import Any, Mapping

ROOT=Path(__file__).resolve().parents[2]
_HEX=re.compile(r'[0-9a-f]{64}\Z')
_UNKNOWN={'status':'unknown','reason':'OBSERVER_MODULE_BINDING_UNAVAILABLE'}


def validate_binding(value: Any, descriptor: Mapping[str, Any]) -> dict:
    """Validate recorded metadata without making an operating-system call."""
    if not isinstance(value,dict):raise ValueError('OBSERVER_MODULE_BINDING_SHAPE')
    if value.get('status')=='unknown':
        if value!=_UNKNOWN:raise ValueError('OBSERVER_MODULE_BINDING_UNKNOWN_SHAPE')
        return dict(_UNKNOWN)
    if set(value)!={'status','module_base','observed_path','file'} or value.get('status')!='bound':
        raise ValueError('OBSERVER_MODULE_BINDING_SHAPE')
    expected=descriptor['module_file']
    if (not isinstance(expected,dict) or set(expected)!={'path','bytes','sha256'}
            or type(expected['bytes']) is not int or expected['bytes']<=0
            or not isinstance(expected['sha256'],str) or not _HEX.fullmatch(expected['sha256'])
            or value['file']!=expected):
        raise ValueError('OBSERVER_MODULE_BINDING_FILE')
    path=(ROOT/expected['path']).resolve();path.relative_to(ROOT)
    if (not isinstance(value['observed_path'],str)
            or str(Path(value['observed_path']).resolve()).casefold()!=str(path).casefold()):
        raise ValueError('OBSERVER_MODULE_BINDING_PATH')
    raw_base=value['module_base']
    if not isinstance(raw_base,str):raise ValueError('OBSERVER_MODULE_BINDING_BASE')
    base=int(raw_base,0);size=descriptor['image_size']
    if (type(size) is not int or not 0<size<=128*1024*1024 or base<0x10000
            or base&0xffff or base>0x800000000000-size or raw_base!=hex(base)):
        raise ValueError('OBSERVER_MODULE_BINDING_BASE')
    return {'status':'bound','module_base':hex(base),'observed_path':str(path),'file':dict(expected)}


def from_held_reader(reader: Any, descriptor: Mapping[str, Any]) -> dict:
    """No OpenProcess, handle closing, target-memory write, or native game call."""
    try:
        held=reader
        for _ in range(4):
            if getattr(held,'kernel',None) is not None and getattr(held,'handle',None):break
            held=getattr(held,'reader',None)
            if held is None:return dict(_UNKNOWN)
        kernel,handle=held.kernel,held.handle
        expected=descriptor['module_file'];path=(ROOT/expected['path']).resolve();path.relative_to(ROOT)
        values=(W.HMODULE*1024)();needed=W.DWORD()
        if not kernel.K32EnumProcessModulesEx(handle,values,C.sizeof(values),C.byref(needed),3):
            return dict(_UNKNOWN)
        if not 0<needed.value<=C.sizeof(values) or needed.value%C.sizeof(W.HMODULE):
            return dict(_UNKNOWN)
        matches=[]
        for item in values[:needed.value//C.sizeof(W.HMODULE)]:
            name=C.create_unicode_buffer(32768)
            length=kernel._probe_get_module_name(handle,item,name,len(name))
            if not 0<length<len(name):continue
            observed=Path(name.value).resolve()
            if str(observed).casefold()==str(path).casefold():
                base=int(getattr(item,'value',item))
                matches.append({'status':'bound','module_base':hex(base),'observed_path':str(observed),'file':dict(expected)})
        if len(matches)!=1:return dict(_UNKNOWN)
        return validate_binding(matches[0],descriptor)
    except Exception:
        return dict(_UNKNOWN)


__all__=['from_held_reader','validate_binding']
