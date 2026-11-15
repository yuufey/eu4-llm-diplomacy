from copy import deepcopy
import ctypes as C
from ctypes import wintypes as W
import hashlib
import struct
import unittest

from bridge.information import observer_module_binding as modules
from bridge.information import observer_registry_memory as registry

CREATION=134376782534496994
BASE=0x180000000
PREFERRED=0x2568d0000
REFERENCE=0x196ea2bf040
IDENTIFIER='war_1c5b10c9b19ce405_00000001'


class Memory:
    def __init__(self):self.data={};self.calls=[];self.short=None;self.fail=None
    def put(self,at,data):self.data.update({at+i:b for i,b in enumerate(data)})
    def read(self,at,size,label):
        self.calls.append((at,size,label))
        if self.fail and self.fail in label:raise OSError('fixture read failure')
        value=bytes(self.data[at+i] for i in range(size))
        return value[:-1] if self.short and self.short in label else value


def fixture(count=1,*,loaded_header=False):
    header=bytearray(1024);header[:2]=b'MZ';struct.pack_into('<I',header,0x3c,0x80)
    header[0x80:0x84]=b'PE\0\0';struct.pack_into('<H',header,0x98,0x20b)
    struct.pack_into('<Q',header,0xb0,PREFERRED);struct.pack_into('<I',header,0xd0,0x20000)
    file={'path':'work/runtime/registry-unit-fixture.dll','bytes':4096,'sha256':'a'*64}
    code=b'\x90\x90\xc3'
    layout={'module_file':file,'image_size':0x20000,'header_raw_hex':header.hex(),
        'header_image_base_offset':0xb0,'preferred_image_base':hex(PREFERRED),
        'count_rva':0x1000,'entries_rva':0x1100,'creation_rva':0x4000,
        'code_guards':[{'rva':'0x800','end_rva_exclusive':'0x803','bytes':code.hex(),
                        'sha256':hashlib.sha256(code).hexdigest(),'relocation_offsets':[]}]}
    binding={'status':'bound','module_base':hex(BASE),'observed_path':str(modules.ROOT/file['path']),'file':dict(file)}
    memory=Memory()
    if loaded_header:struct.pack_into('<Q',header,0xb0,BASE)
    memory.put(BASE,header);memory.put(BASE+0x800,code)
    memory.put(BASE+0x1000,count.to_bytes(4,'little'));memory.put(BASE+0x4000,CREATION.to_bytes(8,'little'))
    for index in range(count):
        name=f'war_1c5b10c9b19ce405_{index+1:08x}'.encode()+b'\0'
        record=(REFERENCE+index*0x1000).to_bytes(8,'little')+name+b'\0\0'
        memory.put(BASE+0x1100+index*40,record)
    return memory,binding,layout


def read(memory,binding,layout,creation=CREATION):
    return registry.read_registry(memory,0x140000000,binding=binding,layout=layout,expected_creation=creation)


class RegistryMemoryTests(unittest.TestCase):
    def test_reusable_slots_accept_lifetime_serials_and_sort_current_ids(self):
        memory,binding,layout=fixture(2)
        layout.update(registry_format='reusable_slots_v1',revision_rva=0x4100)
        memory.put(BASE+0x4100,(12).to_bytes(8,'little'))
        memory.put(BASE+0x1108,b'war_1c5b10c9b19ce405_00000258\0')
        result=read(memory,binding,layout)
        self.assertEqual((result['status'],result['count'],result['allocated_count']),('known',2,2))
        self.assertEqual(result['serial_scope'],'observer_lifetime')
        self.assertEqual([entry['serial'] for entry in result['entries']],[2,600])
        self.assertEqual(len([call for call in memory.calls if '.revision_' in call[2]]),2)

    def test_reusable_slots_reject_inflight_or_changed_revision(self):
        for initial,change in ((1,False),(2,True)):
            with self.subTest(initial=initial):
                memory,binding,layout=fixture()
                layout.update(registry_format='reusable_slots_v1',revision_rva=0x4100)
                memory.put(BASE+0x4100,initial.to_bytes(8,'little'))
                ordinary_read=memory.read
                def changing_read(at,size,label):
                    result=ordinary_read(at,size,label)
                    if change and label.endswith('.entries'):
                        memory.put(BASE+0x4100,(4).to_bytes(8,'little'))
                    return result
                memory.read=changing_read
                result=read(memory,binding,layout)
                self.assertEqual(result['status'],'unknown')
                self.assertEqual(result['reason'],'OBSERVER_REGISTRY_CHANGED_DURING_READ'
                                 if change else 'OBSERVER_REGISTRY_MUTATING')
                self.assertNotIn('entries',result)

    def test_reusable_slots_require_a_distinct_aligned_revision_field(self):
        for revision in (None,0x1000,0x1100,0x4101):
            with self.subTest(revision=revision):
                memory,binding,layout=fixture()
                layout.update(registry_format='reusable_slots_v1',revision_rva=revision)
                self.assertEqual(read(memory,binding,layout)['reason'],
                                 'OBSERVER_REGISTRY_REVISION_PROFILE_INVALID')
                self.assertEqual(memory.calls,[])

    def test_reusable_slots_still_reject_duplicate_zero_and_wrong_epoch_ids(self):
        for identifier in ('war_1c5b10c9b19ce405_00000002',
                           'war_1c5b10c9b19ce405_00000000',
                           'war_0000000000000000_00000001'):
            with self.subTest(identifier=identifier):
                memory,binding,layout=fixture(2)
                layout.update(registry_format='reusable_slots_v1',revision_rva=0x4100)
                memory.put(BASE+0x4100,(2).to_bytes(8,'little'))
                memory.put(BASE+0x1108,identifier.encode()+b'\0')
                self.assertEqual(read(memory,binding,layout)['reason'],
                                 'OBSERVER_REGISTRY_ID_BINDING_INVALID')

    def test_matches_observed_native_epoch_and_serial(self):
        memory,binding,layout=fixture();result=read(memory,binding,layout)
        self.assertEqual(result['status'],'known');self.assertEqual(result['entries'],[
            {'native_reference':hex(REFERENCE),'war_id':IDENTIFIER,'serial':1}])
        self.assertFalse(result['lifetime_binding_verified'])
        self.assertEqual(registry.epoch(CREATION),0x1c5b10c9b19ce405)

    def test_empty_initialized_registry_is_known_without_entry_read(self):
        memory,binding,layout=fixture(0);result=read(memory,binding,layout)
        self.assertEqual((result['status'],result['count'],result['entries']),('known',0,[]))
        self.assertFalse(any(label.endswith('.entries') for _,_,label in memory.calls))

    def test_supports_only_the_declared_header_base_variants(self):
        memory,binding,layout=fixture(loaded_header=True)
        self.assertEqual(read(memory,binding,layout)['status'],'known')
        memory.put(BASE+0xb0,(BASE+0x10000).to_bytes(8,'little'))
        self.assertEqual(read(memory,binding,layout)['reason'],'OBSERVER_REGISTRY_IMAGE_BASE_VARIANT_INVALID')

    def test_does_not_mask_unrelated_header_changes(self):
        memory,binding,layout=fixture();memory.put(BASE+0x20,b'X')
        self.assertEqual(read(memory,binding,layout)['reason'],'OBSERVER_REGISTRY_HEADER_MISMATCH')

    def test_wrong_creation_does_not_read_entries(self):
        memory,binding,layout=fixture();result=read(memory,binding,layout,CREATION+1)
        self.assertEqual(result['reason'],'OBSERVER_REGISTRY_CREATION_MISMATCH')
        self.assertFalse(any(label.endswith('.entries') for _,_,label in memory.calls))

    def test_count_over_capacity_does_not_follow_array(self):
        memory,binding,layout=fixture();memory.put(BASE+0x1000,(257).to_bytes(4,'little'))
        self.assertEqual(read(memory,binding,layout)['reason'],'OBSERVER_REGISTRY_COUNT_OUT_OF_RANGE')
        self.assertFalse(any(label.endswith('.entries') for _,_,label in memory.calls))

    def test_rejects_old_epoch_and_wrong_serial(self):
        for name in ('war_0000000000000000_00000001','war_1c5b10c9b19ce405_00000002'):
            with self.subTest(name=name):
                memory,binding,layout=fixture();memory.put(BASE+0x1108,name.encode()+b'\0')
                self.assertEqual(read(memory,binding,layout)['reason'],'OBSERVER_REGISTRY_ID_BINDING_INVALID')

    def test_rejects_missing_terminator(self):
        memory,binding,layout=fixture();memory.put(BASE+0x1108,IDENTIFIER.encode()+b'x')
        self.assertEqual(read(memory,binding,layout)['reason'],'OBSERVER_REGISTRY_ID_WIDTH_INVALID')

    def test_rejects_duplicate_or_noncanonical_references(self):
        for reference in (REFERENCE,REFERENCE+1):
            with self.subTest(reference=reference):
                memory,binding,layout=fixture(2);memory.put(BASE+0x1128,reference.to_bytes(8,'little'))
                self.assertEqual(read(memory,binding,layout)['reason'],'OBSERVER_REGISTRY_REFERENCE_INVALID')

    def test_retired_slot_preserves_serial_and_only_exposes_current_lifetime(self):
        memory,binding,layout=fixture(2)
        memory.put(BASE+0x1100,(0).to_bytes(8,'little'))
        memory.put(BASE+0x1128,REFERENCE.to_bytes(8,'little'))
        result=read(memory,binding,layout)
        self.assertEqual((result['status'],result['count'],result['allocated_count']),('known',1,2))
        self.assertEqual(result['entries'],[{'native_reference':hex(REFERENCE),
            'war_id':'war_1c5b10c9b19ce405_00000002','serial':2}])
        memory.put(BASE+0x1108,b'war_0000000000000000_00000001\0')
        self.assertEqual(read(memory,binding,layout)['reason'],'OBSERVER_REGISTRY_ID_BINDING_INVALID')

    def test_short_and_failed_reads_remain_unknown(self):
        for kind in ('short','fail'):
            with self.subTest(kind=kind):
                memory,binding,layout=fixture();setattr(memory,kind,'.entries')
                result=read(memory,binding,layout)
                self.assertEqual(result['status'],'unknown');self.assertNotIn('entries',result)

    def test_bad_binding_and_invalid_creation_perform_no_reads(self):
        for creation in (True,0,-1,2**64):
            memory,binding,layout=fixture();self.assertEqual(read(memory,binding,layout,creation)['status'],'unknown')
            self.assertEqual(memory.calls,[])
        memory,binding,layout=fixture();binding['file']['sha256']='b'*64
        self.assertEqual(read(memory,binding,layout)['status'],'unknown');self.assertEqual(memory.calls,[])

    def test_unavailable_module_is_distinct_from_empty_registry(self):
        memory,_,layout=fixture();binding={'status':'unknown','reason':'OBSERVER_MODULE_BINDING_UNAVAILABLE'}
        result=read(memory,binding,layout);self.assertEqual(result['status'],'unknown');self.assertNotIn('count',result)
        self.assertEqual(memory.calls,[])

    def test_aliasing_layout_is_rejected_before_reads(self):
        memory,binding,layout=fixture();layout['creation_rva']=layout['entries_rva']
        self.assertEqual(read(memory,binding,layout)['reason'],'OBSERVER_REGISTRY_LAYOUT_ALIAS')
        self.assertEqual(memory.calls,[])

    def test_code_mismatch_retracts_registry(self):
        memory,binding,layout=fixture();memory.put(BASE+0x800,b'\xcc')
        self.assertEqual(read(memory,binding,layout)['reason'],'OBSERVER_REGISTRY_CODE_MISMATCH')

    def test_dir64_guard_relocation_is_exact_and_bounded(self):
        memory,binding,layout=fixture()
        code=b'\x48\xb8'+(PREFERRED+0x5000).to_bytes(8,'little')+b'\xc3'
        layout['code_guards']=[{'rva':'0x800','end_rva_exclusive':hex(0x800+len(code)),
            'bytes':code.hex(),'sha256':hashlib.sha256(code).hexdigest(),'relocation_offsets':[2]}]
        relocated=bytearray(code);struct.pack_into('<Q',relocated,2,BASE+0x5000)
        memory.put(BASE+0x800,relocated);self.assertEqual(read(memory,binding,layout)['status'],'known')
        layout['code_guards'][0]['relocation_offsets']=[2,2]
        self.assertEqual(read(memory,binding,layout)['reason'],'OBSERVER_REGISTRY_RELOCATION_PROFILE_INVALID')


class Kernel:
    def __init__(self,paths):self.paths=paths;self.calls=[]
    def K32EnumProcessModulesEx(self,handle,values,size,needed,flags):
        self.calls.append('enum')
        for index,(base,_) in enumerate(self.paths):values[index]=base
        needed._obj.value=len(self.paths)*C.sizeof(W.HMODULE);return True
    def _probe_get_module_name(self,handle,module,buffer,length):
        self.calls.append('name');base=int(getattr(module,'value',module))
        buffer.value=next(path for address,path in self.paths if address==base)
        return len(buffer.value)
    def OpenProcess(self,*args):self.calls.append('open');raise AssertionError('must borrow handle')
    def CloseHandle(self,*args):self.calls.append('close');raise AssertionError('owner closes handle')


class ModuleBindingTests(unittest.TestCase):
    def test_uses_only_borrowed_handle_and_exact_module_path(self):
        _,binding,layout=fixture();kernel=Kernel([(0x140000000,str(modules.ROOT/'unit.exe')),(BASE,binding['observed_path'])])
        held=type('Held',(),{'kernel':kernel,'handle':123})()
        wrapper=type('Wrapper',(),{'reader':held})()
        self.assertEqual(modules.from_held_reader(wrapper,layout),binding)
        self.assertNotIn('open',kernel.calls);self.assertNotIn('close',kernel.calls)

    def test_missing_and_duplicate_modules_stay_unknown(self):
        _,binding,layout=fixture()
        for paths in ([],[(BASE,binding['observed_path']),(BASE+0x100000,binding['observed_path'])]):
            with self.subTest(paths=paths):
                kernel=Kernel(paths);held=type('Held',(),{'kernel':kernel,'handle':123})()
                self.assertEqual(modules.from_held_reader(held,layout)['status'],'unknown')

    def test_recorded_binding_validation_makes_no_os_calls(self):
        _,binding,layout=fixture();self.assertEqual(modules.validate_binding(binding,layout),binding)
        changed=deepcopy(binding);changed['module_base']=hex(BASE+1)
        with self.assertRaises(ValueError):modules.validate_binding(changed,layout)
        self.assertEqual(modules.from_held_reader(object(),layout)['status'],'unknown')


if __name__=='__main__':unittest.main()
