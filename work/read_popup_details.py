"""Bounded, read-only startup dialog inspection for the verified executable."""
from pathlib import Path

source_path = Path(__file__).with_name("probe_native_state.py")
source = source_path.read_text(encoding="utf-8")
body = r'''
        import struct
        def string(addr):
            size=qword(addr+16); cap=qword(addr+24)
            if size>2048: return '?'
            return read(qword(addr) if cap>=16 else addr,size).decode('utf-8','replace') if size else ''
        obj=args.peace_address; widget=qword(obj+8)
        for namesoff,ptrsoff in ((0x5d0,0x5b8),(0x720,0x708)):
            names=qword(widget+namesoff); end=qword(widget+namesoff+8); ptrs=qword(widget+ptrsoff)
            if not 0<end-names<=32*128: continue
            for i in range((end-names)//32):
                name=string(names+32*i); child=qword(ptrs+8*i)
                item={'name':name,'child':hex(child),'vtable':hex(qword(child)-base)}
                if name in ('title','description'): item['text']=string(child+0x170)
                if name=='agreebutton':
                    node=qword(child+0xd0); listeners=[]; seen=set()
                    while node and node not in seen and len(seen)<16:
                        seen.add(node); listener=qword(node)
                        listeners.append({'node':hex(node),'listener':hex(listener),'data':read(listener,0x50).hex()})
                        node=qword(node+0x10)
                    item['listeners']=listeners
                print(json.dumps(item,ensure_ascii=False))
        return
'''
assert source.count("        slots = []") == 1
source = source.replace("        slots = []", body + "\n        slots = []")
exec(compile(source, str(source_path), "exec"),
     {"__name__": "__main__", "__file__": str(source_path)})
