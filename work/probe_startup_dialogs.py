"""Bounded, read-only startup dialog inspection for the verified executable."""
from pathlib import Path

source_path = Path(__file__).with_name("probe_native_state.py")
source = source_path.read_text(encoding="utf-8")
body = r'''
        import struct
        class MBI(C.Structure):
            _fields_=[('BaseAddress',C.c_void_p),('AllocationBase',C.c_void_p),('AllocationProtect',W.DWORD),('PartitionId',W.WORD),('RegionSize',C.c_size_t),('State',W.DWORD),('Protect',W.DWORD),('Type',W.DWORD)]
        kernel.VirtualQueryEx.argtypes=[W.HANDLE,C.c_void_p,C.POINTER(MBI),C.c_size_t]
        kernel.VirtualQueryEx.restype=C.c_size_t
        needle=struct.pack('<Q',base+0x1d57328)
        address=0; scanned=0; deadline=time.monotonic()+20; found=[]
        while address<0x7fffffffffff and scanned<3*1024**3 and time.monotonic()<deadline:
            mbi=MBI()
            if not kernel.VirtualQueryEx(handle,address,C.byref(mbi),C.sizeof(mbi)): break
            region=int(mbi.BaseAddress or 0); length=mbi.RegionSize
            if not length: break
            address=region+length
            if mbi.State!=0x1000 or mbi.Type!=0x20000 or mbi.Protect&0x101 or not mbi.Protect&0xcc: continue
            for off in range(0,length,1024*1024):
                if scanned>=3*1024**3 or time.monotonic()>=deadline: break
                n=min(1024*1024,length-off); scanned+=n
                try: chunk=read(region+off,n)
                except OSError: continue
                at=chunk.find(needle)
                while at>=0:
                    obj=region+off+at
                    try:
                        name=obj+0x118; size=qword(name+16); capacity=qword(name+24)
                        if size<=256 and capacity<=1024:
                            text=read(qword(name) if capacity>=16 else name,size).decode('utf-8','replace') if size else ''
                            found.append({'object':hex(obj),'name':text,'widget':hex(qword(obj+8)),'raw':read(obj,0x1b8).hex()})
                    except (OSError,RuntimeError): pass
                    at=chunk.find(needle,at+8)
        report={'pid':args.pid,'read_only':True,'player_slot':player_slot,'scanned_bytes':scanned,'dialogs':found}
        args.output.write_text(json.dumps(report,indent=2),encoding='utf-8'); print(json.dumps(report,indent=2)); return
'''
assert source.count("        slots = []") == 1
source = source.replace("        slots = []", body + "\n        slots = []")
exec(compile(source, str(source_path), "exec"),
     {"__name__": "__main__", "__file__": str(source_path)})
