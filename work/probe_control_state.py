"""Read-only speed and server accessor evidence; no game calls."""
from pathlib import Path
source_path = Path(__file__).with_name('probe_native_state.py')
source = source_path.read_text(encoding='utf-8')
marker = '        slots = []'
assert source.count(marker) == 1
body = '''
        server = qword(game+0x1e00)
        vt = qword(server)
        getter = qword(vt+0x100)
        report = {'pid': args.pid, 'read_only': True, 'player_slot': player_slot,
                  'date_raw': int.from_bytes(read(game+0x1dd0,4),'little',signed=True),
                  'speed': int.from_bytes(read(game+0x1e08,4),'little',signed=True),
                  'server': hex(server), 'server_vtable_rva': hex(vt-base),
                  'pause_getter_rva': hex(getter-base), 'pause_getter_bytes': read(getter,32).hex(),
                  'autosave_rva': hex(qword(vt+0x150)-base)}
        if getter-base == 0x802500:
            pause = qword(server+0x418)
            report['pause_object'] = hex(pause)
            if pause:
                report['paused_flag'] = read(pause+0x48,1)[0]
                report['pause_vector_begin'] = hex(qword(pause))
                report['pause_vector_end'] = hex(qword(pause+8))
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(report,indent=2),encoding='utf-8')
        print(json.dumps(report,indent=2))
        return
'''
source = source.replace(marker, body + '\n' + marker)
exec(compile(source, str(source_path), 'exec'),
     {'__name__': '__main__', '__file__': str(source_path)})
