"""Run exact fixed-build age code in a new owned Python process, never EU4.

Code occupies its original relative RVAs inside a private reserved region.
Only the five necessary pages are committed. Code bytes are not patched.
"""
from __future__ import annotations

import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import random
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from work.verify_information_foreign_technology import pin,write_new

STAGE=ROOT/'work/runtime/information-country-person-20261029-001/owned-age-verified-001'
EXE='b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77'
SLICES=((0xcfd70,160),(0xcfe10,103),(0x14c8020,287),(0xa4e140,208),(0x1c3a5c8,48))
MONTHS=(31,28,31,30,31,30,31,31,30,31,30,31)


def sha_bytes(raw):return hashlib.sha256(raw).hexdigest()


def encode_date(date):
    year,month,day,hour=date
    assert 1<=month<=12 and 1<=day<=MONTHS[month-1] and 0<=hour<24
    raw=((year+5000)*365+sum(MONTHS[:month-1])+day-1)*24+hour
    assert 0<=raw<=0x7fffffff
    return raw


def oracle(birth,now):
    """Independent calendar tuples, with birthday comparison and future clamp."""
    return max(0,now[0]-birth[0]-int(now[1:3]<birth[1:3]))


def decode_date(raw):
    day=(raw//24)-5000*365;year,ordinal=divmod(day,365);month=1
    for length in MONTHS:
        if ordinal<length:return (year,month,ordinal+1,raw%24)
        month+=1;ordinal-=length
    raise ValueError('date_ordinal_out_of_bound')


def prepare():
    from work.discover_diplomacy import PE
    from work.local_config import game_exe
    STAGE.mkdir(exist_ok=False)
    pe=PE(game_exe());assert sha_bytes(pe.data)==EXE
    slices=[]
    for rva,size in SLICES:
        raw=pe.bytes_at(rva,size);assert len(raw)==size
        path=STAGE/f'{rva:08x}.bin'
        with path.open('xb') as stream:stream.write(raw)
        slices.append({'rva':rva,'size':size,'sha256':sha_bytes(raw),'file':path.name})
    assert pe.bytes_at(0xcfe03,1)==b'\xc3'
    assert pe.bytes_at(0x1c3a5c8,48)==b''.join(x.to_bytes(4,'little') for x in MONTHS)
    rows=[]
    explicit=[((1400,1,1,0),(1400,1,1,0)),((1400,3,1,0),(1440,2,28,0)),
        ((1400,3,1,0),(1440,3,1,0)),((1400,3,1,0),(1440,3,2,0)),
        ((1400,12,31,0),(1440,1,1,0)),((1400,12,31,0),(1440,12,30,23)),
        ((1400,12,31,23),(1440,12,31,0)),((1400,2,28,0),(1440,3,1,0)),
        ((1500,1,1,0),(1400,1,1,0)),((1457,2,17,0),(1457,2,17,23)),
        ((1457,2,17,23),(1457,2,17,0)),((1457,1,1,0),(1456,12,31,23)),
        ((1,1,1,0),(2,1,1,0)),((1,1,2,0),(2,1,1,0)),
        ((-5000,1,1,0),(1457,2,17,0)),((1457,2,17,0),(1457,2,16,23)),
        ((1457,2,17,0),(1458,2,16,23)),((1457,2,17,23),(1458,2,17,0)),
        ((1457,2,17,0),(1458,2,18,0)),((1399,12,31,0),(1400,1,1,0)),
        ((1457,2,17,0),(1457,2,18,0))]
    rng=random.Random(78137)
    def random_date():
        year=rng.randint(1,3000);month=rng.randint(1,12)
        return year,month,rng.randint(1,MONTHS[month-1]),rng.randrange(24)
    for birth,now in explicit+[(random_date(),random_date()) for _ in range(1024)]:
        rows.append({'birth_raw':encode_date(birth),'current_raw':encode_date(now),
            'birth_calendar':birth,'current_calendar':now,'expected':oracle(birth,now)})
    probe=ROOT/'work/runtime/information-country-person-20261029-001/probe_person_native_inputs_001.json'
    assert probe.stat().st_size<10*1024*1024
    document=json.loads(probe.read_text(encoding='utf-8'))
    for entry in document['capture_reports']:
        report=entry['capture'];target=report['observation']['backend']['targets'][0]
        inputs=target['fields']['S04.native_inputs']['value']
        now=report['observation']['context_before']['game_date']
        for role in ('ruler','heir'):
            header=bytes.fromhex(inputs[role]['header_read']['raw_hex'])
            birth=int.from_bytes(header[0x70:0x74],'little',signed=True)
            b,n=decode_date(birth),decode_date(now)
            rows.append({'birth_raw':birth,'current_raw':now,'expected':oracle(b,n),
                'birth_calendar':b,'current_calendar':n,'source':entry['country']+'.'+role})
    write_new(STAGE/'inputs.json',{'slices':slices,'cases':rows,'probe':pin(probe),
        'executable_sha256':EXE,'runner':pin(Path(__file__).resolve())})
    return len(rows)


def child():
    manifest=json.loads((STAGE/'inputs.json').read_text(encoding='utf-8'))
    kernel=C.WinDLL('kernel32',use_last_error=True)
    kernel.VirtualAlloc.argtypes=[C.c_void_p,C.c_size_t,C.c_uint32,C.c_uint32];kernel.VirtualAlloc.restype=C.c_void_p
    kernel.VirtualProtect.argtypes=[C.c_void_p,C.c_size_t,C.c_uint32,C.POINTER(C.c_uint32)];kernel.VirtualProtect.restype=C.c_int
    kernel.VirtualFree.argtypes=[C.c_void_p,C.c_size_t,C.c_uint32];kernel.VirtualFree.restype=C.c_int
    kernel.GetCurrentProcess.restype=C.c_void_p
    kernel.FlushInstructionCache.argtypes=[C.c_void_p,C.c_void_p,C.c_size_t];kernel.FlushInstructionCache.restype=C.c_int
    extent=0x2341000;base=kernel.VirtualAlloc(None,extent,0x2000,1)
    if not base:raise C.WinError(C.get_last_error())
    print(json.dumps({'stage':'reserved','owned_base':hex(base),'extent':extent}),flush=True)
    try:
        code_pages={rva&~4095 for rva,size in SLICES[:4]}
        data_pages={0x1c3a5c8&~4095,0x233fe58&~4095}
        pages=code_pages|data_pages
        assert not code_pages&data_pages
        for offset in sorted(pages):
            address=kernel.VirtualAlloc(base+offset,4096,0x1000,4)
            if address!=base+offset:raise C.WinError(C.get_last_error())
        print(json.dumps({'stage':'committed','pages':[hex(x) for x in sorted(pages)],'committed_bytes':len(pages)*4096}),flush=True)
        for row in manifest['slices']:
            raw=(STAGE/row['file']).read_bytes();assert len(raw)==row['size'] and sha_bytes(raw)==row['sha256']
            C.memmove(base+row['rva'],raw,len(raw))
        world=C.create_string_buffer(0x2000);person=C.create_string_buffer(0x80)
        C.c_uint64.from_address(base+0x233fe58).value=C.addressof(world)
        for offset in sorted(code_pages):
            old=C.c_uint32()
            if not kernel.VirtualProtect(base+offset,4096,0x20,C.byref(old)):raise C.WinError(C.get_last_error())
            if not kernel.FlushInstructionCache(kernel.GetCurrentProcess(),base+offset,4096):raise C.WinError(C.get_last_error())
        old=C.c_uint32()
        if not kernel.VirtualProtect(base+(0x1c3a5c8&~4095),4096,2,C.byref(old)):raise C.WinError(C.get_last_error())
        print(json.dumps({'stage':'ready','code_pages_RX':len(code_pages),'month_page_RO':True,'world_global_page_RW':True}),flush=True)
        routine=C.WINFUNCTYPE(C.c_int,C.c_void_p)(base+0xa4e140)
        for index,case in enumerate(manifest['cases']):
            C.c_int32.from_buffer(person,0x70).value=case['birth_raw']
            C.c_int32.from_buffer(world,0x1dd0).value=case['current_raw']
            actual=routine(C.addressof(person))
            print(json.dumps({'case':index,'actual':actual,'expected':case['expected'],'matches':actual==case['expected']}),flush=True)
        for row in manifest['slices']:
            assert sha_bytes(C.string_at(base+row['rva'],row['size']))==row['sha256']
        print(json.dumps({'stage':'code_and_data_unchanged','verified':True}),flush=True)
    finally:
        freed=bool(kernel.VirtualFree(base,0,0x8000))
        print(json.dumps({'stage':'released','VirtualFree':freed}),flush=True)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--child',action='store_true');args=parser.parse_args()
    if args.child:return child()
    count=prepare();command=[sys.executable,'-B',str(Path(__file__).resolve()),'--child']
    with (STAGE/'child-output.jsonl').open('xb') as out,(STAGE/'child-stderr.log').open('xb') as err:
        process=subprocess.Popen(command,cwd=ROOT,stdout=out,stderr=err,creationflags=subprocess.CREATE_NO_WINDOW)
        pid=process.pid
        try:exitcode=process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            process.kill();process.wait();exitcode=process.returncode
    inputs=json.loads((STAGE/'inputs.json').read_text(encoding='utf-8'))
    from bridge.information.person_age_memory import project_age
    lines=[json.loads(line) for line in (STAGE/'child-output.jsonl').read_text(encoding='utf-8').splitlines()]
    cases=[row for row in lines if 'case' in row]
    comparisons=[]
    for result in cases:
        case=inputs['cases'][result['case']];projection=project_age(case['birth_raw'],case['current_raw'])
        comparisons.append({**case,**result,'projection':projection,'three_way_match':projection==result['actual']==case['expected']})
    write_new(STAGE/'three-way-comparison.json',comparisons)
    released=any(row.get('stage')=='released' and row.get('VirtualFree') is True for row in lines)
    passed=(exitcode==0 and len(cases)==count and released and all(x['three_way_match'] for x in comparisons))
    receipt={'status':'passed' if passed else 'failed','owned_child_pid':pid,'argv':command,'exitcode':exitcode,
        'case_count':count,'actual_return_count':len(cases),'matches':sum(x['three_way_match'] for x in comparisons),
        'VirtualFree':released,'new_owned_process_only':True,'game_access':False,'game_native_calls':0,
        'classification':'Observed copied machine code in a new owned process; not a game-process call or UI observation',
        'inputs':pin(STAGE/'inputs.json'),'stdout':pin(STAGE/'child-output.jsonl'),'stderr':pin(STAGE/'child-stderr.log'),
        'comparison':pin(STAGE/'three-way-comparison.json'),'runner':pin(Path(__file__).resolve()),
        'projection_source':pin(ROOT/'bridge/information/person_age_memory.py'),
        'unsupported_prior_agent_claims':'No retained fixture artifacts support the earlier 533/PID46444/SHA claims; they are withdrawn, not imported as evidence'}
    write_new(STAGE/'receipt.json',receipt);print(json.dumps(receipt,ensure_ascii=False));return 0 if passed else 2


if __name__=='__main__':raise SystemExit(main())
