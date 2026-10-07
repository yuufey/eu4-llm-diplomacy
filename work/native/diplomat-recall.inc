// Experimental fixed POR diplomat 0 in FRA recall, on the game frame thread.
// Uses the command built by native CANCEL_DIPLOMAT confirmation, not field edits.
static wchar_t recall_request[MAX_PATH];
static bool recall_used=false;
static void diplomat_recall_tick() {
    if (GetFileAttributesW(recall_request)==INVALID_FILE_ATTRIBUTES) return;
    char request[64]{}; DWORD got=0;
    HANDLE file=CreateFileW(recall_request,GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    if (file==INVALID_HANDLE_VALUE) return;
    DWORD size=GetFileSize(file,nullptr);
    bool valid=size<sizeof(request) && ReadFile(file,request,size,&got,nullptr) && got==size;
    CloseHandle(file);
    if (!DeleteFileW(recall_request)) return;
    valid=valid && strcmp(request,"TEST_ONLY POR diplomat_0\n")==0 && !recall_used && control_ready()
        && !control_target && !control_pause_after_load && !control_load_wait_frames;
    uintptr_t game=0,db=0,array=0,fra=0,holder=0,container=0,begin=0,end=0,entry=0,record=0,vt=0,can=0,type=0;
    uint64_t player=0,actor=0,record_actor=0,recipient=0; int32_t id=-1; unsigned char active=0;
    valid=valid && read(base+0x233fe58,game) && read(game+0x1e60,player)
        && (player&0xffffff)==0x524f50 && ((player>>32)&0xffff)==189
        && read(base+0x233d8b0,db) && read(db+0x118,array) && read(array+189*8,fra)
        && read(fra+0x20,actor) && actor==0x10000bd00524f50ULL
        && read(fra+0x1480,holder) && read(holder+0x18,container)
        && read(container+0x20,begin) && read(container+0x28,end)
        && begin<=end && (end-begin)%8==0 && end-begin<=2048;
    if (valid) for (uintptr_t at=begin;at<end;at+=8) {
        uintptr_t candidate=0; int32_t candidate_id=-1;
        if (!read(at,candidate) || !read(candidate+0x44,candidate_id)) { valid=false; break; }
        if (candidate_id==0) { if (entry) { valid=false; break; } entry=candidate; }
    }
    valid=valid && entry && read(entry+0x44,id) && id==0 && read(entry+0x18,active) && active==2
        && read(entry+0x10,record) && read(record,vt) && vt==base+0x1c4b2b8
        && read(record+0x80,record_actor) && record_actor==actor
        && read(record+0x88,recipient) && recipient==0x100007a00415246ULL
        && read(vt+0x70,type) && type>=base+0x1000 && type<base+0x1c00000
        && read(entry,vt) && read(vt+0x40,can) && can>=base+0x1000 && can<base+0x1c00000;
    if (valid) valid=reinterpret_cast<bool (*)(void*)>(can)(reinterpret_cast<void*>(entry))
        && reinterpret_cast<unsigned char (*)(void*)>(type)(reinterpret_cast<void*>(record))==1;
    uintptr_t server=0,context=0,dispatcher=0,transport=0,execute=0;
    valid=valid && read(game+0x1e00,server) && read(server+0x330,context)
        && read(context+0x370,dispatcher) && read(dispatcher+0x58,transport) && transport
        && read(base+0x1c4d770+0x48,execute) && execute==base+0x274d50;
    if (!valid) { line("{\"event\":\"diplomat_recall_rejected\"}\n"); return; }
    auto command=reinterpret_cast<unsigned char* (*)(size_t)>(base+0x1a33230)(0x60);
    if (!command) { line("{\"event\":\"diplomat_recall_allocation_failed\"}\n"); return; }
    memset(command,0,0x60);
    auto put=[&](size_t offset,const auto& value) { memcpy(command+offset,&value,sizeof(value)); };
    put(0,base+0x1c4d770); put(8,uint32_t{0x165});
    put(0x30,uint64_t{15}); put(0x38,int32_t{-1}); put(0x44,uint32_t{0x2b22});
    put(0x48,uint64_t{0xffff}); put(0x50,actor); put(0x58,id);
    bool queued=reinterpret_cast<bool (*)(void*,void*)>(base+0x14ca1d0)(reinterpret_cast<void*>(dispatcher),command);
    if (!queued) {
        // Dispatcher did not take ownership. Use this command's native deleting destructor.
        uintptr_t destructor=0;
        if (read(base+0x1c4d770,destructor)) reinterpret_cast<void (*)(void*,unsigned)>(destructor)(command,1);
    } else recall_used=true;
    line(queued?"{\"event\":\"diplomat_recall_queued\",\"actor\":\"POR\",\"id\":0}\n":
        "{\"event\":\"diplomat_recall_dispatch_rejected\"}\n");
}
