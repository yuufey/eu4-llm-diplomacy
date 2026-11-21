// Test-save control, evaluated exclusively on the observed game frame thread.
static wchar_t control_request[MAX_PATH];
static int32_t control_target=0;
static ULONGLONG control_deadline=0;
static bool control_pause_after_load=false;
static unsigned control_load_wait_frames=0;
static LONG control_legacy_action_frame=0;
#ifdef BRIDGE_NATIVE_COUNTRY_CONTROL
static wchar_t control_game_speed_request[MAX_PATH]{};
static wchar_t control_game_speed_claim_base[MAX_PATH]{};
static char control_game_speed_session_id[32]{};
static ULONGLONG control_game_speed_creation=0;
static ULONGLONG control_game_speed_last_revision=0;
static ULONGLONG control_game_speed_claim_sequence=0;
static LONG control_game_speed_inside=0;
#endif
static bool control_ready() {
    uintptr_t game=0,server=0,vtable=0,get_pause=0;
    if (!read(base+0x233fe58,game) || !read(game+0x1e00,server)
        || !read(server,vtable) || !read(vtable+0x100,get_pause)
        || get_pause<base+0x1000 || get_pause>=base+0x1c00000) return false;
    // This is the same accessor used by gamespeed before IsPaused.
    // During load it can return null even after POR's world has appeared.
    uintptr_t pause=reinterpret_cast<uintptr_t (*)(void*)>(get_pause)(reinterpret_cast<void*>(server));
    unsigned char paused=0;
    return read(pause+0x48,paused) && pause>=0x10000;
}
static bool automated_control_start(const wchar_t* directory) {
    if (swprintf(control_request,MAX_PATH,L"%ls\\game-control.request",directory)<0) return false;
    if (GetFileAttributesW(control_request)!=INVALID_FILE_ATTRIBUTES && !DeleteFileW(control_request)) return false;
#ifdef BRIDGE_NATIVE_COUNTRY_CONTROL
    if (swprintf(control_game_speed_request,MAX_PATH,L"%ls\\game-speed.req",directory)<0
        || swprintf(control_game_speed_claim_base,MAX_PATH,L"%ls\\game-speed",directory)<0) return false;
    FILETIME created{},exited{},kernel{},user{};
    if (!GetProcessTimes(GetCurrentProcess(),&created,&exited,&kernel,&user)) return false;
    control_game_speed_creation=(static_cast<ULONGLONG>(created.dwHighDateTime)<<32)|created.dwLowDateTime;
    if (!control_game_speed_creation) return false;
    const int session_length=snprintf(control_game_speed_session_id,sizeof(control_game_speed_session_id),
        "%lu-%llx",static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long long>(control_game_speed_creation));
    if (session_length<=0 || static_cast<size_t>(session_length)>=sizeof(control_game_speed_session_id)) return false;
#endif
    return true;
}
static bool control_call(int operation,const char* argument,bool* call_entered=nullptr) {
    if (call_entered) *call_entered=false;
    if (!control_ready()) return false;
    uintptr_t entry=0;
    uintptr_t slot=0x1fce998,function=0xe91210;
    const char* command=argument;
    if (operation==1) {
        slot=0x1fc74b8; function=0xe7b250; command="savegame";
    } else if (operation==2) {
        slot=0x1fc7558; function=0xe7ac80; command="autosave";
    } else if (operation==3) {
        slot=0x1fc2558; function=0xe4f040; command="run_p1_script";
    }
    if (!read(base+slot,entry) || entry!=base+function) return false;
    NativeShortString value{}; value.capacity=15;
    NativeStringVector args{};
    if (argument) {
        const size_t length=strlen(argument);
        if (length>15) return false;
        memcpy(value.text,argument,length+1); value.size=length;
        args={&value,&value+1,&value+1};
    }
    NativeConsoleResult result{};
    using Evaluate=void* (*)(void*,const void*);
    if (call_entered) *call_entered=true;
    reinterpret_cast<Evaluate>(entry)(&result,&args);
    bool success=result.success!=0;
    reinterpret_cast<void (*)(void*)>(base+0x95660)(&result.message);
    char message[200];
    snprintf(message,sizeof(message),"{\"event\":\"control_console_result\",\"command\":\"%s\",\"success\":%s,\"thread\":%lu}\n",
        command,success?"true":"false",static_cast<unsigned long>(GetCurrentThreadId()));
    line(message); return success;
}

#ifdef BRIDGE_NATIVE_COUNTRY_CONTROL
struct NativeGameSpeedRequest {
    char session_id[32]{};
    ULONGLONG revision=0;
    ULONGLONG expires_filetime=0;
    unsigned speed=0;
};
struct NativeGameSpeedField { const char* data=nullptr; size_t size=0; };
struct NativeGameSpeedWorld {
    uintptr_t game=0,server=0,pause_manager=0;
    ULONGLONG player_ref=0;
    int32_t date_raw=0,native_speed_index=0;
    bool paused=false;
};

static bool native_game_speed_parse_u64(NativeGameSpeedField field,ULONGLONG& output) {
    if (!field.data || !field.size) return false;
    ULONGLONG value=0;
    for (size_t i=0;i<field.size;++i) {
        const char digit=field.data[i];
        if (digit<'0' || digit>'9') return false;
        const ULONGLONG number=static_cast<ULONGLONG>(digit-'0');
        if (value>(~static_cast<ULONGLONG>(0)-number)/10) return false;
        value=value*10+number;
    }
    output=value; return true;
}

static bool native_game_speed_parse(const char* bytes,size_t length,
    NativeGameSpeedRequest& output,const char*& reason) {
    reason="malformed_request";
    if (!bytes || !length || length>128 || bytes[length-1]!='\n') return false;
    const size_t end=length-1;
    for (size_t i=0;i<end;++i)
        if (bytes[i]=='\0' || bytes[i]=='\r' || bytes[i]=='\n') return false;
    NativeGameSpeedField fields[5]{};
    size_t count=0,start=0;
    for (size_t i=0;i<=end;++i) {
        if (i!=end && bytes[i]!='\t') continue;
        if (count>=5) return false;
        fields[count++]={bytes+start,i-start};
        start=i+1;
    }
    if (count!=5) return false;
    if (fields[0].size!=9 || memcmp(fields[0].data,"EU4SPEED1",9)!=0) {
        reason="protocol_mismatch"; return false;
    }
    if (!fields[1].size || fields[1].size>=sizeof(output.session_id)) {
        reason="invalid_session"; return false;
    }
    memcpy(output.session_id,fields[1].data,fields[1].size);
    output.session_id[fields[1].size]=0;
    if (!native_game_speed_parse_u64(fields[2],output.revision) || !output.revision) {
        reason="invalid_revision"; return false;
    }
    if (!native_game_speed_parse_u64(fields[3],output.expires_filetime)) {
        reason="invalid_expiration"; return false;
    }
    if (fields[4].size!=1 || fields[4].data[0]<'0' || fields[4].data[0]>'5') {
        reason="invalid_speed"; return false;
    }
    output.speed=static_cast<unsigned>(fields[4].data[0]-'0');
    reason="ok"; return true;
}

static bool native_game_speed_pointer(uintptr_t value) {
    return value>=0x10000 && value<0x800000000000ull && (value&7)==0;
}

static bool native_control_is_canonical_player(ULONGLONG player_ref) {
    const uint32_t tag=static_cast<uint32_t>(player_ref&0xffffffu);
    for (unsigned shift=0;shift<24;shift+=8) {
        const unsigned ch=(tag>>shift)&0xffu;
        if (!(ch>='A' && ch<='Z') && !(ch>='0' && ch<='9')) return false;
    }
    const unsigned slot=static_cast<unsigned>((player_ref>>32)&0xffffu);
    uintptr_t database=0,array=0,country=0; ULONGLONG actual=0;
    return slot<4096
        && read(base+0x233d8b0,database) && native_game_speed_pointer(database)
        && read(database+0x118,array) && native_game_speed_pointer(array)
        && read(array+static_cast<uintptr_t>(slot)*8,country) && native_game_speed_pointer(country)
        && read(country+0x20,actual) && actual==player_ref;
}

static const char* native_game_speed_read_world(NativeGameSpeedWorld& state, bool observer_only=true) {
    if (frame_count<120 || thread_changed || !frame_thread || frame_thread!=GetCurrentThreadId())
        return "frame_not_ready";
    uintptr_t vtable=0,get_pause=0,manager_server=0;
    unsigned char manual_pause=0,server_mode=0,server_network=0;
    uintptr_t pauses_begin=0,pauses_end=0; uint32_t frontend_mode=0;
    if (!read(base+0x233fe58,state.game) || !native_game_speed_pointer(state.game)
        || !read(state.game+0x1e60,state.player_ref)
        || !read(state.game+0x1dd0,state.date_raw)
        || !read(state.game+0x1e08,state.native_speed_index)
        || !read(state.game+0x1e00,state.server) || !native_game_speed_pointer(state.server)
        || !read(state.game+0x747c,frontend_mode)
        || !read(state.server,vtable) || vtable!=base+0x1cb8460
        || !read(vtable+0x100,get_pause) || get_pause!=base+0x802500
        || !read(state.server+0x418,state.pause_manager) || !native_game_speed_pointer(state.pause_manager)
        || !read(state.pause_manager+0x50,manager_server) || manager_server!=state.server
        || !read(state.server+0x19f0,server_mode) || !read(state.server+0x19f1,server_network)
        || !read(state.pause_manager+0x48,manual_pause)
        || !read(state.pause_manager,pauses_begin) || !read(state.pause_manager+8,pauses_end))
        return "world_unavailable";
    if (state.date_raw<=0 || state.native_speed_index<0 || state.native_speed_index>4
        || manual_pause>1) return "world_unavailable";
    if ((pauses_begin==0)!=(pauses_end==0)
        || (pauses_begin && (!native_game_speed_pointer(pauses_begin) || !native_game_speed_pointer(pauses_end)))
        || pauses_end<pauses_begin || ((pauses_end-pauses_begin)%8)!=0
        || ((pauses_end-pauses_begin)/8)>256) return "world_unavailable";
    // This narrows requests to the observed local test profile. It does not
    // prove offline or strict single-player origin. With server+19f1 == 0, the
    // verified pause read uses the manual flag and bounded pause-token vector.
    state.paused=manual_pause!=0 || pauses_begin!=pauses_end;
    if (observer_only && (state.player_ref&0xffffffu)!=0x30304fu) return "player_not_o00";
    if (!native_control_is_canonical_player(state.player_ref))
        return observer_only?"player_not_o00":"player_unavailable";
    if (frontend_mode!=0 || server_mode!=1 || server_network!=0)
        return "test_context_not_observed";
    return "ok";
}

static bool native_game_speed_same_world(const NativeGameSpeedWorld& before,
    const NativeGameSpeedWorld& after) {
    return before.game==after.game && before.server==after.server
        && before.pause_manager==after.pause_manager && before.player_ref==after.player_ref
        && before.date_raw==after.date_raw;
}

static void native_control_finish_campaign_load() {
    // Finish the one-shot startup pause for any canonical local player.
    NativeGameSpeedWorld state{};
    if (strcmp(native_game_speed_read_world(state,false),"ok")!=0) return;
    if (control_load_wait_frames) {
        --control_load_wait_frames;
        return;
    }
    if (control_pause_after_load) {
        control_pause_after_load=false;
        control_legacy_action_frame=frame_count;
        if (!state.paused) control_call(0,"0");
        line("{\"event\":\"control_loaded_pause_requested\"}\n");
    }
}

static int native_game_speed_effective(const NativeGameSpeedWorld& state) {
    return state.paused?0:state.native_speed_index+1;
}

static void native_game_speed_emit(ULONGLONG revision,unsigned requested_speed,
    const char* status,const NativeGameSpeedWorld& state,const char* reason) {
    char message[420]{};
    snprintf(message,sizeof(message),
        "{\"event\":\"native_game_speed_result\",\"session_id\":\"%s\","
        "\"revision\":%llu,\"requested_speed\":%u,\"status\":\"%s\","
        "\"speed\":%d,\"paused\":%s,\"date_raw\":%d,\"reason\":\"%s\"}\n",
        control_game_speed_session_id,static_cast<unsigned long long>(revision),requested_speed,
        status,native_game_speed_effective(state),state.paused?"true":"false",state.date_raw,
        reason?reason:"unknown");
    line(message);
}

static bool native_game_speed_take_request(char* bytes,size_t capacity,size_t& length,
    const char*& reason) {
    reason="request_unreadable"; length=0;
    wchar_t claim_path[MAX_PATH]{}; bool claimed=false;
    for (unsigned attempt=0;attempt<4 && !claimed;++attempt) {
        ++control_game_speed_claim_sequence;
        const int path_length=swprintf(claim_path,MAX_PATH,
            L"%ls.%lu-%llx.%llu-%llu.claim",control_game_speed_claim_base,
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long long>(control_game_speed_creation),
            static_cast<unsigned long long>(GetTickCount64()),
            static_cast<unsigned long long>(control_game_speed_claim_sequence));
        if (path_length<=0 || path_length>=MAX_PATH) return false;
        claimed=MoveFileExW(control_game_speed_request,claim_path,MOVEFILE_WRITE_THROUGH)!=FALSE;
        if (!claimed && GetLastError()!=ERROR_ALREADY_EXISTS && GetLastError()!=ERROR_FILE_EXISTS)
            return false;
    }
    if (!claimed) return false;
    HANDLE file=CreateFileW(claim_path,GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,nullptr);
    if (file!=INVALID_HANDLE_VALUE) {
        LARGE_INTEGER size{}; DWORD got=0;
        const bool bounded=GetFileSizeEx(file,&size) && size.QuadPart>0
            && static_cast<unsigned long long>(size.QuadPart)<capacity;
        if (bounded && ReadFile(file,bytes,static_cast<DWORD>(size.QuadPart),&got,nullptr)
            && got==static_cast<DWORD>(size.QuadPart)) {
            length=static_cast<size_t>(got); reason="ok";
        }
        CloseHandle(file);
    }
    DeleteFileW(claim_path);
    return reason[0]=='o' && reason[1]=='k' && reason[2]==0;
}

static ULONGLONG native_game_speed_now_filetime() {
    FILETIME now{}; GetSystemTimeAsFileTime(&now);
    return (static_cast<ULONGLONG>(now.dwHighDateTime)<<32)|now.dwLowDateTime;
}

static bool native_game_speed_call(unsigned speed,const NativeGameSpeedWorld& before,
    bool& call_entered) {
    call_entered=false;
    if (speed>5) return false;
    if (speed!=1) {
        // The running UI speeds are one-based. The console uses raw indices
        // and reserves zero for pause.
        const char argument[2]={speed?static_cast<char>('0'+speed-1):'0',0};
        return control_call(0,argument,&call_entered);
    }

    // The console cannot resume at index zero. Resume through the same
    // console callback when paused, then invoke its pinned speed setter
    // directly to select the first UI speed without toggling pause again.
    constexpr uintptr_t setter_rva=0x757a20;
    constexpr unsigned char setter_prefix[]={
        0x48,0x81,0xec,0x88,0x00,0x00,0x00,0x41,0xb8,0x04,0x00,0x00,0x00,
        0x41,0x3b,0xd0,0x44,0x0f,0x4e,0xc2,0x33,0xc0,0x45,0x85,0xc0,0x41,
        0x0f,0x49,0xc0,0x89,0x81,0x08,0x1e,0x00,0x00,0x8d,0x48,0x01};
    unsigned char live[sizeof(setter_prefix)]{};
    if (!read(base+setter_rva,live) || memcmp(live,setter_prefix,sizeof(live))!=0) return false;
    if (before.paused) {
        if (!control_call(0,"1",&call_entered)) return false;
        NativeGameSpeedWorld running{};
        if (strcmp(native_game_speed_read_world(running),"ok")!=0 || running.paused
            || !native_game_speed_same_world(before,running)) return false;
    }
    using SetSpeedIndex=void (*)(void*,int32_t);
    call_entered=true;
    reinterpret_cast<SetSpeedIndex>(base+setter_rva)(reinterpret_cast<void*>(before.game),0);
    return true;
}

static void native_game_speed_tick() {
    if (InterlockedCompareExchange(&control_game_speed_inside,1,0)) return;
    do {
        if (!control_game_speed_request[0] || frame_count<120 || thread_changed || !frame_thread
            || frame_thread!=GetCurrentThreadId()) break;
        if (control_load_wait_frames || control_pause_after_load) {
            native_control_finish_campaign_load();
            break;
        }
        if (control_target || control_legacy_action_frame==frame_count) break;
        char packet[129]{}; size_t packet_length=0; const char* read_reason=nullptr;
        if (!native_game_speed_take_request(packet,sizeof(packet),packet_length,read_reason)) break;
        NativeGameSpeedRequest request{}; const char* parse_reason="request_read_failed";
        NativeGameSpeedWorld before{};
        const char* world_reason=native_game_speed_read_world(before);
        if (!read_reason || strcmp(read_reason,"ok")!=0) {
            native_game_speed_emit(0,0,"rejected",before,read_reason?read_reason:"request_read_failed"); break;
        }
        if (!native_game_speed_parse(packet,packet_length,request,parse_reason)) {
            native_game_speed_emit(request.revision,request.speed,"rejected",before,parse_reason); break;
        }
        if (strcmp(request.session_id,control_game_speed_session_id)!=0) {
            native_game_speed_emit(request.revision,request.speed,"rejected",before,"wrong_session"); break;
        }
        if (request.revision<=control_game_speed_last_revision) {
            native_game_speed_emit(request.revision,request.speed,"rejected",before,"revision_not_monotonic"); break;
        }
        control_game_speed_last_revision=request.revision;
        if (request.expires_filetime<=native_game_speed_now_filetime()) {
            native_game_speed_emit(request.revision,request.speed,"rejected",before,"expired"); break;
        }
        if (strcmp(world_reason,"ok")!=0) {
            native_game_speed_emit(request.revision,request.speed,"rejected",before,world_reason); break;
        }
        NativeGameSpeedWorld fresh{};
        const char* fresh_reason=native_game_speed_read_world(fresh);
        if (strcmp(fresh_reason,"ok")!=0 || !native_game_speed_same_world(before,fresh)) {
            native_game_speed_emit(request.revision,request.speed,"rejected",fresh,
                strcmp(fresh_reason,"ok")!=0?fresh_reason:"world_changed_before_call"); break;
        }
        if (request.expires_filetime<=native_game_speed_now_filetime()) {
            native_game_speed_emit(request.revision,request.speed,"rejected",fresh,"expired"); break;
        }
        if (control_target || control_pause_after_load || control_load_wait_frames
            || control_legacy_action_frame==frame_count) {
            native_game_speed_emit(request.revision,request.speed,"rejected",fresh,"legacy_control_busy"); break;
        }
        bool call_entered=false;
        const bool callback_success=native_game_speed_call(request.speed,fresh,call_entered);
        if (!call_entered) {
            native_game_speed_emit(request.revision,request.speed,"rejected",fresh,"speed_call_unavailable"); break;
        }
        NativeGameSpeedWorld after{};
        const char* after_reason=native_game_speed_read_world(after);
        const int expected_index=request.speed?static_cast<int>(request.speed)-1:0;
        const bool verified=callback_success && strcmp(after_reason,"ok")==0
            && native_game_speed_same_world(fresh,after)
            && after.native_speed_index==expected_index
            && after.paused==(request.speed==0);
        if (verified)
            native_game_speed_emit(request.revision,request.speed,"applied",after,"verified");
        else
            native_game_speed_emit(request.revision,request.speed,"unconfirmed",
                strcmp(after_reason,"ok")==0?after:fresh,
                !callback_success?"native_callback_failed":
                strcmp(after_reason,"ok")!=0?after_reason:"readback_mismatch");
    } while (false);
    InterlockedExchange(&control_game_speed_inside,0);
}
#endif

static void automated_control_tick() {
    uintptr_t game=0; uint64_t player=0; int32_t date=0;
    if (!read(base+0x233fe58,game) || !read(game+0x1e60,player)
        || !read(game+0x1dd0,date)) return;
#ifdef BRIDGE_CURRENT_COUNTRY_CONTROL
    const bool legacy_automation=current_country_control_allows_automation(player);
#else
    const bool legacy_automation=(player&0xffffff)==0x524f50 && ((player>>32)&0xffff)==189;
#endif
    if (legacy_automation) {
        if (control_load_wait_frames) { --control_load_wait_frames; return; }
        if (!control_ready()) return;
        if (control_pause_after_load) {
            control_legacy_action_frame=frame_count;
            control_pause_after_load=false; control_call(0,"0");
            line("{\"event\":\"control_loaded_pause_requested\"}\n");
        }
        if (control_target) control_legacy_action_frame=frame_count;
        if (control_target && (date>=control_target || GetTickCount64()>=control_deadline)) {
            bool paused=control_call(false,"0");
            char message[220];
            snprintf(message,sizeof(message),"{\"event\":\"control_advance_complete\",\"date_raw\":%d,\"target_raw\":%d,\"reached\":%s,\"paused_command_success\":%s}\n",
                date,control_target,date>=control_target?"true":"false",paused?"true":"false");
            line(message); control_target=0;
        }
    } else {
#ifdef BRIDGE_NATIVE_COUNTRY_CONTROL
        if (control_load_wait_frames || control_pause_after_load || control_target) return;
#else
        return;
#endif
    }
    if (GetFileAttributesW(control_request)==INVALID_FILE_ATTRIBUTES) return;
    char request[64]{};
    HANDLE file=CreateFileW(control_request,GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    if (file==INVALID_HANDLE_VALUE) return;
    DWORD size=GetFileSize(file,nullptr),got=0;
    bool valid=size<sizeof(request) && ReadFile(file,request,size,&got,nullptr) && got==size;
    CloseHandle(file);
    const bool autosave=valid && strcmp(request,"TEST_ONLY autosave\n")==0;
    if (!legacy_automation && !autosave) return;
    if (!DeleteFileW(control_request) || !valid) return;
    control_legacy_action_frame=frame_count;
    if (autosave) {
#ifdef BRIDGE_NATIVE_COUNTRY_CONTROL
        NativeGameSpeedWorld state{};
        if (control_target || strcmp(native_game_speed_read_world(state,false),"ok")!=0 || !state.paused) {
            line("{\"event\":\"control_console_result\",\"command\":\"autosave\",\"success\":false}\n");
            return;
        }
#endif
        if (!control_target) control_call(2,nullptr);
        return;
    }
    if (strcmp(request,"TEST_ONLY savegame\n")==0) {
        if (!control_target) control_call(true,nullptr);
        return;
    }
    if (strcmp(request,"TEST_ONLY pause\n")==0) {
        control_call(false,"0"); control_target=0; return;
    }
    // Operator-owned source acceptance effects run through the game's script
    // interpreter on this frame thread. The request selects a fixed filename.
    if (strcmp(request,"TEST_ONLY run_p1_script\n")==0) {
        if (!control_target)
            control_call(3,"llm_p1.txt");
        return;
    }
    if (strcmp(request,"TEST_ONLY advance_35_days\n")==0
        || strcmp(request,"TEST_ONLY advance_5_days\n")==0
        || strcmp(request,"TEST_ONLY advance_1_days\n")==0) {
        if (control_target) return;
        const int days=strcmp(request,"TEST_ONLY advance_1_days\n")==0?1:
            strcmp(request,"TEST_ONLY advance_5_days\n")==0?5:35;
        control_target=date+days*24; control_deadline=GetTickCount64()+120000;
        if (!control_call(false,"4")) control_target=0;
        char message[80];
        snprintf(message,sizeof(message),"{\"event\":\"control_advance_begin\",\"days\":%d}\n",days);
        line(message);
    }
}
