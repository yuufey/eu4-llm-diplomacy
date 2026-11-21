// ID-based diplomat recall for the v65 native managed-country build.
// Requests are atomically moved out of the public path before parsing. The
// dispatcher owns accepted commands; a separate bounded readback reports the
// resulting N05 state without treating queue acceptance as task completion.
static_assert(sizeof(void*)==8,"diplomat recall requires the verified x64 ABI");

static wchar_t native_diplomat_recall_request_path[MAX_PATH]{};
static wchar_t native_diplomat_recall_claim_base[MAX_PATH]{};
static std::uint64_t native_diplomat_recall_last_revision=0;
static std::uint64_t native_diplomat_recall_claim_sequence=0;

struct NativeDiplomatRecallRequest {
    char session_id[64]{};
    char actor[4]={'U','N','K',0};
    std::uint64_t revision=0;
    std::uint64_t expires=0;
    std::int32_t diplomat_id=-1;
};

struct NativeDiplomatRecallPending {
    bool active=false;
    std::uint64_t revision=0;
    std::uint64_t actor=0;
    std::int32_t diplomat_id=-1;
    std::uintptr_t world=0;
    std::uintptr_t entry=0;
    ULONGLONG deadline=0;
    char actor_tag[4]{};
};
static NativeDiplomatRecallPending native_diplomat_recall_pending{};

static bool native_diplomat_recall_set_paths(const wchar_t* directory) noexcept {
    if (!directory || !directory[0]) return false;
    const int request_length=swprintf(native_diplomat_recall_request_path,MAX_PATH,
        L"%ls\\diplomat-recall-mcp.req",directory);
    const int claim_length=swprintf(native_diplomat_recall_claim_base,MAX_PATH,
        L"%ls\\diplomat-recall-mcp",directory);
    return request_length>=0 && request_length<MAX_PATH
        && claim_length>=0 && claim_length<MAX_PATH;
}

static bool native_diplomat_recall_decimal(const char* text,std::size_t length,
    std::uint64_t& value) noexcept {
    value=0;
    if (!text || !length || (length>1 && text[0]=='0')) return false;
    for (std::size_t index=0;index<length;++index) {
        const unsigned char ch=static_cast<unsigned char>(text[index]);
        if (ch<'0' || ch>'9') return false;
        const std::uint64_t digit=ch-'0';
        if (value>(~std::uint64_t{0}-digit)/10) return false;
        value=value*10+digit;
    }
    return true;
}

static bool native_diplomat_recall_session_token(const char* text,
    std::size_t length) noexcept {
    if (!text || !length || length>=64)
        return false;
    bool separator=false,have_prefix=false,have_suffix=false;
    for (std::size_t index=0;index<length;++index) {
        const unsigned char ch=static_cast<unsigned char>(text[index]);
        if (ch=='-' && !separator && have_prefix) { separator=true; continue; }
        if (!separator) {
            if (ch<'0' || ch>'9') return false;
            have_prefix=true;
        } else {
            if (!((ch>='0' && ch<='9') || (ch>='a' && ch<='f')
                || (ch>='A' && ch<='F'))) return false;
            have_suffix=true;
        }
    }
    return separator && have_prefix && have_suffix;
}

static bool native_diplomat_recall_tag_token(const char* text,
    std::size_t length) noexcept {
    if (!text || length!=3) return false;
    for (std::size_t index=0;index<3;++index) {
        const unsigned char ch=static_cast<unsigned char>(text[index]);
        if (!((ch>='A' && ch<='Z') || (ch>='0' && ch<='9'))) return false;
    }
    return true;
}

static bool native_diplomat_recall_parse(char* wire,std::size_t size,
    NativeDiplomatRecallRequest& request) noexcept {
    if (!wire || size<12 || size>256 || wire[size-1]!='\n') return false;
    for (std::size_t index=0;index+1<size;++index) {
        const unsigned char ch=static_cast<unsigned char>(wire[index]);
        if (ch==0 || ch=='\r' || ch=='\n' || (ch<0x20 && ch!='\t') || ch>0x7e)
            return false;
    }
    wire[size-1]=0;
    char* fields[6]{};
    std::size_t lengths[6]{};
    std::size_t field=0,start=0;
    for (std::size_t index=0;index<size-1;++index) {
        if (wire[index]!='\t') continue;
        if (field>=5) return false;
        fields[field]=wire+start;
        lengths[field]=index-start;
        ++field;
        start=index+1;
    }
    if (field!=5) return false;
    fields[field]=wire+start;
    lengths[field]=(size-1)-start;
    constexpr char protocol[]="EU4RECALL1";
    std::uint64_t id=0;
    if (!native_diplomat_recall_decimal(fields[5],lengths[5],id)
        || id>static_cast<std::uint64_t>(0x7fffffff)
        || lengths[0]!=sizeof(protocol)-1 || std::memcmp(fields[0],protocol,sizeof(protocol)-1)!=0
        || !native_diplomat_recall_session_token(fields[1],lengths[1])
        || lengths[1]>=sizeof(request.session_id)
        || !native_diplomat_recall_decimal(fields[2],lengths[2],request.revision)
        || !request.revision
        || !native_diplomat_recall_decimal(fields[3],lengths[3],request.expires)
        || !native_diplomat_recall_tag_token(fields[4],lengths[4])) return false;
    std::memcpy(request.session_id,fields[1],lengths[1]);
    request.session_id[lengths[1]]=0;
    std::memcpy(request.actor,fields[4],3);
    request.actor[3]=0;
    request.diplomat_id=static_cast<std::int32_t>(id);
    return true;
}

static void native_diplomat_recall_current_session(char (&session)[64]) noexcept {
    snprintf(session,sizeof(session),"%lu-%llx",
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long long>(observation_creation));
}

static void native_diplomat_recall_emit_result(const char* session,
    std::uint64_t revision,const char* actor,std::int32_t diplomat_id,
    const char* status,const char* reason) noexcept {
    char message[400]{};
    const int written=snprintf(message,sizeof(message),
        "{\"event\":\"native_diplomat_recall_result\",\"session_id\":\"%s\","
        "\"revision\":%llu,\"actor\":\"%.3s\",\"diplomat_id\":%d,"
        "\"status\":\"%s\",\"reason\":\"%s\"}\n",
        session?session:"",static_cast<unsigned long long>(revision),
        actor?actor:"UNK",static_cast<int>(diplomat_id),status?status:"rejected",
        reason?reason:"invalid_request");
    if (written>0 && static_cast<std::size_t>(written)<sizeof(message)) line(message);
}

static void native_diplomat_recall_emit_postcondition(
    const NativeDiplomatRecallPending& pending,const char* status,
    const char* reason,const char* state,bool include_date,
    std::int32_t date_raw) noexcept {
    char session[64]{};
    native_diplomat_recall_current_session(session);
    char message[512]{};
    int written=0;
    if (include_date) {
        written=snprintf(message,sizeof(message),
            "{\"event\":\"native_diplomat_recall_postcondition\","
            "\"session_id\":\"%s\",\"revision\":%llu,\"actor\":\"%.3s\","
            "\"diplomat_id\":%d,\"status\":\"%s\",\"reason\":\"%s\","
            "\"state\":\"%s\",\"date_raw\":%d}\n",
            session,static_cast<unsigned long long>(pending.revision),pending.actor_tag,
            static_cast<int>(pending.diplomat_id),status,reason,state,date_raw);
    } else {
        written=snprintf(message,sizeof(message),
            "{\"event\":\"native_diplomat_recall_postcondition\","
            "\"session_id\":\"%s\",\"revision\":%llu,\"actor\":\"%.3s\","
            "\"diplomat_id\":%d,\"status\":\"%s\",\"reason\":\"%s\","
            "\"state\":\"%s\"}\n",
            session,static_cast<unsigned long long>(pending.revision),pending.actor_tag,
            static_cast<int>(pending.diplomat_id),status,reason,state);
    }
    if (written>0 && static_cast<std::size_t>(written)<sizeof(message)) line(message);
}

static bool native_diplomat_recall_game_code(std::uintptr_t address) noexcept {
    if (!base || address<base+0x1000 || address>=base+0x1c00000) return false;
    MEMORY_BASIC_INFORMATION info{};
    if (VirtualQuery(reinterpret_cast<const void*>(address),&info,sizeof(info))!=sizeof(info)
        || info.AllocationBase!=reinterpret_cast<void*>(base)
        || info.Type!=MEM_IMAGE || info.State!=MEM_COMMIT) return false;
    const DWORD protection=info.Protect&0xff;
    return protection==PAGE_EXECUTE || protection==PAGE_EXECUTE_READ
        || protection==PAGE_EXECUTE_READWRITE || protection==PAGE_EXECUTE_WRITECOPY;
}

static bool native_diplomat_recall_game_vtable(std::uintptr_t address) noexcept {
    if (!base || address<base+0x1000) return false;
    MEMORY_BASIC_INFORMATION info{};
    if (VirtualQuery(reinterpret_cast<const void*>(address),&info,sizeof(info))!=sizeof(info))
        return false;
    return info.AllocationBase==reinterpret_cast<void*>(base)
        && info.Type==MEM_IMAGE && info.State==MEM_COMMIT
        && !(info.Protect&(PAGE_GUARD|PAGE_NOACCESS));
}

enum class NativeDiplomatRecallScan : unsigned char {
    found,missing,ambiguous,unavailable
};
struct NativeDiplomatRecallTask {
    std::uintptr_t entry=0;
    std::uintptr_t record=0;
    std::uint8_t state=0xff;
};

static bool native_diplomat_recall_country_handle(std::uint64_t actor,
    std::uintptr_t& country) noexcept {
    country=0;
    std::uintptr_t database=0,array=0;
    std::uint32_t count=0;
    if (!actor || !observation_country_handle(actor)
        || !read(base+0x233d8b0,database) || !read(database+0x118,array)
        || !read(database+0x124,count) || !count || count>4096) return false;
    const std::uint32_t slot=static_cast<std::uint32_t>((actor>>32)&0xffff);
    std::uint64_t actual=0;
    return slot<count && read(array+static_cast<std::uintptr_t>(slot)*8,country)
        && country && read(country+0x20,actual) && actual==actor;
}

static bool native_diplomat_recall_actor(const char* tag,
    std::uint64_t& actor,std::uintptr_t& country) noexcept {
    actor=0; country=0;
    return tag && observation_control_country_configured()
        && observation_control_country_contains(tag)
        && alliance_query_country(tag,actor)
        && observation_country_tag_matches_handle(tag,actor)
        && native_diplomat_recall_country_handle(actor,country);
}

static NativeDiplomatRecallScan native_diplomat_recall_find_task(
    std::uintptr_t country,std::int32_t diplomat_id,
    NativeDiplomatRecallTask& task) noexcept {
    task={};
    std::uintptr_t holder=0,container=0,begin=0,end=0;
    if (!country || !read(country+0x1480,holder) || !holder
        || !read(holder+0x18,container) || !container
        || !read(container+0x20,begin) || !read(container+0x28,end)
        || end<begin || (end-begin)%8 || (end-begin)/8>256)
        return NativeDiplomatRecallScan::unavailable;
    unsigned matches=0;
    for (std::uintptr_t at=begin;at<end;at+=8) {
        std::uintptr_t candidate=0;
        std::int32_t candidate_id=-1;
        if (!read(at,candidate) || !candidate || !read(candidate+0x44,candidate_id))
            return NativeDiplomatRecallScan::unavailable;
        if (candidate_id!=diplomat_id) continue;
        if (++matches>1) return NativeDiplomatRecallScan::ambiguous;
        task.entry=candidate;
    }
    if (!matches) return NativeDiplomatRecallScan::missing;
    std::uintptr_t record=0;
    if (!read(task.entry+0x18,task.state) || !read(task.entry+0x10,record)
        || (!record && task.state!=0))
        return NativeDiplomatRecallScan::unavailable;
    task.record=record;
    return NativeDiplomatRecallScan::found;
}

static bool native_diplomat_recall_task_category(std::uint64_t actor,
    const NativeDiplomatRecallTask& task,const char*& reason) noexcept {
    reason="task_shape_invalid";
    std::uint64_t record_actor=0;
    std::uintptr_t entry_vtable=0,record_vtable=0,can_cancel=0,category=0;
    if (!task.entry || !task.record || !read(task.record+0x80,record_actor)
        || record_actor!=actor || !read(task.entry,entry_vtable)
        || !read(task.record,record_vtable)
        || !native_diplomat_recall_game_vtable(entry_vtable)
        || !native_diplomat_recall_game_vtable(record_vtable)
        || !read(entry_vtable+0x40,can_cancel)
        || !read(record_vtable+0x70,category)
        || !native_diplomat_recall_game_code(can_cancel)
        || !native_diplomat_recall_game_code(category)) {
        reason="machine_abi_guard_failed";
        return false;
    }
    // The known 1.37.4 CANCEL_DIPLOMAT executor at RVA 0x274d50 accepts only
    // category-1 tasks. These virtual calls use the observed x64 this-pointer
    // ABI and are permitted only after code/vtable image guards above.
    using CanCancel=bool (*)(void*);
    using TaskCategory=unsigned char (*)(void*);
    if (reinterpret_cast<CanCancel>(can_cancel)(reinterpret_cast<void*>(task.entry))==false) {
        reason="task_not_cancellable";
        return false;
    }
    if (reinterpret_cast<TaskCategory>(category)(reinterpret_cast<void*>(task.record))!=1) {
        reason="task_category_unsupported";
        return false;
    }
    reason="ok";
    return true;
}

static bool native_diplomat_recall_read_request(char (&wire)[256],
    std::size_t& size,bool& claimed) noexcept {
    size=0; claimed=false;
    if (!native_diplomat_recall_request_path[0]
        || !native_diplomat_recall_claim_base[0]) return false;
    wchar_t claim_path[MAX_PATH]{};
    const std::uint64_t sequence=++native_diplomat_recall_claim_sequence;
    const int length=swprintf(claim_path,MAX_PATH,L"%ls.%lu.%llx.%llu.claim",
        native_diplomat_recall_claim_base,
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long long>(observation_creation),
        static_cast<unsigned long long>(sequence));
    if (length<0 || length>=MAX_PATH
        || !MoveFileExW(native_diplomat_recall_request_path,claim_path,
            MOVEFILE_WRITE_THROUGH)) return false;
    claimed=true;
    HANDLE file=CreateFileW(claim_path,GENERIC_READ,FILE_SHARE_READ,nullptr,
        OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    if (file==INVALID_HANDLE_VALUE) {
        DeleteFileW(claim_path);
        return false;
    }
    LARGE_INTEGER file_size{};
    DWORD bytes_read=0;
    const bool read_ok=GetFileSizeEx(file,&file_size) && file_size.QuadPart>0
        && file_size.QuadPart<=static_cast<LONGLONG>(sizeof(wire))
        && ReadFile(file,wire,static_cast<DWORD>(file_size.QuadPart),&bytes_read,nullptr)
        && bytes_read==static_cast<DWORD>(file_size.QuadPart);
    CloseHandle(file);
    DeleteFileW(claim_path);
    if (!read_ok) return false;
    size=static_cast<std::size_t>(bytes_read);
    return true;
}

static void native_diplomat_recall_postcondition_tick() noexcept {
    if (!native_diplomat_recall_pending.active) return;
    NativeDiplomatRecallPending pending=native_diplomat_recall_pending;
    const auto finish=[&]() noexcept {
        native_diplomat_recall_pending={};
    };
    if (!control_ready() || !observation_control_country_configured()
        || !observation_control_country_contains(pending.actor_tag)) {
        native_diplomat_recall_emit_postcondition(pending,"unconfirmed",
            "world_invalidated","unknown",false,0);
        finish(); return;
    }
    std::uintptr_t world=0,country=0;
    if (!read(base+0x233fe58,world) || world!=pending.world
        || !observation_country_tag_matches_handle(pending.actor_tag,pending.actor)
        || !native_diplomat_recall_country_handle(pending.actor,country)) {
        native_diplomat_recall_emit_postcondition(pending,"unconfirmed",
            "world_invalidated","unknown",false,0);
        finish(); return;
    }
    NativeDiplomatRecallTask task{};
    const auto scan=native_diplomat_recall_find_task(country,pending.diplomat_id,task);
    if (scan==NativeDiplomatRecallScan::ambiguous
        || scan==NativeDiplomatRecallScan::unavailable) {
        native_diplomat_recall_emit_postcondition(pending,"unconfirmed",
            "world_invalidated","unknown",false,0);
        finish(); return;
    }
    if (scan==NativeDiplomatRecallScan::missing) {
        native_diplomat_recall_emit_postcondition(pending,"unconfirmed",
            "task_identity_missing","unknown",false,0);
        finish(); return;
    }
    if (task.entry!=pending.entry) {
        native_diplomat_recall_emit_postcondition(pending,"unconfirmed",
            "task_identity_changed","unknown",false,0);
        finish(); return;
    }
    if (task.state==0 || task.state==1) {
        const char* state=task.state==0?"idle":"returning";
        std::uintptr_t game=0;
        std::int32_t date_raw=0;
        const bool date_available=read(base+0x233fe58,game)
            && read(game+0x1dd0,date_raw) && date_raw>0;
        if (date_available) {
            native_diplomat_recall_emit_postcondition(pending,"executed",
                task.state==0?"observed_idle":"observed_returning",state,true,date_raw);
        } else {
            native_diplomat_recall_emit_postcondition(pending,"unconfirmed",
                "date_unavailable",state,false,0);
        }
        finish(); return;
    }
    if (task.state!=2) {
        native_diplomat_recall_emit_postcondition(pending,"unconfirmed",
            "task_state_unknown","unknown",false,0);
        finish(); return;
    }
    if (GetTickCount64()>=pending.deadline) {
        std::uintptr_t game=0;
        std::int32_t date_raw=0;
        const bool date_available=read(base+0x233fe58,game)
            && read(game+0x1dd0,date_raw) && date_raw>0;
        native_diplomat_recall_emit_postcondition(pending,"unconfirmed",
            "postcondition_timeout","active",date_available,date_raw);
        finish();
    }
}

static void native_diplomat_recall_mcp_tick() noexcept {
    native_diplomat_recall_postcondition_tick();
    if (!native_diplomat_recall_request_path[0]
        || GetFileAttributesW(native_diplomat_recall_request_path)==INVALID_FILE_ATTRIBUTES
        || !control_ready()
        || control_target || control_pause_after_load || control_load_wait_frames)
        return;
    char wire[256]{};
    std::size_t size=0;
    bool claimed=false;
    if (!native_diplomat_recall_read_request(wire,size,claimed)) {
        if (claimed) {
            char session[64]{};
            native_diplomat_recall_current_session(session);
            native_diplomat_recall_emit_result(session,0,"UNK",-1,"rejected",
                "request_read_failed");
        }
        return;
    }
    NativeDiplomatRecallRequest request{};
    char session[64]{};
    native_diplomat_recall_current_session(session);
    if (!native_diplomat_recall_parse(wire,size,request)) {
        native_diplomat_recall_emit_result(session,request.revision,request.actor,
            request.diplomat_id,"rejected","malformed_wire");
        return;
    }
    if (std::strcmp(request.session_id,session)!=0) {
        native_diplomat_recall_emit_result(session,request.revision,request.actor,
            request.diplomat_id,"rejected","session_mismatch");
        return;
    }
    if (request.revision<=native_diplomat_recall_last_revision) {
        native_diplomat_recall_emit_result(session,request.revision,request.actor,
            request.diplomat_id,"rejected","replay_revision");
        return;
    }
    native_diplomat_recall_last_revision=request.revision;
    FILETIME now_filetime{};
    GetSystemTimeAsFileTime(&now_filetime);
    const std::uint64_t now=(static_cast<std::uint64_t>(now_filetime.dwHighDateTime)<<32)
        |now_filetime.dwLowDateTime;
    if (request.expires<=now) {
        native_diplomat_recall_emit_result(session,request.revision,request.actor,
            request.diplomat_id,"rejected","expired");
        return;
    }
    if (!observation_control_country_configured()) {
        native_diplomat_recall_emit_result(session,request.revision,request.actor,
            request.diplomat_id,"rejected","control_set_unconfigured");
        return;
    }
    if (!observation_control_country_contains(request.actor)) {
        native_diplomat_recall_emit_result(session,request.revision,request.actor,
            request.diplomat_id,"rejected","actor_not_managed");
        return;
    }
    if (native_diplomat_recall_pending.active) {
        native_diplomat_recall_emit_result(session,request.revision,request.actor,
            request.diplomat_id,"rejected","prior_result_pending");
        return;
    }
    std::uint64_t actor=0;
    std::uintptr_t country=0;
    if (!native_diplomat_recall_actor(request.actor,actor,country)) {
        native_diplomat_recall_emit_result(session,request.revision,request.actor,
            request.diplomat_id,"rejected","actor_unavailable");
        return;
    }
    NativeDiplomatRecallTask task{};
    const auto scan=native_diplomat_recall_find_task(country,request.diplomat_id,task);
    if (scan!=NativeDiplomatRecallScan::found) {
        const char* reason=scan==NativeDiplomatRecallScan::missing?"diplomat_id_not_found":
            scan==NativeDiplomatRecallScan::ambiguous?"diplomat_id_ambiguous":"task_container_unavailable";
        native_diplomat_recall_emit_result(session,request.revision,request.actor,
            request.diplomat_id,"rejected",reason);
        return;
    }
    if (task.state!=2) {
        native_diplomat_recall_emit_result(session,request.revision,request.actor,
            request.diplomat_id,"rejected","task_not_active");
        return;
    }
    const char* category_reason="task_shape_invalid";
    if (!native_diplomat_recall_task_category(actor,task,category_reason)) {
        native_diplomat_recall_emit_result(session,request.revision,request.actor,
            request.diplomat_id,"rejected",category_reason);
        return;
    }
    std::uintptr_t game=0,server=0,context=0,dispatcher=0,transport=0,execute=0;
    std::uintptr_t allocator=base+0x1a33230,dispatch=base+0x14ca1d0,destructor=0;
    if (!read(base+0x233fe58,game) || !read(game+0x1e00,server)
        || !read(server+0x330,context) || !read(context+0x370,dispatcher)
        || !read(dispatcher+0x58,transport) || !transport
        || !read(base+0x1c4d770+0x48,execute) || execute!=base+0x274d50
        || !native_diplomat_recall_game_code(allocator)
        || !native_diplomat_recall_game_code(dispatch)
        || !read(base+0x1c4d770,destructor)
        || !native_diplomat_recall_game_code(destructor)) {
        native_diplomat_recall_emit_result(session,request.revision,request.actor,
            request.diplomat_id,"rejected","native_execute_guard_failed");
        return;
    }
    auto command=reinterpret_cast<unsigned char* (*)(std::size_t)>(allocator)(0x60);
    if (!command) {
        native_diplomat_recall_emit_result(session,request.revision,request.actor,
            request.diplomat_id,"rejected","allocation_failed");
        return;
    }
    std::memset(command,0,0x60);
    auto put=[&](std::size_t offset,const auto& value) {
        std::memcpy(command+offset,&value,sizeof(value));
    };
    put(0,base+0x1c4d770);
    put(8,std::uint32_t{0x165});
    put(0x30,std::uint64_t{15});
    put(0x38,std::int32_t{-1});
    put(0x44,std::uint32_t{0x2b22});
    put(0x48,std::uint64_t{0xffff});
    put(0x50,actor);
    put(0x58,request.diplomat_id);
    const bool queued=reinterpret_cast<bool (*)(void*,void*)>(dispatch)(
        reinterpret_cast<void*>(dispatcher),command);
    if (!queued) {
        reinterpret_cast<void (*)(void*,unsigned)>(destructor)(command,1);
        native_diplomat_recall_emit_result(session,request.revision,request.actor,
            request.diplomat_id,"rejected","dispatch_rejected");
        return;
    }
    native_diplomat_recall_pending.active=true;
    native_diplomat_recall_pending.revision=request.revision;
    native_diplomat_recall_pending.actor=actor;
    native_diplomat_recall_pending.diplomat_id=request.diplomat_id;
    native_diplomat_recall_pending.world=game;
    native_diplomat_recall_pending.entry=task.entry;
    native_diplomat_recall_pending.deadline=GetTickCount64()+2000;
    std::memcpy(native_diplomat_recall_pending.actor_tag,request.actor,4);
    native_diplomat_recall_emit_result(session,request.revision,request.actor,
        request.diplomat_id,"queued","dispatch_accepted");
}

