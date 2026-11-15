// Explicit TEST_ONLY maintenance control; never used by an information query.
// The complete native switch function owns its Human command and UI cleanup.
#include "information-current-country-control-plan.h"
#include "information-current-country-control-policy.h"

namespace current_country_host {
namespace policy = information::current_country_control;
namespace plan = information::battle::current_country_control_plan;
namespace policy_detail = information::current_country_control::detail;

static wchar_t request_path[MAX_PATH]{}, processing_path[MAX_PATH]{}, status_path[MAX_PATH]{},
    status_temp[MAX_PATH]{}, attempt_paths[2][MAX_PATH]{}, directory_path[MAX_PATH]{};
static policy::Identity identity{};
static policy::Request operation{};
static policy::Snapshot before{}, observed{};
static unsigned attempted_mask=0;
static uint64_t authorized_fra_ref=0, native_return=0, native_calls=0;
static LONG invoked_frame=0;
static ULONGLONG verify_deadline=0, last_poll=0, last_status=0;
static HANDLE attempt_file=INVALID_HANDLE_VALUE;
static const char* phase="ready";
static const char* reason="awaiting_explicit_test_only_request";
static std::atomic<bool> initialized{false};
static bool pending=false, native_attempted=false, have_operation=false;

struct Reader final {
    bool read(uintptr_t address,unsigned char* destination,size_t size) noexcept {
        SIZE_T got=0;
        return destination && size && size<=4096 && address>=0x10000
            && address<0x800000000000ull && size<=0x800000000000ull-address
            && ReadProcessMemory(GetCurrentProcess(),reinterpret_cast<void*>(address),
                                 destination,size,&got) && got==size;
    }
};

static bool guard() noexcept {
    Reader reader;
    if (!plan::guard(reader,base,plan::kSizeOfImage)) return false;
    DWORD64 image=0;
    auto row=RtlLookupFunctionEntry(base+plan::kNativeGuardRva+1,&image,nullptr);
    RUNTIME_FUNCTION value{};
    return row && image==base && read(reinterpret_cast<uintptr_t>(row),value)
        && value.BeginAddress==plan::kPdataBeginRva && value.EndAddress==plan::kPdataEndRva
        && value.UnwindData==plan::kUnwindInfoRva;
}

static bool resolve(policy::Country wanted,uintptr_t& country,uint64_t& fullref) noexcept {
    uintptr_t database=0,table=0; uint32_t count=0; unsigned matches=0;
    country=0;fullref=0;
    uintptr_t checked=0;
    // Only the short in-flight confirmation reuses the admitted exact target;
    // a new operation still performs a complete bounded tag resolution.
    if (pending && before.target_ref && policy_detail::reference_has_tag(before.target_ref,wanted)
        && insult_query_country(before.target_ref,checked) && checked==before.target_country) {
        country=checked;fullref=before.target_ref;return true;
    }
    if (!read(base+0x233d8b0,database) || !read(database+0x118,table)
        || !read(database+0x124,count) || !count || count>4096
        || !policy_detail::canonical_pointer(database) || !policy_detail::canonical_pointer(table)) return false;
    const uint32_t tag=policy_detail::tag_value(wanted);
    for (uint32_t slot=0;slot<count;++slot) {
        uintptr_t pointer=0;uint64_t ref=0;
        if (!read(table+static_cast<uintptr_t>(slot)*8,pointer)) return false;
        if (!pointer) continue;
        if (!policy_detail::canonical_pointer(pointer) || !read(pointer+0x20,ref)) return false;
        if ((ref&0xffffffu)!=tag) continue;
        if (!policy_detail::reference_valid(ref) || ((ref>>32)&0xffffu)!=slot) return false;
        ++matches;country=pointer;fullref=ref;
    }
    if (matches!=1) return false;
    return true;
}

static policy::Snapshot snapshot(policy::Country target) noexcept {
    policy::Snapshot value{};
    uintptr_t server=0,vtable=0,getter=0,pause=0,provinces=0;
    int32_t old_count=0;unsigned char paused=0,alternate=0;
    if (frame_count<120 || !read(base+0x233fe58,value.game)
        || !policy_detail::canonical_pointer(value.game) || value.game>=0x800000000000ull-0x8000
        || !read(value.game+0x1e60,value.player_ref)
        || !insult_query_country(value.player_ref,value.player_country)
        || !resolve(target,value.target_country,value.target_ref)
        || !read(value.game+0x1dd0,value.date) || !read(value.game+0x1e08,value.speed)
        || !read(value.game+0xa60,value.human_count) || !read(value.game+0x1e6f,alternate)
        || !read(value.game+0x1e00,server) || !policy_detail::canonical_pointer(server)
        || !read(server,vtable) || !read(vtable+0x100,getter) || getter!=base+0x802500
        || !read(server+0x418,pause) || !policy_detail::canonical_pointer(pause)
        || !read(pause+0x48,paused)
        || !read(value.target_country+0x1344,value.province_count)
        || value.province_count<0 || value.province_count>65536
        || !read(value.player_country+0x1344,old_count) || old_count<0 || old_count>65536
        || (old_count && (!read(value.player_country+0x1338,provinces)
                         || !policy_detail::canonical_pointer(provinces)))) return value;
    value.paused=paused==1;
    value.alternate_current=((value.player_ref>>48)&0xffu)==7 && alternate!=0;
    value.read_ok=true;
    return value;
}

static bool capture_idle() noexcept {
    const long current=information_battle_source::state.load(std::memory_order_acquire);
    return (current==information_battle_source::ready || current==information_battle_source::disabled)
        && control_target==0 && !thread_changed && frame_thread && frame_thread==GetCurrentThreadId();
}

static bool write_handle(HANDLE file,const char* bytes,DWORD count) noexcept {
    DWORD written=0;
    return file!=INVALID_HANDLE_VALUE && WriteFile(file,bytes,count,&written,nullptr)
        && written==count && FlushFileBuffers(file);
}

static bool publish() noexcept {
    char bytes[2200]{};
    const int length=snprintf(bytes,sizeof(bytes),
        "{\"schema\":\"EU4COUNTRY1\",\"state\":\"%s\",\"pid\":%lu,"
        "\"creation_filetime\":\"%llu\",\"dll_sha256\":\"%s\",\"request_id\":\"%s\","
        "\"request_from\":\"%s\",\"request_to\":\"%s\","
        "\"before_player_ref\":\"%016llx\",\"target_player_ref\":\"%016llx\","
        "\"observed_player_ref\":\"%016llx\",\"date_before\":%d,\"date_raw\":%d,"
        "\"speed\":%d,\"paused\":%s,\"native_attempted\":%s,\"native_return\":%llu,"
        "\"native_calls\":%llu,\"attempted_mask\":%u,\"authorized_fra_ref\":\"%016llx\","
        "\"frame_thread\":%lu,\"reason\":\"%s\"}\n",
        phase,static_cast<unsigned long>(identity.pid),static_cast<unsigned long long>(identity.creation),
        identity.dll_sha.data(),have_operation?operation.id.data():"",
        have_operation?policy::tag(operation.from):"",have_operation?policy::tag(operation.to):"",
        static_cast<unsigned long long>(before.player_ref),static_cast<unsigned long long>(before.target_ref),
        static_cast<unsigned long long>(observed.player_ref),before.date,observed.date,observed.speed,
        observed.paused?"true":"false",native_attempted?"true":"false",
        static_cast<unsigned long long>(native_return),static_cast<unsigned long long>(native_calls),
        attempted_mask,static_cast<unsigned long long>(authorized_fra_ref),
        static_cast<unsigned long>(frame_thread),reason);
    if (length<=0 || static_cast<size_t>(length)>=sizeof(bytes)) return false;
    HANDLE file=CreateFileW(status_temp,GENERIC_WRITE,FILE_SHARE_READ,nullptr,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);
    if (file==INVALID_HANDLE_VALUE) return false;
    const bool written=write_handle(file,bytes,static_cast<DWORD>(length));
    const bool closed=CloseHandle(file)!=FALSE;
    return written && closed && MoveFileExW(status_temp,status_path,MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH);
}

static unsigned index(policy::Country country) noexcept {return country==policy::Country::fra?0u:1u;}

static uint8_t invoke_switch(void* game,uint64_t target) noexcept {
#ifdef INFORMATION_CURRENT_COUNTRY_HOST_FIXTURE
    // Compiled only by the owned host fixture. Production manifests reject it.
    return ::current_country_fixture_invoke(game,target,nullptr);
#else
    // Native caller e6a1cc zero-extends AL. Upper RAX bits are unspecified.
    using NativeSwitch=uint8_t (*)(void*,uint64_t,void*);
    return reinterpret_cast<NativeSwitch>(base+plan::kNativeGuardRva)(game,target,nullptr);
#endif
}

static bool reserve(const char* packet,size_t bytes) noexcept {
    attempt_file=CreateFileW(attempt_paths[index(operation.to)],GENERIC_WRITE,FILE_SHARE_READ,
                             nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
    if (attempt_file==INVALID_HANDLE_VALUE) return false;
    // Reserve the direction even when later I/O fails. A started/unknown native
    // operation is never made retryable by a failed diagnostic write.
    attempted_mask|=policy::bit(operation.to);
    char entry[1000]{};
    const int length=snprintf(entry,sizeof(entry),
        "{\"event\":\"reserved_before_native\",\"request_id\":\"%s\",\"request_ascii\":\"%.*s\","
        "\"before_ref\":\"%016llx\",\"target_ref\":\"%016llx\",\"date\":%d,\"native_outcome\":\"not_yet_known\"}\n",
        operation.id.data(),static_cast<int>(bytes-1),packet,
        static_cast<unsigned long long>(before.player_ref),static_cast<unsigned long long>(before.target_ref),before.date);
    return length>0 && static_cast<size_t>(length)<sizeof(entry)
        && write_handle(attempt_file,entry,static_cast<DWORD>(length));
}

static void finish(const char* new_phase,const char* why) noexcept {
    phase=new_phase;reason=why;pending=false;
    if (attempt_file!=INVALID_HANDLE_VALUE) {
        char entry[600]{};
        const int length=snprintf(entry,sizeof(entry),
            "{\"event\":\"terminal\",\"request_id\":\"%s\",\"state\":\"%s\",\"reason\":\"%s\","
            "\"native_attempted\":%s,\"native_return\":%llu,\"observed_ref\":\"%016llx\",\"date\":%d}\n",
            operation.id.data(),phase,reason,native_attempted?"true":"false",
            static_cast<unsigned long long>(native_return),static_cast<unsigned long long>(observed.player_ref),observed.date);
        if (length<=0 || static_cast<size_t>(length)>=sizeof(entry)
            || !write_handle(attempt_file,entry,static_cast<DWORD>(length))) {phase="failed";reason="terminal_audit_write_failed";}
        if (!CloseHandle(attempt_file)) {phase="failed";reason="terminal_audit_close_failed";}
        attempt_file=INVALID_HANDLE_VALUE;
    }
    // Keep the original consumed request as an independent immutable receipt.
    wchar_t id[65]{}, destination[MAX_PATH]{};
    for (size_t i=0;i<operation.id.size() && operation.id[i];++i) id[i]=static_cast<unsigned char>(operation.id[i]);
    if (swprintf(destination,MAX_PATH,L"%ls\\country-control-%ls.request.saved",directory_path,id)<0
        || !MoveFileExW(processing_path,destination,MOVEFILE_WRITE_THROUGH)) {
        phase="failed";reason="consumed_request_preservation_failed";
    }
    publish();
}

static void poll() noexcept {
    if (pending || GetFileAttributesW(request_path)==INVALID_FILE_ATTRIBUTES) return;
    if (GetFileAttributesW(processing_path)!=INVALID_FILE_ATTRIBUTES
        || !MoveFileExW(request_path,processing_path,MOVEFILE_WRITE_THROUGH)) return;
    HANDLE input=CreateFileW(processing_path,GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    char packet[321]{};DWORD got=0;LARGE_INTEGER size{};
    const bool read_ok=input!=INVALID_HANDLE_VALUE && GetFileSizeEx(input,&size)
        && size.QuadPart>0 && size.QuadPart<=320
        && ReadFile(input,packet,static_cast<DWORD>(size.QuadPart),&got,nullptr)
        && got==static_cast<DWORD>(size.QuadPart);
    const bool closed=input!=INVALID_HANDLE_VALUE && CloseHandle(input);
    policy::Request parsed{};
    if (!read_ok || !closed || !policy::parse_request(std::string_view(packet,got),parsed)) {
        // Invalid bytes are retained in .processing; they cannot trigger a call
        // and cannot be silently replaced by a later request.
        phase="rejected";reason="invalid_request_preserved";publish();return;
    }
    operation=parsed;have_operation=true;native_attempted=false;native_return=0;
    before=snapshot(operation.to);observed=before;
    const auto admission=policy::admit(operation,identity,before,guard(),capture_idle(),attempted_mask);
    if (admission!=policy::Reason::ok) {finish("rejected",policy::reason_name(admission));return;}
    if (!reserve(packet,got)) {finish("failed","durable_reservation_failed");return;}
    const auto fresh=snapshot(operation.to);
    if (!policy::same_precondition(before,fresh) || !guard() || !capture_idle()) {
        observed=fresh;finish("rejected","precondition_changed_after_reservation");return;
    }
    phase="attempting";reason="durably_reserved_outcome_unknown";native_attempted=true;
    if (!publish()) {native_attempted=false;finish("failed","precall_status_write_failed");return;}
    ++native_calls;
    native_return=static_cast<uint64_t>(invoke_switch(reinterpret_cast<void*>(before.game),before.target_ref));
    invoked_frame=frame_count;verify_deadline=GetTickCount64()+5000;pending=true;
    phase="pending";reason="awaiting_subsequent_frame_effect";publish();
}

static bool start(const wchar_t* directory) noexcept {
    if (initialized.load(std::memory_order_acquire) || !directory || wcslen(directory)>=MAX_PATH-100
        || !observation_creation || !guard()) return false;
    wcscpy(directory_path,directory);
    if (swprintf(request_path,MAX_PATH,L"%ls\\information-country-control.request",directory)<0
        || swprintf(processing_path,MAX_PATH,L"%ls\\information-country-control.processing",directory)<0
        || swprintf(status_path,MAX_PATH,L"%ls\\information-country-control-status.json",directory)<0
        || swprintf(status_temp,MAX_PATH,L"%ls\\information-country-control-status.json.tmp",directory)<0) return false;
    for (unsigned i=0;i<2;++i) {
        const wchar_t* tag=i==0?L"FRA":L"POR";
        if (swprintf(attempt_paths[i],MAX_PATH,L"%ls\\information-country-control-%ls.attempt.jsonl",directory,tag)<0
            || GetFileAttributesW(attempt_paths[i])!=INVALID_FILE_ATTRIBUTES) return false;
    }
    if (GetFileAttributesW(request_path)!=INVALID_FILE_ATTRIBUTES
        || GetFileAttributesW(processing_path)!=INVALID_FILE_ATTRIBUTES) return false;
    identity.pid=GetCurrentProcessId();identity.creation=observation_creation;
    std::memcpy(identity.dll_sha.data(),information_battle_source::dll_sha,65);
    if (!publish()) return false;
    initialized.store(true,std::memory_order_release);
    return true;
}

static void tick() noexcept {
    if (!initialized.load(std::memory_order_acquire)) return;
    const auto now=GetTickCount64();
    if (pending && frame_count>invoked_frame) {
        observed=snapshot(operation.to);
        const bool waiting_for_command=native_return==1 && now<verify_deadline
            && (!observed.read_ok || (observed.game==before.game && observed.date==before.date
                && observed.speed==0 && observed.paused && observed.human_count==1
                && observed.target_ref==before.target_ref && observed.player_ref==before.player_ref));
        if (guard() && capture_idle() && policy::effect_confirmed(operation,before,observed,native_return)) {
            authorized_fra_ref=operation.to==policy::Country::fra?observed.player_ref:0;
            finish("confirmed","subsequent_frame_exact_effect");
        } else if (!waiting_for_command || !guard() || !capture_idle()) {
            finish("failed",native_return==1?"subsequent_frame_effect_mismatch":"native_returned_false");
        }
    }
    if (!pending && now-last_poll>=100) {last_poll=now;poll();}
    if (now-last_status>=1000) {
        last_status=now;
        if (!pending) observed=snapshot(have_operation?operation.to:policy::Country::fra);
        publish();
    }
}
} // namespace current_country_host

static bool current_country_control_allows_automation(uint64_t player) noexcept {
    return information::current_country_control::allow_automation(player,current_country_host::authorized_fra_ref);
}
