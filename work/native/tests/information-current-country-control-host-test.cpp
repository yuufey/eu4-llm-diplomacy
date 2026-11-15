#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <array>
#include <atomic>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iterator>
#include <string>
#include <string_view>

#include "../information-current-country-control-plan.h"
#include "../information-current-country-control-policy.h"

namespace information_battle_source {
enum : long { ready=0, enabled=1, disabled=2 };
inline std::atomic<long> state{ready};
inline constexpr char dll_sha[65] =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
}

namespace current_country_host {
using namespace information::battle::current_country_control_plan;
static uintptr_t base=0, game_address=0, server_address=0, vtable_address=0,
    pause_address=0, database_address=0, table_address=0, france_address=0,
    portugal_address=0, duplicate_france_address=0, provinces_address=0, arena_base=0;
static LONG frame_count=120;
static DWORD frame_thread=0;
static bool thread_changed=false;
static DWORD control_target=0;
static uint64_t observation_creation=987654321u;
template<class T>
static bool read(uintptr_t address,T& value) noexcept {
    SIZE_T got=0;
    return ReadProcessMemory(GetCurrentProcess(),reinterpret_cast<const void*>(address),
                             &value,sizeof(value),&got)!=FALSE && got==sizeof(value);
}
static bool insult_query_country(uint64_t reference,uintptr_t& country) noexcept {
    if (reference==((UINT64_C(1)<<56u)|(UINT64_C(122)<<32u)|0x00415246u)) {
        country=france_address;return country!=0;
    }
    if (reference==((UINT64_C(1)<<56u)|(UINT64_C(189)<<32u)|0x00524f50u)) {
        country=portugal_address;return country!=0;
    }
    return false;
}
}

static constexpr uint64_t kFranceRef=(UINT64_C(1)<<56u)|(UINT64_C(122)<<32u)|0x00415246u;
static constexpr uint64_t kPortugalRef=(UINT64_C(1)<<56u)|(UINT64_C(189)<<32u)|0x00524f50u;
static uintptr_t g_expected_game=0;
static uint64_t g_expected_target=0;
static unsigned g_mock_calls=0;
static bool g_mock_change_reference=true;
static bool g_mock_contract_ok=true;
static uint8_t g_mock_result=1;

template<class T>
static bool self_write(uintptr_t address,const T& value) noexcept {
    SIZE_T wrote=0;
    return WriteProcessMemory(GetCurrentProcess(),reinterpret_cast<void*>(address),
                              &value,sizeof(value),&wrote)!=FALSE && wrote==sizeof(value);
}

uint8_t current_country_fixture_invoke(void* game,uint64_t target,void* reason) noexcept {
    // Under the Win64 ABI these three arguments arrive in RCX/RDX/R8.
    assert(reason==nullptr);
    assert(reinterpret_cast<uintptr_t>(game)==g_expected_game);
    assert(target==g_expected_target);
    ++g_mock_calls;
    if (reason!=nullptr || reinterpret_cast<uintptr_t>(game)!=g_expected_game
        || target!=g_expected_target) g_mock_contract_ok=false;
    if (g_mock_change_reference && g_mock_result==1u
        && !self_write(reinterpret_cast<uintptr_t>(game)+0x1e60,target))
        g_mock_contract_ok=false;
    return g_mock_result;
}

static ULONGLONG current_country_fixture_clock_ms=10000u;
static ULONGLONG WINAPI current_country_fixture_get_tick_count64() noexcept {
    return current_country_fixture_clock_ms;
}

extern "C" PRUNTIME_FUNCTION NTAPI current_country_fixture_lookup(
    DWORD64 control_pc,PDWORD64 image_base,PUNWIND_HISTORY_TABLE history_table) noexcept {
    (void)history_table;
    using namespace information::battle::current_country_control_plan;
    const DWORD64 base=static_cast<DWORD64>(current_country_host::base);
    if (!image_base || !base || control_pc!=base+kNativeGuardRva+1u) return nullptr;
    *image_base=base;
    // This pointer addresses inert fixture data inside PAGE_READWRITE memory.
    return reinterpret_cast<PRUNTIME_FUNCTION>(base+kPdataRowRva);
}

#define RtlLookupFunctionEntry current_country_fixture_lookup
#define INFORMATION_CURRENT_COUNTRY_HOST_FIXTURE 1
#define GetTickCount64 current_country_fixture_get_tick_count64
#include "../information-current-country-control.inc"
#undef GetTickCount64
#undef INFORMATION_CURRENT_COUNTRY_HOST_FIXTURE
#undef RtlLookupFunctionEntry

namespace {
using namespace information::battle::current_country_control_plan;
using information::current_country_control::Country;

constexpr int32_t kDate=56562768;
constexpr uintptr_t kArenaBytes=0x20000u;
constexpr uint64_t kCreation=987654321u;
constexpr char kSha[]= "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

bool fail(const char* expression,int line) {
    std::fprintf(stderr,"FAIL line %d: %s (winerr=%lu)\n",line,expression,
                 static_cast<unsigned long>(GetLastError()));
    return false;
}
#define CHECK(expression) do { if (!(expression)) return fail(#expression,__LINE__); } while (0)

bool ascii_to_wide(const char* input,wchar_t* output,size_t capacity) {
    if (!input || !output || capacity==0) return false;
    size_t index=0;
    for (;input[index] && index+1<capacity;++index) {
        const unsigned char value=static_cast<unsigned char>(input[index]);
        if (value>0x7fu) return false;
        output[index]=static_cast<wchar_t>(value);
    }
    if (input[index]) return false;
    output[index]=L'\0';
    return true;
}

bool safe_output_path(const wchar_t* path) {
    static constexpr wchar_t prefix[]=L"work\\runtime\\information-battle-recipient-20261028-001\\owned-host-fixture-001\\";
    if (!path || wcsncmp(path,prefix,std::size(prefix)-1u)!=0) return false;
    if (wcsstr(path,L"..") || wcschr(path,L':') || wcschr(path,L'/')) return false;
    return wcsstr(path+std::size(prefix)-1u,L"\\scenarios\\")!=nullptr;
}

bool write_durable_new(const wchar_t* path,const char* bytes,size_t count) {
    if (!path || !bytes || count==0 || count>4096) return false;
    HANDLE file=CreateFileW(path,GENERIC_WRITE,FILE_SHARE_READ,nullptr,CREATE_NEW,
                            FILE_ATTRIBUTE_NORMAL,nullptr);
    if (file==INVALID_HANDLE_VALUE) return false;
    DWORD wrote=0;
    const bool wrote_all=WriteFile(file,bytes,static_cast<DWORD>(count),&wrote,nullptr)!=FALSE
        && wrote==count;
    const bool flushed=wrote_all && FlushFileBuffers(file)!=FALSE;
    const bool closed=CloseHandle(file)!=FALSE;
    return wrote_all && flushed && closed;
}

bool read_closed(const wchar_t* path,std::string& output) {
    HANDLE file=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,
                            OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    if (file==INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER size{};
    bool ok=GetFileSizeEx(file,&size)!=FALSE && size.QuadPart>=0 && size.QuadPart<=8192;
    std::string local;
    if (ok) {
        local.resize(static_cast<size_t>(size.QuadPart));
        DWORD got=0;
        ok=ReadFile(file,local.data(),static_cast<DWORD>(local.size()),&got,nullptr)!=FALSE
            && got==local.size();
    }
    const bool closed=CloseHandle(file)!=FALSE;
    if (!closed) ok=false;
    if (ok) output.swap(local);
    return ok;
}

bool exists(const wchar_t* path) {
    return GetFileAttributesW(path)!=INVALID_FILE_ATTRIBUTES;
}

bool contains(const std::string& text,std::string_view token) {
    return text.find(token)!=std::string::npos;
}

bool status_file(std::string& content) {
    return read_closed(current_country_host::status_path,content);
}

bool write_named_receipt(const char* name,const std::string& content) {
    wchar_t path[MAX_PATH]{};
    if (!name || swprintf(path,MAX_PATH,L"%ls\\%hs",current_country_host::directory_path,name)<0)
        return false;
    return write_durable_new(path,content.data(),content.size());
}

bool check_status(std::string_view state,std::string_view reason,unsigned calls,
                  unsigned mask,uint64_t authorized_ref) {
    std::string text;
    CHECK(status_file(text));
    CHECK(contains(text,"\"schema\":\"EU4COUNTRY1\""));
    CHECK(contains(text,std::string("\"state\":\"")+std::string(state)+"\""));
    CHECK(contains(text,std::string("\"reason\":\"")+std::string(reason)+"\""));
    CHECK(contains(text,std::string("\"native_calls\":")+std::to_string(calls)));
    CHECK(contains(text,std::string("\"attempted_mask\":")+std::to_string(mask)));
    char ref[40]{};
    std::snprintf(ref,sizeof(ref),"\"authorized_fra_ref\":\"%016llx\"",
                  static_cast<unsigned long long>(authorized_ref));
    CHECK(contains(text,ref));
    CHECK(!exists(current_country_host::status_temp));
    return true;
}

bool check_observed_player_ref(uint64_t reference) {
    std::string text;
    CHECK(status_file(text));
    char expected[40]{};
    std::snprintf(expected,sizeof(expected),"\"observed_player_ref\":\"%016llx\"",
                  static_cast<unsigned long long>(reference));
    CHECK(contains(text,expected));
    return true;
}

bool saved_request(const char* id,const std::string& expected) {
    wchar_t path[MAX_PATH]{};
    if (swprintf(path,MAX_PATH,L"%ls\\country-control-%hs.request.saved",
                 current_country_host::directory_path,id)<0) return false;
    std::string saved;
    return read_closed(path,saved) && saved==expected;
}

std::string make_request(const char* id,const char* from,const char* to) {
    char bytes[320]{};
    const int length=std::snprintf(bytes,sizeof(bytes),
        "EU4COUNTRY1 TEST_ONLY %s %lu %llu %d %s %s %s\n",id,
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long long>(kCreation),kDate,kSha,from,to);
    if (length<=0 || static_cast<size_t>(length)>=sizeof(bytes)) return {};
    return std::string(bytes,static_cast<size_t>(length));
}

bool submit(const char* id,const char* from,const char* to) {
    const std::string packet=make_request(id,from,to);
    if (packet.empty()) return false;
    g_expected_target=std::strcmp(to,"FRA")==0?kFranceRef:kPortugalRef;
    if (!write_durable_new(current_country_host::request_path,packet.data(),packet.size())) return false;
    current_country_host::last_poll=0;
    current_country_host::tick();
    return true;
}

bool check_saved_request(const char* id,const char* from,const char* to) {
    const std::string packet=make_request(id,from,to);
    return !packet.empty() && saved_request(id,packet)
        && !exists(current_country_host::request_path)
        && !exists(current_country_host::processing_path);
}

bool set_current(uint64_t reference) {
    return self_write(current_country_host::game_address+0x1e60,reference);
}

bool configure_memory(bool duplicate_fra) {
    void* image=VirtualAlloc(nullptr,kSizeOfImage,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    if (!image) return false;
    current_country_host::base=reinterpret_cast<uintptr_t>(image);
    const auto is_read_write=[](uintptr_t address) {
        MEMORY_BASIC_INFORMATION region{};
        return VirtualQuery(reinterpret_cast<const void*>(address),&region,sizeof(region))==sizeof(region)
            && region.State==MEM_COMMIT && region.Type==MEM_PRIVATE
            && region.Protect==PAGE_READWRITE;
    };
    if (!is_read_write(current_country_host::base)
        || !is_read_write(current_country_host::base+kNativeGuardRva)
        || !is_read_write(current_country_host::base+kPdataRowRva)
        || !is_read_write(current_country_host::base+kUnwindInfoRva)
        || !is_read_write(current_country_host::base+kSizeOfImage-1u)) return false;
    std::memcpy(reinterpret_cast<void*>(current_country_host::base+kNativeGuardRva),
                kNativeGuardBytes.data(),kNativeGuardBytes.size());
    std::memcpy(reinterpret_cast<void*>(current_country_host::base+kPdataRowRva),
                kPdataRowBytes.data(),kPdataRowBytes.size());
    std::memcpy(reinterpret_cast<void*>(current_country_host::base+kUnwindInfoRva),
                kUnwindInfoBytes.data(),kUnwindInfoBytes.size());

    void* arena=VirtualAlloc(nullptr,kArenaBytes,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    if (!arena) return false;
    const uintptr_t a=reinterpret_cast<uintptr_t>(arena);
    current_country_host::arena_base=a;
    current_country_host::database_address=a+0x100u;
    current_country_host::table_address=a+0x1000u;
    current_country_host::france_address=a+0x2000u;
    current_country_host::portugal_address=a+0x4000u;
    current_country_host::duplicate_france_address=a+0x6000u;
    current_country_host::game_address=a+0x8000u;
    current_country_host::server_address=a+0xa000u;
    current_country_host::vtable_address=a+0xc000u;
    current_country_host::pause_address=a+0xe000u;
    current_country_host::provinces_address=a+0x10000u;
    g_expected_game=current_country_host::game_address;

    const uint32_t country_count=190u;
    const uintptr_t game=current_country_host::game_address;
    const uintptr_t server=current_country_host::server_address;
    const uintptr_t vtable=current_country_host::vtable_address;
    const uintptr_t pause=current_country_host::pause_address;
    const uintptr_t database=current_country_host::database_address;
    const uintptr_t table=current_country_host::table_address;
    const uintptr_t france=current_country_host::france_address;
    const uintptr_t portugal=current_country_host::portugal_address;
    const uintptr_t duplicate=current_country_host::duplicate_france_address;
    const uintptr_t provinces=current_country_host::provinces_address;
    const uintptr_t base=current_country_host::base;

    if (!self_write(base+0x233d8b0,database) || !self_write(database+0x118,table)
        || !self_write(database+0x124,country_count)
        || !self_write(table+122u*sizeof(uintptr_t),france)
        || !self_write(table+189u*sizeof(uintptr_t),portugal)
        || !self_write(france+0x20,kFranceRef) || !self_write(portugal+0x20,kPortugalRef)
        || !self_write(france+0x1344,int32_t{4}) || !self_write(portugal+0x1344,int32_t{7})
        || !self_write(france+0x1338,provinces) || !self_write(portugal+0x1338,provinces)
        || !self_write(base+0x233fe58,game) || !self_write(game+0x1e60,kPortugalRef)
        || !self_write(game+0x1dd0,kDate) || !self_write(game+0x1e08,int32_t{0})
        || !self_write(game+0xa60,int32_t{1}) || !self_write(game+0x1e6f,uint8_t{0})
        || !self_write(game+0x1e00,server) || !self_write(server,vtable)
        || !self_write(vtable+0x100,base+0x802500u) || !self_write(server+0x418,pause)
        || !self_write(pause+0x48,uint8_t{1})) return false;
    if (duplicate_fra) {
        const uint64_t duplicate_ref=(UINT64_C(1)<<56u)|(UINT64_C(123)<<32u)|0x00415246u;
        if (!self_write(table+123u*sizeof(uintptr_t),duplicate)
            || !self_write(duplicate+0x20,duplicate_ref)
            || !self_write(duplicate+0x1344,int32_t{2})
            || !self_write(duplicate+0x1338,provinces)) return false;
    }
    current_country_host::frame_count=120;
    current_country_host::frame_thread=GetCurrentThreadId();
    current_country_host::thread_changed=false;
    current_country_host::control_target=0;
    current_country_host::observation_creation=kCreation;
    current_country_fixture_clock_ms=10000u;
    information_battle_source::state.store(information_battle_source::ready,std::memory_order_release);
    g_mock_calls=0;g_mock_change_reference=true;g_mock_contract_ok=true;g_mock_result=1;
    return true;
}

bool start_host(const wchar_t* output) {
    CHECK(safe_output_path(output));
    CHECK(CreateDirectoryW(output,nullptr)!=FALSE);
    CHECK(configure_memory(std::wstring_view(output).find(L"duplicate-target")!=std::wstring_view::npos));
    CHECK(current_country_host::start(output));
    std::string initial;
    CHECK(status_file(initial));
    CHECK(contains(initial,"\"schema\":\"EU4COUNTRY1\""));
    CHECK(contains(initial,"\"state\":\"ready\""));
    CHECK(contains(initial,std::string("\"dll_sha256\":\"")+kSha+"\""));
    CHECK(!exists(current_country_host::request_path));
    CHECK(!exists(current_country_host::processing_path));
    CHECK(!exists(current_country_host::attempt_paths[0]));
    CHECK(!exists(current_country_host::attempt_paths[1]));
    return true;
}

bool complete_one_frame(bool should_confirm,bool fra_authorized_before=false,
                        bool fra_authorized_after=true,const char* pending_snapshot=nullptr) {
    CHECK(current_country_host::pending);
    CHECK(current_country_control_allows_automation(kFranceRef)==fra_authorized_before);
    std::string pending_status;
    CHECK(status_file(pending_status));
    CHECK(contains(pending_status,"\"state\":\"pending\""));
    if (pending_snapshot) CHECK(write_named_receipt(pending_snapshot,pending_status));
    CHECK(current_country_control_allows_automation(kFranceRef)==fra_authorized_before);
    ++current_country_host::frame_count;
    current_country_host::tick();
    if (should_confirm) {
        CHECK(!current_country_host::pending);
        CHECK(std::strcmp(current_country_host::phase,"confirmed")==0);
        CHECK(current_country_control_allows_automation(kFranceRef)==fra_authorized_after);
    } else {
        CHECK(!current_country_host::pending);
        CHECK(std::strcmp(current_country_host::phase,"failed")==0);
        CHECK(!current_country_control_allows_automation(kFranceRef));
    }
    return true;
}

bool hold_pending_one_frame(const char* snapshot_name) {
    CHECK(current_country_host::pending);
    CHECK(current_country_control_allows_automation(kFranceRef)==false);
    ++current_country_host::frame_count;
    current_country_host::tick();
    CHECK(current_country_host::pending);
    CHECK(std::strcmp(current_country_host::phase,"pending")==0);
    CHECK(g_mock_calls==1 && current_country_host::native_calls==1);
    CHECK(!current_country_control_allows_automation(kFranceRef));
    CHECK(check_status("pending","awaiting_subsequent_frame_effect",1,1,0));
    CHECK(check_observed_player_ref(kPortugalRef));
    if (snapshot_name) {
        std::string pending_status;
        CHECK(status_file(pending_status));
        CHECK(write_named_receipt(snapshot_name,pending_status));
    }
    return true;
}

bool capture_gate(const wchar_t* output) {
    CHECK(start_host(output));
    information_battle_source::state.store(information_battle_source::enabled,std::memory_order_release);
    CHECK(submit("capture-gate-reject","POR","FRA"));
    CHECK(check_saved_request("capture-gate-reject","POR","FRA"));
    CHECK(check_status("rejected","capture_not_idle",0,0,0));
    std::string capture_rejected;
    CHECK(status_file(capture_rejected));
    CHECK(write_named_receipt("capture-rejected-status.json",capture_rejected));
    CHECK(g_mock_calls==0 && current_country_host::native_calls==0);
    CHECK(current_country_host::attempted_mask==0);
    CHECK(!exists(current_country_host::attempt_paths[0]));
    CHECK(!current_country_host::pending);

    information_battle_source::state.store(information_battle_source::disabled,std::memory_order_release);
    CHECK(submit("capture-gate-fresh","POR","FRA"));
    CHECK(g_mock_contract_ok && g_mock_calls==1 && current_country_host::native_calls==1);
    CHECK(current_country_host::pending);
    CHECK(current_country_host::frame_count==120);
    CHECK(!current_country_control_allows_automation(kFranceRef));
    CHECK(complete_one_frame(true,false,true,"capture-pending-status.json"));
    CHECK(check_saved_request("capture-gate-fresh","POR","FRA"));
    CHECK(set_current(kFranceRef));
    CHECK(check_status("confirmed","subsequent_frame_exact_effect",1,1,kFranceRef));
    CHECK(current_country_host::attempted_mask==1u);
    CHECK(!current_country_host::pending);
    CHECK(current_country_host::attempt_file==INVALID_HANDLE_VALUE);
    std::string attempt;
    CHECK(read_closed(current_country_host::attempt_paths[0],attempt));
    CHECK(contains(attempt,"\"event\":\"reserved_before_native\""));
    CHECK(contains(attempt,"\"event\":\"terminal\""));
    CHECK(contains(attempt,"\"state\":\"confirmed\""));
    CHECK(!exists(current_country_host::attempt_paths[1]));
    return true;
}

bool por_recovery(const wchar_t* output) {
    CHECK(start_host(output));
    CHECK(submit("recovery-fra","POR","FRA"));
    CHECK(g_mock_calls==1 && current_country_host::native_calls==1);
    CHECK(complete_one_frame(true,false,true,"recovery-fra-pending-status.json"));
    CHECK(check_saved_request("recovery-fra","POR","FRA"));
    CHECK(current_country_control_allows_automation(kFranceRef));
    CHECK(set_current(kFranceRef));

    CHECK(submit("recovery-por","FRA","POR"));
    CHECK(g_mock_calls==2 && current_country_host::native_calls==2);
    CHECK(current_country_host::pending);
    CHECK(complete_one_frame(true,true,false,"recovery-por-pending-status.json"));
    CHECK(check_saved_request("recovery-por","FRA","POR"));
    CHECK(set_current(kPortugalRef));
    CHECK(!current_country_control_allows_automation(kFranceRef));
    CHECK(current_country_control_allows_automation(kPortugalRef));
    CHECK(current_country_host::attempted_mask==3u);
    CHECK(check_status("confirmed","subsequent_frame_exact_effect",2,3,0));
    CHECK(current_country_host::attempt_file==INVALID_HANDLE_VALUE);
    std::string fra_attempt,por_attempt;
    CHECK(read_closed(current_country_host::attempt_paths[0],fra_attempt));
    CHECK(read_closed(current_country_host::attempt_paths[1],por_attempt));
    CHECK(contains(fra_attempt,"\"request_id\":\"recovery-fra\""));
    CHECK(contains(por_attempt,"\"request_id\":\"recovery-por\""));
    CHECK(contains(por_attempt,"\"state\":\"confirmed\""));
    return true;
}

bool duplicate_target(const wchar_t* output) {
    CHECK(start_host(output));
    CHECK(submit("duplicate-fra","POR","FRA"));
    CHECK(check_saved_request("duplicate-fra","POR","FRA"));
    CHECK(check_status("rejected","snapshot_read_failed",0,0,0));
    CHECK(g_mock_calls==0 && current_country_host::native_calls==0);
    CHECK(current_country_host::attempted_mask==0 && !current_country_host::pending);
    CHECK(!exists(current_country_host::attempt_paths[0]));
    return true;
}

bool true_without_effect(const wchar_t* output) {
    CHECK(start_host(output));
    g_mock_change_reference=false;
    CHECK(submit("no-effect-fra","POR","FRA"));
    CHECK(g_mock_contract_ok && g_mock_calls==1 && current_country_host::native_calls==1);
    CHECK(current_country_host::pending);
    CHECK(!current_country_control_allows_automation(kFranceRef));
    CHECK(hold_pending_one_frame("no-effect-pending-status.json"));
    CHECK(current_country_fixture_clock_ms==10000u);
    current_country_fixture_clock_ms+=5001u;
    ++current_country_host::frame_count;
    current_country_host::tick();
    CHECK(!current_country_host::pending);
    CHECK(std::strcmp(current_country_host::phase,"failed")==0);
    CHECK(check_saved_request("no-effect-fra","POR","FRA"));
    CHECK(check_status("failed","subsequent_frame_effect_mismatch",1,1,0));
    CHECK(g_mock_calls==1 && current_country_host::native_calls==1);
    current_country_host::tick();
    CHECK(g_mock_calls==1 && current_country_host::native_calls==1);
    CHECK(!current_country_control_allows_automation(kFranceRef));
    CHECK(current_country_host::attempt_file==INVALID_HANDLE_VALUE);
    std::string attempt;
    CHECK(read_closed(current_country_host::attempt_paths[0],attempt));
    CHECK(contains(attempt,"\"state\":\"failed\""));
    return true;
}

bool deferred_effect(const wchar_t* output) {
    CHECK(start_host(output));
    g_mock_change_reference=false;
    CHECK(submit("deferred-fra","POR","FRA"));
    CHECK(g_mock_contract_ok && g_mock_calls==1 && current_country_host::native_calls==1);
    CHECK(current_country_host::pending);
    CHECK(!current_country_control_allows_automation(kFranceRef));
    CHECK(hold_pending_one_frame("deferred-effect-pending-status.json"));
    CHECK(exists(current_country_host::processing_path));
    CHECK(!exists(current_country_host::request_path));
    CHECK(!current_country_control_allows_automation(kFranceRef));
    CHECK(g_mock_calls==1 && current_country_host::native_calls==1);

    CHECK(set_current(kFranceRef));
    ++current_country_host::frame_count;
    current_country_host::tick();
    CHECK(!current_country_host::pending);
    CHECK(std::strcmp(current_country_host::phase,"confirmed")==0);
    CHECK(current_country_control_allows_automation(kFranceRef));
    CHECK(g_mock_calls==1 && current_country_host::native_calls==1);
    CHECK(check_saved_request("deferred-fra","POR","FRA"));
    CHECK(check_status("confirmed","subsequent_frame_exact_effect",1,1,kFranceRef));
    std::string confirmed_status;
    CHECK(status_file(confirmed_status));
    CHECK(write_named_receipt("deferred-effect-confirmed-status.json",confirmed_status));
    CHECK(current_country_host::attempt_file==INVALID_HANDLE_VALUE);
    std::string attempt;
    CHECK(read_closed(current_country_host::attempt_paths[0],attempt));
    CHECK(contains(attempt,"\"state\":\"confirmed\""));
    return true;
}

bool preexisting_attempt(const wchar_t* output) {
    CHECK(start_host(output));
    static constexpr char sentinel[]="preexisting-attempt-must-survive\n";
    CHECK(write_durable_new(current_country_host::attempt_paths[0],sentinel,sizeof(sentinel)-1u));
    CHECK(submit("occupied-attempt","POR","FRA"));
    CHECK(check_saved_request("occupied-attempt","POR","FRA"));
    CHECK(check_status("failed","durable_reservation_failed",0,0,0));
    CHECK(g_mock_calls==0 && current_country_host::native_calls==0);
    CHECK(current_country_host::attempted_mask==0 && !current_country_host::pending);
    CHECK(current_country_host::attempt_file==INVALID_HANDLE_VALUE);
    std::string retained;
    CHECK(read_closed(current_country_host::attempt_paths[0],retained));
    CHECK(retained==sentinel);
    CHECK(!exists(current_country_host::attempt_paths[1]));
    return true;
}

bool release_fixture_memory() {
    bool success=true;
    if (current_country_host::arena_base) {
        success=VirtualFree(reinterpret_cast<void*>(current_country_host::arena_base),0,MEM_RELEASE)!=FALSE;
        if (success) current_country_host::arena_base=0;
    }
    if (current_country_host::base) {
        const bool freed=VirtualFree(reinterpret_cast<void*>(current_country_host::base),0,MEM_RELEASE)!=FALSE;
        success=freed && success;
        if (freed) current_country_host::base=0;
    }
    return success;
}

bool write_result(const wchar_t* output,const char* scenario,bool memory_released) {
    wchar_t path[MAX_PATH]{};
    if (swprintf(path,MAX_PATH,L"%ls\\fixture-result.json",output)<0) return false;
    char json[1600]{};
    const int length=std::snprintf(json,sizeof(json),
        "{\"schema\":\"information_current_country_owned_host_fixture.v1\","
        "\"scenario\":\"%s\",\"status\":\"passed\","
        "\"mock_invoke_calls\":%u,\"host_native_calls\":%llu,"
        "\"mock_reason_argument_null\":%s,\"real_eu4_calls\":0,"
        "\"native_code_bytes_executed\":false,\"host_status_json_checked\":true,"
        "\"win32_create_write_flush_close_checked\":true,"
        "\"attempt_file_closed\":%s,\"fixture_allocations_released\":%s,"
        "\"capture_state\":%ld,"
        "\"subscriptions\":0,\"date_raw\":%d,\"target_ref\":\"%016llx\"}\n",
        scenario,g_mock_calls,static_cast<unsigned long long>(current_country_host::native_calls),
        g_mock_contract_ok?"true":"false",
        current_country_host::attempt_file==INVALID_HANDLE_VALUE?"true":"false",
        memory_released?"true":"false",
        information_battle_source::state.load(std::memory_order_acquire),kDate,
        static_cast<unsigned long long>(g_expected_target));
    return length>0 && static_cast<size_t>(length)<sizeof(json)
        && write_durable_new(path,json,static_cast<size_t>(length));
}

} // namespace

int main(int argc,char** argv) {
    if (argc==1 || std::strcmp(argv[1],"--test-only")!=0) {
        std::puts("inert: pass --test-only --scenario <name> --output-dir <owned-new-directory>");
        return 0;
    }
    if (argc!=6 || std::strcmp(argv[2],"--scenario")!=0
        || std::strcmp(argv[4],"--output-dir")!=0) {
        std::fputs("usage: --test-only --scenario NAME --output-dir RELATIVE_PATH\n",stderr);
        return 2;
    }
    wchar_t output[MAX_PATH]{};
    if (!ascii_to_wide(argv[5],output,std::size(output)) || !safe_output_path(output)) {
        std::fputs("refusing output path outside the owned fixture stage\n",stderr);
        return 2;
    }
    const char* scenario=argv[3];
    bool success=false;
    if (std::strcmp(scenario,"capture-gate")==0) success=capture_gate(output);
    else if (std::strcmp(scenario,"por-recovery")==0) success=por_recovery(output);
    else if (std::strcmp(scenario,"duplicate-target")==0) success=duplicate_target(output);
    else if (std::strcmp(scenario,"true-without-effect")==0) success=true_without_effect(output);
    else if (std::strcmp(scenario,"deferred-effect")==0) success=deferred_effect(output);
    else if (std::strcmp(scenario,"preexisting-attempt")==0) success=preexisting_attempt(output);
    else {
        std::fprintf(stderr,"unknown scenario: %s\n",scenario);
        return 2;
    }
    if (!success || !g_mock_contract_ok) {
        release_fixture_memory();
        return 1;
    }
    const bool memory_released=release_fixture_memory();
    if (!write_result(output,scenario,memory_released)) {
        std::fputs("could not durably publish fixture result\n",stderr);
        return 1;
    }
    std::printf("PASS scenario=%s mock_calls=%u host_native_calls=%llu real_eu4_calls=0 native_code_bytes_executed=false\n",
        scenario,g_mock_calls,static_cast<unsigned long long>(current_country_host::native_calls));
    return memory_released?0:1;
}
