// Independent common-control/command-observation build. Legacy source and DLL
// remain intact. All observed commands continue through the original executor.
#if defined(BRIDGE_LAND_PROMISE_OBSERVATION) && (!defined(BRIDGE_CLAIM_EXPIRY_OBSERVATION) || !defined(BRIDGE_WAR_DECLARATION_OBSERVATION))
#error Land promise observation requires claim expiry and war declaration observation.
#endif
#if defined(BRIDGE_CLAIM_EXPIRY_OBSERVATION) && (!defined(BRIDGE_SUBSIDY_EXPIRY_OBSERVATION) || !defined(BRIDGE_TRUCE_EXPIRY_OBSERVATION))
#error Claim expiry observation requires the complete v62 feature combination.
#endif
#if defined(BRIDGE_SUBSIDY_EXPIRY_OBSERVATION) && !defined(BRIDGE_RIVAL_RECORD_OBSERVATION)
#error Subsidy expiry observation requires the complete v61 feature combination.
#endif
#if defined(BRIDGE_TRUCE_EXPIRY_OBSERVATION) && !defined(BRIDGE_RIVAL_RECORD_OBSERVATION)
#error Truce expiry observation requires the complete v61 feature combination.
#endif
#if defined(BRIDGE_RIVAL_RECORD_OBSERVATION) && !defined(BRIDGE_SUPPORT_SUBJECT_RECORD_OBSERVATION)
#error Rival record observation requires the complete support-subject record observer combination.
#endif
#if defined(BRIDGE_MISSION_PROVINCE_CONDITION_OBSERVATION) && !defined(BRIDGE_MISSION_CONDITION_OBSERVATION)
#error Province condition observation requires the complete v56 feature combination.
#endif
#if defined(BRIDGE_SUPPORT_SUBJECT_RECORD_OBSERVATION) && !defined(BRIDGE_DIRECTED_RECORD_OBSERVATION)
#error Support and subject record observation requires the complete directed record observer combination.
#endif
#if defined(BRIDGE_DIRECTED_RECORD_OBSERVATION) && !defined(BRIDGE_ROYAL_RECORD_OBSERVATION)
#error Directed record observation requires the complete royal record observer combination.
#endif
#if defined(BRIDGE_ROYAL_RECORD_OBSERVATION) && !defined(BRIDGE_MISSION_PROVINCE_CONDITION_OBSERVATION)
#error Royal record observation requires the complete province condition observer combination.
#endif
#if defined(BRIDGE_MISSION_CONDITION_OBSERVATION) && !defined(BRIDGE_ALLIANCE_RECORD_OBSERVATION)
#error Mission condition observation requires the complete v55 feature combination.
#endif
#if defined(BRIDGE_ALLIANCE_RECORD_OBSERVATION) && !defined(BRIDGE_MISSION_COMPLETED_SET_OBSERVATION)
#error Alliance record observation requires the complete v53 feature combination.
#endif
#if defined(BRIDGE_MISSION_COMPLETED_SET_OBSERVATION) && !defined(BRIDGE_MISSION_AVAILABILITY_OBSERVATION)
#error Completed set observation requires the complete v52 feature combination.
#endif
#if defined(BRIDGE_MISSION_AVAILABILITY_OBSERVATION) && !defined(BRIDGE_MISSION_COMPLETION_OBSERVATION)
#error Mission availability observation requires the complete v51 feature combination.
#endif
#if defined(BRIDGE_MISSION_COMPLETION_OBSERVATION) && !defined(BRIDGE_RELATION_OBSERVATION)
#error Mission completion observation requires the complete v50 feature combination.
#endif
#if defined(BRIDGE_RELATION_OBSERVATION) && !defined(BRIDGE_WAR_DECLARATION_OBSERVATION)
#error Relation observation requires the complete v49 feature combination.
#endif
#if defined(BRIDGE_WAR_DECLARATION_OBSERVATION) && !defined(BRIDGE_RIVAL_OBSERVATION)
#error War declaration observation requires the complete v48 feature combination.
#endif
#if defined(BRIDGE_RIVAL_OBSERVATION) && !defined(BRIDGE_COUNTRY_MODIFIER_EXPIRY)
#error Rival observation requires the complete v47 feature combination.
#endif
#if defined(BRIDGE_COUNTRY_MODIFIER_EXPIRY) && !defined(BRIDGE_COUNTRY_MODIFIER_REMOVAL)
#error Country modifier expiry requires country modifier removal.
#endif
#if defined(BRIDGE_COUNTRY_MODIFIER_REMOVAL) && !defined(BRIDGE_COUNTRY_MODIFIER_OBSERVATION)
#error Country modifier removal requires country modifier observation.
#endif
#if defined(BRIDGE_COUNTRY_MODIFIER_OBSERVATION) && !defined(BRIDGE_SUPPORT_ROLE_CONTEXT)
#error Country modifier observation requires the complete v44 feature combination.
#endif
#if defined(BRIDGE_NATIVE_COUNTRY_CONTROL) && !defined(BRIDGE_LAND_PROMISE_OBSERVATION)
#error Native country control requires the current v64 observer feature combination.
#endif
#ifdef BRIDGE_CURRENT_COUNTRY_CONTROL
#include <cstdint>
static bool current_country_control_allows_automation(uint64_t player) noexcept;
#endif
#define BRIDGE_TRACE_PEACE_RESPONSES 1
#define BRIDGE_TRACE_COMMAND_EXECUTION 1
#define bridge_response_observe observer_legacy_response
#define bridge_frame_tick observer_legacy_frame
#define BridgeStart ObserverControlStart
#include "control-probe.cpp"
#undef bridge_response_observe
#undef bridge_frame_tick
#undef BridgeStart
#ifdef BRIDGE_NATIVE_COUNTRY_CONTROL
#include "control-country-policy.h"
#endif

struct ObservedCommand {
    DWORD thread;
    uintptr_t command,action,action_vtable;
    unsigned char protocol_flags;
    int32_t raw38,raw3c,raw44;
    uint16_t raw40;
    unsigned char raw10;
    bool prefix_readable;
    uint16_t origin;
    uint32_t sequence;
    bool readable;
    uint64_t alliance_actor,alliance_recipient;
    int32_t alliance_state;
    unsigned char alliance_variant;
    bool alliance_identified;
    bool royal_marriage;
    bool improve_relations;
    bool spy_network;
    bool guarantee;
    bool support_independence;
    bool military_access;
    bool vassalization;
    bool favor_gold;
    bool favor_trust;
    bool favor_men;
    bool curry_favors;
    uint64_t callback_sequence;
    char alliance_shape_json[1200];
};
static SRWLOCK observation_lock=SRWLOCK_INIT;
static ObservedCommand observation_events[128]{};
static unsigned observation_head=0,observation_size=0;
static volatile LONG observation_dropped=0;
static uint64_t observation_creation=0;
static uint64_t observation_sequence=0;
static volatile LONG64 observation_callback_sequence=0;
static volatile LONG observation_frame_inside=0;
static ULONGLONG observation_last_health=0;
#ifdef BRIDGE_NATIVE_COUNTRY_CONTROL
static bridge::control_country_policy::PolicyState native_control_country_policy{};
static SRWLOCK native_control_country_lock=SRWLOCK_INIT;
static wchar_t native_control_country_request_path[MAX_PATH]{};
static ULONGLONG native_control_country_next_poll=0;
static uint64_t native_control_country_last_hash=0;
static bridge::control_country_policy::PolicyState native_information_country_policy{};
static SRWLOCK native_information_country_lock=SRWLOCK_INIT;
static wchar_t native_information_country_request_path[MAX_PATH]{};
static ULONGLONG native_information_country_next_poll=0;
static uint64_t native_information_country_last_hash=0;
#endif
#ifdef INFORMATION_BATTLE_WAR_IDENTITY
static bool observation_register_battle_war(uintptr_t reference,char* out,size_t capacity) noexcept;
#endif
#ifdef BRIDGE_INFORMATION_BATTLE
#include "information-battle-observer.inc"
#endif
static void* observation_alliance_validity_original=nullptr;
struct ObservedAllianceRule {
    uint64_t actor,recipient;
    DWORD thread;
    int32_t state_before,state_after;
    unsigned char variant;
    bool result,state_read;
    char query_id[65];
};
static SRWLOCK alliance_rule_lock=SRWLOCK_INIT;
static ObservedAllianceRule alliance_rule_events[128]{};
static unsigned alliance_rule_head=0,alliance_rule_size=0;
static volatile LONG alliance_rule_dropped=0;
static const char* observation_active_query=nullptr;

static bool observation_country_handle(uint64_t handle) {
    uintptr_t database=0,array=0,country=0; uint64_t actual=0;
    unsigned slot=static_cast<unsigned>((handle>>32)&0xffff);
    return slot<4096 && read(base+0x233d8b0,database) && read(database+0x118,array)
        && read(array+static_cast<uintptr_t>(slot)*8,country) && read(country+0x20,actual) && actual==handle;
}

static bool observation_control_country_contains(const char* tag) noexcept {
#ifdef BRIDGE_NATIVE_COUNTRY_CONTROL
    AcquireSRWLockShared(&native_control_country_lock);
    const bool contains=native_control_country_policy.countries.contains(tag);
    ReleaseSRWLockShared(&native_control_country_lock);
    return contains;
#else
    return tag && std::memcmp(tag,"FRA",4)==0;
#endif
}

static bool observation_control_country_handle_tag_only(uint64_t handle) noexcept {
#ifdef BRIDGE_NATIVE_COUNTRY_CONTROL
    char tag[4]{};
    return bridge::control_country_policy::tag_from_handle(handle,tag)
        && observation_control_country_contains(tag);
#else
    char tag[4]={static_cast<char>(handle&0xffu),
        static_cast<char>((handle>>8)&0xffu),
        static_cast<char>((handle>>16)&0xffu),0};
    return observation_control_country_contains(tag);
#endif
}

#ifdef BRIDGE_COUNTRY_MODIFIER_OBSERVATION
static bool observation_information_country_handle(uint64_t handle) noexcept {
#ifdef BRIDGE_NATIVE_COUNTRY_CONTROL
    char tag[4]{};
    if (!bridge::control_country_policy::tag_from_handle(handle,tag)) return false;
    AcquireSRWLockShared(&native_information_country_lock);
    const bool observed=native_information_country_policy.revision!=0
        && native_information_country_policy.countries.contains(tag);
    ReleaseSRWLockShared(&native_information_country_lock);
    return observed && observation_country_handle(handle);
#else
    return (handle&0xffffffu)==0x415246u;
#endif
}
#endif

static bool observation_country_tag_matches_handle(const char* tag,
    std::uint64_t handle) noexcept {
    if (!tag || tag[3]!=0) return false;
    for (unsigned index=0;index<3;++index) {
        const unsigned char value=static_cast<unsigned char>(tag[index]);
        if (!((value>='A' && value<='Z') || (value>='0' && value<='9')))
            return false;
    }
    return static_cast<unsigned char>(tag[0])==static_cast<unsigned char>(handle&0xffu)
        && static_cast<unsigned char>(tag[1])==static_cast<unsigned char>((handle>>8)&0xffu)
        && static_cast<unsigned char>(tag[2])==static_cast<unsigned char>((handle>>16)&0xffu);
}

#ifdef BRIDGE_NATIVE_COUNTRY_CONTROL
static bool observation_ai_recipient(uint64_t recipient,int32_t expected_date) noexcept {
    uintptr_t game=0,controllers=0;
    uint64_t physical_player=0;
    int32_t date=0,human_count=0,kind=0;
    const auto slot=static_cast<unsigned>((recipient>>32)&0xffffu);
    return !observation_control_country_handle_tag_only(recipient)
        && observation_country_handle(recipient)
        && read(base+0x233fe58,game) && game
        && read(game+0x1dd0,date) && date==expected_date
        && read(game+0x1e60,physical_player) && physical_player!=recipient
        && observation_country_handle(physical_player)
        && read(game+0xa60,human_count) && human_count==1
        && read(game+0x1d48,controllers) && controllers
        && read(controllers+slot*sizeof(kind),kind) && kind==0;
}
#endif

static std::size_t observation_control_country_count() noexcept {
#ifdef BRIDGE_NATIVE_COUNTRY_CONTROL
    AcquireSRWLockShared(&native_control_country_lock);
    const std::size_t count=native_control_country_policy.countries.count;
    ReleaseSRWLockShared(&native_control_country_lock);
    return count;
#else
    return 1;
#endif
}

static bool observation_control_country_configured() noexcept {
#ifdef BRIDGE_NATIVE_COUNTRY_CONTROL
    AcquireSRWLockShared(&native_control_country_lock);
    const bool configured=native_control_country_policy.revision!=0;
    ReleaseSRWLockShared(&native_control_country_lock);
    return configured;
#else
    return true;
#endif
}

static bool observation_control_country_copy_at(std::size_t index,
    char (&tag)[4]) noexcept {
#ifdef BRIDGE_NATIVE_COUNTRY_CONTROL
    AcquireSRWLockShared(&native_control_country_lock);
    const char* value=native_control_country_policy.countries.at(index);
    if (value) std::memcpy(tag,value,4);
    ReleaseSRWLockShared(&native_control_country_lock);
    return value!=nullptr;
#else
    if (index!=0) return false;
    std::memcpy(tag,"FRA",4);
    return true;
#endif
}
static bool observation_alliance_validity(void* object,void* diagnostic,unsigned char flags) {
    ObservedAllianceRule event{};
    uintptr_t address=reinterpret_cast<uintptr_t>(object),vtable=0;
    int32_t discriminator=0;
    bool identified=read(address,vtable) && vtable==base+0x1c80720
        && read(address+8,discriminator) && discriminator==0x165
        && read(address+0x10,event.actor) && observation_country_handle(event.actor)
        && read(address+0x20,event.recipient) && observation_country_handle(event.recipient)
        && read(address+0x38,event.variant) && event.variant<=1;
    // Keep high-frequency observations bounded to the experiment countries.
    uint32_t actor=static_cast<uint32_t>(event.actor&0xffffff);
    uint32_t recipient=static_cast<uint32_t>(event.recipient&0xffffff);
    identified=identified && (actor==0x415246 || recipient==0x415246 || actor==0x524f50 || recipient==0x524f50 || actor==0x564153 || recipient==0x564153);
    event.thread=GetCurrentThreadId();
    if (event.thread==frame_thread && observation_active_query)
        strcpy(event.query_id,observation_active_query);
    event.state_read=identified && read(address+0x34,event.state_before);
    using NativeValidity=bool (*)(void*,void*,unsigned char);
    // The original method is called exactly once, with the exact arguments.
    // No new evaluation and no forced result is introduced by observation.
    bool result=reinterpret_cast<NativeValidity>(observation_alliance_validity_original)(object,diagnostic,flags);
    if (identified) {
        event.result=result;
        event.state_read=read(address+0x34,event.state_after) && event.state_read;
        if (TryAcquireSRWLockExclusive(&alliance_rule_lock)) {
            if (alliance_rule_size<128) {
                alliance_rule_events[(alliance_rule_head+alliance_rule_size)%128]=event;
                ++alliance_rule_size;
            } else InterlockedIncrement(&alliance_rule_dropped);
            ReleaseSRWLockExclusive(&alliance_rule_lock);
        } else InterlockedIncrement(&alliance_rule_dropped);
    }
    return result;
}

static bool observation_install_alliance_rule() {
    auto slot=reinterpret_cast<void**>(base+0x1c80720+0x80);
    uintptr_t original=0;
    if (!read(reinterpret_cast<uintptr_t>(slot),original) || original!=base+0x511d90) return false;
    observation_alliance_validity_original=reinterpret_cast<void*>(original);
    DWORD old=0,ignored=0;
    if (!VirtualProtect(slot,8,PAGE_READWRITE,&old)) return false;
    void* previous=InterlockedCompareExchangePointer(reinterpret_cast<void* volatile*>(slot),
        reinterpret_cast<void*>(&observation_alliance_validity),observation_alliance_validity_original);
    bool patched=previous==observation_alliance_validity_original;
    if (!VirtualProtect(slot,8,old,&ignored)) {
        if (patched) InterlockedExchangePointer(reinterpret_cast<void* volatile*>(slot),observation_alliance_validity_original);
        VirtualProtect(slot,8,old,&ignored);
        return false;
    }
    return patched;
}

#include "alliance-lifecycle.inc"
#include "rival-command-observer.inc"
#include "alliance-entry-observer.inc"
#include "alliance-protocol-observer.inc"
#include "alliance-transport.inc"
#include "peace-effects.h"
#include "peace-execution-wire.h"
#include "alliance-query.inc"
static bool observation_control_country_tag(const char* tag,
    std::uint64_t& handle) {
    handle=0;
    return observation_control_country_contains(tag)
        && alliance_query_country(tag,handle)
        && observation_country_handle(handle)
        && observation_country_tag_matches_handle(tag,handle);
}
#ifdef INFORMATION_BATTLE_WAR_IDENTITY
static bool observation_register_battle_war(uintptr_t reference,char* out,size_t capacity) noexcept {
    return peace_query_copy_war_id(reference,out,capacity);
}
#endif
#include "alliance-authority-ledger.h"
#include "alliance-execution-wire.h"
#include "alliance-inbound-response-wire.h"
#include "alliance-inbound.inc"
#ifdef BRIDGE_CALL_TO_ARMS_OBSERVATION
#include "call-to-arms-observer.inc"
#endif
#include "inbound-pending-recovery.inc"
#include "alliance-execution.inc"
#ifdef BRIDGE_WAR_DECLARATION_OBSERVATION
namespace war_declaration_observer = alliance_execution_detail::war_declaration_observer;
#endif
#ifdef BRIDGE_RELATION_OBSERVATION
namespace relation_change_observer = alliance_execution_detail::relation_change_observer;
#endif
#ifdef BRIDGE_ALLIANCE_RECORD_OBSERVATION
#include "information-alliance-record-observer.inc"
#endif
#ifdef BRIDGE_ROYAL_RECORD_OBSERVATION
#include "information-royal-record-observer.inc"
#endif
#ifdef BRIDGE_DIRECTED_RECORD_OBSERVATION
#include "information-directed-record-observer.inc"
#endif
#ifdef BRIDGE_SUPPORT_SUBJECT_RECORD_OBSERVATION
#include "information-support-subject-record-observer.inc"
#endif
#include "peace-handler-authority.inc"
#include "peace-receiver-observer.inc"
static int rival_execution_begin(void* object,unsigned kind) noexcept;
static void rival_execution_finish(unsigned binding) noexcept;
#ifdef BRIDGE_RIVAL_OBSERVATION
#include "information-rival-observer.inc"
#endif
#ifdef BRIDGE_RIVAL_RECORD_OBSERVATION
#include "information-rival-record-observer.inc"
#endif
#include "rival-authority.inc"
#include "rival-execution.inc"
#ifdef BRIDGE_COUNTRY_MODIFIER_OBSERVATION
#include "information-country-modifier-observer.inc"
#endif
#ifdef BRIDGE_SUBSIDY_EXPIRY_OBSERVATION
#include "information-subsidy-expiry-observer.inc"
#endif
#ifdef BRIDGE_TRUCE_EXPIRY_OBSERVATION
#include "information-truce-expiry-observer.inc"
#endif
#ifdef BRIDGE_CLAIM_EXPIRY_OBSERVATION
#include "information-claim-expiry-observer.inc"
#endif
#ifdef BRIDGE_MISSION_COMPLETION_OBSERVATION
#ifdef BRIDGE_MISSION_COMPLETED_SET_OBSERVATION
#include "information-mission-completed-set-observer.inc"
#else
#include "information-mission-observer.inc"
#endif
#endif
#ifdef BRIDGE_MISSION_CONDITION_OBSERVATION
#include "information-mission-condition-observer.inc"
#endif
#ifdef BRIDGE_MISSION_AVAILABILITY_OBSERVATION
#include "information-mission-availability-observer.inc"
#endif
#include "vassal-test-context.inc"
#include "religion-war-context.inc"
#include "vassal-inbound-test-context.inc"
#ifdef BRIDGE_CURRENT_COUNTRY_CONTROL
#include "information-current-country-control.inc"
#endif

#ifdef BRIDGE_NATIVE_COUNTRY_CONTROL
static bool native_control_country_set_paths(const wchar_t* directory) noexcept {
    if (!directory || !directory[0]) return false;
    return swprintf(native_control_country_request_path,MAX_PATH,
        L"%ls\\controlled-countries.req",directory)>=0
        && swprintf(native_information_country_request_path,MAX_PATH,
            L"%ls\\information-observers.req",directory)>=0;
}

static std::uint64_t native_control_country_hash(const char* bytes,
    std::size_t size) noexcept {
    std::uint64_t hash=UINT64_C(14695981039346656037);
    for (std::size_t index=0;index<size;++index) {
        hash^=static_cast<unsigned char>(bytes[index]);
        hash*=UINT64_C(1099511628211);
    }
    return hash;
}

static void native_control_country_emit_ack(const char* session_id,
    std::uint64_t revision,const bridge::control_country_policy::CountrySet& countries,
    bool accepted,const char* reason) noexcept {
    char countries_json[160]="[";
    std::size_t used=1;
    for (std::size_t index=0;index<countries.count;++index) {
        const char* tag=countries.at(index);
        const int written=snprintf(countries_json+used,sizeof(countries_json)-used,
            "%s\"%.3s\"",index?",":"",tag?tag:"");
        if (written<0 || static_cast<std::size_t>(written)>=sizeof(countries_json)-used)
            return;
        used+=static_cast<std::size_t>(written);
    }
    if (used+2>sizeof(countries_json)) return;
    countries_json[used++]=']'; countries_json[used]=0;
    char message[512]{};
    const int written=snprintf(message,sizeof(message),
        "{\"event\":\"native_controlled_countries_set\",\"session_id\":\"%s\","
        "\"revision\":%llu,\"countries\":%s,\"accepted\":%s,\"reason\":\"%s\"}\n",
        session_id?session_id:"",static_cast<unsigned long long>(revision),
        countries_json,accepted?"true":"false",reason?reason:"ok");
    if (written>0 && static_cast<std::size_t>(written)<sizeof(message)) line(message);
}

static void native_control_country_tick() noexcept {
    if (!native_control_country_request_path[0] || !control_ready()) return;
    const ULONGLONG now=GetTickCount64();
    if (now<native_control_country_next_poll) return;
    native_control_country_next_poll=now+500;
    HANDLE file=CreateFileW(native_control_country_request_path,GENERIC_READ,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,nullptr);
    if (file==INVALID_HANDLE_VALUE) return;
    LARGE_INTEGER file_size{};
    const bool size_read=GetFileSizeEx(file,&file_size)!=FALSE;
    char wire[bridge::control_country_policy::kMaxWireBytes]{};
    DWORD bytes_read=0;
    const bool read_ok=size_read && file_size.QuadPart>0
        && file_size.QuadPart<=static_cast<LONGLONG>(sizeof(wire))
        && ReadFile(file,wire,static_cast<DWORD>(file_size.QuadPart),&bytes_read,nullptr)
        && bytes_read==static_cast<DWORD>(file_size.QuadPart);
    CloseHandle(file);
    if (!read_ok) return;
    const std::uint64_t hash=native_control_country_hash(wire,bytes_read);
    if (hash==native_control_country_last_hash) return;
    native_control_country_last_hash=hash;

    bridge::control_country_policy::Request request{};
    const auto parsed=bridge::control_country_policy::parse_request(wire,bytes_read,request);
    if (!parsed.ok()) {
        char message[256]{};
        const int written=snprintf(message,sizeof(message),
            "{\"event\":\"native_controlled_countries_rejected\",\"session_id\":\"%lu-%llx\","
            "\"reason\":\"%s\"}\n",
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long long>(observation_creation),
            bridge::control_country_policy::parse_error_name(parsed.error));
        if (written>0 && static_cast<std::size_t>(written)<sizeof(message)) line(message);
        return;
    }

    char session_id[bridge::control_country_policy::kMaxSessionIdLength+1]{};
    snprintf(session_id,sizeof(session_id),"%lu-%llx",
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long long>(observation_creation));
    const auto reject=[&](const char* reason) noexcept {
        native_control_country_emit_ack(session_id,request.revision,
            request.countries,false,reason);
    };
    if (std::strcmp(request.session_id,session_id)!=0) {
        reject("session_mismatch"); return;
    }
    for (std::size_t index=0;index<request.countries.count;++index) {
        std::uint64_t handle=0;
        if (!alliance_query_country(request.countries.at(index),handle)
            || !observation_country_handle(handle)
            || !bridge::control_country_policy::tag_matches_handle(
                request.countries.at(index),handle)) {
            reject("country_unavailable"); return;
        }
    }
    bridge::control_country_policy::CountrySet accepted_countries{};
    AcquireSRWLockExclusive(&native_control_country_lock);
    const auto applied=native_control_country_policy.apply(request,session_id);
    if (applied==bridge::control_country_policy::ApplyError::ok)
        accepted_countries=native_control_country_policy.countries;
    ReleaseSRWLockExclusive(&native_control_country_lock);
    if (applied!=bridge::control_country_policy::ApplyError::ok) {
        reject(applied==bridge::control_country_policy::ApplyError::invalid_session
            ?"session_mismatch":"stale_revision"); return;
    }
    bridge_alliance_inbound_detail::inbound_saved_queue_reset();
    native_control_country_emit_ack(session_id,request.revision,
        accepted_countries,true,"ok");
}

static void native_information_country_tick() noexcept {
    if (!native_information_country_request_path[0] || !control_ready()) return;
    const ULONGLONG now=GetTickCount64();
    if (now<native_information_country_next_poll) return;
    native_information_country_next_poll=now+500;
    HANDLE file=CreateFileW(native_information_country_request_path,GENERIC_READ,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,nullptr);
    if (file==INVALID_HANDLE_VALUE) return;
    char wire[bridge::control_country_policy::kMaxWireBytes+1]{};
    DWORD bytes=0;
    const bool readable=ReadFile(file,wire,sizeof(wire),&bytes,nullptr)!=FALSE;
    CloseHandle(file);
    if (!readable || !bytes) return;
    const auto hash=native_control_country_hash(wire,bytes);
    if (hash==native_information_country_last_hash) return;
    native_information_country_last_hash=hash;

    namespace policy=bridge::control_country_policy;
    policy::Request request{};
    if (!policy::parse_request(wire,bytes,request,"EU4INFO1").ok()) return;
    char session_id[policy::kMaxSessionIdLength+1]{};
    snprintf(session_id,sizeof(session_id),"%lu-%llx",
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long long>(observation_creation));
    const char* reason=std::strcmp(session_id,request.session_id)==0 ? nullptr : "session_mismatch";
    for (std::size_t index=0;!reason && index<request.countries.count;++index) {
        uint64_t handle=0;
        const char* tag=request.countries.at(index);
        if (!alliance_query_country(tag,handle) || !observation_country_handle(handle)
            || !policy::tag_matches_handle(tag,handle)) reason="country_unavailable";
    }
    if (!reason) {
        AcquireSRWLockExclusive(&native_information_country_lock);
        const auto applied=native_information_country_policy.apply(request,session_id);
        ReleaseSRWLockExclusive(&native_information_country_lock);
        if (applied!=policy::ApplyError::ok) reason="stale_revision";
    }
    char countries[200]{};
    std::size_t used=0;
    for (std::size_t index=0;index<request.countries.count;++index) {
        const int count=snprintf(countries+used,sizeof(countries)-used,"%s\"%.3s\"",
            index?",":"",request.countries.at(index));
        if (count<0 || static_cast<std::size_t>(count)>=sizeof(countries)-used) return;
        used+=static_cast<std::size_t>(count);
    }
    char message[512]{};
    snprintf(message,sizeof(message),
        "{\"event\":\"native_information_observers_set\",\"session_id\":\"%s\","
        "\"revision\":%llu,\"countries\":[%s],\"accepted\":%s,\"reason\":\"%s\"}\n",
        session_id,static_cast<unsigned long long>(request.revision),countries,
        reason?"false":"true",reason?reason:"ok");
    line(message);
}
#endif

#ifdef BRIDGE_NATIVE_COUNTRY_CONTROL
#include "diplomat-recall-mcp.inc"
#endif

static bool observation_rollback_family() {
    struct Slot { uintptr_t address; void* original; void* replacement; } slots[]={
        {base+0x1c80720,reinterpret_cast<void*>(base+0x129450),reinterpret_cast<void*>(&lifecycle_destructor_observe)},
        {base+0x1c80720+0x40,reinterpret_cast<void*>(base+0x4e9960),reinterpret_cast<void*>(&lifecycle_wrapper_observe)},
        {base+0x1c80720+0xb0,reinterpret_cast<void*>(base+0x513090),reinterpret_cast<void*>(&lifecycle_clone_observe)},
        {base+0x1c80720+0x80,reinterpret_cast<void*>(base+0x511d90),reinterpret_cast<void*>(&observation_alliance_validity)},
        {base+0x1c80720+0x20,reinterpret_cast<void*>(base+0x4e8b70),reinterpret_cast<void*>(&bridge_field_reader_stub)},
        {base+0x1c80ab0,reinterpret_cast<void*>(base+0x4ed5e0),reinterpret_cast<void*>(&lifecycle_destructor_observe)},
        {base+0x1c80ab0+0x20,reinterpret_cast<void*>(base+0x4f0900),reinterpret_cast<void*>(&bridge_royal_field_reader_stub)},
        {base+0x1c80ab0+0x40,reinterpret_cast<void*>(base+0x4e9960),reinterpret_cast<void*>(&lifecycle_wrapper_observe)},
        {base+0x1c80ab0+0xb0,reinterpret_cast<void*>(base+0x4f0800),reinterpret_cast<void*>(&lifecycle_clone_observe)},
        {base+0x1c7dd68,reinterpret_cast<void*>(base+0x129450),reinterpret_cast<void*>(&lifecycle_destructor_observe)},
        {base+0x1c7dd68+0x40,reinterpret_cast<void*>(base+0x4e9960),reinterpret_cast<void*>(&lifecycle_wrapper_observe)},
        {base+0x1c7dd68+0xb0,reinterpret_cast<void*>(base+0x574b50),reinterpret_cast<void*>(&lifecycle_clone_observe)},
        {base+0x1c7cc48+0x00,reinterpret_cast<void*>(base+0x129450),reinterpret_cast<void*>(&lifecycle_destructor_observe)},
        {base+0x1c7cc48+0x40,reinterpret_cast<void*>(base+0x4e9960),reinterpret_cast<void*>(&lifecycle_wrapper_observe)},
        {base+0x1c7cc48+0xb0,reinterpret_cast<void*>(base+0x586230),reinterpret_cast<void*>(&lifecycle_clone_observe)},
        {base+0x1c7fe50+0x00,reinterpret_cast<void*>(base+0x129450),reinterpret_cast<void*>(&lifecycle_destructor_observe)},
        {base+0x1c7fe50+0x40,reinterpret_cast<void*>(base+0x4e9960),reinterpret_cast<void*>(&lifecycle_wrapper_observe)},
        {base+0x1c7fe50+0xb0,reinterpret_cast<void*>(base+0x5224f0),reinterpret_cast<void*>(&lifecycle_clone_observe)},
        {base+0x1c805f0+0x00,reinterpret_cast<void*>(base+0x129450),reinterpret_cast<void*>(&lifecycle_destructor_observe)},
        {base+0x1c805f0+0x40,reinterpret_cast<void*>(base+0x4e9960),reinterpret_cast<void*>(&lifecycle_wrapper_observe)},
        {base+0x1c805f0+0xb0,reinterpret_cast<void*>(base+0x50f0c0),reinterpret_cast<void*>(&lifecycle_clone_observe)},
        {base+0x1c7fb70+0x00,reinterpret_cast<void*>(base+0x129450),reinterpret_cast<void*>(&lifecycle_destructor_observe)},
        {base+0x1c7fb70+0x40,reinterpret_cast<void*>(base+0x4e9960),reinterpret_cast<void*>(&lifecycle_wrapper_observe)},
        {base+0x1c7fb70+0xb0,reinterpret_cast<void*>(base+0x525da0),reinterpret_cast<void*>(&lifecycle_clone_observe)},
        {base+0x1c7fd20+0x00,reinterpret_cast<void*>(base+0x129450),reinterpret_cast<void*>(&lifecycle_destructor_observe)},
        {base+0x1c7fd20+0x20,reinterpret_cast<void*>(base+0x4e8b70),reinterpret_cast<void*>(&bridge_field_reader_stub)},
        {base+0x1c7fd20+0x40,reinterpret_cast<void*>(base+0x4e9960),reinterpret_cast<void*>(&lifecycle_wrapper_observe)},
        {base+0x1c7fd20+0xb0,reinterpret_cast<void*>(base+0x51fa30),reinterpret_cast<void*>(&lifecycle_clone_observe)},
        // Favor-for-gold uses the common lifecycle hooks at +0x00/+0x40 and
        // its confirmed clone at +0xb0.  Its response-choice gate is a
        // separate inbound hook at +0xd0; rollback for that hook is handled
        // by inbound_rollback(), never by the lifecycle slots below.
        {base+0x1c80980+0x00,reinterpret_cast<void*>(base+0x129450),reinterpret_cast<void*>(&lifecycle_destructor_observe)},
        {base+0x1c80980+0x40,reinterpret_cast<void*>(base+0x4e9960),reinterpret_cast<void*>(&lifecycle_wrapper_observe)},
        {base+0x1c80980+0xb0,reinterpret_cast<void*>(base+0x4f5c00),reinterpret_cast<void*>(&lifecycle_clone_observe)},
        {base+0x1c80c60+0x00,reinterpret_cast<void*>(base+0x129500),reinterpret_cast<void*>(&lifecycle_destructor_observe)},
        {base+0x1c80c60+0x40,reinterpret_cast<void*>(base+0x4e9960),reinterpret_cast<void*>(&lifecycle_wrapper_observe)},
        {base+0x1c80c60+0xb0,reinterpret_cast<void*>(base+0x4fe770),reinterpret_cast<void*>(&lifecycle_clone_observe)},
        {base+0x1c80ff0+0x00,reinterpret_cast<void*>(base+0x129450),reinterpret_cast<void*>(&lifecycle_destructor_observe)},
        {base+0x1c80ff0+0x40,reinterpret_cast<void*>(base+0x4e9960),reinterpret_cast<void*>(&lifecycle_wrapper_observe)},
        {base+0x1c80ff0+0xb0,reinterpret_cast<void*>(base+0x4f8420),reinterpret_cast<void*>(&lifecycle_clone_observe)},
        {base+0x1c7aef8+0x00,reinterpret_cast<void*>(base+0x129450),reinterpret_cast<void*>(&lifecycle_destructor_observe)},
        {base+0x1c7aef8+0x40,reinterpret_cast<void*>(base+0x4e9960),reinterpret_cast<void*>(&lifecycle_wrapper_observe)},
        {base+0x1c7aef8+0xb0,reinterpret_cast<void*>(base+0x5ae2e0),reinterpret_cast<void*>(&lifecycle_clone_observe)},
        {base+0x1c7f6b0+0x00,reinterpret_cast<void*>(base+0x129500),reinterpret_cast<void*>(&lifecycle_destructor_observe)},
        {base+0x1c7f6b0+0x40,reinterpret_cast<void*>(base+0x4e9960),reinterpret_cast<void*>(&lifecycle_wrapper_observe)},
        {base+0x1c7f6b0+0xb0,reinterpret_cast<void*>(base+0x538e50),reinterpret_cast<void*>(&lifecycle_clone_observe)},
        {base+0x1c7b840+0x00,reinterpret_cast<void*>(base+0x598b90),reinterpret_cast<void*>(&lifecycle_destructor_observe)},
        {base+0x1c7b840+0x40,reinterpret_cast<void*>(base+0x4e9960),reinterpret_cast<void*>(&lifecycle_wrapper_observe)},
        {base+0x1c7b840+0xb0,reinterpret_cast<void*>(base+0x59ba70),reinterpret_cast<void*>(&lifecycle_clone_observe)},
        {base+0x1c814b0+0x10,reinterpret_cast<void*>(base+0x4e8470),reinterpret_cast<void*>(&bridge_serializer_stub)},
        {base+0x1c814b0+0x20,reinterpret_cast<void*>(base+0x4e84c0),reinterpret_cast<void*>(&bridge_wrapper_reader_stub)},
        {base+0x1c814b0+0x60,reinterpret_cast<void*>(base+0x4e8550),reinterpret_cast<void*>(&bridge_wrapper_clone_stub)}
    };
    bool complete=true;
    complete=lifecycle_rollback_declarewar_field_reader() && complete;
    complete=lifecycle_rollback_declarewar() && complete;
    complete=lifecycle_rollback_peace_field_reader() && complete;
#if defined(BRIDGE_ALLIANCE_REASON_METADATA)
    complete=bridge_alliance_reason_metadata_rollback() && complete;
#endif
    for (const auto& slot:slots) {
        void* current=nullptr;
        if (!read(slot.address,current)) { complete=false; continue; }
        if (current==slot.original) continue;
        if (current!=slot.replacement) { complete=false; continue; }
        DWORD protection=0,ignored=0;
        if (!VirtualProtect(reinterpret_cast<void*>(slot.address),8,PAGE_READWRITE,&protection)) { complete=false; continue; }
        void* previous=InterlockedCompareExchangePointer(reinterpret_cast<void* volatile*>(slot.address),slot.original,slot.replacement);
        complete=(previous==slot.replacement || previous==slot.original) && complete;
        complete=VirtualProtect(reinterpret_cast<void*>(slot.address),8,protection,&ignored)!=FALSE && complete;
    }
#ifdef BRIDGE_COUNTRY_MODIFIER_OBSERVATION
    complete=country_modifier_observer::rollback() && complete;
#endif
#ifdef BRIDGE_SUBSIDY_EXPIRY_OBSERVATION
    complete=subsidy_expiry_observer::rollback() && complete;
#endif
#ifdef BRIDGE_TRUCE_EXPIRY_OBSERVATION
    complete=truce_expiry_observer::rollback() && complete;
#endif
#ifdef BRIDGE_CLAIM_EXPIRY_OBSERVATION
    complete=claim_expiry_observer::rollback() && complete;
#endif
#ifdef BRIDGE_LAND_PROMISE_OBSERVATION
    complete=land_promise_observer::rollback() && complete;
#endif
#ifdef BRIDGE_MISSION_COMPLETION_OBSERVATION
    complete=mission_completion_observer::rollback() && complete;
#endif
#ifdef BRIDGE_MISSION_AVAILABILITY_OBSERVATION
    complete=mission_availability_observer::rollback() && complete;
#endif
#ifdef BRIDGE_SUPPORT_SUBJECT_RECORD_OBSERVATION
    complete=support_subject_record_observer::rollback() && complete;
#endif
#ifdef BRIDGE_RIVAL_RECORD_OBSERVATION
    complete=rival_record_observer::rollback() && complete;
#endif
#ifdef BRIDGE_DIRECTED_RECORD_OBSERVATION
    complete=directed_record_observer::rollback() && complete;
#endif
#ifdef BRIDGE_ROYAL_RECORD_OBSERVATION
    complete=royal_record_observer::rollback() && complete;
#endif
#ifdef BRIDGE_MISSION_CONDITION_OBSERVATION
    complete=mission_condition_observer::rollback() && complete;
#endif
#ifdef BRIDGE_ALLIANCE_RECORD_OBSERVATION
    complete=alliance_record_observer::rollback() && complete;
#endif
    complete=direct_break_rollback() && complete;
#ifdef BRIDGE_WAR_DECLARATION_OBSERVATION
    complete=war_declaration_observer::rollback() && complete;
#endif
#ifdef BRIDGE_RELATION_OBSERVATION
    relation_change_observer::installed=false;
#endif
    complete=inbound_rollback() && complete;
#ifdef BRIDGE_RIVAL_OBSERVATION
    rival_change_observer::installed=false;
#endif
    complete=rival_authority_rollback() && complete;
    rival_execution_detail::enabled=false;
    complete=rival_command_observer_rollback() && complete;
    complete=execution_rollback() && complete;
    complete=peace_handler_authority_rollback() && complete;
    complete=peace_receiver_observer_rollback() && complete;
    complete=transport_rollback() && complete;
    complete=control_rollback_hooks() && complete;
    // Original pointers/trampolines remain alive after publication: a native
    // thread may already have fetched a replacement virtual-method pointer.
    return complete;
}

extern "C" int bridge_response_observe(void* value) {
    ObservedCommand event{};
    event.thread=GetCurrentThreadId();
    event.command=reinterpret_cast<uintptr_t>(value);
    event.callback_sequence=static_cast<uint64_t>(InterlockedIncrement64(&observation_callback_sequence));
    uintptr_t vtable=0;
    // This is the verified generic diplomatic command, not an assumed layout
    // for each action. Unknown action payloads are never interpreted here.
    event.readable=read(event.command,vtable) && vtable==base+0x1c814b0
        && read(event.command+0x50,event.action) && read(event.action,event.action_vtable)
        && read(event.command+0x48,event.origin) && read(event.command+0x4a,event.protocol_flags)
        && read(event.command+0x4c,event.sequence);
    event.prefix_readable=event.readable && read(event.command+0x10,event.raw10)
        && read(event.command+0x38,event.raw38) && read(event.command+0x3c,event.raw3c)
        && read(event.command+0x40,event.raw40) && read(event.command+0x44,event.raw44);
    if (event.readable && (event.action_vtable==base+0x1c80720
        || event.action_vtable==base+0x1c80ab0 || event.action_vtable==base+0x1c7dd68
        || event.action_vtable==base+0x1c7cc48 || event.action_vtable==base+0x1c7fe50 || event.action_vtable==base+0x1c805f0
        || event.action_vtable==base+0x1c7fb70 || event.action_vtable==base+0x1c7fd20
        || event.action_vtable==base+0x1c80980 || event.action_vtable==base+0x1c80c60
        || event.action_vtable==base+0x1c80ff0 || event.action_vtable==base+0x1c7aef8)) {
        LifecycleActionShape shape=lifecycle_capture_shape(reinterpret_cast<void*>(event.action));
        event.alliance_identified=shape.matched && shape.tracked;
        if (event.alliance_identified) {
            event.alliance_actor=shape.actor10;
            event.alliance_recipient=shape.recipient20;
            event.alliance_state=shape.state34;
            event.alliance_variant=shape.variant38;
            event.royal_marriage=shape.royal_marriage;
            event.improve_relations=shape.improve_relations;
            event.spy_network=shape.spy_network;
            event.guarantee=shape.guarantee;
            event.support_independence=shape.support_independence;
            event.military_access=shape.military_access;
            event.vassalization=shape.vassalization;
            event.favor_gold=shape.favor_gold;
            event.favor_trust=shape.favor_trust;
            event.favor_men=shape.favor_men;
            event.curry_favors=shape.curry_favors;
            lifecycle_shape_json(event.alliance_shape_json,sizeof(event.alliance_shape_json),shape);
        }
    }
    if (!TryAcquireSRWLockExclusive(&observation_lock)) {
        InterlockedIncrement(&observation_dropped); return 1;
    }
    if (observation_size<128) {
        observation_events[(observation_head+observation_size)%128]=event;
        ++observation_size;
    } else InterlockedIncrement(&observation_dropped);
    ReleaseSRWLockExclusive(&observation_lock);
    // The assembly stub restores every register and calls the original exactly
    // once. Observation cannot turn an AI decision into an authorized choice.
    return 1;
}

static void observation_flush() {
    // Bounded and reusable rather than a lifetime-only 64-event array.
    for (unsigned i=0;i<32;++i) {
        ObservedCommand event{};
        AcquireSRWLockExclusive(&observation_lock);
        if (!observation_size) { ReleaseSRWLockExclusive(&observation_lock); break; }
        event=observation_events[observation_head];
        observation_head=(observation_head+1)%128; --observation_size;
        ReleaseSRWLockExclusive(&observation_lock);
        char message[600];
        snprintf(message,sizeof(message),
            "{\"event\":\"diplomatic_command_observed\",\"version\":10,\"pid\":%lu,\"session_id\":\"%lu-%llx\",\"event_sequence\":%llu,\"thread\":%lu,\"readable\":%s,\"command\":\"0x%llx\",\"action\":\"0x%llx\",\"action_vtable_rva\":\"0x%llx\",\"origin\":%u,\"protocol_sequence\":%u,\"protocol_flags\":%u,\"forward_to_original\":true,\"business_result\":\"unknown\"}\n",
            static_cast<unsigned long>(GetCurrentProcessId()),static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long long>(observation_creation),static_cast<unsigned long long>(++observation_sequence),
            static_cast<unsigned long>(event.thread),event.readable?"true":"false",
            static_cast<unsigned long long>(event.command),static_cast<unsigned long long>(event.action),
            static_cast<unsigned long long>(event.action_vtable>=base?event.action_vtable-base:0),
            event.origin,event.sequence,event.protocol_flags);
        line(message);
        if (event.alliance_identified) {
            char alliance[2400];
            snprintf(alliance,sizeof(alliance),"{\"event\":\"native_alliance_command_entry_observed\",\"session_id\":\"%lu-%llx\",\"event_sequence\":%llu,\"callback_sequence\":%llu,\"protocol_sequence\":%u,\"origin\":%u,\"protocol_flags\":%u,\"command\":\"0x%llx\",\"action\":\"0x%llx\",\"readable\":true,\"prefix_readable\":%s,\"raw10\":%u,\"raw38\":%d,\"raw3c\":%d,\"raw40\":%u,\"raw44\":%d,\"source\":%s,\"actor_field\":\"%c%c%c\",\"recipient_field\":\"%c%c%c\",\"action_id\":\"%s\",\"state_raw\":%d,\"decision_country\":null,\"business_result\":\"unknown\",\"rule_result\":\"unknown\",\"complete\":false}\n",
                static_cast<unsigned long>(GetCurrentProcessId()),static_cast<unsigned long long>(observation_creation),
                static_cast<unsigned long long>(observation_sequence),static_cast<unsigned long long>(event.callback_sequence),
                event.sequence,event.origin,event.protocol_flags,static_cast<unsigned long long>(event.command),
                static_cast<unsigned long long>(event.action),event.prefix_readable?"true":"false",
                static_cast<unsigned>(event.raw10),event.raw38,event.raw3c,static_cast<unsigned>(event.raw40),event.raw44,event.alliance_shape_json,
                static_cast<char>(event.alliance_actor),static_cast<char>(event.alliance_actor>>8),static_cast<char>(event.alliance_actor>>16),
                static_cast<char>(event.alliance_recipient),static_cast<char>(event.alliance_recipient>>8),static_cast<char>(event.alliance_recipient>>16),
                event.spy_network?(event.alliance_variant?"build_spy_network":"stop_building_spy_network"):
                event.improve_relations?(event.alliance_variant?"improve_relations":"stop_improving_relations"):
                event.guarantee?(event.alliance_variant?"proclaim_guarantee":"revoke_guarantee"):
                event.support_independence?(event.alliance_variant?"support_independence":"revoke_support_independence"):
                event.military_access?(event.alliance_variant?"ask_military_access":"cancel_military_access"):
                event.vassalization?(event.alliance_variant?"offer_vassalization":"cancel_vassalization"):
                event.favor_gold?"trade_favors_for_gold":event.favor_trust?"trade_favors_for_trust":event.favor_men?"trade_favors_for_men":
                event.curry_favors?(event.alliance_variant?"curry_favors":"stop_curry_favors"):
                event.royal_marriage?(event.alliance_variant?"offer_royal_marriage":"break_royal_ties"):
                    (event.alliance_variant?"offer_alliance":"dissolve_alliance"),event.alliance_state);
            line(alliance);
        }
    }
    LONG dropped=InterlockedExchange(&observation_dropped,0);
    if (dropped) {
        char message[180];
        snprintf(message,sizeof(message),"{\"event\":\"observation_incomplete\",\"dropped\":%ld,\"business_result\":\"unknown\"}\n",static_cast<long>(dropped));
        line(message);
    }
    for (unsigned i=0;i<32;++i) {
        ObservedAllianceRule event{};
        AcquireSRWLockExclusive(&alliance_rule_lock);
        if (!alliance_rule_size) { ReleaseSRWLockExclusive(&alliance_rule_lock); break; }
        event=alliance_rule_events[alliance_rule_head];
        alliance_rule_head=(alliance_rule_head+1)%128; --alliance_rule_size;
        ReleaseSRWLockExclusive(&alliance_rule_lock);
        char message[640];
        snprintf(message,sizeof(message),"{\"event\":\"native_alliance_validity_observed\",\"session_id\":\"%lu-%llx\",\"query_id\":\"%s\",\"actor_field\":\"%c%c%c\",\"recipient_field\":\"%c%c%c\",\"action_id\":\"%s\",\"thread\":%lu,\"native_result\":%s,\"state_before\":%d,\"state_after\":%d,\"state_read\":%s,\"extra_engine_calls\":false,\"full_rules_complete\":false,\"reasons_complete\":false}\n",
            static_cast<unsigned long>(GetCurrentProcessId()),static_cast<unsigned long long>(observation_creation),
            event.query_id,
            static_cast<char>(event.actor),static_cast<char>(event.actor>>8),static_cast<char>(event.actor>>16),
            static_cast<char>(event.recipient),static_cast<char>(event.recipient>>8),static_cast<char>(event.recipient>>16),
            event.variant?"offer_alliance":"dissolve_alliance",static_cast<unsigned long>(event.thread),
            event.result?"true":"false",event.state_before,event.state_after,event.state_read?"true":"false");
        line(message);
    }
    dropped=InterlockedExchange(&alliance_rule_dropped,0);
    if (dropped) {
        char message[180];
        snprintf(message,sizeof(message),"{\"event\":\"alliance_rules_observation_incomplete\",\"dropped\":%ld}\n",static_cast<long>(dropped));
        line(message);
    }
}

extern "C" void bridge_frame_tick(void* context) {
    // Use the same reentrancy/thread policy as the control build.
    if (InterlockedCompareExchange(&observation_frame_inside,1,0)) return;
    observer_legacy_frame(context);
    if (!thread_changed && frame_thread==GetCurrentThreadId()) {
#ifdef BRIDGE_NATIVE_COUNTRY_CONTROL
        if (frame_count>=100) native_control_country_tick();
#endif
#ifdef BRIDGE_NATIVE_COUNTRY_CONTROL
        if (frame_count>=100) native_information_country_tick();
#endif
#ifdef BRIDGE_NATIVE_COUNTRY_CONTROL
        if (frame_count>=100) native_game_speed_tick();
#endif
#ifdef BRIDGE_NATIVE_COUNTRY_CONTROL
        if (frame_count>=100) native_diplomat_recall_mcp_tick();
#endif
        uintptr_t vassal_context_game=0;
        if (read(base+0x233fe58,vassal_context_game)) {
            vassal_test_context_tick(vassal_context_game);
            religion_war_context_tick(vassal_context_game);
            vassal_inbound_test_context_tick(vassal_context_game);
        }
        inbound_saved_queue_tick();
        inbound_test_tick();
        execution_inbound_tick();
        observation_flush();
        lifecycle_flush();
        field_read_flush();
        direct_break_flush();
        protocol_flush();
        transport_flush();
        inbound_flush();
#ifdef BRIDGE_CALL_TO_ARMS_OBSERVATION
        bridge_call_to_arms::flush();
#endif
        execution_flush();
#ifdef BRIDGE_WAR_DECLARATION_OBSERVATION
        war_declaration_observer::flush();
#endif
#ifdef BRIDGE_RELATION_OBSERVATION
        relation_change_observer::flush();
#endif
#ifdef BRIDGE_MISSION_COMPLETION_OBSERVATION
        mission_completion_observer::flush();
#endif
#ifdef BRIDGE_MISSION_AVAILABILITY_OBSERVATION
        mission_availability_observer::flush();
#endif
#ifdef BRIDGE_MISSION_CONDITION_OBSERVATION
        mission_condition_observer::flush();
#endif
        rival_authority_flush();
#ifdef BRIDGE_RIVAL_OBSERVATION
#ifdef BRIDGE_RIVAL_RECORD_OBSERVATION
        rival_change_observer::flush(&rival_record_observer::format_event);
#else
        rival_change_observer::flush();
#endif
#endif
        rival_command_observer_flush();
#ifdef BRIDGE_COUNTRY_MODIFIER_OBSERVATION
        country_modifier_observer::flush();
#endif
#ifdef BRIDGE_SUBSIDY_EXPIRY_OBSERVATION
        subsidy_expiry_observer::flush();
#endif
#ifdef BRIDGE_TRUCE_EXPIRY_OBSERVATION
        truce_expiry_observer::flush();
#endif
#ifdef BRIDGE_CLAIM_EXPIRY_OBSERVATION
        claim_expiry_observer::flush();
#endif
#ifdef BRIDGE_LAND_PROMISE_OBSERVATION
        land_promise_observer::flush();
#endif
        rival_execution_flush();
        if (frame_count>=100) alliance_query_tick();
        if (frame_count>=100) rival_authority_tick();
        execution_tick();
        rival_execution_tick();
    }
#ifdef BRIDGE_INFORMATION_BATTLE
    information_battle_tick();
#endif
#ifdef BRIDGE_CURRENT_COUNTRY_CONTROL
    current_country_host::tick();
#endif
    if (GetTickCount64()-observation_last_health>=1000) {
        observation_last_health=GetTickCount64();
        uintptr_t game=0; uint64_t player=0; int32_t date=0;
        bool readable=read(base+0x233fe58,game) && read(game+0x1e60,player) && read(game+0x1dd0,date);
#if defined(BRIDGE_COUNTRY_MODIFIER_OBSERVATION) || defined(BRIDGE_RIVAL_OBSERVATION)
        char message[4096];
#else
        char message[360];
#endif
        snprintf(message,sizeof(message),"{\"event\":\"diplomacy_observer_health\",\"session_id\":\"%lu-%llx\",\"thread_changed\":%s,\"frames\":%ld,\"state_readable\":%s,\"player\":\"%c%c%c\",\"date_raw\":%d}\n",
            static_cast<unsigned long>(GetCurrentProcessId()),static_cast<unsigned long long>(observation_creation),
            thread_changed?"true":"false",static_cast<long>(frame_count),readable?"true":"false",
            readable?static_cast<char>(player):'-',readable?static_cast<char>(player>>8):'-',
            readable?static_cast<char>(player>>16):'-',date);
#ifdef BRIDGE_COUNTRY_MODIFIER_OBSERVATION
        country_modifier_observer::append_health(message,sizeof(message));
#endif
#ifdef BRIDGE_SUBSIDY_EXPIRY_OBSERVATION
        subsidy_expiry_observer::append_health(message,sizeof(message));
#endif
#ifdef BRIDGE_TRUCE_EXPIRY_OBSERVATION
        truce_expiry_observer::append_health(message,sizeof(message));
#endif
#ifdef BRIDGE_CLAIM_EXPIRY_OBSERVATION
        claim_expiry_observer::append_health(message,sizeof(message));
#endif
#ifdef BRIDGE_LAND_PROMISE_OBSERVATION
        land_promise_observer::append_health(message,sizeof(message));
#endif
#ifdef BRIDGE_RIVAL_OBSERVATION
        rival_change_observer::append_health(message,sizeof(message));
#endif
#ifdef BRIDGE_WAR_DECLARATION_OBSERVATION
        war_declaration_observer::append_health(message,sizeof(message));
#endif
#ifdef BRIDGE_RELATION_OBSERVATION
        relation_change_observer::append_health(message,sizeof(message));
#endif
#ifdef BRIDGE_MISSION_COMPLETION_OBSERVATION
        mission_completion_observer::append_health(message,sizeof(message));
#endif
#ifdef BRIDGE_MISSION_AVAILABILITY_OBSERVATION
        mission_availability_observer::append_health(message,sizeof(message));
#endif
#ifdef BRIDGE_MISSION_CONDITION_OBSERVATION
        mission_condition_observer::append_health(message,sizeof(message));
#endif
        line(message);
    }
    InterlockedExchange(&observation_frame_inside,0);
}

extern "C" __declspec(dllexport) DWORD WINAPI BridgeStart(void* argument) {
    FILETIME created{},exited{},kernel{},user{};
    if (!GetProcessTimes(GetCurrentProcess(),&created,&exited,&kernel,&user)) return 26;
    observation_creation=(static_cast<uint64_t>(created.dwHighDateTime)<<32)|created.dwLowDateTime;
    wchar_t module_path[MAX_PATH]{};
    DWORD length=GetModuleFileNameW(self_module,module_path,MAX_PATH);
    wchar_t* slash=length && length<MAX_PATH?wcsrchr(module_path,L'\\'):nullptr;
    if (!slash) return 27;
    *slash=0;
    if (swprintf(alliance_query_path,MAX_PATH,L"%ls\\diplomacy-query.request",module_path)<0) return 27;
    if (swprintf(execution_request_path,MAX_PATH,L"%ls\\diplomacy-execute.req",module_path)<0) return 27;
    if (swprintf(execution_authority_test_path,MAX_PATH,L"%ls\\diplomacy-authority-test.req",module_path)<0) return 27;
#ifdef BRIDGE_NATIVE_COUNTRY_CONTROL
    if (!native_control_country_set_paths(module_path)) return 27;
    if (!native_diplomat_recall_set_paths(module_path)) return 27;
#endif
    if (!rival_authority_set_paths(module_path)) return 27;
    if (!rival_execution_set_paths(module_path)) return 27;
    if (!vassal_test_context_start(module_path)) return 27;
    if (!religion_war_context_start(module_path)) return 29;
    if (!vassal_inbound_test_context_start(module_path)) return 27;
    execution_authority_tests_consumed=0;
    if (!inbound_set_test_path(module_path)) return 27;
    if (!execution_set_inbound_response_paths(module_path)) return 27;
    if (!execution_peace_set_paths(module_path)) return 27;
    if (GetFileAttributesW(alliance_query_path)!=INVALID_FILE_ATTRIBUTES && !DeleteFileW(alliance_query_path)) return 27;
    if (GetFileAttributesW(execution_request_path)!=INVALID_FILE_ATTRIBUTES && !DeleteFileW(execution_request_path)) return 27;
    DWORD result=ObserverControlStart(argument);
    if (result) return result;
#ifdef BRIDGE_INFORMATION_BATTLE
    if (!information_battle_start(module_path,observation_creation)) {
        line("{\"event\":\"information_battle_start_failed\",\"restart_required\":true}\n");
        return 30;
    }
#endif
#ifdef BRIDGE_CURRENT_COUNTRY_CONTROL
    if (!current_country_host::start(module_path)) {
        line("{\"event\":\"current_country_control_start_failed\",\"restart_required\":true}\n");
        return 31;
    }
#endif
    const bool coalition_capture_installed=coalition_install();
    line(coalition_capture_installed
        ?"{\"event\":\"peace_coalition_capture_installed\",\"all_native_returns_preserved\":true}\n"
        :"{\"event\":\"peace_coalition_capture_unavailable\",\"other_peace_consequences_available\":true}\n");
    bool rule_installed=observation_install_alliance_rule();
    line(rule_installed?"{\"event\":\"alliance_rule_observer_installed\",\"runtime_verified\":false,\"changes_rule_result\":false}\n":
        "{\"event\":\"alliance_rule_observer_unavailable\",\"base_observer_remains_installed\":true}\n");
    bool lifecycle_installed=lifecycle_install();
    line(lifecycle_installed?"{\"event\":\"alliance_lifecycle_observer_installed\",\"all_native_returns_preserved\":true,\"authority_enabled\":false}\n":
        "{\"event\":\"alliance_lifecycle_observer_unavailable\",\"authority_enabled\":false}\n");
    bool royal_lifecycle_installed=lifecycle_installed && !lifecycle_rollback_incomplete && lifecycle_install_royal();
    bool improve_lifecycle_installed=royal_lifecycle_installed && !lifecycle_rollback_incomplete && lifecycle_install_improve();
    bool spy_lifecycle_installed=improve_lifecycle_installed && !lifecycle_rollback_incomplete && lifecycle_install_spy();
    bool guarantee_lifecycle_installed=spy_lifecycle_installed && !lifecycle_rollback_incomplete && lifecycle_install_guarantee();
    line(guarantee_lifecycle_installed?"{\"event\":\"guarantee_lifecycle_observer_installed\",\"native_vtable_rva\":\"0x1c7fe50\",\"native_clone_rva\":\"0x5224f0\",\"slots\":\"0x00,0x40,0xb0\"}\n":
        "{\"event\":\"guarantee_lifecycle_observer_unavailable\"}\n");
    bool support_lifecycle_installed=guarantee_lifecycle_installed && !lifecycle_rollback_incomplete && lifecycle_install_support();
    line(support_lifecycle_installed?"{\"event\":\"support_independence_lifecycle_observer_installed\",\"native_vtable_rva\":\"0x1c805f0\",\"native_clone_rva\":\"0x50f0c0\"}\n":
        "{\"event\":\"support_independence_lifecycle_observer_unavailable\"}\n");
    bool military_lifecycle_installed=support_lifecycle_installed && !lifecycle_rollback_incomplete && lifecycle_install_military_access();
    line(military_lifecycle_installed?"{\"event\":\"military_access_lifecycle_observer_installed\",\"native_vtable_rva\":\"0x1c7fb70\",\"native_clone_rva\":\"0x525da0\"}\n":
        "{\"event\":\"military_access_lifecycle_observer_unavailable\"}\n");
    bool insult_lifecycle_installed=military_lifecycle_installed && !lifecycle_rollback_incomplete && lifecycle_install_insult();
    line(insult_lifecycle_installed?"{\"event\":\"insult_lifecycle_observer_installed\",\"native_vtable_rva\":\"0x1c7f6b0\",\"native_clone_rva\":\"0x538e50\"}\n":
        "{\"event\":\"insult_lifecycle_observer_unavailable\"}\n");
    bool vassal_lifecycle_installed=insult_lifecycle_installed && !lifecycle_rollback_incomplete
        && lifecycle_install_vassalization();
    bool favor_gold_lifecycle_installed=vassal_lifecycle_installed && !lifecycle_rollback_incomplete
        && lifecycle_install_favor_gold();
    line(favor_gold_lifecycle_installed
        ?"{\"event\":\"favor_gold_lifecycle_observer_installed\",\"native_vtable_rva\":\"0x1c80980\",\"native_clone_rva\":\"0x4f5c00\",\"slots\":\"0x00,0x40,0xb0\",\"choice_slot\":\"0xd0\",\"choice_method_rva\":\"0x8f440\"}\n"
        :"{\"event\":\"favor_gold_lifecycle_observer_unavailable\"}\n");
    bool favor_trust_lifecycle_installed=favor_gold_lifecycle_installed && !lifecycle_rollback_incomplete
        && lifecycle_install_favor_trust();
    line(favor_trust_lifecycle_installed
        ?"{\"event\":\"favor_trust_lifecycle_observer_installed\",\"native_selector\":\"0x3bd3\",\"native_vtable_rva\":\"0x1c80c60\",\"native_rule_rva\":\"0x4fdfd0\",\"native_display_rva\":\"0x4fe2d0\",\"native_effect_rva\":\"0x4fd250\",\"native_clone_rva\":\"0x4fe770\",\"destructor_rva\":\"0x129500\",\"slots\":\"0x00,0x40,0xb0\",\"choice_slot\":\"0xd0\",\"choice_method_rva\":\"0x8f440\"}\n"
        :"{\"event\":\"favor_trust_lifecycle_observer_unavailable\"}\n");
    bool favor_men_lifecycle_installed=favor_trust_lifecycle_installed && !lifecycle_rollback_incomplete
        && lifecycle_install_favor_men();
    line(favor_men_lifecycle_installed
        ?"{\"event\":\"favor_men_lifecycle_observer_installed\",\"native_selector\":\"0x3bcf\",\"native_vtable_rva\":\"0x1c80ff0\",\"native_rule_rva\":\"0x4f7600\",\"native_display_rva\":\"0x4f7ca0\",\"native_effect_rva\":\"0x4f67c0\",\"native_clone_rva\":\"0x4f8420\",\"destructor_rva\":\"0x129450\",\"slots\":\"0x00,0x40,0xb0\",\"choice_slot\":\"0xd0\",\"choice_method_rva\":\"0x8f440\"}\n"
        :"{\"event\":\"favor_men_lifecycle_observer_unavailable\"}\n");
    bool curry_favors_lifecycle_installed=favor_men_lifecycle_installed && !lifecycle_rollback_incomplete
        && lifecycle_install_curry_favors();
    line(curry_favors_lifecycle_installed
        ?"{\"event\":\"curry_favors_lifecycle_observer_installed\",\"native_selector\":\"0x3acc\",\"native_vtable_rva\":\"0x1c7aef8\",\"native_rule_rva\":\"0x5ade90\",\"native_display_rva\":\"0x5ae140\",\"native_effect_rva\":\"0x5ace80\",\"native_clone_rva\":\"0x5ae2e0\",\"slots\":\"0x00,0x40,0xb0\",\"diplomat_slot\":\"0xf8\",\"diplomat_rva\":\"0x4e4d80\"}\n"
        :"{\"event\":\"curry_favors_lifecycle_observer_unavailable\"}\n");
    bool gift_lifecycle_installed=curry_favors_lifecycle_installed && !lifecycle_rollback_incomplete
        && lifecycle_install_gift();
    line(gift_lifecycle_installed
        ?"{\"event\":\"gift_lifecycle_observer_installed\",\"native_selector\":\"0x2948\",\"native_vtable_rva\":\"0x1c7f450\",\"native_rule_rva\":\"0x53a630\",\"native_display_rva\":\"0x53a8d0\",\"native_effect_rva\":\"0x539570\",\"native_clone_rva\":\"0x53b0c0\",\"destructor_rva\":\"0x129500\",\"amount_offset\":\"0x40\"}\n"
        :"{\"event\":\"gift_lifecycle_observer_unavailable\"}\n");
    bool influence_lifecycle_installed=gift_lifecycle_installed && !lifecycle_rollback_incomplete
        && lifecycle_install_influence();
    line(influence_lifecycle_installed
        ?"{\"event\":\"influence_lifecycle_observer_installed\",\"native_selector\":\"0x346e\",\"native_vtable_rva\":\"0x1cb3cf8\",\"native_rule_rva\":\"0x7c4430\",\"native_display_rva\":\"0x7c48a0\",\"native_effect_rva\":\"0x7c35b0\",\"native_clone_rva\":\"0x7c4d10\",\"destructor_rva\":\"0x129450\"}\n"
        :"{\"event\":\"influence_lifecycle_observer_unavailable\"}\n");
    bool declarewar_lifecycle_installed=influence_lifecycle_installed && !lifecycle_rollback_incomplete
        && lifecycle_install_declarewar();
    bool peace_lifecycle_installed=declarewar_lifecycle_installed && !lifecycle_rollback_incomplete
        && lifecycle_install_peace();
    line(peace_lifecycle_installed?"{\"event\":\"peace_lifecycle_observer_installed\",\"vtable_rva\":\"0x1c7b840\",\"clone_rva\":\"0x59ba70\",\"complete_offer_snapshot\":true}\n":
        "{\"event\":\"peace_lifecycle_observer_failed\"}\n");
    bool serializer_installed=peace_lifecycle_installed && !lifecycle_rollback_incomplete && lifecycle_install_serializer();
    line(serializer_installed?"{\"event\":\"alliance_serializer_observer_installed\",\"authority_enabled\":false,\"submit_receipt\":false}\n":
        "{\"event\":\"alliance_serializer_observer_unavailable\",\"authority_enabled\":false}\n");
    bool field_reader_installed=serializer_installed && !lifecycle_rollback_incomplete && lifecycle_install_field_reader();
    line(field_reader_installed?"{\"event\":\"alliance_field_reader_observer_installed\",\"authority_enabled\":false,\"native_arguments_preserved\":true}\n":
        "{\"event\":\"alliance_field_reader_observer_unavailable\",\"authority_enabled\":false}\n");
    bool royal_field_reader_installed=field_reader_installed && !lifecycle_rollback_incomplete && lifecycle_install_royal_field_reader();
    line(royal_field_reader_installed?"{\"event\":\"royal_lifecycle_observer_installed\",\"native_arguments_preserved\":true}\n":
        "{\"event\":\"royal_lifecycle_observer_unavailable\"}\n");
    bool vassal_field_reader_installed=royal_field_reader_installed && !lifecycle_rollback_incomplete
        && lifecycle_install_vassalization_field_reader();
    bool declarewar_field_reader_installed=vassal_field_reader_installed && !lifecycle_rollback_incomplete
        && lifecycle_install_declarewar_field_reader();
    bool peace_field_reader_installed=declarewar_field_reader_installed && !lifecycle_rollback_incomplete
        && lifecycle_install_peace_field_reader();
    bool direct_break_installed=peace_field_reader_installed && !lifecycle_rollback_incomplete && direct_break_install();
    line(direct_break_installed?"{\"event\":\"direct_break_entry_observer_installed\",\"authority_enabled\":false,\"before_relationship_writes\":true}\n":
        "{\"event\":\"direct_break_entry_observer_unavailable\",\"authority_enabled\":false}\n");
    bool protocol_installed=direct_break_installed && !lifecycle_rollback_incomplete && protocol_install();
    line(protocol_installed?"{\"event\":\"alliance_wrapper_protocol_observer_installed\",\"authority_enabled\":false,\"native_arguments_preserved\":true}\n":
        "{\"event\":\"alliance_wrapper_protocol_observer_unavailable\",\"authority_enabled\":false}\n");
    bool transport_installed=protocol_installed && !lifecycle_rollback_incomplete && transport_install();
    line(transport_installed?"{\"event\":\"alliance_transport_observer_installed\",\"authority_enabled\":false,\"native_arguments_preserved\":true}\n":
        "{\"event\":\"alliance_transport_observer_unavailable\",\"authority_enabled\":false}\n");
    bool rival_observer_installed=transport_installed && !lifecycle_rollback_incomplete
        && rival_command_observer_install();
    bool execution_installed=rival_observer_installed && !rival_command_observer_rollback_incomplete
        && !lifecycle_rollback_incomplete && execution_install();
    bool peace_handler_guard_installed=execution_installed && !lifecycle_rollback_incomplete
        && peace_handler_authority_install();
    line(peace_handler_guard_installed?"{\"event\":\"peace_handler_authority_installed\",\"slot\":\"0x48\",\"native_handler_rva\":\"0x598f00\"}\n":
        "{\"event\":\"peace_handler_authority_failed\"}\n");
    bool peace_receiver_observer_installed=peace_handler_guard_installed && !lifecycle_rollback_incomplete
        && peace_receiver_observer_install();
    line(peace_receiver_observer_installed?"{\"event\":\"peace_receiver_head_observer_installed\",\"slot\":\"0x48\",\"native_accessor_rva\":\"0x8b0e0\"}\n":
        "{\"event\":\"peace_receiver_head_observer_failed\"}\n");
    bool rival_authority_installed=peace_receiver_observer_installed && !lifecycle_rollback_incomplete
        && rival_authority_install();
    bool rival_execution_installed=rival_authority_installed && rival_execution_install();
    bool response_installed=rival_execution_installed && !lifecycle_rollback_incomplete
        && execution_inbound_response_install();
    bool inbound_installed=execution_installed && !lifecycle_rollback_incomplete && inbound_install();
#ifdef BRIDGE_WAR_DECLARATION_OBSERVATION
    const bool war_declaration_ready=inbound_installed && response_installed
        && !lifecycle_rollback_incomplete && war_declaration_observer::install();
#endif
#ifdef BRIDGE_COUNTRY_MODIFIER_OBSERVATION
    const bool modifier_ready=inbound_installed && response_installed
        && !lifecycle_rollback_incomplete && country_modifier_observer::install();
#endif
#ifdef BRIDGE_MISSION_COMPLETION_OBSERVATION
    const bool mission_ready=modifier_ready && !lifecycle_rollback_incomplete
        && mission_completion_observer::install();
#endif
#ifdef BRIDGE_MISSION_AVAILABILITY_OBSERVATION
    const bool mission_availability_ready=mission_ready && !lifecycle_rollback_incomplete
        && mission_availability_observer::install();
#endif
#ifdef BRIDGE_ALLIANCE_RECORD_OBSERVATION
    const bool alliance_record_ready=mission_availability_ready && !lifecycle_rollback_incomplete
        && alliance_record_observer::install();
#endif
#ifdef BRIDGE_MISSION_CONDITION_OBSERVATION
    const bool mission_condition_ready=alliance_record_ready && !lifecycle_rollback_incomplete
        && mission_condition_observer::install()
#ifdef BRIDGE_MISSION_PROVINCE_CONDITION_OBSERVATION
        && mission_condition_observer::province::install()
#endif
        ;
#endif
#ifdef BRIDGE_ROYAL_RECORD_OBSERVATION
    const bool royal_record_ready=mission_condition_ready && !lifecycle_rollback_incomplete
        && royal_record_observer::install();
#endif
#ifdef BRIDGE_DIRECTED_RECORD_OBSERVATION
    const bool directed_record_ready=royal_record_ready && !lifecycle_rollback_incomplete
        && directed_record_observer::install();
#endif
#ifdef BRIDGE_SUPPORT_SUBJECT_RECORD_OBSERVATION
    const bool support_subject_record_ready=directed_record_ready && !lifecycle_rollback_incomplete
        && support_subject_record_observer::install();
#endif
#ifdef BRIDGE_RIVAL_RECORD_OBSERVATION
    const bool rival_record_ready=support_subject_record_ready && !lifecycle_rollback_incomplete
        && rival_record_observer::install();
#endif
#ifdef BRIDGE_SUBSIDY_EXPIRY_OBSERVATION
    const bool subsidy_expiry_ready=rival_record_ready && !lifecycle_rollback_incomplete
        && subsidy_expiry_observer::install();
#endif
#ifdef BRIDGE_TRUCE_EXPIRY_OBSERVATION
    const bool truce_expiry_ready=rival_record_ready && !lifecycle_rollback_incomplete
        && truce_expiry_observer::install();
#endif
#ifdef BRIDGE_CLAIM_EXPIRY_OBSERVATION
    const bool claim_expiry_ready=subsidy_expiry_ready && truce_expiry_ready && !lifecycle_rollback_incomplete
        && claim_expiry_observer::install();
#endif
#ifdef BRIDGE_LAND_PROMISE_OBSERVATION
    const bool land_promise_ready=claim_expiry_ready && war_declaration_ready && !lifecycle_rollback_incomplete
        && land_promise_observer::install();
#endif
    bool reason_metadata_required=false,reason_metadata_installed=false;
#if defined(BRIDGE_ALLIANCE_REASON_METADATA)
    reason_metadata_required=true;
    reason_metadata_installed=inbound_installed && response_installed
        && !lifecycle_rollback_incomplete && bridge_alliance_reason_metadata_install();
    line(reason_metadata_installed?"{\"event\":\"alliance_reason_metadata_installed\",\"native_alliance_reason_metadata\":true,\"scope\":\"text_bearing_alliance_query_only\"}\n":
        "{\"event\":\"alliance_reason_metadata_unavailable\",\"native_alliance_reason_metadata\":false}\n");
#endif
    const bool r74_lifecycle_ready=gift_lifecycle_installed
        && influence_lifecycle_installed;
    line(inbound_installed && response_installed && vassal_lifecycle_installed && favor_gold_lifecycle_installed && favor_trust_lifecycle_installed && favor_men_lifecycle_installed && curry_favors_lifecycle_installed && vassal_field_reader_installed?"{\"event\":\"alliance_execution_handler_installed\",\"native_offer_submission\":true,\"native_dissolve_submission\":true,\"native_guarantee_query\":true,\"native_guarantee_submission\":true,\"native_support_independence_query\":true,\"native_support_independence_submission\":true,\"native_inbound_support_independence_response\":true,\"native_military_access_query\":true,\"native_insult_query\":true,\"native_rival_query\":true,\"native_declare_war_query\":true,\"native_peace_context_query\":true,\"native_war_participants_query\":true,\"native_peace_empty_offer_query\":true,\"native_peace_offer_evaluation_query\":true,\"native_peace_money_offer_query\":true,\"native_peace_province_offer_query\":true,\"native_peace_combined_query\":true,\"native_peace_reparations_query\":true,\"native_peace_reparations_execution\":true,\"native_peace_trade_power_query\":true,\"native_peace_trade_power_execution\":true,\"native_peace_trade_power_sources\":true,\"native_peace_concede_defeat_query\":true,\"native_peace_concede_defeat_execution\":true,\"native_peace_annul_treaties_query\":true,\"native_peace_annul_treaties_execution\":true,\"native_peace_special_terms_query\":true,\"native_peace_special_terms_execution\":true,\"native_peace_core_terms_query\":true,\"native_peace_subject_terms_query\":true,\"native_peace_subject_terms_execution\":true,\"native_peace_country_terms_query\":true,\"native_peace_country_money_query\":true,\"native_peace_country_terms_execution\":true,\"native_peace_core_terms_execution\":true,\"native_peace_subject_terms_execution\":true,\"native_peace_country_terms_execution\":true,\"native_peace_core_terms_execution\":true,\"native_peace_war_context_query\":true,\"native_peace_serialized_payload_query\":true,\"native_declare_war_submission\":true,\"native_declare_war_participants\":true,\"native_declare_war_forces\":true,\"native_declare_war_peace_options\":true,\"native_peace_consequences\":true,\"native_peace_submission\":true,\"native_peace_wrapper_rule_query\":true,\"native_peace_inbound_pending\":true,\"native_inbound_peace_response\":true,\"native_vassalization_query\":true,\"native_vassalization_submission\":true,\"native_inbound_vassalization_response\":true,\"native_favor_gold_query\":true,\"native_favor_gold_submission\":true,\"native_inbound_favor_gold_response\":true,\"native_favor_trust_query\":true,\"native_favor_trust_submission\":true,\"native_inbound_favor_trust_response\":true,\"native_favor_men_query\":true,\"native_favor_men_submission\":true,\"native_inbound_favor_men_response\":true,\"native_curry_favors_query\":true,\"native_curry_favors_submission\":true,\"native_rival_submission\":true,\"native_rival_authority\":true,\"native_insult_submission\":true,\"native_military_access_submission\":true,\"native_inbound_military_access_response\":true,\"native_inbound_alliance\":true,\"native_inbound_alliance_response\":true,\"incoming_offer\":true,\"incoming_mode\":\"state0_deferred_pending_observe;state1_2_llm_response\",\"accept\":true,\"reject\":true,\"withdraw\":false,\"dissolve\":true,\"parameters_empty_only\":false,\"authority_lock_enabled\":true,\"authority_scope\":\"outbound FRA Alliance/Royal/Support/MilitaryAccess/Vassalization requests and revocations require generic-entry authority; FRA Improve/Spy/Guarantee/Insult/DeclareWar/CurryFavors unilateral operations require authority; FRA Rival Set/Replace/Remove native handlers deny ungranted choices; Alliance/Royal/Support/MilitaryAccess/Vassalization incoming recipient FRA deferred for LLM accept/reject; Peace incoming recipient FRA retained pending with native AI choice held; Peace incoming responses require a consumed full-payload pending binding; offer_alliance sender SAV|LIT; other implemented senders native-valid canonical recipients; unbound FRA receiver state1/2 blocked\",\"other_actions_forwarded\":true}\n":
        "{\"event\":\"alliance_execution_handler_unavailable\",\"native_offer_submission\":false}\n");
    if (lifecycle_rollback_incomplete || !lifecycle_installed || !royal_lifecycle_installed || !improve_lifecycle_installed || !spy_lifecycle_installed || !guarantee_lifecycle_installed || !support_lifecycle_installed || !military_lifecycle_installed || !insult_lifecycle_installed || !serializer_installed || !field_reader_installed || !royal_field_reader_installed || !direct_break_installed || !protocol_installed || !transport_installed || !execution_installed || !response_installed || !inbound_installed
        || !rival_authority_installed || !rival_observer_installed || !rival_execution_installed
        || !vassal_lifecycle_installed || !favor_gold_lifecycle_installed
        || !favor_trust_lifecycle_installed || !favor_men_lifecycle_installed
        || !curry_favors_lifecycle_installed || !vassal_field_reader_installed
        || !r74_lifecycle_ready
        || !declarewar_lifecycle_installed || !declarewar_field_reader_installed
        || !peace_lifecycle_installed || !peace_field_reader_installed
        || !peace_handler_guard_installed
        || !peace_receiver_observer_installed
        || (reason_metadata_required && !reason_metadata_installed)
#ifdef BRIDGE_COUNTRY_MODIFIER_OBSERVATION
        || !modifier_ready
#endif
#ifdef BRIDGE_WAR_DECLARATION_OBSERVATION
        || !war_declaration_ready
#endif
#ifdef BRIDGE_MISSION_COMPLETION_OBSERVATION
        || !mission_ready
#endif
#ifdef BRIDGE_MISSION_AVAILABILITY_OBSERVATION
        || !mission_availability_ready
#endif
#ifdef BRIDGE_ALLIANCE_RECORD_OBSERVATION
        || !alliance_record_ready
#endif
#ifdef BRIDGE_MISSION_CONDITION_OBSERVATION
        || !mission_condition_ready
#endif
#ifdef BRIDGE_ROYAL_RECORD_OBSERVATION
        || !royal_record_ready
#endif
#ifdef BRIDGE_DIRECTED_RECORD_OBSERVATION
        || !directed_record_ready
#endif
#ifdef BRIDGE_SUPPORT_SUBJECT_RECORD_OBSERVATION
        || !support_subject_record_ready
#endif
#ifdef BRIDGE_RIVAL_RECORD_OBSERVATION
        || !rival_record_ready
#endif
#ifdef BRIDGE_SUBSIDY_EXPIRY_OBSERVATION
        || !subsidy_expiry_ready
#endif
#ifdef BRIDGE_TRUCE_EXPIRY_OBSERVATION
        || !truce_expiry_ready
#endif
#ifdef BRIDGE_CLAIM_EXPIRY_OBSERVATION
        || !claim_expiry_ready
#endif
#ifdef BRIDGE_LAND_PROMISE_OBSERVATION
        || !land_promise_ready
#endif
        ) {
        bool rolled_back=observation_rollback_family();
        line(rolled_back?"{\"event\":\"observer_family_install_failed\",\"all_hooks_rolled_back\":true,\"restart_required\":true}\n":
            "{\"event\":\"observer_family_rollback_incomplete\",\"restart_required\":true}\n"); return 28;
    }
#ifdef BRIDGE_RIVAL_OBSERVATION
    rival_change_observer::installed=true;
#endif
#ifdef BRIDGE_WAR_DECLARATION_OBSERVATION
    war_declaration_observer::installed=true;
#endif
#ifdef BRIDGE_RELATION_OBSERVATION
    relation_change_observer::installed=true;
#endif
#ifdef BRIDGE_ALLIANCE_RECORD_OBSERVATION
    alliance_record_observer::installed=true;
#endif
#ifdef BRIDGE_ROYAL_RECORD_OBSERVATION
    royal_record_observer::installed=true;
#endif
#ifdef BRIDGE_DIRECTED_RECORD_OBSERVATION
    directed_record_observer::installed=true;
#endif
#ifdef BRIDGE_SUPPORT_SUBJECT_RECORD_OBSERVATION
    support_subject_record_observer::installed=true;
#endif
#ifdef BRIDGE_RIVAL_RECORD_OBSERVATION
    rival_record_observer::installed=true;
#endif
#ifdef BRIDGE_MISSION_COMPLETION_OBSERVATION
    mission_completion_observer::installed=true;
#endif
#ifdef BRIDGE_MISSION_CONDITION_OBSERVATION
    mission_condition_observer::installed=true;
#endif
#ifdef BRIDGE_MISSION_AVAILABILITY_OBSERVATION
    mission_availability_observer::installed=true;
#endif
    // Keep R74 capability literals in the exact installation ACK consumed by
    // the Python adapter.  The long legacy format string remains untouched;
    // bounded insertion avoids duplicating that contract here.
    auto append_r74_capabilities=[](char* text,size_t capacity) {
        if (!text || capacity==0) return;
        constexpr char marker[]="\"native_generic_execution_entry_guard\":true";
        constexpr char fields[]=",\"native_gift_query\":true,\"native_gift_submission\":true,\"native_influence_query\":true,\"native_influence_submission\":true,\"native_live_war_score_query\":true,\"native_proposal_expiry_observation\":true,\"native_result_game_date_observation\":true"
#ifdef BRIDGE_NATIVE_COUNTRY_CONTROL
            ",\"native_country_control_configuration\":true,\"native_country_control_protocol\":\"EU4CONTROL1\",\"native_country_control_ack\":\"native_controlled_countries_set\",\"native_country_control_request\":\"controlled-countries.req\",\"native_game_speed_control\":true,\"native_game_speed_control_protocol\":\"EU4SPEED1\",\"native_diplomat_recall_by_id\":true,\"native_diplomat_recall_protocol\":\"EU4RECALL1\""
#endif
#ifdef BRIDGE_RIVAL_OBSERVATION
#ifdef BRIDGE_RIVAL_RECORD_OBSERVATION
            ",\"native_rival_change_observation\":true,\"native_rival_change_wire\":2,"
            "\"native_rival_change_scope\":\"FRA_actor_target_or_old_rival_at_command_or_country_rival_record_returns\","
            "\"native_rival_record_observation\":true,\"native_rival_record_count_basis\":\"active_nonretired_nodes\""
#else
            ",\"native_rival_change_observation\":true,\"native_rival_change_wire\":1,"
            "\"native_rival_change_scope\":\"FRA_actor_target_or_old_rival_at_three_country_command_entries\""
#endif
#endif
#ifdef BRIDGE_WAR_DECLARATION_OBSERVATION
            ",\"native_war_declaration_observation\":true,\"native_war_declaration_wire\":1,"
            "\"native_war_declaration_scope\":\"FRA_member_in_new_declared_pair_war\""
#endif
#ifdef BRIDGE_RELATION_OBSERVATION
#ifdef BRIDGE_SUPPORT_SUBJECT_RECORD_OBSERVATION
            ",\"native_relation_change_observation\":true,\"native_relation_change_wire\":5,"
            "\"native_relation_change_scope\":\"FRA_pair_at_six_relation_command_or_six_family_record_returns\","
            "\"native_alliance_record_observation\":true,\"native_royal_record_observation\":true,\"native_directed_record_observation\":true,\"native_support_subject_record_observation\":true"
#elif defined(BRIDGE_DIRECTED_RECORD_OBSERVATION)
            ",\"native_relation_change_observation\":true,\"native_relation_change_wire\":4,"
            "\"native_relation_change_scope\":\"FRA_pair_at_six_relation_command_or_alliance_or_royal_or_directed_record_returns\","
            "\"native_alliance_record_observation\":true,\"native_royal_record_observation\":true,\"native_directed_record_observation\":true"
#elif defined(BRIDGE_ROYAL_RECORD_OBSERVATION)
            ",\"native_relation_change_observation\":true,\"native_relation_change_wire\":3,"
            "\"native_relation_change_scope\":\"FRA_pair_at_six_relation_command_or_alliance_or_royal_record_returns\","
            "\"native_alliance_record_observation\":true,\"native_royal_record_observation\":true"
#elif !defined(BRIDGE_ALLIANCE_RECORD_OBSERVATION)
            ",\"native_relation_change_observation\":true,\"native_relation_change_wire\":1,"
            "\"native_relation_change_scope\":\"FRA_pair_at_six_relation_command_returns\""
#else
            ",\"native_relation_change_observation\":true,\"native_relation_change_wire\":2,"
            "\"native_relation_change_scope\":\"FRA_pair_at_six_relation_command_or_alliance_record_returns\","
            "\"native_alliance_record_observation\":true"
#endif
#endif
#ifndef BRIDGE_MISSION_COMPLETED_SET_OBSERVATION
#ifdef BRIDGE_MISSION_COMPLETION_OBSERVATION
            ",\"native_mission_completion_observation\":true,\"native_mission_completion_wire\":1,"
            "\"native_mission_completion_scope\":\"FRA_completed_transition_at_native_mission_command_return\""
#endif
#else
            ",\"native_mission_completion_observation\":true,\"native_mission_completion_wire\":2,"
            "\"native_mission_completion_scope\":\"FRA_completed_set_insert_at_command_or_effect_return\","
            "\"native_mission_completed_set_observation\":true"
#endif
#ifdef BRIDGE_MISSION_AVAILABILITY_OBSERVATION
            ",\"native_mission_availability_observation\":true,\"native_mission_availability_wire\":1,"
            "\"native_mission_availability_scope\":\"FRA_native_task_eligibility_return\""
#endif
#ifdef BRIDGE_MISSION_CONDITION_OBSERVATION
#ifdef BRIDGE_MISSION_PROVINCE_CONDITION_OBSERVATION
            ",\"native_mission_condition_observation\":true,\"native_mission_condition_wire\":2,"
            "\"native_mission_condition_scope\":\"FRA_root_and_direct_area_province_holding_returns\","
            "\"native_mission_province_condition_observation\":true"
#else
            ",\"native_mission_condition_observation\":true,\"native_mission_condition_wire\":1,"
            "\"native_mission_condition_scope\":\"FRA_root_conjunction_child_returns\""
#endif
#endif
#ifdef BRIDGE_SUPPORT_ROLE_CONTEXT
            ",\"native_support_role_context\":true"
#endif
            ;
        char* at=strstr(text,marker);
        if (!at) return;
        const size_t marker_size=sizeof(marker)-1;
        const size_t fields_size=sizeof(fields)-1;
        const size_t used=strlen(text);
        const size_t offset=static_cast<size_t>(at-text)+marker_size;
        if (offset>used || used+fields_size+1>capacity) return;
        memmove(text+offset+fields_size,text+offset,used-offset+1);
        memcpy(text+offset,fields,fields_size);
    };
#ifdef BRIDGE_INFORMATION_BATTLE
    auto append_information_battle_capability=[](char* text,size_t capacity) {
        if (!text || capacity==0) return;
        constexpr char marker[]="\"native_generic_execution_entry_guard\":true";
#ifdef INFORMATION_BATTLE_OUTCOME_TAIL
#ifdef INFORMATION_BATTLE_FLAG_INPUTS
        constexpr char fields[]=",\"native_information_battle_research_lifecycle\":true,\"native_information_battle_message_scope\":true,\"native_information_battle_formatter_container\":true,\"native_information_battle_wire\":15,\"native_information_battle_display_context\":true,\"native_information_battle_end_state\":true,\"native_information_battle_retreat\":true,\"native_information_battle_name_sources\":true,\"native_information_battle_outcome_text\":true,\"native_information_battle_outcome_tail\":true,\"native_information_battle_independent_line\":true,\"native_information_battle_flag_inputs\":true"
#elif defined(INFORMATION_BATTLE_INDEPENDENT_LINE)
        constexpr char fields[]=",\"native_information_battle_research_lifecycle\":true,\"native_information_battle_message_scope\":true,\"native_information_battle_formatter_container\":true,\"native_information_battle_wire\":14,\"native_information_battle_display_context\":true,\"native_information_battle_end_state\":true,\"native_information_battle_retreat\":true,\"native_information_battle_name_sources\":true,\"native_information_battle_outcome_text\":true,\"native_information_battle_outcome_tail\":true,\"native_information_battle_independent_line\":true"
#else
        constexpr char fields[]=",\"native_information_battle_research_lifecycle\":true,\"native_information_battle_message_scope\":true,\"native_information_battle_formatter_container\":true,\"native_information_battle_wire\":13,\"native_information_battle_display_context\":true,\"native_information_battle_end_state\":true,\"native_information_battle_retreat\":true,\"native_information_battle_name_sources\":true,\"native_information_battle_outcome_text\":true,\"native_information_battle_outcome_tail\":true"
#endif
#ifdef BRIDGE_CALL_TO_ARMS_OBSERVATION
            ",\"native_call_to_arms_observation\":true,\"native_call_to_arms_ai_response_held\":false"
#endif
#ifdef INFORMATION_BATTLE_NAME_HANDOFF
            ",\"native_information_battle_name_handoff\":true"
#endif
            ;
#elif defined(INFORMATION_BATTLE_OUTCOME_TEXT)
        constexpr char fields[]=",\"native_information_battle_research_lifecycle\":true,\"native_information_battle_message_scope\":true,\"native_information_battle_formatter_container\":true,\"native_information_battle_wire\":12,\"native_information_battle_display_context\":true,\"native_information_battle_end_state\":true,\"native_information_battle_retreat\":true,\"native_information_battle_name_sources\":true,\"native_information_battle_outcome_text\":true"
#ifdef INFORMATION_BATTLE_NAME_HANDOFF
            ",\"native_information_battle_name_handoff\":true"
#endif
            ;
#elif defined(INFORMATION_BATTLE_NAME_SOURCES)
        constexpr char fields[]=",\"native_information_battle_research_lifecycle\":true,\"native_information_battle_message_scope\":true,\"native_information_battle_formatter_container\":true,\"native_information_battle_wire\":11,\"native_information_battle_display_context\":true,\"native_information_battle_end_state\":true,\"native_information_battle_retreat\":true,\"native_information_battle_name_sources\":true"
#ifdef INFORMATION_BATTLE_NAME_HANDOFF
            ",\"native_information_battle_name_handoff\":true"
#endif
            ;
#elif defined(INFORMATION_BATTLE_RETREAT)
        constexpr char fields[]=",\"native_information_battle_research_lifecycle\":true,\"native_information_battle_message_scope\":true,\"native_information_battle_formatter_container\":true,\"native_information_battle_wire\":10,\"native_information_battle_display_context\":true,\"native_information_battle_end_state\":true,\"native_information_battle_retreat\":true"
#ifdef INFORMATION_BATTLE_NAME_HANDOFF
            ",\"native_information_battle_name_handoff\":true"
#endif
            ;
#elif defined(INFORMATION_BATTLE_END_STATE)
        constexpr char fields[]=",\"native_information_battle_research_lifecycle\":true,\"native_information_battle_message_scope\":true,\"native_information_battle_formatter_container\":true,\"native_information_battle_wire\":9,\"native_information_battle_display_context\":true,\"native_information_battle_end_state\":true"
#ifdef INFORMATION_BATTLE_NAME_HANDOFF
            ",\"native_information_battle_name_handoff\":true"
#endif
            ;
#elif defined(INFORMATION_BATTLE_NAME_HANDOFF)
        constexpr char fields[]=",\"native_information_battle_research_lifecycle\":true,\"native_information_battle_message_scope\":true,\"native_information_battle_formatter_container\":true,\"native_information_battle_wire\":8,\"native_information_battle_display_context\":true,\"native_information_battle_name_handoff\":true";
#elif defined(INFORMATION_BATTLE_DISPLAY_CONTEXT)
        constexpr char fields[]=",\"native_information_battle_research_lifecycle\":true,\"native_information_battle_message_scope\":true,\"native_information_battle_formatter_container\":true,\"native_information_battle_wire\":7,\"native_information_battle_display_context\":true";
#elif defined(INFORMATION_BATTLE_CONTAINER)
        constexpr char fields[]=",\"native_information_battle_research_lifecycle\":true,\"native_information_battle_message_scope\":true,\"native_information_battle_formatter_container\":true,\"native_information_battle_wire\":4";
#elif defined(INFORMATION_BATTLE_TEMPLATE)
        constexpr char fields[]=",\"native_information_battle_research_lifecycle\":true,\"native_information_battle_message_scope\":true,\"native_information_battle_wire\":4";
#else
        constexpr char fields[]=",\"native_information_battle_research_lifecycle\":true";
#endif
        char* at=strstr(text,marker);
        if (!at) return;
        const size_t marker_size=sizeof(marker)-1;
        const size_t fields_size=sizeof(fields)-1;
        const size_t used=strlen(text);
        const size_t offset=static_cast<size_t>(at-text)+marker_size;
        if (offset>used || used+fields_size+1>capacity) return;
        memmove(text+offset+fields_size,text+offset,used-offset+1);
        memcpy(text+offset,fields,fields_size);
    };
#endif
    char message[8192];
    snprintf(message,sizeof(message),"{\"event\":\"diplomacy_observer_installed\",\"version\":22,\"pid\":%lu,\"session_id\":\"%lu-%llx\",\"creation_filetime\":%llu,\"native_queries_enabled\":true,\"native_spy_network_query\":true,\"native_spy_network_submission\":true,\"native_improve_relations_query\":true,\"native_improve_relations_submission\":true,\"native_guarantee_query\":true,\"native_guarantee_submission\":true,\"native_support_independence_query\":true,\"native_support_independence_submission\":true,\"native_inbound_support_independence_response\":true,\"native_military_access_query\":true,\"native_insult_query\":true,\"native_rival_query\":true,\"native_declare_war_query\":true,\"native_peace_context_query\":true,\"native_war_participants_query\":true,\"native_peace_empty_offer_query\":true,\"native_peace_offer_evaluation_query\":true,\"native_peace_money_offer_query\":true,\"native_peace_province_offer_query\":true,\"native_peace_combined_query\":true,\"native_peace_reparations_query\":true,\"native_peace_reparations_execution\":true,\"native_peace_trade_power_query\":true,\"native_peace_trade_power_execution\":true,\"native_peace_trade_power_sources\":true,\"native_peace_concede_defeat_query\":true,\"native_peace_concede_defeat_execution\":true,\"native_peace_annul_treaties_query\":true,\"native_peace_annul_treaties_execution\":true,\"native_peace_special_terms_query\":true,\"native_peace_special_terms_execution\":true,\"native_peace_core_terms_query\":true,\"native_peace_subject_terms_query\":true,\"native_peace_subject_terms_execution\":true,\"native_peace_country_terms_query\":true,\"native_peace_country_money_query\":true,\"native_peace_country_terms_execution\":true,\"native_peace_core_terms_execution\":true,\"native_peace_war_context_query\":true,\"native_peace_serialized_payload_query\":true,\"native_declare_war_submission\":true,\"native_declare_war_participants\":true,\"native_declare_war_forces\":true,\"native_declare_war_peace_options\":true,\"native_peace_consequences\":true,\"native_peace_submission\":true,\"native_peace_wrapper_rule_query\":true,\"native_peace_inbound_pending\":true,\"native_inbound_peace_response\":true,\"native_vassalization_query\":true,\"native_vassalization_submission\":true,\"native_inbound_vassalization_response\":true,\"native_favor_gold_query\":true,\"native_favor_gold_submission\":true,\"native_inbound_favor_gold_response\":true,\"native_favor_trust_query\":true,\"native_favor_trust_submission\":true,\"native_inbound_favor_trust_response\":true,\"native_favor_men_query\":true,\"native_favor_men_submission\":true,\"native_inbound_favor_men_response\":true,\"native_curry_favors_query\":true,\"native_curry_favors_submission\":true,\"native_rival_submission\":true,\"native_rival_authority\":true,\"native_insult_submission\":true,\"native_military_access_submission\":true,\"native_inbound_military_access_response\":true,\"native_generic_execution_entry_guard\":true,\"native_royal_marriage_query\":true,\"native_royal_marriage_submission\":true,\"native_inbound_royal_marriage_response\":true,\"native_execution_enabled\":true,\"native_offer_submission\":true,\"native_dissolve_submission\":true,\"native_inbound_alliance\":true,\"native_inbound_alliance_response\":true,\"native_alliance_reason_metadata\":%s,\"incoming_offer\":true,\"incoming_mode\":\"state0_deferred_pending_observe;state1_2_llm_response\",\"accept\":true,\"reject\":true,\"withdraw\":false,\"dissolve\":true,\"authority_lock_enabled\":true,\"authority_scope\":\"outbound FRA Alliance/Royal/Support/MilitaryAccess/Vassalization requests and revocations require generic-entry authority; FRA Improve/Spy/Guarantee/Insult/DeclareWar/CurryFavors unilateral operations require authority; FRA Rival Set/Replace/Remove native handlers deny ungranted choices; Alliance/Royal/Support/MilitaryAccess/Vassalization incoming recipient FRA deferred for LLM accept/reject; Peace incoming recipient FRA retained pending with native AI choice held; Peace incoming responses require a consumed full-payload pending binding; offer_alliance sender SAV|LIT; other implemented senders native-valid canonical recipients; unbound FRA receiver state1/2 blocked\",\"other_actions_forwarded\":true,\"all_commands_forwarded\":false}\n",
        static_cast<unsigned long>(GetCurrentProcessId()),static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long long>(observation_creation),static_cast<unsigned long long>(observation_creation),
        reason_metadata_installed?"true":"false");
    append_r74_capabilities(message,sizeof(message));
#ifdef BRIDGE_INFORMATION_BATTLE
    char* version_marker=strstr(message,"\"version\":22");
    if (version_marker) {
#ifdef BRIDGE_MISSION_COMPLETION_OBSERVATION
        version_marker[sizeof("\"version\":")-1]='5';
        version_marker[sizeof("\"version\":")]='1';
#elif defined(BRIDGE_RELATION_OBSERVATION)
        version_marker[sizeof("\"version\":")-1]='5';
        version_marker[sizeof("\"version\":")]='0';
#elif defined(BRIDGE_WAR_DECLARATION_OBSERVATION)
        version_marker[sizeof("\"version\":")-1]='4';
        version_marker[sizeof("\"version\":")]='9';
#elif defined(BRIDGE_RIVAL_OBSERVATION)
        version_marker[sizeof("\"version\":")-1]='4';
        version_marker[sizeof("\"version\":")]='8';
#elif defined(BRIDGE_COUNTRY_MODIFIER_EXPIRY)
        version_marker[sizeof("\"version\":")-1]='4';
        version_marker[sizeof("\"version\":")]='7';
#elif defined(BRIDGE_COUNTRY_MODIFIER_REMOVAL)
        version_marker[sizeof("\"version\":")-1]='4';
        version_marker[sizeof("\"version\":")]='6';
#elif defined(BRIDGE_COUNTRY_MODIFIER_OBSERVATION)
        version_marker[sizeof("\"version\":")-1]='4';
        version_marker[sizeof("\"version\":")]='5';
#elif defined(BRIDGE_SUPPORT_ROLE_CONTEXT)
        version_marker[sizeof("\"version\":")-1]='4';
        version_marker[sizeof("\"version\":")]='4';
#elif defined(INFORMATION_BATTLE_FLAG_INPUTS)
        version_marker[sizeof("\"version\":")-1]='4';
        version_marker[sizeof("\"version\":")]='3';
#elif defined(INFORMATION_BATTLE_INDEPENDENT_LINE)
        version_marker[sizeof("\"version\":")-1]='4';
        version_marker[sizeof("\"version\":")]='2';
#elif defined(BRIDGE_CALL_TO_ARMS_OBSERVATION)
        version_marker[sizeof("\"version\":")-1]='4';
        version_marker[sizeof("\"version\":")]='1';
#elif defined(INFORMATION_BATTLE_OUTCOME_TAIL)
        version_marker[sizeof("\"version\":")-1]='4';
        version_marker[sizeof("\"version\":")]='0';
#elif defined(INFORMATION_BATTLE_OUTCOME_TEXT)
        version_marker[sizeof("\"version\":")-1]='3';
        version_marker[sizeof("\"version\":")]='9';
#elif defined(INFORMATION_BATTLE_NAME_SOURCES)
        version_marker[sizeof("\"version\":")-1]='3';
        version_marker[sizeof("\"version\":")]='8';
#elif defined(INFORMATION_BATTLE_RETREAT)
        version_marker[sizeof("\"version\":")-1]='3';
        version_marker[sizeof("\"version\":")]='7';
#elif defined(INFORMATION_BATTLE_END_STATE)
        version_marker[sizeof("\"version\":")-1]='3';
        version_marker[sizeof("\"version\":")]='6';
#elif defined(INFORMATION_BATTLE_NAME_HANDOFF)
        version_marker[sizeof("\"version\":")-1]='3';
        version_marker[sizeof("\"version\":")]='5';
#elif defined(BRIDGE_DEBT_QUOTE_QUERY)
        version_marker[sizeof("\"version\":")-1]='3';
        version_marker[sizeof("\"version\":")]='4';
#elif defined(INFORMATION_BATTLE_DISPLAY_CONTEXT)
        version_marker[sizeof("\"version\":")-1]='3';
        version_marker[sizeof("\"version\":")]='3';
#elif defined(INFORMATION_BATTLE_CONTAINER)
        version_marker[sizeof("\"version\":")]='7'; // second digit: 22 -> 27
#elif defined(INFORMATION_BATTLE_TEMPLATE)
        version_marker[sizeof("\"version\":")]='6'; // second digit: 22 -> 26
#else
        version_marker[sizeof("\"version\":")]='3'; // second digit: 22 -> 23
#endif
#ifdef BRIDGE_MISSION_AVAILABILITY_OBSERVATION
        version_marker[sizeof("\"version\":")-1]='5';
        version_marker[sizeof("\"version\":")]='2';
#endif
#ifdef BRIDGE_MISSION_COMPLETED_SET_OBSERVATION
        version_marker[sizeof("\"version\":")-1]='5';
        version_marker[sizeof("\"version\":")]='3';
#endif
#ifdef BRIDGE_ALLIANCE_RECORD_OBSERVATION
        version_marker[sizeof("\"version\":")-1]='5';
        version_marker[sizeof("\"version\":")]='5';
#endif
#ifdef BRIDGE_MISSION_CONDITION_OBSERVATION
        version_marker[sizeof("\"version\":")-1]='5';
        version_marker[sizeof("\"version\":")]='6';
#endif
#ifdef BRIDGE_MISSION_PROVINCE_CONDITION_OBSERVATION
        version_marker[sizeof("\"version\":")-1]='5';
        version_marker[sizeof("\"version\":")]='7';
#endif
#ifdef BRIDGE_NATIVE_COUNTRY_CONTROL
        version_marker[sizeof("\"version\":")-1]='6';
        version_marker[sizeof("\"version\":")]='5';
#elif defined(BRIDGE_LAND_PROMISE_OBSERVATION)
        version_marker[sizeof("\"version\":")-1]='6';
        version_marker[sizeof("\"version\":")]='4';
#elif defined(BRIDGE_CLAIM_EXPIRY_OBSERVATION)
        version_marker[sizeof("\"version\":")-1]='6';
        version_marker[sizeof("\"version\":")]='3';
#elif defined(BRIDGE_SUBSIDY_EXPIRY_OBSERVATION) || defined(BRIDGE_TRUCE_EXPIRY_OBSERVATION)
        version_marker[sizeof("\"version\":")-1]='6';
        version_marker[sizeof("\"version\":")]='2';
#elif defined(BRIDGE_RIVAL_RECORD_OBSERVATION)
        version_marker[sizeof("\"version\":")-1]='6';
        version_marker[sizeof("\"version\":")]='1';
#elif defined(BRIDGE_SUPPORT_SUBJECT_RECORD_OBSERVATION)
        version_marker[sizeof("\"version\":")-1]='6';
        version_marker[sizeof("\"version\":")]='0';
#elif defined(BRIDGE_DIRECTED_RECORD_OBSERVATION)
        version_marker[sizeof("\"version\":")-1]='5';
        version_marker[sizeof("\"version\":")]='9';
#elif defined(BRIDGE_ROYAL_RECORD_OBSERVATION)
        version_marker[sizeof("\"version\":")-1]='5';
        version_marker[sizeof("\"version\":")]='8';
#endif
    }
    append_information_battle_capability(message,sizeof(message));
#endif
    {
        char* end=strrchr(message,'}');
        if (end) snprintf(end,sizeof(message)-static_cast<size_t>(end-message),
            ",\"native_territorial_interest_query\":true,\"native_territorial_interest_query_wire\":24"
#ifdef BRIDGE_NATIVE_COUNTRY_CONTROL
            ",\"native_information_observer_configuration\":true,\"native_country_modifier_scoped_schema\":2"
            ",\"native_relation_change_scoped_schema\":6,\"native_war_declaration_scoped_schema\":2"
            ",\"native_land_promise_scoped_schema\":2,\"native_mission_completion_scoped_schema\":3"
            ",\"native_mission_availability_scoped_schema\":2,\"native_mission_condition_scoped_schema\":4"
            ",\"native_expiry_scoped_wire\":2,\"native_rival_change_scoped_schema\":4"
#endif
            "}\n");
    }
#ifdef BRIDGE_DEBT_QUOTE_QUERY
    char* end=strrchr(message,'}');
    if (end) {
        const size_t used=static_cast<size_t>(end-message);
        snprintf(end,sizeof(message)-used,
            ",\"native_debt_quote_query\":true,\"native_debt_quote_query_wire\":1,"
            "\"native_debt_quote_read_only\":true,\"native_debt_quote_fp_context\":true"
#ifdef BRIDGE_NATIVE_COUNTRY_CONTROL
            ",\"native_debt_quote_configured_country_scope\":true"
#endif
            "}\n");
    }
#endif
#ifdef BRIDGE_COUNTRY_MODIFIER_OBSERVATION
    {
        char* end=strrchr(message,'}');
        if (end) snprintf(end,sizeof(message)-static_cast<size_t>(end-message),
            ",\"native_country_modifier_add_observation\":true,\"native_country_modifier_add_wire\":1,"
            "\"native_country_modifier_scope\":\"FRA_direct_temporary_records\"}\n");
    }
#endif
#ifdef BRIDGE_COUNTRY_MODIFIER_REMOVAL
    {
        char* end=strrchr(message,'}');
        if (end) snprintf(end,sizeof(message)-static_cast<size_t>(end-message),
            ",\"native_country_modifier_remove_observation\":true,\"native_country_modifier_remove_wire\":1}\n");
    }
#endif
#ifdef BRIDGE_COUNTRY_MODIFIER_EXPIRY
    {
        char* end=strrchr(message,'}');
        if (end) snprintf(end,sizeof(message)-static_cast<size_t>(end-message),
            ",\"native_country_modifier_expiry_observation\":true,\"native_country_modifier_expiry_wire\":1}\n");
    }
#endif
#ifdef BRIDGE_SUBSIDY_EXPIRY_OBSERVATION
    {
        char* end=strrchr(message,'}');
        if (end) snprintf(end,sizeof(message)-static_cast<size_t>(end-message),
            ",\"native_subsidy_expiry_observation\":true,\"native_subsidy_expiry_wire\":1}\n");
    }
#endif
#ifdef BRIDGE_TRUCE_EXPIRY_OBSERVATION
    {
        char* end=strrchr(message,'}');
        if (end) snprintf(end,sizeof(message)-static_cast<size_t>(end-message),
            ",\"native_truce_expiry_observation\":true,\"native_truce_expiry_wire\":1,"
            "\"native_truce_expiry_scope\":\"FRA_actor_or_recipient_directional_direct_truce_expiry_returns\"}\n");
    }
#endif
#ifdef BRIDGE_CLAIM_EXPIRY_OBSERVATION
    {
        char* end=strrchr(message,'}');
        if (end) snprintf(end,sizeof(message)-static_cast<size_t>(end-message),
            ",\"native_claim_expiry_observation\":true,\"native_claim_expiry_wire\":1,"
            "\"native_claim_expiry_scope\":\"FRA_claimant_or_current_owner_at_native_claim_expiry_remove_return\"}\n");
    }
#endif
#ifdef BRIDGE_LAND_PROMISE_OBSERVATION
    {
        char* end=strrchr(message,'}');
        if (end) snprintf(end,sizeof(message)-static_cast<size_t>(end-message),
            ",\"native_land_promise_observation\":true,\"native_land_promise_wire\":1,"
            "\"native_land_promise_scope\":\"FRA_member_in_observed_promise_war\"}\n");
    }
#endif
    line(message); return 0;
}
