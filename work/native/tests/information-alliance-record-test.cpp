#define BRIDGE_ALLIANCE_RECORD_OBSERVATION 1
#define read fixture_read
#define main legacy_relation_fixture_main
#include "information-relation-observer-test.cpp"
#undef main
#undef read
#include "../entry-patch-transaction.inc"
#include <stdexcept>

namespace bridge::alliance_authority {
using AlliancePayload = ::AlliancePayload;
using ActionFamily = ::ActionFamily;
}
static bool lifecycle_rollback_incomplete = false;
static uintptr_t record_words[6]{};
static bool record_readable = true;
static unsigned record_reads_after_release = 0;
template<class Value> static bool read(uintptr_t address,Value& output) noexcept {
    const auto begin = reinterpret_cast<uintptr_t>(record_words);
    if (address >= begin && address+sizeof(Value) <= begin+sizeof(record_words)) {
        if (!record_readable) { ++record_reads_after_release; return false; }
        std::memcpy(&output,reinterpret_cast<void*>(address),sizeof(Value));
        return true;
    }
    return fixture_read(address,output);
}
#include "../information-alliance-record-observer.inc"
namespace Record = alliance_record_observer;
static unsigned original_calls = 0;
static bool throw_original = false, release_record = false, change_date = false;
static uintptr_t received[4]{};
static DWORD original_error = 0;
static uintptr_t original(uintptr_t first,uintptr_t second,uintptr_t third,uintptr_t fourth) {
    ++original_calls;
    received[0]=first; received[1]=second; received[2]=third; received[3]=fourth;
    original_error=GetLastError();
    arena->after_phase=true;
    if (change_date) ++arena->date;
    if (release_record) record_readable=false;
    if (throw_original) throw std::runtime_error("owned original");
    SetLastError(8821);
    return UINT64_C(0xfedcba9876543210);
}
static void setup(bool before,bool after) {
    reset_case();
    Record::installed=true;
    Record::active_count=0;
    Record::hooks[0].original=&original;
    Record::hooks[1].original=&original;
    original_calls=0;
    throw_original=false; release_record=false; change_date=false;
    record_readable=true; record_reads_after_release=0;
    const auto fra=fullref("FRA",0x12000001), eng=fullref("ENG",0x23000002);
    auto& forward=add_pair(0,fra,eng);
    forward.before_active=before; forward.after_active=after;
    auto& reverse=add_pair(1,eng,fra);
    reverse.actor_country=forward.recipient_country;
    reverse.recipient_country=forward.actor_country;
    reverse.before_active=before; reverse.after_active=after;
    record_words[0]=base+0x1c7a740;
    record_words[2]=fra; record_words[3]=eng;
}
static uintptr_t invoke(bool enable=true) {
    SetLastError(7771);
    auto call=enable ? &Record::observe_enable : &Record::observe_disable;
    const auto result=call(reinterpret_cast<uintptr_t>(record_words),UINT64_MAX,0x12345678,0x87654321);
    const auto error=GetLastError();
    CHECK(result==UINT64_C(0xfedcba9876543210),"full original RAX");
    CHECK(error==8821 && original_error==7771,"original LastError at entry and return");
    CHECK(original_calls==1 && received[1]==UINT64_MAX && received[2]==0x12345678
        && received[3]==0x87654321,"exactly once with all four args");
    CHECK(Record::active_count==0,"owned nesting closed");
    return result;
}
int main() {
    auto* memory=VirtualAlloc(nullptr,sizeof(FixtureArena),MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    if (!memory) return 2;
    arena=new(memory) FixtureArena{};
    if (!GetEnvironmentVariableW(L"INFORMATION_RELATION_FIXTURE_LOG",log_path,32768)) return 3;
    log_file=CreateFileW(log_path,GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);
    if (log_file==INVALID_HANDLE_VALUE) return 4;

    setup(false,true); invoke();
    CHECK(Observer::size==1 && Observer::events[Observer::head].value.path==Observer::Path::alliance_record_enable,"direct enable event");
    flush_case();
    setup(true,false); release_record=true; invoke(false);
    CHECK(record_reads_after_release==0 && Observer::size==1,"disable retains owned endpoints after release");
    flush_case();
    setup(false,true);
    auto& command=add_action(0,0,Kind::alliance,record_words[2],record_words[3]);
    auto outer=Observer::begin(command.wrapper);
    invoke(); Observer::finish(outer);
    CHECK(Observer::size==1,"outer command and record yield one event");
    flush_case();
    setup(false,true);
    auto& fallback=add_action(0,0,Kind::alliance,record_words[2],record_words[3]);
    outer=Observer::begin(fallback.wrapper);
    arena->after_phase=true; Observer::finish(outer);
    CHECK(Observer::size==1 && Observer::events[Observer::head].value.path==Observer::Path::command_return,"command fallback without record callback");
    flush_case();
    setup(true,true); invoke(); CHECK(Observer::size==0,"unchanged omitted");
    setup(false,true); record_words[0]=0; invoke(); CHECK(Observer::size==0,"foreign record class ignored");
    setup(false,true); record_words[2]=fullref("SCO",3); record_words[3]=fullref("SAV",4);
    invoke(); CHECK(Observer::size==0,"non FRA ignored");
    setup(false,true); change_date=true; invoke(); CHECK(Observer::size==0 && Observer::dropped==1,"changed date gap"); flush_case();
    setup(false,true); arena->pairs[1].after_active=false; invoke();
    CHECK(Observer::size==0 && Observer::dropped==1,"inconsistent two-direction state gap"); flush_case();
    setup(false,true); throw_original=true;
    try { Record::observe_enable(reinterpret_cast<uintptr_t>(record_words),0,0,0); CHECK(false,"exception propagates"); }
    catch (const std::runtime_error&) { CHECK(original_calls==1 && Record::active_count==0 && Observer::dropped==1,"owned exception closes depth and marks gap"); }
    flush_case();
    setup(false,true);
    auto first=Record::begin(reinterpret_cast<uintptr_t>(record_words),Record::plan::Kind::enable);
    auto nested=Record::begin(reinterpret_cast<uintptr_t>(record_words),Record::plan::Kind::disable);
    CHECK(first.observed && !nested.observed,"nested same pair folds into outer net change");
    arena->after_phase=true; Record::finish(first); CHECK(Observer::size==1,"one nested event"); flush_case();

    CHECK(CloseHandle(log_file),"close writer"); log_file=INVALID_HANDLE_VALUE;
    arena->~FixtureArena(); CHECK(VirtualFree(memory,0,MEM_RELEASE),"free arena");
    std::printf("{\"checks\":%u,\"failures\":%u,\"scenarios\":11,\"game_access\":false}\n",checks,failures);
    return failures ? 1 : 0;
}
