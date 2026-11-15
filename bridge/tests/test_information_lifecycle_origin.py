"""Execute the production destructor callback and formatter against native stubs."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'work/native/alliance-lifecycle.inc'


@pytest.fixture(scope='module')
def callback_fixture(tmp_path_factory):
    compiler = shutil.which('g++')
    if compiler is None:
        pytest.skip('native callback fixture requires the existing C++ compiler')
    directory = tmp_path_factory.mktemp('lifecycle-origin')
    source = SOURCE.read_text(encoding='utf-8')

    def section(begin, end):
        start = source.index(begin)
        return source[start:source.index(end, start)]

    event_enum = section('enum LifecycleEventKind', 'struct LifecycleActionShape')
    event_struct = section('struct LifecycleEvent {', 'struct AllianceFieldReadEvent')
    callback = section('static void* lifecycle_destructor_observe(',
                       'extern "C" void bridge_serializer_observe')
    kind_name = section('static const char* lifecycle_kind_name(',
                        'static void lifecycle_shape_json(')
    formatter = section('static void lifecycle_emit(', 'static void lifecycle_flush(')
    preamble = r'''
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
using DWORD=unsigned long;
static uintptr_t base=0;
static const uintptr_t source_address=0x200000,game_address=0x300000;
static bool tracked=true,game_readable=true,date_readable=true,destroyed=false;
static unsigned forwards=0,notifications=0,date_reads=0;
static uint64_t observation_creation=1234;
static int32_t current_date=56566584;
static DWORD frame_thread=7;
static const char* observation_active_query="synthetic";
static uintptr_t fixture_caller_return=0;
using LONG64=long long;
static volatile LONG64 lifecycle_temporary_ui_cleanup_suppressed=0;
static LONG64 InterlockedIncrement64(volatile LONG64* value) { return ++(*value); }
static uintptr_t lifecycle_fixture_return_address() { return fixture_caller_return; }
struct LifecycleActionShape {
    bool readable=false,handles_canonical=false,matched=false,tracked=false;
    int32_t state34=0,proposal3c=0;
    unsigned char variant38=0;
    int marker=0;
};
static LifecycleActionShape lifecycle_capture_shape(void*) {
    assert(!destroyed);
    LifecycleActionShape shape{};
    shape.readable=true;
    shape.handles_canonical=true;
    shape.matched=true;
    shape.tracked=tracked;
    shape.state34=0;
    shape.variant38=1;
    shape.proposal3c=0;
    shape.marker=55;
    return shape;
}
template<class T> static bool read(uintptr_t address,T& value) {
    if (address==source_address) {
        assert(!destroyed); value=static_cast<T>(base+0x100); return true;
    }
    if (address==base+0x233fe58) {
        ++date_reads; value=static_cast<T>(game_address); return game_readable;
    }
    if (address==game_address+0x1dd0) {
        ++date_reads; value=static_cast<T>(current_date); return date_readable;
    }
    return false;
}
static void* native_destructor(void*,unsigned flags) {
    assert(!destroyed && flags==1); ++forwards; destroyed=true;
    current_date+=24;
    return reinterpret_cast<void*>(0x44440000);
}
using LifecycleDestructorMethod=void* (*)(void*,unsigned);
static LifecycleDestructorMethod lifecycle_destructor_original=native_destructor;
static LifecycleDestructorMethod lifecycle_peace_destructor_original=native_destructor;
static LifecycleDestructorMethod lifecycle_declarewar_destructor_original=native_destructor;
static LifecycleDestructorMethod lifecycle_royal_destructor_original=native_destructor;
static LifecycleDestructorMethod lifecycle_insult_destructor_original=native_destructor;
static LifecycleDestructorMethod lifecycle_favor_trust_destructor_original=native_destructor;
static LifecycleDestructorMethod lifecycle_gift_destructor_original=native_destructor;
static const uintptr_t lifecycle_peace_vtable_rva=0x200,lifecycle_declarewar_vtable_rva=0x300;
static const uintptr_t lifecycle_royal_vtable_rva=0x400,lifecycle_insult_vtable_rva=0x500;
static const uintptr_t lifecycle_favor_trust_vtable_rva=0x600,lifecycle_gift_vtable_rva=0x700;
static void execution_lifecycle_source_destroyed(void*,const LifecycleActionShape& snapshot,unsigned) {
    assert(!destroyed && snapshot.marker==55); ++notifications;
}
static uint64_t lifecycle_next_sequence() { static uint64_t sequence=0; return ++sequence; }
static DWORD GetCurrentThreadId() { return frame_thread; }
static DWORD GetCurrentProcessId() { return 1; }
static void lifecycle_copy_query(char (&destination)[65]) { std::strcpy(destination,"synthetic"); }
static void lifecycle_shape_json(char* output,size_t capacity,const LifecycleActionShape&) {
    std::snprintf(output,capacity,"{}");
}
static void line(const char* value) { std::cout<<value; }
'''
    queue = r'''
static std::vector<LifecycleEvent> events;
static void lifecycle_enqueue(const LifecycleEvent& event) { events.push_back(event); }
'''
    main = r'''
int main(int argc,char** argv) {
    base=reinterpret_cast<uintptr_t>(&main)&~uintptr_t{0xffff};
    const std::string mode=argc>1?argv[1]:"normal";
    tracked=mode!="untracked";
    game_readable=mode!="global_failure";
    date_readable=mode!="date_failure";
    observation_active_query=mode=="temporary_ui_cleanup"?nullptr:"synthetic";
    fixture_caller_return=base+(mode=="temporary_ui_cleanup"?0xf0bf77:0x1234);
    if (mode=="missing_original") lifecycle_destructor_original=nullptr;
    void* result=lifecycle_destructor_observe(reinterpret_cast<void*>(source_address),1);
    if (mode=="missing_original") {
        assert(result==nullptr && forwards==0 && events.empty() && date_reads==0);
        return 0;
    }
    assert(forwards==1 && result==reinterpret_cast<void*>(0x44440000));
    assert(notifications==(tracked?1u:0u));
    if (!tracked) { assert(events.empty() && date_reads==0); return 0; }
    if (mode=="temporary_ui_cleanup") {
        assert(events.empty() && date_reads==0);
        assert(lifecycle_temporary_ui_cleanup_suppressed==1);
        return 0;
    }
    assert(lifecycle_temporary_ui_cleanup_suppressed==0);
    assert(events.size()==2);
    assert(events[0].caller_return!=0 && events[0].caller_return==events[1].caller_return);
    for (const auto& event:events) {
        assert(event.source.marker==55 && event.native_flags==1);
        lifecycle_emit(event);
    }
}
'''
    path = directory / 'callback.cpp'
    return_address_stub = r'''
// Keep the production callback body intact while making caller RVA an
// explicit fixture input for the temporary-UI cleanup predicate.
#define __builtin_return_address(level) lifecycle_fixture_return_address()
'''
    path.write_text(preamble + event_enum + event_struct + queue + return_address_stub + callback
                    + '#undef __builtin_return_address\n' + kind_name + formatter + main,
                    encoding='utf-8')
    executable = directory / 'callback.exe'
    built = subprocess.run([compiler, '-std=c++17', '-O2', '-fno-inline', '-Wall', '-Wextra', '-Werror',
                            str(path), '-o', str(executable)], cwd=ROOT, capture_output=True,
                           text=True, timeout=45)
    assert built.returncode == 0, built.stderr
    return executable


@pytest.mark.parametrize('mode', ['normal', 'global_failure', 'date_failure', 'untracked',
                                  'missing_original', 'temporary_ui_cleanup'])
def test_destructor_origin_date_and_exact_forwarding(callback_fixture, mode):
    run = subprocess.run([str(callback_fixture), mode], cwd=ROOT, capture_output=True,
                         text=True, timeout=10)
    assert run.returncode == 0, run.stderr
    events = [json.loads(line) for line in run.stdout.splitlines()]
    if mode in ('untracked', 'missing_original', 'temporary_ui_cleanup'):
        assert events == []
        return
    assert [event['kind'] for event in events] == ['destructor', 'destructor_return']
    assert events[0]['caller_return_rva'] == events[1]['caller_return_rva']
    assert int(events[0]['caller_return_rva'], 16) > 0
    assert [event['native_return_observed'] for event in events] == [False, True]
    assert all(event['observed_game_date_verified'] is (mode == 'normal') for event in events)
    assert all(event['observed_game_date_raw'] == (56566584 if mode == 'normal' else 0)
               for event in events)
    assert all(event['business_result'] == 'unknown' and event['authorization'] == 'unknown'
               for event in events)
