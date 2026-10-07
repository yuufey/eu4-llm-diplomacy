// Test-save startup confirmation, time control and native saving; v3.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <cstdint>
#include <cstring>
#include <cstdio>
#if defined(BRIDGE_PEACE_AUTHORITY_LOCK) && (!defined(BRIDGE_TRACE_COMMAND_EXECUTION) || defined(BRIDGE_ENABLE_PEACE_SEND))
#error Peace quarantine requires command tracing and disabled bridge sending.
#endif

extern "C" void bridge_frame_stub();
extern "C" void bridge_response_stub();
extern "C" { void* bridge_trampoline = nullptr; }
extern "C" { void* bridge_response_original = nullptr; }
static HMODULE self_module;
static uintptr_t base;
static HANDLE log_file = INVALID_HANDLE_VALUE;
static volatile LONG started = 0, inside = 0, frame_count = 0;
static DWORD frame_thread = 0;
static bool thread_changed = false;
static ULONGLONG last_log = 0;
static const unsigned char expected[20] = {
    0x4c,0x89,0x44,0x24,0x18,0x55,0x53,0x57,0x48,0x8d,
    0x6c,0x24,0xb0,0x48,0x81,0xec,0x50,0x01,0x00,0x00};

static void line(const char* message) {
    DWORD written;
    if (log_file != INVALID_HANDLE_VALUE) {
        WriteFile(log_file, message, static_cast<DWORD>(strlen(message)), &written, nullptr);
        FlushFileBuffers(log_file);
    }
}
template<typename T> static bool read(uintptr_t address, T& value) {
    SIZE_T size = 0;
    return address >= 0x10000 && ReadProcessMemory(GetCurrentProcess(),
        reinterpret_cast<void*>(address), &value, sizeof(value), &size) && size == sizeof(value);
}

static void absolute_jump(unsigned char* bytes, uintptr_t destination) {
    bytes[0]=0xff; bytes[1]=0x25;
    memset(bytes+2, 0, 4);
    memcpy(bytes+6, &destination, 8);
}

struct NativeShortString { char text[16]; uint64_t size,capacity; };
struct NativeStringVector { NativeShortString* begin; NativeShortString* end; NativeShortString* capacity; };
struct NativeConsoleResult { unsigned char success; unsigned char padding[7]; NativeShortString message; };
static_assert(sizeof(NativeConsoleResult)==40,"ABI");
#include "automated-control.inc"
#include "popup-control.inc"
#ifdef BRIDGE_DIPLOMAT_RECALL
#include "diplomat-recall.inc"
#endif
extern "C" int bridge_response_observe(void*) { return 1; }
extern "C" void bridge_frame_tick(void*) {
    if (InterlockedCompareExchange(&inside,1,0)) return;
    DWORD tid=GetCurrentThreadId();
    if (!frame_thread) frame_thread=tid;
    if (frame_thread!=tid) thread_changed=true;
    LONG count=InterlockedIncrement(&frame_count);
    if (!thread_changed && count>=100) { popup_control_tick(); automated_control_tick(); }
#ifdef BRIDGE_DIPLOMAT_RECALL
    if (!thread_changed && count>=100) diplomat_recall_tick();
#endif
    if (GetTickCount64()-last_log>=1000) {
        last_log=GetTickCount64();
        char message[160];
        snprintf(message,sizeof(message),"{\"event\":\"control_frame\",\"pid\":%lu,\"thread\":%lu,\"frames\":%ld}\n",static_cast<unsigned long>(GetCurrentProcessId()),static_cast<unsigned long>(tid),static_cast<long>(count));
        line(message);
    }
    InterlockedExchange(&inside,0);
}
extern "C" __declspec(dllexport) DWORD WINAPI BridgeStart(void*) {
    if (InterlockedCompareExchange(&started,1,0)) return 10;
    wchar_t directory[MAX_PATH];
    DWORD length=GetModuleFileNameW(self_module,directory,MAX_PATH);
    if (!length || length>=MAX_PATH) return 11;
    wchar_t* slash=wcsrchr(directory,L'\\');
    if (!slash) return 11;
    *slash=0;
    wchar_t path[MAX_PATH];
    if (swprintf(path,MAX_PATH,L"%ls\\control-probe.jsonl",directory)<0) return 11;
    log_file=CreateFileW(path,GENERIC_WRITE,FILE_SHARE_READ,nullptr,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);
    if (log_file==INVALID_HANDLE_VALUE) return 12;
    if (!automated_control_start(directory)) return 25;
    if (swprintf(popup_request,MAX_PATH,L"%ls\\popup-confirm.request",directory)<0) return 25;
    DeleteFileW(popup_request);
#ifdef BRIDGE_DIPLOMAT_RECALL
    if (swprintf(recall_request,MAX_PATH,L"%ls\\diplomat-recall.request",directory)<0) return 25;
    DeleteFileW(recall_request);
#endif
    base=reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
#ifdef BRIDGE_TRACE_PEACE_RESPONSES
    uintptr_t trace_slot_rva=0x1c7b840+0x48,trace_original_rva=0x598f00;
#ifdef BRIDGE_TRACE_COMMAND_EXECUTION
    trace_slot_rva=0x1c814b0+0x48; trace_original_rva=0x4e7c80;
#endif
    auto response_slot=reinterpret_cast<void**>(base+trace_slot_rva);
    uintptr_t response_method=0;
    if (!read(reinterpret_cast<uintptr_t>(response_slot),response_method) || response_method!=base+trace_original_rva) {
        line("{\"event\":\"response_slot_identity_failed\"}\n"); return 20;
    }
    bridge_response_original=reinterpret_cast<void*>(response_method);
#endif
    auto target=reinterpret_cast<unsigned char*>(base+0x10a6d90);
    unsigned char actual[20]; SIZE_T n=0;
    if (!ReadProcessMemory(GetCurrentProcess(),target,actual,20,&n) || n!=20 || memcmp(actual,expected,20)) {
        line("{\"event\":\"signature_mismatch\"}\n"); return 14;
    }
    auto trampoline=static_cast<unsigned char*>(VirtualAlloc(nullptr,34,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE));
    if (!trampoline) return 15;
    memcpy(trampoline,expected,20); absolute_jump(trampoline+20,reinterpret_cast<uintptr_t>(target+20));
    DWORD old=0;
    if (!VirtualProtect(trampoline,34,PAGE_EXECUTE_READ,&old)) return 16;
    FlushInstructionCache(GetCurrentProcess(),trampoline,34);
    bridge_trampoline=trampoline;
    unsigned char patch[20]; memset(patch,0x90,20);
    absolute_jump(patch,reinterpret_cast<uintptr_t>(&bridge_frame_stub));

    // Prepare all allocations/handles before suspending other threads.
    HANDLE threads[2048]; size_t thread_count=0;
    HANDLE snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);
    if (snapshot==INVALID_HANDLE_VALUE) return 17;
    THREADENTRY32 entry{}; entry.dwSize=sizeof(entry);
    bool enumeration_ok=Thread32First(snapshot,&entry);
    bool handles_ok=enumeration_ok;
    if (enumeration_ok) do {
        if (entry.th32OwnerProcessID==GetCurrentProcessId() && entry.th32ThreadID!=GetCurrentThreadId()) {
            HANDLE h=OpenThread(THREAD_SUSPEND_RESUME|THREAD_GET_CONTEXT,FALSE,entry.th32ThreadID);
            if (!h) { handles_ok=false; break; }
            if (thread_count==2048) { CloseHandle(h); handles_ok=false; break; }
            threads[thread_count++]=h;
        }
    } while (Thread32Next(snapshot,&entry));
    CloseHandle(snapshot);
    size_t suspended=0;
    bool safe=handles_ok && thread_count>0;
    if (safe) for (size_t i=0;i<thread_count;++i) {
        HANDLE h=threads[i];
        if (SuspendThread(h)==static_cast<DWORD>(-1)) { safe=false; break; }
        ++suspended;
        CONTEXT context{}; context.ContextFlags=CONTEXT_CONTROL;
        if (!GetThreadContext(h,&context) || (context.Rip>=reinterpret_cast<uintptr_t>(target) &&
            context.Rip<reinterpret_cast<uintptr_t>(target+20))) { safe=false; break; }
    }
    bool patched=false, protection_restored=true, rollback_complete=true;
#ifdef BRIDGE_TRACE_PEACE_RESPONSES
    bool response_patched=false;
    DWORD response_old=0;
#endif
    if (safe && VirtualProtect(target,20,PAGE_EXECUTE_READWRITE,&old)) {
        // Verify again after every existing thread has stopped.
        if (!memcmp(target,expected,20)) {
            memcpy(target,patch,20); FlushInstructionCache(GetCurrentProcess(),target,20); patched=true;
#ifdef BRIDGE_TRACE_PEACE_RESPONSES
            if (*response_slot==bridge_response_original && VirtualProtect(response_slot,8,PAGE_READWRITE,&response_old)) {
                InterlockedExchangePointer(reinterpret_cast<void* volatile*>(response_slot),reinterpret_cast<void*>(&bridge_response_stub));
                response_patched=true;
                DWORD response_ignored;
                if (!VirtualProtect(response_slot,8,response_old,&response_ignored)) {
                    // A failed protection change leaves this slot writable.
                    InterlockedExchangePointer(reinterpret_cast<void* volatile*>(response_slot),bridge_response_original);
                    response_patched=false;
                    VirtualProtect(response_slot,8,response_old,&response_ignored);
                    memcpy(target,expected,20); FlushInstructionCache(GetCurrentProcess(),target,20);
                    patched=false; protection_restored=false;
                }
            } else {
                memcpy(target,expected,20); FlushInstructionCache(GetCurrentProcess(),target,20); patched=false;
            }
#endif
        }
        DWORD ignored;
        if (!VirtualProtect(target,20,old,&ignored)) {
            // Do not leave an installed hook behind an installation error.
            // This failed call leaves the frame page writable.
            memcpy(target,expected,20); FlushInstructionCache(GetCurrentProcess(),target,20);
            patched=false; protection_restored=false;
            VirtualProtect(target,20,old,&ignored);
#ifdef BRIDGE_TRACE_PEACE_RESPONSES
            if (response_patched) {
                DWORD temporary=0;
                if (VirtualProtect(response_slot,8,PAGE_READWRITE,&temporary)) {
                    InterlockedExchangePointer(reinterpret_cast<void* volatile*>(response_slot),bridge_response_original);
                    response_patched=false;
                    VirtualProtect(response_slot,8,response_old,&temporary);
                } else rollback_complete=false;
            }
#endif
        }
    }
    for (size_t i=0;i<suspended;++i) ResumeThread(threads[i]);
    for (size_t i=0;i<thread_count;++i) CloseHandle(threads[i]);
    if (!patched) {
        line(rollback_complete?"{\"event\":\"hook_not_installed\",\"hooks_rolled_back\":true}\n":
            "{\"event\":\"hook_rollback_incomplete\",\"restart_required\":true}\n");
        return rollback_complete?18:21;
    }
#ifdef BRIDGE_TRACE_PEACE_RESPONSES
    char trace_installed[240];
    snprintf(trace_installed,sizeof(trace_installed),"{\"event\":\"%s\",\"slot_rva\":\"0x%llx\",\"original_rva\":\"0x%llx\",\"mutates_actions\":false,\"capacity\":64}\n",
#ifdef BRIDGE_TRACE_COMMAND_EXECUTION
        "command_execution_trace_installed",
#else
        "response_trace_installed",
#endif
        static_cast<unsigned long long>(trace_slot_rva),static_cast<unsigned long long>(trace_original_rva));
    line(trace_installed);
#endif
#ifdef BRIDGE_PEACE_AUTHORITY_LOCK
    line("{\"event\":\"peace_authority_lock_installed\",\"controlled_country\":\"FRA\",\"scope\":\"verified_native_peace_actions_involving_FRA\",\"bridge_sending_enabled\":false,\"other_diplomacy_locked\":false}\n");
#endif
    line(protection_restored?"{\"event\":\"hook_installed\",\"mode\":\"observe\"}\n":
        "{\"event\":\"hook_installed_protection_restore_failed\"}\n");
    return protection_restored?0:19;
}

BOOL WINAPI DllMain(HINSTANCE module,DWORD reason,LPVOID) {
    if (reason==DLL_PROCESS_ATTACH) { self_module=module; DisableThreadLibraryCalls(module); }
    return TRUE;
}
