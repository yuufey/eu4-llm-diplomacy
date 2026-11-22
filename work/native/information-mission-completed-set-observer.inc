// This replaces command-slot observation only in the completed-set build.
#include "information-mission-completion.h"
#include "information-mission-completed-set-entry-plan.h"
#include <atomic>

namespace mission_completion_observer {

namespace owned = information::mission_completion;
namespace plan = information::mission_completed_set::entry;
using Original = uintptr_t(*)(uintptr_t, uintptr_t, uintptr_t, uintptr_t);
struct Value final { uint64_t country = 0; int32_t date = 0; owned::Name mission{}; plan::Path path = plan::Path::none; };
struct Event final { Value value{}; uint64_t sequence = 0; };
struct Pending final {
    Value value{};
    uintptr_t country_pointer = 0, definition = 0, output = 0;
    uint64_t count_before = 0;
    bool observed = false, ready = false, completed_before = false;
};
struct Reader final {
    bool read(uintptr_t address, void* output, size_t bytes) noexcept {
        SIZE_T copied = 0;
        return owned::range(address, bytes)
            && ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<void*>(address), output, bytes, &copied)
            && copied == bytes;
    }
};
static Original original = nullptr;
static plan::Plan image{};
static unsigned char* executable = nullptr;
static RUNTIME_FUNCTION unwind{};
static bridge_entry_patch::PatchPlan patch{};
static bool table_registered = false, published = false;
static std::atomic<bool> installed{false}, transport_fault{false};
static SRWLOCK queue_lock = SRWLOCK_INIT;
static Event events[64]{};
static unsigned head = 0, size = 0;
static volatile LONG64 sequence = 0;
static volatile LONG dropped = 0, total_dropped = 0;

static void note_drop() noexcept {
    InterlockedIncrement(&dropped);
    InterlockedIncrement(&total_dropped);
}

static bool date_now(int32_t& date) noexcept {
    uintptr_t game = 0;
    return !thread_changed && frame_thread == GetCurrentThreadId()
        && read(base+0x233fe58, game) && read(game+0x1dd0, date) && date > 0;
}

static Pending begin(uintptr_t container, uintptr_t output, uintptr_t key, uintptr_t caller) noexcept {
    Pending pending{};
    pending.value.path = plan::classify(base, caller);
    if (!installed || transport_fault || pending.value.path == plan::Path::none) return {};
    pending.observed = true;
    if (!owned::range(container, 0x40) || container < 0x19998) return pending;
    pending.country_pointer = container-0x9998;
    uint64_t reference = 0;
    if (!read(pending.country_pointer+0x20, reference)) return pending;
#ifdef BRIDGE_NATIVE_COUNTRY_CONTROL
    if (!observation_information_country_handle(reference)) return {};
#else
    if ((reference & 0xffffffu) != 0x415246u) return {};
#endif
    pending.value.country = reference;
    pending.output = output;
    uintptr_t canonical = 0;
    Reader reader;
    pending.ready = date_now(pending.value.date)
        && insult_query_country(reference, canonical) && canonical == pending.country_pointer
        && owned::range(output, 16) && owned::range(key, 8) && read(key, pending.definition)
        && owned::range(pending.definition, 0x30)
        && owned::name(reader, pending.definition+0x10, pending.value.mission)
        && read(container+0x10, pending.count_before) && pending.count_before <= owned::kMaxCompleted
        && owned::definition_membership(reader, canonical, pending.definition, pending.completed_before);
    return pending;
}

static void finish(Pending& pending, uintptr_t returned) noexcept {
    if (!pending.observed) return;
    pending.observed = false;
    uintptr_t canonical = 0, node = 0, stored_definition = 0;
    int32_t date = 0;
    uint64_t count_after = 0;
    unsigned char inserted = 0xff;
    owned::Name after_name{};
    bool completed_after = false;
    Reader reader;
    if (!pending.ready || transport_fault || returned != pending.output
        || !date_now(date) || date != pending.value.date
        || !insult_query_country(pending.value.country, canonical) || canonical != pending.country_pointer
        || !owned::name(reader, pending.definition+0x10, after_name)
        || !owned::equal(pending.value.mission, after_name)
        || !read(pending.output, node) || !read(pending.output+8, inserted) || inserted > 1
        || !owned::range(node, 24) || !read(node+0x10, stored_definition) || stored_definition != pending.definition
        || !read(canonical+0x99a8, count_after) || count_after > owned::kMaxCompleted
        || !owned::definition_membership(reader, canonical, pending.definition, completed_after)) {
        note_drop();
        return;
    }
    // A duplicate return is not a new insertion. Nested insertions are observed
    // by their own invocation, without an outer command producing a duplicate.
    if (!inserted) return;
    if (pending.completed_before || !completed_after || count_after <= pending.count_before) { note_drop(); return; }
    Event event{pending.value, static_cast<uint64_t>(InterlockedIncrement64(&sequence))};
    if (!TryAcquireSRWLockExclusive(&queue_lock)) { note_drop(); return; }
    if (size < 64) { events[(head+size)%64] = event; ++size; }
    else note_drop();
    ReleaseSRWLockExclusive(&queue_lock);
}

struct PendingCleanup final {
    Pending& pending;
    ~PendingCleanup() noexcept {
        if (pending.observed) { pending.observed = false; note_drop(); }
    }
};

static uintptr_t observe(uintptr_t container, uintptr_t output, uintptr_t key, uintptr_t fourth) {
    const auto call = original;
    if (!call) return 0;
    const auto caller = reinterpret_cast<uintptr_t>(__builtin_return_address(0));
    if (!installed || transport_fault || plan::classify(base, caller) == plan::Path::none)
        return call(container, output, key, fourth);
    const DWORD incoming_error = GetLastError();
    auto pending = begin(container, output, key, caller);
    PendingCleanup cleanup{pending};
    SetLastError(incoming_error);
    const uintptr_t returned = call(container, output, key, fourth);
    const DWORD returned_error = GetLastError();
    finish(pending, returned);
    SetLastError(returned_error);
    return returned;
}

static bool caller_guard(uint32_t return_rva) noexcept {
    unsigned char bytes[5]{};
    const int32_t displacement = static_cast<int32_t>(plan::kEntryRva)-static_cast<int32_t>(return_rva);
    return read(base+return_rva-5, bytes) && bytes[0] == 0xe8
        && !std::memcmp(bytes+1, &displacement, sizeof(displacement));
}

static void release_unpublished() noexcept {
    if (published) return;
    if (table_registered && !RtlDeleteFunctionTable(&unwind)) { lifecycle_rollback_incomplete = true; return; }
    if (executable) VirtualFree(executable, 0, MEM_RELEASE);
    table_registered = false;
    executable = nullptr;
    original = nullptr;
}

static bool install() noexcept {
    if (original || published) return false;
    Reader reader;
    std::array<unsigned char, plan::kPatchBytes> prefix{};
    std::array<unsigned char, 32> metadata{};
    DWORD64 image_base = 0;
    const auto parent = RtlLookupFunctionEntry(base+plan::kEntryRva, &image_base, nullptr);
    if (!parent || image_base != base || parent->BeginAddress != plan::kEntryRva
        || parent->EndAddress != plan::kSourceEndRva || parent->UnwindData != plan::kUnwindRva
        || !caller_guard(plan::kCommandReturnRva) || !caller_guard(plan::kEffectReturnRva)
        || !reader.read(base+plan::kEntryRva, prefix.data(), prefix.size())
        || !reader.read(base+plan::kUnwindRva, metadata.data(), metadata.size())
        || !plan::prepare(prefix, metadata, base+plan::kEntryRva, reinterpret_cast<uintptr_t>(&observe), image)) return false;
    executable = static_cast<unsigned char*>(VirtualAlloc(nullptr, image.image.size(), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE));
    if (!executable) return false;
    std::memcpy(executable, image.image.data(), image.image.size());
    DWORD previous = 0;
    if (!VirtualProtect(executable, image.image.size(), PAGE_EXECUTE_READ, &previous)
        || !FlushInstructionCache(GetCurrentProcess(), executable, image.image.size())) {
        release_unpublished();
        return false;
    }
    unwind = {image.runtime.begin, image.runtime.end, image.runtime.unwind};
    table_registered = RtlAddFunctionTable(&unwind, 1, reinterpret_cast<DWORD64>(executable)) != FALSE;
    if (!table_registered) { release_unpublished(); return false; }
    original = reinterpret_cast<Original>(executable);
    patch.count = 1;
    patch.targets[0] = {reinterpret_cast<void*>(base+plan::kEntryRva), plan::kPatchBytes,
        plan::kPrefix.data(), image.patch.data(), executable, image.runtime.end};
    const auto result = bridge_entry_patch::guarded_patch_apply(patch);
    published = result.published;
    if (!published) release_unpublished();
    return result.success && result.threads_resumed && result.protection_restored;
}

static bool rollback() noexcept {
    installed = false;
    if (!published) return true;
    const auto result = bridge_entry_patch::guarded_patch_rollback(patch);
    return result.success && result.threads_resumed && result.protection_restored;
}

static bool append(const char* message, size_t bytes) noexcept {
    if (transport_fault || log_file == INVALID_HANDLE_VALUE) { transport_fault = true; return false; }
    DWORD written = 0;
    if (!WriteFile(log_file, message, static_cast<DWORD>(bytes), &written, nullptr)
        || written != bytes || !FlushFileBuffers(log_file)) { transport_fault = true; return false; }
    return true;
}

static void flush() noexcept {
    if (!installed || transport_fault) return;
    for (unsigned index = 0; index < 32; ++index) {
        Event event{};
        if (!TryAcquireSRWLockExclusive(&queue_lock)) return;
        if (!size) { ReleaseSRWLockExclusive(&queue_lock); break; }
        event = events[head];
        ReleaseSRWLockExclusive(&queue_lock);
        char name_hex[owned::kMaxName*2+1]{};
        for (unsigned byte = 0; byte < event.value.mission.length; ++byte)
            std::snprintf(name_hex+byte*2, 3, "%02x", static_cast<unsigned char>(event.value.mission.text[byte]));
        const auto reference=event.value.country;
        const char country[4]={static_cast<char>(reference),static_cast<char>(reference>>8),
                               static_cast<char>(reference>>16),0};
#ifdef BRIDGE_NATIVE_COUNTRY_CONTROL
        constexpr unsigned schema=3;
#else
        constexpr unsigned schema=2;
#endif
        char message[1400]{};
        const int bytes = std::snprintf(message, sizeof(message),
            "{\"event\":\"native_mission_completed\",\"schema_version\":%u,\"session_id\":\"%lu-%llx\","
            "\"sequence\":%llu,\"country\":\"%.3s\",\"country_fullref\":\"0x%llx\",\"date_raw\":%d,"
            "\"mission_id_hex\":\"%s\",\"completed_before\":false,\"completed_after\":true,"
            "\"completion_path\":\"%s\",\"source\":\"mission_completed_set_insert_normal_return\",\"complete\":true}\n",
            schema,static_cast<unsigned long>(GetCurrentProcessId()), static_cast<unsigned long long>(observation_creation),
            static_cast<unsigned long long>(event.sequence),country,static_cast<unsigned long long>(reference),
            event.value.date, name_hex, event.value.path == plan::Path::command ? "command_handler" : "script_effect");
        if (bytes <= 0 || static_cast<size_t>(bytes) >= sizeof(message)) { transport_fault = true; return; }
        if (!append(message, static_cast<size_t>(bytes))) return;
        AcquireSRWLockExclusive(&queue_lock);
        head = (head+1)%64;
        --size;
        ReleaseSRWLockExclusive(&queue_lock);
    }
    const LONG count = InterlockedCompareExchange(&dropped, 0, 0);
    if (count) {
        char message[256]{};
        const int bytes = std::snprintf(message, sizeof(message),
            "{\"event\":\"native_mission_capture_gap\",\"session_id\":\"%lu-%llx\",\"dropped\":%ld,\"complete\":false}\n",
            static_cast<unsigned long>(GetCurrentProcessId()), static_cast<unsigned long long>(observation_creation),
            static_cast<long>(count));
        if (bytes > 0 && static_cast<size_t>(bytes) < sizeof(message) && append(message, bytes))
            InterlockedExchangeAdd(&dropped, -count);
    }
}

static void append_health(char* message, size_t capacity) noexcept {
    char* end = std::strrchr(message, '}');
    if (!end) return;
    const bool readable = TryAcquireSRWLockShared(&queue_lock) != FALSE;
    const unsigned queued = readable ? size : 0;
    if (readable) ReleaseSRWLockShared(&queue_lock);
    std::snprintf(end, capacity-static_cast<size_t>(end-message),
        ",\"mission_source\":{\"installed\":%s,\"transport_fault\":%s,\"total_dropped\":%ld,"
        "\"queue_readable\":%s,\"queued\":%u}}\n",
        installed.load() ? "true" : "false", transport_fault.load() ? "true" : "false",
        static_cast<long>(InterlockedCompareExchange(&total_dropped, 0, 0)), readable ? "true" : "false", queued);
}

} // namespace mission_completion_observer
