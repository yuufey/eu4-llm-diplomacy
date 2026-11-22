// The native predicate is shared by task callers. Observation never invokes it.
#include "information-mission-availability.h"
#include "information-mission-availability-entry-plan.h"
#include <atomic>

namespace mission_availability_observer {

namespace owned = information::mission_availability;
namespace plan = information::mission_availability::entry;
namespace names = information::mission_completion;
using Original = uint64_t(*)(void*, uint64_t);
struct Event final { owned::Change change{}; uint64_t sequence = 0; };
enum class DropReason : unsigned {
    clock_before, country_before, name_before, nesting_limit, invalid_return,
    clock_after, country_after, name_after, baseline_rejected, queue_busy,
    queue_full, original_unwound, transport_fault, count,
};
struct Pending final {
    owned::Value value{};
    uintptr_t country_pointer = 0;
    DropReason failure = DropReason::clock_before;
    bool observed = false, ready = false, entered = false;
#ifdef BRIDGE_MISSION_CONDITION_OBSERVATION
    uint64_t condition_scope = 0;
#endif
};
struct Reader final {
    bool read(uintptr_t address, void* output, size_t bytes) noexcept {
        SIZE_T copied = 0;
        return names::range(address, bytes)
            && ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<void*>(address), output, bytes, &copied)
            && copied == bytes;
    }
};
struct Active final { uint64_t country = 0; uintptr_t definition = 0; };
static thread_local Active active[16]{};
static thread_local unsigned depth = 0;
static Original original = nullptr;
static plan::Plan image{};
static unsigned char* executable = nullptr;
static RUNTIME_FUNCTION unwind{};
static bridge_entry_patch::PatchPlan patch{};
static bool table_registered = false, published = false;
static std::atomic<bool> installed{false}, transport_fault{false};
static owned::Baselines baselines{};
static SRWLOCK queue_lock = SRWLOCK_INIT;
static Event events[64]{};
static unsigned head = 0, size = 0;
static volatile LONG64 sequence = 0;
static volatile LONG dropped = 0, total_dropped = 0;
static volatile LONG reason_drops[static_cast<unsigned>(DropReason::count)]{};
static volatile LONG64 evaluations = 0, worker_evaluations = 0, validated_evaluations = 0;
static volatile LONG last_evaluation_thread = 0;

static void note_drop(DropReason reason) noexcept {
    InterlockedIncrement(&reason_drops[static_cast<unsigned>(reason)]);
    InterlockedIncrement(&dropped);
    InterlockedIncrement(&total_dropped);
}

static bool date_now(int32_t& date) noexcept {
    uintptr_t game = 0;
    // Task callers may run on AI workers. These are bounded value reads,
    // with the country, date and definition checked again after its own call.
    return !thread_changed
        && read(base+0x233fe58, game) && read(game+0x1dd0, date) && date > 0;
}

static Pending begin(void* definition, uint64_t country) noexcept {
    Pending pending{};
    if (!installed || transport_fault) return pending;
#ifdef BRIDGE_NATIVE_COUNTRY_CONTROL
    if (!observation_information_country_handle(country)) return pending;
#else
    if ((country & 0xffffffu) != 0x415246u) return pending;
#endif
    pending.observed = true;
    pending.value.country = country;
    pending.value.definition = reinterpret_cast<uintptr_t>(definition);
    InterlockedIncrement64(&evaluations);
    const DWORD caller = GetCurrentThreadId();
    InterlockedExchange(&last_evaluation_thread, static_cast<LONG>(caller));
    if (caller != frame_thread) InterlockedIncrement64(&worker_evaluations);
    Reader reader;
    if (!date_now(pending.value.date)) return pending;
    pending.failure = DropReason::country_before;
    if (!insult_query_country(country, pending.country_pointer)) return pending;
    pending.failure = DropReason::name_before;
    if (!names::range(pending.value.definition, 0x30)
            || !names::name(reader, pending.value.definition+0x10, pending.value.mission)) return pending;
    pending.ready = true;
    if (pending.ready) {
        for (unsigned index = 0; index < depth; ++index) {
            if (active[index].country == country && active[index].definition == pending.value.definition) return {};
        }
        if (depth == 16) { pending.ready = false; pending.failure = DropReason::nesting_limit; }
        else {
            active[depth++] = {country, pending.value.definition};
            pending.entered = true;
#ifdef BRIDGE_MISSION_CONDITION_OBSERVATION
            pending.condition_scope = mission_condition_observer::begin(country, pending.value.definition,
                pending.value.mission, pending.value.date);
#endif
        }
    }
    return pending;
}

static void finish(Pending& pending, uint64_t returned) noexcept {
    if (!pending.observed) return;
    pending.observed = false;
    if (pending.entered) --depth;
    uintptr_t country = 0;
    int32_t date = 0;
    Reader reader;
    names::Name after_name{};
    if (!pending.ready) { note_drop(pending.failure); return; }
    if (returned > 1) { note_drop(DropReason::invalid_return); return; }
    if (transport_fault) { note_drop(DropReason::transport_fault); return; }
    if (!date_now(date) || date != pending.value.date) { note_drop(DropReason::clock_after); return; }
    if (!insult_query_country(pending.value.country, country) || country != pending.country_pointer) {
        note_drop(DropReason::country_after);
        return;
    }
    if (!names::name(reader, pending.value.definition+0x10, after_name)
            || !names::equal(pending.value.mission, after_name)) { note_drop(DropReason::name_after); return; }
    InterlockedIncrement64(&validated_evaluations);
    pending.value.eligible = returned != 0;
#ifdef BRIDGE_MISSION_CONDITION_OBSERVATION
    mission_condition_observer::finish(pending.condition_scope);
#endif
    if (!TryAcquireSRWLockExclusive(&queue_lock)) { note_drop(DropReason::queue_busy); return; }
    // One lock orders the baseline update, sequence assignment and publication.
    // Frame-thread flushing uses the same lock for its short queue operations.
    struct QueueRelease final {
        ~QueueRelease() { ReleaseSRWLockExclusive(&queue_lock); }
    } release;
    owned::Change change{};
    const auto result = baselines.observe(pending.value, change);
    if (result == owned::Result::reset || result == owned::Result::invalid || result == owned::Result::full) {
        note_drop(DropReason::baseline_rejected);
        return;
    }
    if (result != owned::Result::changed) return;
    Event event{change, static_cast<uint64_t>(InterlockedIncrement64(&sequence))};
    if (size < 64) { events[(head+size)%64] = event; ++size; }
    else note_drop(DropReason::queue_full);
}

struct PendingCleanup final {
    Pending& pending;
    ~PendingCleanup() noexcept {
#ifdef BRIDGE_MISSION_CONDITION_OBSERVATION
        mission_condition_observer::abort(pending.condition_scope);
#endif
        if (!pending.observed) return;
        pending.observed = false;
        if (pending.entered) --depth;
        note_drop(DropReason::original_unwound);
    }
};

static uint64_t observe(void* definition, uint64_t country) {
    const auto call = original;
    if (!call) return 0;
    const DWORD incoming_error = GetLastError();
    auto pending = begin(definition, country);
    PendingCleanup cleanup{pending};
    SetLastError(incoming_error);
    const uint64_t returned = call(definition, country);
    const DWORD returned_error = GetLastError();
    finish(pending, returned);
    SetLastError(returned_error);
    return returned;
}

static void release_unpublished() noexcept {
    if (published) return;
    if (table_registered && !RtlDeleteFunctionTable(&unwind)) {
        lifecycle_rollback_incomplete = true;
        return;
    }
    if (executable) VirtualFree(executable, 0, MEM_RELEASE);
    table_registered = false;
    executable = nullptr;
    original = nullptr;
}

static bool install() noexcept {
    if (original || published) return false;
    Reader reader;
    std::array<unsigned char, plan::kPatchBytes> prefix{};
    std::array<unsigned char, 28> metadata{};
    DWORD64 image_base = 0;
    const auto parent = RtlLookupFunctionEntry(base+plan::kEntryRva, &image_base, nullptr);
    if (!parent || image_base != base || parent->BeginAddress != plan::kEntryRva
        || parent->EndAddress != plan::kSourceEndRva || parent->UnwindData != plan::kUnwindRva
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
    const bool ready = result.success && result.threads_resumed && result.protection_restored;
    if (!published) release_unpublished();
    return ready;
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
        const auto& value = event.change.after;
        char name_hex[names::kMaxName*2+1]{};
        for (unsigned byte = 0; byte < value.mission.length; ++byte)
            std::snprintf(name_hex+byte*2, 3, "%02x", static_cast<unsigned char>(value.mission.text[byte]));
        const char country[4]={static_cast<char>(value.country),static_cast<char>(value.country>>8),
                               static_cast<char>(value.country>>16),0};
#ifdef BRIDGE_NATIVE_COUNTRY_CONTROL
        constexpr unsigned schema=2;
#else
        constexpr unsigned schema=1;
#endif
        char message[1400]{};
        const int bytes = std::snprintf(message, sizeof(message),
            "{\"event\":\"native_mission_availability_changed\",\"schema_version\":%u,\"session_id\":\"%lu-%llx\","
            "\"sequence\":%llu,\"country\":\"%.3s\",\"country_fullref\":\"0x%llx\",\"date_raw\":%d,"
            "\"previous_observed_date_raw\":%d,\"mission_id_hex\":\"%s\",\"eligible_before\":%s,\"eligible_after\":%s,"
            "\"source\":\"mission_eligibility_native_return\",\"complete\":true}\n",
            schema,static_cast<unsigned long>(GetCurrentProcessId()), static_cast<unsigned long long>(observation_creation),
            static_cast<unsigned long long>(event.sequence),country,static_cast<unsigned long long>(value.country),
            value.date, event.change.previous_date, name_hex,
            event.change.before ? "true" : "false", value.eligible ? "true" : "false");
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
            "{\"event\":\"native_mission_availability_capture_gap\",\"session_id\":\"%lu-%llx\",\"dropped\":%ld,\"complete\":false}\n",
            static_cast<unsigned long>(GetCurrentProcessId()), static_cast<unsigned long long>(observation_creation),
            static_cast<long>(count));
        if (bytes > 0 && static_cast<size_t>(bytes) < sizeof(message) && append(message, bytes))
            InterlockedExchangeAdd(&dropped, -count);
    }
}

static void append_health(char* message, size_t capacity) noexcept {
    char* end = std::strrchr(message, '}');
    if (!end || end-message < 1) return;
    const bool readable = TryAcquireSRWLockShared(&queue_lock) != FALSE;
    const unsigned queued = readable ? size : 0;
    const unsigned baseline_count = readable ? baselines.count : 0;
    if (readable) ReleaseSRWLockShared(&queue_lock);
    std::snprintf(end, capacity-static_cast<size_t>(end-message),
        ",\"mission_availability_source\":{\"installed\":%s,\"transport_fault\":%s,\"total_dropped\":%ld,"
        "\"queue_readable\":%s,\"queued\":%u,\"baseline_count\":%u,"
        "\"evaluations\":%llu,\"worker_evaluations\":%llu,\"validated_evaluations\":%llu,"
        "\"last_evaluation_thread\":%lu,\"frame_thread\":%lu,\"drops_by_reason\":{"
        "\"clock_before\":%ld,\"country_before\":%ld,\"name_before\":%ld,\"nesting_limit\":%ld,"
        "\"invalid_return\":%ld,\"clock_after\":%ld,\"country_after\":%ld,\"name_after\":%ld,"
        "\"baseline_rejected\":%ld,\"queue_busy\":%ld,\"queue_full\":%ld,\"original_unwound\":%ld,"
        "\"transport_fault\":%ld}}}\n",
        installed.load() ? "true" : "false", transport_fault.load() ? "true" : "false",
        static_cast<long>(InterlockedCompareExchange(&total_dropped, 0, 0)), readable ? "true" : "false", queued, baseline_count,
        static_cast<unsigned long long>(InterlockedCompareExchange64(&evaluations, 0, 0)),
        static_cast<unsigned long long>(InterlockedCompareExchange64(&worker_evaluations, 0, 0)),
        static_cast<unsigned long long>(InterlockedCompareExchange64(&validated_evaluations, 0, 0)),
        static_cast<unsigned long>(InterlockedCompareExchange(&last_evaluation_thread, 0, 0)),
        static_cast<unsigned long>(frame_thread),
        static_cast<long>(InterlockedCompareExchange(&reason_drops[0], 0, 0)),
        static_cast<long>(InterlockedCompareExchange(&reason_drops[1], 0, 0)),
        static_cast<long>(InterlockedCompareExchange(&reason_drops[2], 0, 0)),
        static_cast<long>(InterlockedCompareExchange(&reason_drops[3], 0, 0)),
        static_cast<long>(InterlockedCompareExchange(&reason_drops[4], 0, 0)),
        static_cast<long>(InterlockedCompareExchange(&reason_drops[5], 0, 0)),
        static_cast<long>(InterlockedCompareExchange(&reason_drops[6], 0, 0)),
        static_cast<long>(InterlockedCompareExchange(&reason_drops[7], 0, 0)),
        static_cast<long>(InterlockedCompareExchange(&reason_drops[8], 0, 0)),
        static_cast<long>(InterlockedCompareExchange(&reason_drops[9], 0, 0)),
        static_cast<long>(InterlockedCompareExchange(&reason_drops[10], 0, 0)),
        static_cast<long>(InterlockedCompareExchange(&reason_drops[11], 0, 0)),
        static_cast<long>(InterlockedCompareExchange(&reason_drops[12], 0, 0)));
}

} // namespace mission_availability_observer
