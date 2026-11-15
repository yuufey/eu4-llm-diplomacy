#include "information-mission-conditions.h"
#include "information-mission-condition-entry-plan.h"
#include <atomic>
#ifdef BRIDGE_MISSION_PROVINCE_CONDITION_OBSERVATION
#include "information-mission-province-conditions.h"
#include "information-mission-province-entry-plan.h"
#endif

namespace mission_condition_observer {

namespace owned = information::mission_conditions;
namespace plan = information::mission_condition::dispatch;
namespace names = information::mission_completion;
struct Reader final {
    bool read(uintptr_t address, void* output, size_t bytes) noexcept {
        SIZE_T copied = 0;
        return names::range(address, bytes)
            && ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<void*>(address), output, bytes, &copied)
            && copied == bytes;
    }
};
struct Scope final {
    owned::Evaluation value{};
    uint64_t token = 0;
#ifdef BRIDGE_MISSION_PROVINCE_CONDITION_OBSERVATION
    struct ProvinceSample final {
        information::mission_province_condition::Binding binding{};
        uint64_t returned = 0;
    };
    ProvinceSample province_samples[128]{};
    unsigned province_count = 0;
    bool province_valid = true;
#endif
};
struct Event final {
    names::Name mission{};
    owned::Node node{};
    owned::NodeChange change{};
    uint64_t country = 0, sequence = 0;
    int32_t date = 0;
    unsigned root_count = 0, observed_count = 0;
    unsigned child_index = 0, child_count = 0, province_id = 0;
};
static thread_local Scope scopes[16]{};
static thread_local unsigned depth = 0;
static thread_local uint64_t next_token = 0;
static std::atomic<unsigned> active_scopes{0};
static std::atomic<bool> installed{false}, transport_fault{false};
static std::atomic<const char*> last_drop_reason{"none"};
static volatile LONG dropped = 0, total_dropped = 0;
static volatile LONG64 evaluations = 0, observed_evaluations = 0, unevaluated = 0, ignored_nested = 0;
static SRWLOCK queue_lock = SRWLOCK_INIT;
static owned::Baselines baselines{};
static Event events[64]{};
static unsigned head = 0, size = 0;
static uint64_t sequence = 0;
static plan::Plan image{};
static unsigned char* executable = nullptr;
static RUNTIME_FUNCTION unwind[2]{};
static bridge_entry_patch::PatchPlan patch{};
static bool table_registered = false, published = false;
#ifdef BRIDGE_MISSION_PROVINCE_CONDITION_OBSERVATION
namespace province {
static void commit(const Scope& scope, Reader& reader) noexcept;
static bool rollback() noexcept;
static unsigned baseline_count_locked() noexcept;
}
#endif

static void note_drop(const char* reason = "unspecified") noexcept {
    last_drop_reason.store(reason, std::memory_order_relaxed);
    InterlockedIncrement(&dropped);
    InterlockedIncrement(&total_dropped);
}

static uint64_t begin(uint64_t country, uintptr_t definition, const names::Name& mission, int32_t date) noexcept {
    if (!installed || transport_fault) return 0;
    if (depth == 16 || !names::valid(mission) || date <= 0 || (country&0xffffffu) != 0x415246u) {
        note_drop("scope_limit_or_invalid_input");
        return 0;
    }
    auto& scope = scopes[depth];
    scope = {};
    Reader reader;
    if (!owned::read_root(reader, base, definition, scope.value.root)) { note_drop("root_read_or_contract"); return 0; }
    scope.value.country = country;
    scope.value.mission = mission;
    scope.value.date = date;
    scope.value.valid = true;
    scope.token = ++next_token;
    if (!scope.token) { transport_fault = true; note_drop("token_exhausted"); return 0; }
    ++depth;
    active_scopes.fetch_add(1, std::memory_order_relaxed);
    InterlockedIncrement64(&evaluations);
    return scope.token;
}

static Scope* current(uint64_t token) noexcept {
    if (!token) return nullptr;
    if (!depth || scopes[depth-1].token != token) {
        transport_fault = true;
        note_drop("scope_ownership");
        return nullptr;
    }
    return &scopes[depth-1];
}

static void close(uint64_t& token) noexcept {
    if (!token) return;
    if (current(token)) {
        scopes[--depth].token = 0;
        active_scopes.fetch_sub(1, std::memory_order_relaxed);
    }
    token = 0;
}

static void abort(uint64_t& token) noexcept {
    if (token && installed && !transport_fault) note_drop("parent_evaluation_rejected_or_unwound");
    close(token);
}

static void observe(void* child, void* context, uint64_t returned, void* slot, void* callee) noexcept {
    // No TLS lookup or Windows call on the common unowned path.
    if (!active_scopes.load(std::memory_order_relaxed) || !installed || transport_fault) return;
    const DWORD error = GetLastError();
    if (depth) {
        Reader reader;
        const auto result = scopes[depth-1].value.observe(reader, base, reinterpret_cast<uintptr_t>(child),
            reinterpret_cast<uintptr_t>(context), returned, reinterpret_cast<uintptr_t>(slot),
            reinterpret_cast<uintptr_t>(callee));
        if (result == owned::CaptureResult::ignored) InterlockedIncrement64(&ignored_nested);
    }
    SetLastError(error);
}

static void finish(uint64_t& token) noexcept {
    auto* scope = current(token);
    if (!scope) { token = 0; return; }
    struct Close final { uint64_t& token; ~Close() { close(token); } } cleanup{token};
    if (!installed || transport_fault) return;
    const auto& value = scope->value;
    if (!value.seen && value.valid) { InterlockedIncrement64(&unevaluated); return; }
    Reader reader;
    owned::Root after{};
    if (!value.complete()) { note_drop("root_callback_binding_or_incomplete"); return; }
    if (!owned::read_root(reader, base, value.root.definition, after)
        || !owned::same(value.root, after)) { note_drop("root_changed_after_evaluation"); return; }
    if (!TryAcquireSRWLockExclusive(&queue_lock)) { note_drop("queue_busy"); return; }
    struct Unlock final { ~Unlock() { ReleaseSRWLockExclusive(&queue_lock); } } unlock;
    owned::Changes changes{};
    const auto result = baselines.observe(value, changes);
    if (result == owned::Result::invalid || result == owned::Result::full || result == owned::Result::reset) {
        note_drop("baseline_invalid_full_or_reset");
        return;
    }
    InterlockedIncrement64(&observed_evaluations);
    for (unsigned index = 0; index < changes.count; ++index) {
        const auto& change = changes.nodes[index];
        Event event{value.mission, value.root.nodes[change.index], change, value.country,
            ++sequence, value.date, value.root.count, value.seen};
        if (size < 64) { events[(head+size)%64] = event; ++size; }
        else note_drop("queue_full");
    }
#ifdef BRIDGE_MISSION_PROVINCE_CONDITION_OBSERVATION
    province::commit(*scope, reader);
#endif
}

static void release_unpublished() noexcept {
    if (published) return;
    if (table_registered && !RtlDeleteFunctionTable(unwind)) { lifecycle_rollback_incomplete = true; return; }
    if (executable) VirtualFree(executable, 0, MEM_RELEASE);
    executable = nullptr;
    table_registered = false;
}

static bool install() noexcept {
    if (executable || published) return false;
    Reader reader;
    std::array<unsigned char, 96> source{};
    std::array<unsigned char, 16> metadata{};
    DWORD64 image_base = 0;
    const auto parent = RtlLookupFunctionEntry(base+plan::kFunctionRva, &image_base, nullptr);
    if (!parent || image_base != base || parent->BeginAddress != plan::kFunctionRva
        || parent->EndAddress != plan::kFunctionEndRva || parent->UnwindData != plan::kSourceUnwindRva
        || !reader.read(base+plan::kFunctionRva, source.data(), source.size())
        || !reader.read(base+plan::kSourceUnwindRva, metadata.data(), metadata.size())) return false;
    // Reuse the existing bounded near-allocation strategy used by inbound hooks.
    for (unsigned index = 0; index < 2048; ++index) {
        const uintptr_t desired = base+0x10000000u+static_cast<uintptr_t>(index)*0x100000u;
        auto* block = static_cast<unsigned char*>(VirtualAlloc(reinterpret_cast<void*>(desired), image.image.size(),
            MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE));
        if (!block) continue;
        if (plan::prepare(source, metadata, base+plan::kFunctionRva, reinterpret_cast<uintptr_t>(block),
                          reinterpret_cast<uintptr_t>(&observe), image)) { executable = block; break; }
        VirtualFree(block, 0, MEM_RELEASE);
    }
    if (!executable) return false;
    std::memcpy(executable, image.image.data(), image.image.size());
    DWORD previous = 0;
    if (!VirtualProtect(executable, image.image.size(), PAGE_EXECUTE_READ, &previous)
        || !FlushInstructionCache(GetCurrentProcess(), executable, image.image.size())) {
        release_unpublished(); return false;
    }
    unwind[0] = {image.runtime.begin, image.runtime.end, image.runtime.unwind};
    unwind[1] = {image.barrier_runtime.begin, image.barrier_runtime.end, image.barrier_runtime.unwind};
    table_registered = RtlAddFunctionTable(unwind, 2, reinterpret_cast<DWORD64>(executable)) != FALSE;
    if (!table_registered) { release_unpublished(); return false; }
    patch.count = 1;
    patch.targets[0] = {reinterpret_cast<void*>(base+plan::kFunctionRva+plan::kPatchOffset), plan::kPatchBytes,
        plan::kSource.data()+plan::kPatchOffset, image.patch.data(),
        executable+plan::kBarrierFunctionOffset+plan::kPatchOffset,
        plan::kSource.size()-plan::kPatchOffset};
    const auto result = bridge_entry_patch::guarded_patch_apply(patch);
    published = result.published;
    if (!published) release_unpublished();
    return result.success && result.threads_resumed && result.protection_restored;
}

static bool rollback() noexcept {
    installed = false;
#ifdef BRIDGE_MISSION_PROVINCE_CONDITION_OBSERVATION
    const bool province_restored = province::rollback();
#endif
    if (!published) {
#ifdef BRIDGE_MISSION_PROVINCE_CONDITION_OBSERVATION
        return province_restored;
#else
        return true;
#endif
    }
    const auto result = bridge_entry_patch::guarded_patch_rollback(patch);
    return result.success && result.threads_resumed && result.protection_restored
#ifdef BRIDGE_MISSION_PROVINCE_CONDITION_OBSERVATION
        && province_restored
#endif
        ;
}

static bool append(const char* text, size_t bytes) noexcept {
    DWORD written = 0;
    if (log_file == INVALID_HANDLE_VALUE || !WriteFile(log_file, text, static_cast<DWORD>(bytes), &written, nullptr)
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
        char name_hex[names::kMaxName*2+1]{};
        for (unsigned byte = 0; byte < event.mission.length; ++byte)
            std::snprintf(name_hex+byte*2, 3, "%02x", static_cast<unsigned char>(event.mission.text[byte]));
        char message[1700]{};
        char province_fields[128]{};
        if (event.province_id) std::snprintf(province_fields, sizeof(province_fields),
            ",\"child_index\":%u,\"child_count\":%u,\"province_id\":%u",
            event.child_index, event.child_count, event.province_id);
        const int bytes = std::snprintf(message, sizeof(message),
            "{\"event\":\"native_mission_condition_changed\",\"schema_version\":%u,\"session_id\":\"%lu-%llx\","
            "\"sequence\":%llu,\"country\":\"FRA\",\"country_fullref\":\"0x%llx\",\"date_raw\":%d,"
            "\"previous_observed_date_raw\":%d,\"mission_id_hex\":\"%s\",\"condition_index\":%u,"
            "\"condition_node\":\"0x%llx\",\"condition_method_rva\":%llu,"
            "\"satisfied_before\":%s,\"satisfied_after\":%s,\"native_return_before\":\"0x%llx\","
            "\"native_return_after\":\"0x%llx\",\"root_condition_count\":%u,\"observed_condition_count\":%u,"
            "\"source\":\"%s\",\"complete\":false%s}\n",
            event.province_id ? 2u : 1u,
            static_cast<unsigned long>(GetCurrentProcessId()), static_cast<unsigned long long>(observation_creation),
            static_cast<unsigned long long>(event.sequence), static_cast<unsigned long long>(event.country), event.date,
            event.change.previous_date, name_hex, event.change.index,
            static_cast<unsigned long long>(event.node.child), static_cast<unsigned long long>(event.node.callee-base),
            (event.change.before&0xff) ? "true" : "false", (event.change.after&0xff) ? "true" : "false",
            static_cast<unsigned long long>(event.change.before), static_cast<unsigned long long>(event.change.after),
            event.root_count, event.observed_count,
            event.province_id ? "mission_direct_area_province_holding_return" : "mission_root_conjunction_child_return",
            province_fields);
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
            "{\"event\":\"native_mission_condition_capture_gap\",\"session_id\":\"%lu-%llx\",\"dropped\":%ld,\"complete\":false}\n",
            static_cast<unsigned long>(GetCurrentProcessId()), static_cast<unsigned long long>(observation_creation), static_cast<long>(count));
        if (bytes > 0 && static_cast<size_t>(bytes) < sizeof(message) && append(message, bytes)) InterlockedExchangeAdd(&dropped, -count);
    }
}

static void append_health(char* message, size_t capacity) noexcept {
    const bool readable = TryAcquireSRWLockShared(&queue_lock) != FALSE;
    const unsigned queued = readable ? size : 0;
    const unsigned count = readable ? baselines.count : 0;
#ifdef BRIDGE_MISSION_PROVINCE_CONDITION_OBSERVATION
    const unsigned province_count = readable ? province::baseline_count_locked() : 0;
#endif
    if (readable) ReleaseSRWLockShared(&queue_lock);
    char status[800]{};
    const int bytes = std::snprintf(status, sizeof(status),
        ",\"mission_condition_source\":{\"installed\":%s,\"transport_fault\":%s,\"total_dropped\":%ld,"
        "\"queue_readable\":%s,\"queued\":%u,\"baseline_count\":%u,\"active_scopes\":%u,"
        "\"evaluations\":%llu,\"observed_evaluations\":%llu,\"unevaluated\":%llu,\"ignored_nested\":%llu,"
        "\"last_drop_reason\":\"%s\"}",
        installed ? "true" : "false", transport_fault ? "true" : "false",
        static_cast<long>(InterlockedCompareExchange(&total_dropped, 0, 0)), readable ? "true" : "false", queued, count,
        active_scopes.load(std::memory_order_relaxed),
        static_cast<unsigned long long>(InterlockedCompareExchange64(&evaluations, 0, 0)),
        static_cast<unsigned long long>(InterlockedCompareExchange64(&observed_evaluations, 0, 0)),
        static_cast<unsigned long long>(InterlockedCompareExchange64(&unevaluated, 0, 0)),
        static_cast<unsigned long long>(InterlockedCompareExchange64(&ignored_nested, 0, 0)),
        last_drop_reason.load(std::memory_order_relaxed));
#ifdef BRIDGE_MISSION_PROVINCE_CONDITION_OBSERVATION
    if (bytes > 0 && static_cast<size_t>(bytes) < sizeof(status) && status[bytes-1] == '}') {
        const size_t remaining = sizeof(status)-static_cast<size_t>(bytes)+1;
        const int added = std::snprintf(status+bytes-1, remaining,
            ",\"province_baseline_count\":%u}", province_count);
        if (added <= 0 || static_cast<size_t>(added) >= remaining) return;
    }
#endif
    const size_t used = std::strlen(message);
    const size_t status_bytes = std::strlen(status);
    if (bytes > 0 && static_cast<size_t>(bytes) < sizeof(status) && status_bytes < sizeof(status)
        && used >= 2 && message[used-2] == '}'
        && used+status_bytes < capacity) {
        std::memcpy(message+used-2, status, status_bytes);
        std::memcpy(message+used-2+status_bytes, "}\n", 3);
    }
}

#ifdef BRIDGE_MISSION_PROVINCE_CONDITION_OBSERVATION
#include "information-mission-province-observer.inc"
#endif

} // namespace mission_condition_observer
