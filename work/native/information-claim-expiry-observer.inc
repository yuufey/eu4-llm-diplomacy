#include "information-claim-expiry.h"
#include "information-claim-expiry-entry-plan.h"
#include <atomic>

namespace claim_expiry_observer {
namespace owned = information::claim_expiry;
namespace plan = owned::entry;
constexpr unsigned kCapacity = 64;
struct Event final {
    owned::Value value{};
    uint64_t sequence = 0;
};
struct Reader final {
    bool read(uintptr_t address, unsigned char* output, size_t bytes) noexcept {
        SIZE_T actual = 0;
        return owned::detail::shared::range(address, bytes)
            && bytes <= information::country_modifier::kMaxSingleRead
            && ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<void*>(address), output, bytes, &actual)
            && actual == bytes;
    }
};
using Original = uintptr_t(*)(uintptr_t, uint64_t, unsigned char);
static Original original = nullptr;
static plan::Plan image{};
static unsigned char* executable = nullptr;
static RUNTIME_FUNCTION unwind{};
static bridge_entry_patch::PatchPlan patch{};
static bool table_registered = false, published = false;
static std::atomic<bool> installed{false}, transport_fault{false};
static SRWLOCK queue_lock = SRWLOCK_INIT;
static Event events[kCapacity]{};
static unsigned head = 0, size = 0;
static volatile LONG64 sequence = 0;
static volatile LONG dropped = 0, total_dropped = 0;

static void note_drop() noexcept {
    InterlockedIncrement(&dropped);
    InterlockedIncrement(&total_dropped);
}

static void queue(const owned::Value& value) noexcept {
    const Event event{value, static_cast<uint64_t>(InterlockedIncrement64(&sequence))};
    if (!TryAcquireSRWLockExclusive(&queue_lock)) { note_drop(); return; }
    if (size < kCapacity) {
        events[(head + size) % kCapacity] = event;
        ++size;
    } else note_drop();
    ReleaseSRWLockExclusive(&queue_lock);
}

extern "C" uintptr_t claim_remove_observe(uintptr_t instance, uint64_t claimant, unsigned char record_history) {
    const uintptr_t caller = reinterpret_cast<uintptr_t>(__builtin_return_address(0));
    Reader reader;
    owned::Pending pending{};
    auto decision = owned::Decision::ignored;
    if (installed && !transport_fault && caller == base + owned::kExpiryReturnRva) {
        uintptr_t game = 0;
        int32_t date = 0;
        if (!thread_changed && frame_thread == GetCurrentThreadId()
            && read(base + 0x233fe58, game) && read(game + 0x1dd0, date)) {
            decision = owned::begin(reader, {base, date, true}, instance, claimant, caller, pending);
        } else decision = owned::Decision::unreadable;
    }
    // Preserve the original invocation and return value even when capture fails.
    const uintptr_t result = original(instance, claimant, record_history);
    owned::Value value{};
    if (decision == owned::Decision::ready) {
        if (owned::finish(reader, pending, value)) queue(value);
        else note_drop();
    } else if (decision == owned::Decision::unreadable) note_drop();
    return result;
}

static void release_unpublished() noexcept {
    if (published) return;
    if (table_registered) RtlDeleteFunctionTable(&unwind);
    if (executable) VirtualFree(executable, 0, MEM_RELEASE);
    table_registered = false;
    executable = nullptr;
    original = nullptr;
}

static bool install() noexcept {
    Reader reader;
    std::array<unsigned char, plan::kPrefix.size()> prefix{};
    std::array<unsigned char, plan::kSourceUnwind.size()> metadata{};
    DWORD64 image_base = 0;
    const auto parent = RtlLookupFunctionEntry(base + plan::kEntryRva, &image_base, nullptr);
    if (!parent || image_base != base || parent->BeginAddress != plan::kEntryRva
        || parent->EndAddress != plan::kSourceEndRva || parent->UnwindData != plan::kUnwindRva
        || !owned::guards(reader, base)
        || !reader.read(base + plan::kEntryRva, prefix.data(), prefix.size())
        || !reader.read(base + plan::kUnwindRva, metadata.data(), metadata.size())
        || !plan::prepare(prefix, metadata, base + plan::kEntryRva,
            reinterpret_cast<uintptr_t>(&claim_remove_observe), image)) return false;
    executable = static_cast<unsigned char*>(VirtualAlloc(nullptr, image.image.size(),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!executable) return false;
    memcpy(executable, image.image.data(), image.image.size());
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
    patch.targets[0] = {reinterpret_cast<void*>(base + plan::kEntryRva), plan::kPrefix.size(),
        plan::kPrefix.data(), image.patch.data(), executable, image.runtime.end};
    const auto result = bridge_entry_patch::guarded_patch_apply(patch);
    published = result.published;
    installed = result.success && result.threads_resumed && result.protection_restored;
    if (!published) release_unpublished();
    return installed;
}

static bool rollback() noexcept {
    installed = false;
    if (!published) return true;
    const auto result = bridge_entry_patch::guarded_patch_rollback(patch);
    // Published code and unwind metadata remain alive through process exit.
    return result.success && result.threads_resumed && result.protection_restored;
}

static bool append(const char* message, size_t bytes) noexcept {
    if (transport_fault || log_file == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    if (!WriteFile(log_file, message, static_cast<DWORD>(bytes), &written, nullptr)
        || written != bytes || !FlushFileBuffers(log_file)) {
        transport_fault = true;
        return false;
    }
    return true;
}

static void flush() noexcept {
    if (!installed || transport_fault) return;
    for (unsigned index = 0; index < 32; ++index) {
        if (!TryAcquireSRWLockExclusive(&queue_lock)) return;
        if (!size) { ReleaseSRWLockExclusive(&queue_lock); break; }
        const Event event = events[head];
        ReleaseSRWLockExclusive(&queue_lock);
        const auto& value = event.value;
        char message[768]{};
        const int bytes = snprintf(message, sizeof(message),
            "{\"event\":\"native_claim_expired\",\"session_id\":\"%lu-%llx\","
            "\"sequence\":%llu,\"date_raw\":%d,\"claimant_ref\":\"0x%llx\","
            "\"owner_ref\":\"0x%llx\",\"observer_ref\":\"0x%llx\","
            "\"province_id\":%d,"
            "\"source\":\"claim_record_natural_expiry_remove_return\",\"wire\":1}\n",
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long long>(observation_creation),
            static_cast<unsigned long long>(event.sequence), value.date,
            static_cast<unsigned long long>(value.claimant), static_cast<unsigned long long>(value.owner),
            static_cast<unsigned long long>(value.observer), value.province);
        if (bytes < 0 || static_cast<size_t>(bytes) >= sizeof(message)) { transport_fault = true; return; }
        if (!append(message, static_cast<size_t>(bytes))) return;
        AcquireSRWLockExclusive(&queue_lock);
        head = (head + 1) % kCapacity;
        --size;
        ReleaseSRWLockExclusive(&queue_lock);
    }
    const LONG count = InterlockedCompareExchange(&dropped, 0, 0);
    if (count) {
        char message[256]{};
        const int bytes = snprintf(message, sizeof(message),
            "{\"event\":\"native_claim_expiry_capture_gap\",\"session_id\":\"%lu-%llx\","
            "\"dropped\":%ld,\"complete\":false}\n", static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long long>(observation_creation), static_cast<long>(count));
        if (bytes > 0 && static_cast<size_t>(bytes) < sizeof(message) && append(message, bytes))
            InterlockedExchangeAdd(&dropped, -count);
    }
}

static void append_health(char* message, size_t capacity) noexcept {
    char* end = strrchr(message, '}');
    if (!end) return;
    unsigned queued = 0;
    const bool queue_readable = TryAcquireSRWLockExclusive(&queue_lock) != FALSE;
    if (queue_readable) { queued = size; ReleaseSRWLockExclusive(&queue_lock); }
    snprintf(end, capacity - static_cast<size_t>(end - message),
        ",\"claim_expiry_source\":{\"installed\":%s,\"queue_readable\":%s,\"queued\":%u,"
        "\"dropped\":%ld,\"total_dropped\":%ld,\"transport_fault\":%s}}\n",
        installed.load() ? "true" : "false", queue_readable ? "true" : "false", queued,
        static_cast<long>(InterlockedCompareExchange(&dropped, 0, 0)),
        static_cast<long>(InterlockedCompareExchange(&total_dropped, 0, 0)),
        transport_fault.load() ? "true" : "false");
}
} // namespace claim_expiry_observer
