// Included after the inbound helpers by the optional macro-event build.
#include "information-country-modifier-add.h"
#include "information-country-modifier-entry-plan.h"
#ifdef BRIDGE_COUNTRY_MODIFIER_REMOVAL
#include "information-country-modifier-remove.h"
#include "information-country-modifier-remove-entry-plan.h"
#endif
#ifdef BRIDGE_COUNTRY_MODIFIER_EXPIRY
#include "information-country-modifier-expiry.h"
extern "C" void bridge_country_modifier_remove_expiry_entry(void*, void*);
#endif
#include <atomic>

namespace country_modifier_observer {

namespace owned = information::country_modifier;
namespace plan = information::country_modifier::entry;
constexpr unsigned kCapacity = 64;
struct Event final {
    owned::Added value{};
    uint64_t sequence = 0;
    bool removed = false;
    bool expired = false;
};
struct Reader final {
    bool read(uintptr_t address, unsigned char* output, size_t size) noexcept {
        SIZE_T actual = 0;
        return owned::detail::range(address, size) && size <= owned::kMaxSingleRead
            && ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<void*>(address), output, size, &actual)
            && actual == size;
    }
};
using Original = void(*)(void*, void*, unsigned char);
static Original original = nullptr;
static plan::Plan image{};
static unsigned char* executable = nullptr;
static RUNTIME_FUNCTION unwind{};
static bridge_entry_patch::PatchPlan patch{};
static bool table_registered = false, published = false;
static std::atomic<bool> installed{false};
static SRWLOCK queue_lock = SRWLOCK_INIT;
static Event events[kCapacity]{};
static unsigned head = 0, size = 0;
static volatile LONG64 sequence = 0;
static volatile LONG dropped = 0;
static volatile LONG total_dropped = 0;
static std::atomic<bool> transport_fault{false};
#ifdef BRIDGE_COUNTRY_MODIFIER_REMOVAL
namespace removal = information::country_modifier::removal;
namespace remove_plan = information::country_modifier::removal_entry;
using RemoveOriginal = void(*)(void*, void*);
static RemoveOriginal remove_original = nullptr;
static remove_plan::Plan remove_image{};
static unsigned char* remove_executable = nullptr;
static RUNTIME_FUNCTION remove_unwind{};
static bool remove_table_registered = false;
#endif

static void note_drop() noexcept {
    InterlockedIncrement(&dropped);
    InterlockedIncrement(&total_dropped);
}

static void queue(const owned::Added& value, bool removed = false, bool expired = false) noexcept {
    Event event{value, static_cast<uint64_t>(InterlockedIncrement64(&sequence)), removed || expired, expired};
    if (!TryAcquireSRWLockExclusive(&queue_lock)) {
        note_drop();
        return;
    }
    if (size < kCapacity) {
        events[(head + size) % kCapacity] = event;
        ++size;
    } else {
        note_drop();
    }
    ReleaseSRWLockExclusive(&queue_lock);
}

extern "C" void country_modifier_insert_observe(void* country, void* instance, unsigned char flag) {
    Reader reader;
    owned::Pending pending{};
    const uintptr_t caller = reinterpret_cast<uintptr_t>(__builtin_return_address(0));
    const uintptr_t owner = reinterpret_cast<uintptr_t>(country);
    uint64_t reference = 0;
    uintptr_t game = 0;
    int32_t date = 0;
    const bool relevant = installed && caller == base + owned::kCreatorReturnRva
        && read(owner + 0x20, reference) && observation_information_country_handle(reference);
    bool captured = false;
    if (relevant && !thread_changed && frame_thread == GetCurrentThreadId()
        && !transport_fault && read(base + 0x233fe58, game) && read(game + 0x1dd0, date)) {
        const owned::Context context{base, owner, reference, date, true};
        captured = owned::begin(reader, context, reinterpret_cast<uintptr_t>(instance), caller, pending);
    }
    // Observation cannot block or replace the native mutation. A call that
    // does not return normally never reaches finish and produces no added event.
    original(country, instance, flag);
    if (!relevant) return;
    owned::Added value{};
    if (captured && owned::finish(reader, pending, value)) queue(value);
    else note_drop();
}

#ifdef BRIDGE_COUNTRY_MODIFIER_REMOVAL
extern "C" void country_modifier_remove_observe(void* country, void* instance
#ifdef BRIDGE_COUNTRY_MODIFIER_EXPIRY
    , void* function
#endif
) {
    Reader reader;
    removal::Pending pending{};
    const uintptr_t caller = reinterpret_cast<uintptr_t>(__builtin_return_address(0));
    const uintptr_t owner = reinterpret_cast<uintptr_t>(country);
    uint64_t reference = 0;
    uintptr_t game = 0;
    int32_t date = 0;
#ifdef BRIDGE_COUNTRY_MODIFIER_EXPIRY
    auto reason = owned::expiry::Reason::other;
#endif
    const bool relevant = installed
        && (caller == base + removal::kPredicateReturnRva || caller == base + removal::kReligionReturnRva)
        && read(owner + 0x20, reference) && observation_information_country_handle(reference);
    bool captured = false;
    if (relevant && !thread_changed && frame_thread == GetCurrentThreadId()
        && !transport_fault && read(base + 0x233fe58, game) && read(game + 0x1dd0, date)) {
        const owned::Context context{base, owner, reference, date, true};
        captured = removal::begin(reader, context, reinterpret_cast<uintptr_t>(instance), caller, pending);
#ifdef BRIDGE_COUNTRY_MODIFIER_EXPIRY
        if (captured) reason = owned::expiry::classify(reader, context, pending.value,
            caller, reinterpret_cast<uintptr_t>(function));
#endif
    }
    remove_original(country, instance);
    if (!relevant) return;
    owned::Added value{};
    if (captured && removal::finish(reader, pending, value)) {
#ifdef BRIDGE_COUNTRY_MODIFIER_EXPIRY
        queue(value, true, reason == owned::expiry::Reason::expired);
        if (reason == owned::expiry::Reason::unreadable) note_drop();
#else
        queue(value, true);
#endif
    } else note_drop();
}
#endif

static void release_unpublished() noexcept {
    if (published) return;
    if (table_registered) RtlDeleteFunctionTable(&unwind);
    if (executable) VirtualFree(executable, 0, MEM_RELEASE);
    table_registered = false;
    executable = nullptr;
    original = nullptr;
#ifdef BRIDGE_COUNTRY_MODIFIER_REMOVAL
    if (remove_table_registered) RtlDeleteFunctionTable(&remove_unwind);
    if (remove_executable) VirtualFree(remove_executable, 0, MEM_RELEASE);
    remove_table_registered = false;
    remove_executable = nullptr;
    remove_original = nullptr;
#endif
}

#ifdef BRIDGE_COUNTRY_MODIFIER_REMOVAL
static bool prepare_removal() noexcept {
    Reader reader;
    std::array<unsigned char, remove_plan::kPatchBytes> prefix{};
    std::array<unsigned char, 12> metadata{};
    DWORD64 image_base = 0;
    auto parent = RtlLookupFunctionEntry(base + remove_plan::kEntryRva, &image_base, nullptr);
#ifdef BRIDGE_COUNTRY_MODIFIER_EXPIRY
    const auto hook = &bridge_country_modifier_remove_expiry_entry;
#else
    const auto hook = &country_modifier_remove_observe;
#endif
    if (!parent || image_base != base || parent->BeginAddress != remove_plan::kEntryRva
        || parent->EndAddress != remove_plan::kSourceEndRva || parent->UnwindData != remove_plan::kUnwindRva
        || !reader.read(base + remove_plan::kEntryRva, prefix.data(), prefix.size())
        || !reader.read(base + remove_plan::kUnwindRva, metadata.data(), metadata.size())
        || !remove_plan::prepare(prefix, metadata, base + remove_plan::kEntryRva,
            reinterpret_cast<uintptr_t>(hook), remove_image)) return false;
    remove_executable = static_cast<unsigned char*>(VirtualAlloc(nullptr, remove_image.image.size(),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!remove_executable) return false;
    memcpy(remove_executable, remove_image.image.data(), remove_image.image.size());
    DWORD previous = 0;
    if (!VirtualProtect(remove_executable, remove_image.image.size(), PAGE_EXECUTE_READ, &previous)
        || !FlushInstructionCache(GetCurrentProcess(), remove_executable, remove_image.image.size())) return false;
    remove_unwind = {remove_image.runtime.begin, remove_image.runtime.end, remove_image.runtime.unwind};
    remove_table_registered = RtlAddFunctionTable(&remove_unwind, 1,
        reinterpret_cast<DWORD64>(remove_executable)) != FALSE;
    if (!remove_table_registered) return false;
    remove_original = reinterpret_cast<RemoveOriginal>(remove_executable);
    return true;
}
#endif

static bool install() noexcept {
    Reader reader;
    std::array<unsigned char, plan::kPatchBytes> prefix{};
    std::array<unsigned char, 12> metadata{};
    DWORD64 image_base = 0;
    auto parent = RtlLookupFunctionEntry(base + plan::kEntryRva, &image_base, nullptr);
    if (!parent || image_base != base || parent->BeginAddress != plan::kEntryRva
        || parent->EndAddress != plan::kSourceEndRva || parent->UnwindData != plan::kUnwindRva
        || !reader.read(base + plan::kEntryRva, prefix.data(), prefix.size())
        || !reader.read(base + plan::kUnwindRva, metadata.data(), metadata.size())
        || !plan::prepare(prefix, metadata, base + plan::kEntryRva,
            reinterpret_cast<uintptr_t>(&country_modifier_insert_observe), image)) return false;
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
    if (!table_registered) {
        release_unpublished();
        return false;
    }
    original = reinterpret_cast<Original>(executable);
    patch.count = 1;
    patch.targets[0] = {reinterpret_cast<void*>(base + plan::kEntryRva), plan::kPatchBytes,
        plan::kPrefix.data(), image.patch.data(), executable, image.runtime.end};
#ifdef BRIDGE_COUNTRY_MODIFIER_REMOVAL
    if (!prepare_removal()) {
        release_unpublished();
        return false;
    }
    patch.count = 2;
    patch.targets[1] = {reinterpret_cast<void*>(base + remove_plan::kEntryRva), remove_plan::kPatchBytes,
        remove_plan::kPrefix.data(), remove_image.patch.data(), remove_executable, remove_image.runtime.end};
#endif
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
    // Published code and its function table stay alive through process exit.
    return result.success && result.threads_resumed && result.protection_restored;
}

static bool append(const char* message, size_t bytes) noexcept {
    if (transport_fault || log_file == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    if (!WriteFile(log_file, message, static_cast<DWORD>(bytes), &written, nullptr)
        || written != bytes || !FlushFileBuffers(log_file)) {
        // Partial/unknown writes are never retried automatically. Keep the
        // owned queue head for diagnosis and expose the latched gap counter.
        transport_fault.store(true);
        return false;
    }
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
        const auto& value = event.value;
        const char tag[4]={static_cast<char>(value.country),static_cast<char>(value.country>>8),
                           static_cast<char>(value.country>>16),0};
#ifdef BRIDGE_NATIVE_COUNTRY_CONTROL
        constexpr unsigned schema=2;
#else
        constexpr unsigned schema=1;
#endif
        char message[1024]{};
        const int bytes = snprintf(message, sizeof(message),
            "{\"event\":\"%s\",\"schema_version\":%u,"
            "\"session_id\":\"%lu-%llx\",\"sequence\":%llu,\"country\":\"%.3s\","
            "\"country_fullref\":\"0x%llx\",\"modifier_id\":\"%s\",\"date_raw\":%d,"
            "\"start_date_raw\":%d,\"end_date_raw\":%d,\"flags\":[%u,%u,%u,%u],"
            "\"source\":\"%s\",\"complete\":true}\n",
            event.expired ? "native_country_modifier_expired" :
                (event.removed ? "native_country_modifier_removed" : "native_country_modifier_added"),
            schema,
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long long>(observation_creation),
            static_cast<unsigned long long>(event.sequence),tag,static_cast<unsigned long long>(value.country),
            value.key.data(), value.date, value.start_date, value.end_date,
            static_cast<unsigned>(value.flags[0]), static_cast<unsigned>(value.flags[1]),
            static_cast<unsigned>(value.flags[2]), static_cast<unsigned>(value.flags[3]),
            event.expired ? "temporary_country_modifier_expiry_remove_return" :
                (event.removed ? "temporary_country_modifier_remove_return" : "temporary_country_modifier_insert_return"));
        if (bytes < 0 || static_cast<size_t>(bytes) >= sizeof(message)
            || !append(message, static_cast<size_t>(bytes))) return;
        AcquireSRWLockExclusive(&queue_lock);
        head = (head + 1) % kCapacity;
        --size;
        ReleaseSRWLockExclusive(&queue_lock);
    }
    const LONG count = InterlockedCompareExchange(&dropped, 0, 0);
    if (count) {
        char message[256]{};
        const int bytes = snprintf(message, sizeof(message),
            "{\"event\":\"native_country_modifier_capture_gap\",\"session_id\":\"%lu-%llx\","
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
    if (queue_readable) {
        queued = size;
        ReleaseSRWLockExclusive(&queue_lock);
    }
    snprintf(end, capacity - static_cast<size_t>(end - message),
        ",\"country_modifier_source\":{\"installed\":%s,\"transport_fault\":%s,"
        "\"total_dropped\":%ld,\"queue_readable\":%s,\"queued\":%u}}\n",
        installed.load() ? "true" : "false", transport_fault.load() ? "true" : "false",
        static_cast<long>(InterlockedCompareExchange(&total_dropped, 0, 0)),
        queue_readable ? "true" : "false", queued);
}

} // namespace country_modifier_observer
