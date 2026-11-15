// The exact mission-command slot is distinct from diplomacy command payloads.
#include "information-mission-completion.h"
#include <atomic>

namespace mission_completion_observer {

namespace owned = information::mission_completion;
constexpr uintptr_t kVtableRva = 0x1c3a100;
constexpr uintptr_t kMethodRva = 0xc1680;
constexpr unsigned kCapacity = 64;
using Original = void(*)(void*);
struct Value final { uint64_t country = 0; int32_t date = 0; owned::Name mission{}; };
struct Event final { Value value{}; uint64_t sequence = 0; };
struct Pending final {
    Value value{};
    uintptr_t country_pointer = 0;
    bool observed = false, ready = false, completed_before = false, entered = false;
};
struct Active final { uint64_t country = 0; owned::Name mission{}; };
static thread_local Active active[16]{};
static thread_local unsigned depth = 0;
struct Reader final {
    bool read(uintptr_t address, void* output, size_t bytes) noexcept {
        SIZE_T copied = 0;
        return owned::range(address, bytes)
            && ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<void*>(address), output, bytes, &copied)
            && copied == bytes;
    }
};
static std::atomic<Original> original{nullptr};
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

static bool date_now(int32_t& date) noexcept {
    uintptr_t game = 0;
    return !thread_changed && frame_thread == GetCurrentThreadId()
        && read(base + 0x233fe58, game) && read(game + 0x1dd0, date) && date > 0;
}

static Pending begin(void* command) noexcept {
    Pending pending{};
    if (!installed || transport_fault) return pending;
    const auto address = reinterpret_cast<uintptr_t>(command);
    uintptr_t table = 0;
    uint32_t discriminator = 0;
    if (!owned::range(address, 0x78) || !read(address, table) || table != base + kVtableRva
        || !read(address + 8, discriminator) || discriminator != 0x165
        || !read(address + 0x70, pending.value.country)
        || (pending.value.country & 0xffffffu) != 0x415246u) return pending;
    pending.observed = true;
    Reader reader;
    pending.ready = date_now(pending.value.date)
        && insult_query_country(pending.value.country, pending.country_pointer)
        && owned::name(reader, address + 0x50, pending.value.mission)
        && owned::membership(reader, pending.country_pointer, pending.value.mission, pending.completed_before);
    if (pending.ready) {
        for (unsigned index = 0; index < depth; ++index) {
            if (active[index].country == pending.value.country
                && owned::equal(active[index].mission, pending.value.mission)) return {};
        }
        if (depth == 16) pending.ready = false;
        else {
            active[depth++] = {pending.value.country, pending.value.mission};
            pending.entered = true;
        }
    }
    return pending;
}

static void finish(Pending& pending) noexcept {
    if (!pending.observed) return;
    pending.observed = false;
    if (pending.entered) --depth;
    uintptr_t country = 0;
    int32_t date = 0;
    bool after = false;
    Reader reader;
    if (!pending.ready || transport_fault || !date_now(date) || date != pending.value.date
        || !insult_query_country(pending.value.country, country) || country != pending.country_pointer
        || !owned::membership(reader, country, pending.value.mission, after)) { note_drop(); return; }
    if (pending.completed_before || !after) return;
    Event event{pending.value, static_cast<uint64_t>(InterlockedIncrement64(&sequence))};
    if (!TryAcquireSRWLockExclusive(&queue_lock)) { note_drop(); return; }
    if (size < kCapacity) { events[(head + size) % kCapacity] = event; ++size; }
    else note_drop();
    ReleaseSRWLockExclusive(&queue_lock);
}

static void observe(void* command) noexcept {
    const auto call = original.load(std::memory_order_acquire);
    if (!call) return;
    const DWORD incoming_error = GetLastError();
    auto pending = begin(command);
    SetLastError(incoming_error);
    call(command);
    const DWORD returned_error = GetLastError();
    finish(pending);
    SetLastError(returned_error);
}

static bool rollback() noexcept {
    installed = false;
    auto slot = reinterpret_cast<void* volatile*>(base + kVtableRva + 0x48);
    auto expected = reinterpret_cast<void*>(base + kMethodRva);
    void* current = nullptr;
    if (!read(reinterpret_cast<uintptr_t>(slot), current)) return false;
    if (current == expected) return true;
    if (current != reinterpret_cast<void*>(&observe)) return false;
    DWORD protection = 0, ignored = 0;
    if (!VirtualProtect(const_cast<void**>(slot), 8, PAGE_READWRITE, &protection)) return false;
    void* previous = InterlockedCompareExchangePointer(slot, expected, reinterpret_cast<void*>(&observe));
    const bool restored = VirtualProtect(const_cast<void**>(slot), 8, protection, &ignored) != FALSE;
    return (previous == reinterpret_cast<void*>(&observe) || previous == expected) && restored;
}

static bool install() noexcept {
    auto slot = reinterpret_cast<void* volatile*>(base + kVtableRva + 0x48);
    auto expected = reinterpret_cast<void*>(base + kMethodRva);
    void* current = nullptr;
    static constexpr unsigned char jump[] = {0xe9, 0x4b, 0x62, 0x81, 0x00};
    unsigned char observed[sizeof(jump)]{};
    if (original.load() || !read(reinterpret_cast<uintptr_t>(slot), current) || current != expected
        || !read(base + kMethodRva, observed) || memcmp(observed, jump, sizeof(jump))) return false;
    original.store(reinterpret_cast<Original>(expected), std::memory_order_release);
    DWORD protection = 0, ignored = 0;
    if (!VirtualProtect(const_cast<void**>(slot), 8, PAGE_READWRITE, &protection)) return false;
    const bool replaced = InterlockedCompareExchangePointer(slot, reinterpret_cast<void*>(&observe), expected) == expected;
    const bool restored = VirtualProtect(const_cast<void**>(slot), 8, protection, &ignored) != FALSE;
    if (!replaced || !restored) {
        const bool reverted = rollback();
        const bool protection_restored = restored
            || VirtualProtect(const_cast<void**>(slot), 8, protection, &ignored) != FALSE;
        lifecycle_rollback_incomplete = !reverted || !protection_restored || lifecycle_rollback_incomplete;
        return false;
    }
    return true;
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
        char name_hex[owned::kMaxName * 2 + 1]{};
        for (unsigned byte = 0; byte < event.value.mission.length; ++byte)
            snprintf(name_hex + byte * 2, 3, "%02x", static_cast<unsigned char>(event.value.mission.text[byte]));
        char message[1200]{};
        const int bytes = snprintf(message, sizeof(message),
            "{\"event\":\"native_mission_completed\",\"schema_version\":1,\"session_id\":\"%lu-%llx\","
            "\"sequence\":%llu,\"country\":\"FRA\",\"country_fullref\":\"0x%llx\",\"date_raw\":%d,"
            "\"mission_id_hex\":\"%s\",\"completed_before\":false,\"completed_after\":true,"
            "\"source\":\"mission_command_return_completed_membership_transition\",\"complete\":true}\n",
            static_cast<unsigned long>(GetCurrentProcessId()), static_cast<unsigned long long>(observation_creation),
            static_cast<unsigned long long>(event.sequence), static_cast<unsigned long long>(event.value.country),
            event.value.date, name_hex);
        if (bytes <= 0 || static_cast<size_t>(bytes) >= sizeof(message)) { transport_fault = true; return; }
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
            "{\"event\":\"native_mission_capture_gap\",\"session_id\":\"%lu-%llx\",\"dropped\":%ld,\"complete\":false}\n",
            static_cast<unsigned long>(GetCurrentProcessId()), static_cast<unsigned long long>(observation_creation),
            static_cast<long>(count));
        if (bytes > 0 && static_cast<size_t>(bytes) < sizeof(message) && append(message, bytes))
            InterlockedExchangeAdd(&dropped, -count);
    }
}

static void append_health(char* message, size_t capacity) noexcept {
    char* end = strrchr(message, '}');
    if (!end) return;
    unsigned queued = 0;
    const bool readable = TryAcquireSRWLockExclusive(&queue_lock) != FALSE;
    if (readable) { queued = size; ReleaseSRWLockExclusive(&queue_lock); }
    snprintf(end, capacity - static_cast<size_t>(end - message),
        ",\"mission_source\":{\"installed\":%s,\"transport_fault\":%s,\"total_dropped\":%ld,"
        "\"queue_readable\":%s,\"queued\":%u}}\n", installed.load() ? "true" : "false",
        transport_fault.load() ? "true" : "false", static_cast<long>(InterlockedCompareExchange(&total_dropped, 0, 0)),
        readable ? "true" : "false", queued);
}

} // namespace mission_completion_observer
