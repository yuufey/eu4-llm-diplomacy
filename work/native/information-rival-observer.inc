// Reuses the three existing rival authority trampolines. No additional game
// patch, command dispatch or native rule invocation is introduced here.
#include "information-rival-change.h"
#include <atomic>

namespace rival_change_observer {

namespace owned = information::rival_change;
constexpr unsigned kCapacity = 64;
struct Event final { owned::Change value{}; uint64_t sequence = 0, observer = 0; unsigned char path = 0; };
struct Pending final {
    owned::Change value{};
    uintptr_t actor_country = 0;
    bool relevant = false, ready = false;
};
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

static bool observes(uint64_t reference) noexcept {
#ifdef BRIDGE_NATIVE_COUNTRY_CONTROL
    return observation_information_country_handle(reference);
#else
    return (reference & 0xffffffu) == 0x415246u;
#endif
}

static bool valid_tag(uint64_t reference) noexcept {
    for (unsigned shift = 0; shift < 24; shift += 8) {
        const auto byte = static_cast<unsigned char>(reference >> shift);
        if (!(byte >= 'A' && byte <= 'Z') && !(byte >= '0' && byte <= '9')) return false;
    }
    return true;
}

static bool read_date(int32_t& date) noexcept {
    uintptr_t game = 0;
    return !thread_changed && frame_thread == GetCurrentThreadId()
        && read(base + 0x233fe58, game) && read(game + 0x1dd0, date) && date > 0;
}

static bool snapshot(const owned::Change& value, uintptr_t owner, owned::Snapshot& result) noexcept {
    RivalQueryState target{}, old{};
    if (!rival_query_membership(owner, value.target, target) || !target.state_verified) return false;
    result.count = target.count;
    result.target = {target.active, target.since_date_raw};
    if (value.kind == owned::Kind::replace) {
        if (!rival_query_membership(owner, value.old_rival, old) || !old.state_verified
            || old.count != target.count) return false;
        result.old_rival = {old.active, old.since_date_raw};
    }
    result.verified = true;
    return true;
}

using SnapshotReader = bool(*)(const owned::Change&, uintptr_t, owned::Snapshot&) noexcept;

static Pending begin(unsigned kind, uint64_t actor, uint64_t target, uint64_t old_rival,
    bool command_verified, SnapshotReader read_snapshot = &snapshot) noexcept {
    Pending pending{};
    pending.relevant = installed && (observes(actor) || observes(target) || (kind == 2 && observes(old_rival)));
    if (!pending.relevant || transport_fault || !command_verified) return pending;
    auto& value = pending.value;
    value.kind = static_cast<owned::Kind>(kind);
    value.actor = actor;
    value.target = target;
    value.old_rival = kind == 2 ? old_rival : 0;
    uintptr_t recipient = 0, old_country = 0;
    pending.ready = valid_tag(actor) && valid_tag(target) && actor != target
        && read_date(value.date) && insult_query_country(actor, pending.actor_country)
        && insult_query_country(target, recipient)
        && (kind != 2 || (old_rival != target && old_rival != actor && valid_tag(old_rival)
            && insult_query_country(old_rival, old_country)))
        && read_snapshot(value, pending.actor_country, value.before);
    return pending;
}

static bool enqueue(const owned::Change& value, unsigned char path = 0) noexcept {
    if (path > 2) return false;
    const uint64_t endpoints[] = {value.actor, value.target, value.old_rival};
    uint64_t observers[3]{};
    unsigned count = 0;
    for (const auto handle : endpoints) {
        if (handle && observes(handle)) observers[count++] = handle;
    }
    if (!count || !TryAcquireSRWLockExclusive(&queue_lock)) return false;
    bool complete = true;
    for (unsigned index = 0; index < count; ++index) {
        const auto id = static_cast<uint64_t>(InterlockedIncrement64(&sequence));
        if (size < kCapacity) {
            events[(head + size) % kCapacity] = {value, id, observers[index], path};
            ++size;
        } else complete = false;
    }
    ReleaseSRWLockExclusive(&queue_lock);
    return complete;
}

static void finish(Pending& pending, SnapshotReader read_snapshot = &snapshot) noexcept {
    if (!pending.relevant) return;
    pending.relevant = false;
    auto& value = pending.value;
    uintptr_t owner = 0, recipient = 0, old_country = 0;
    int32_t date = 0;
    if (!pending.ready || transport_fault || !read_date(date) || date != value.date
        || !insult_query_country(value.actor, owner) || owner != pending.actor_country
        || !insult_query_country(value.target, recipient)
        || (value.kind == owned::Kind::replace && !insult_query_country(value.old_rival, old_country))
        || !read_snapshot(value, owner, value.after)) { note_drop(); return; }
    const auto outcome = owned::classify(value.kind, value.date, value.before, value.after);
    pending.ready = false;
    if (outcome == owned::Outcome::unchanged) return;
    if (outcome == owned::Outcome::unreadable) { note_drop(); return; }
    if (!enqueue(value)) note_drop();
}

static bool append(const char* message, size_t bytes) noexcept {
    if (transport_fault || log_file == INVALID_HANDLE_VALUE) { transport_fault = true; return false; }
    DWORD written = 0;
    if (!WriteFile(log_file, message, static_cast<DWORD>(bytes), &written, nullptr)
        || written != bytes || !FlushFileBuffers(log_file)) { transport_fault = true; return false; }
    return true;
}

using RecordFormatter = int(*)(const owned::Change&, unsigned char, uint64_t, uint64_t, char*, size_t) noexcept;

static void flush(RecordFormatter formatter = nullptr) noexcept {
    if (!installed || transport_fault) return;
    for (unsigned index = 0; index < 32; ++index) {
        Event event{};
        if (!TryAcquireSRWLockExclusive(&queue_lock)) return;
        if (!size) { ReleaseSRWLockExclusive(&queue_lock); break; }
        event = events[head];
        ReleaseSRWLockExclusive(&queue_lock);
        const auto& value = event.value;
        const char* kind = value.kind == owned::Kind::set ? "set" : value.kind == owned::Kind::replace ? "replace" : "remove";
        char actor[4]{}, target[4]{}, old[4]{}, observer[4]{};
        for (unsigned byte = 0; byte < 3; ++byte) {
            actor[byte] = static_cast<char>(value.actor >> (byte * 8));
            target[byte] = static_cast<char>(value.target >> (byte * 8));
            old[byte] = value.old_rival ? static_cast<char>(value.old_rival >> (byte * 8)) : '-';
            observer[byte] = static_cast<char>(event.observer >> (byte * 8));
        }
#ifdef BRIDGE_NATIVE_COUNTRY_CONTROL
        constexpr unsigned schema = 3;
#else
        constexpr unsigned schema = 1;
#endif
        char message[1400]{};
        const int bytes = event.path
            ? (formatter ? formatter(value,event.path,event.sequence,event.observer,message,sizeof(message)) : 0)
            : snprintf(message, sizeof(message),
            "{\"event\":\"native_rival_changed\",\"schema_version\":%u,\"session_id\":\"%lu-%llx\","
            "\"sequence\":%llu,\"country\":\"%.3s\",\"actor\":\"%s\",\"target\":\"%s\",\"old_rival\":\"%s\","
            "\"actor_fullref\":\"0x%llx\",\"target_fullref\":\"0x%llx\",\"old_rival_fullref\":\"0x%llx\","
            "\"operation\":\"%s\",\"date_raw\":%d,\"before\":{\"count\":%d,\"target_active\":%s,"
            "\"target_since_date_raw\":%d,\"old_active\":%s,\"old_since_date_raw\":%d},"
            "\"after\":{\"count\":%d,\"target_active\":%s,\"target_since_date_raw\":%d,"
            "\"old_active\":%s,\"old_since_date_raw\":%d},\"source\":\"rival_command_normal_return\",\"complete\":true}\n",
            schema, static_cast<unsigned long>(GetCurrentProcessId()), static_cast<unsigned long long>(observation_creation),
            static_cast<unsigned long long>(event.sequence), observer, actor, target, old,
            static_cast<unsigned long long>(value.actor), static_cast<unsigned long long>(value.target),
            static_cast<unsigned long long>(value.old_rival), kind, value.date,
            value.before.count, value.before.target.active ? "true" : "false", value.before.target.since_date,
            value.before.old_rival.active ? "true" : "false", value.before.old_rival.since_date,
            value.after.count, value.after.target.active ? "true" : "false", value.after.target.since_date,
            value.after.old_rival.active ? "true" : "false", value.after.old_rival.since_date);
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
            "{\"event\":\"native_rival_capture_gap\",\"session_id\":\"%lu-%llx\",\"dropped\":%ld,\"complete\":false}\n",
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
        ",\"rival_change_source\":{\"installed\":%s,\"transport_fault\":%s,\"total_dropped\":%ld,"
        "\"queue_readable\":%s,\"queued\":%u}}\n", installed.load() ? "true" : "false",
        transport_fault.load() ? "true" : "false", static_cast<long>(InterlockedCompareExchange(&total_dropped, 0, 0)),
        readable ? "true" : "false", queued);
}

} // namespace rival_change_observer
