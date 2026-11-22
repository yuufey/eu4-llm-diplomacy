#include <utility>
// Included after execution_read_after. Reads only the executed command's pair.
namespace relation_change_observer {

namespace owned = ::information::relation_change;
constexpr unsigned kCapacity = 64;
enum class Path { command_return, alliance_record_enable, alliance_record_disable,
                  royal_record_enable, royal_record_disable,
                  guarantee_record_enable, guarantee_record_disable,
                  military_record_enable, military_record_disable,
                  support_record_enable, support_record_disable,
                  subject_record_enable, subject_record_disable };
struct Value final {
    owned::Kind kind{};
    uint64_t actor = 0, recipient = 0, observer = 0;
    int32_t date = 0;
    unsigned state = 0, mode = 0;
    owned::Snapshot before{}, after{};
    Path path = Path::command_return;
};
struct Event final { Value value{}; uint64_t sequence = 0; };
struct Pending final {
    Value value{};
    AlliancePayload payload{};
    uintptr_t actor_country = 0, recipient_country = 0;
    bool observed = false, ready = false;
};
struct ActivePair final {
    owned::Kind kind{};
    uint64_t actor = 0, recipient = 0;
    bool record_observed = false;
    owned::Snapshot record_before{}, record_after{};
};
static thread_local ActivePair active_pairs[16]{};
static thread_local unsigned active_pair_count = 0;
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

static bool kind_for_table(uintptr_t table, owned::Kind& kind) noexcept {
    if (table == base + lifecycle_alliance_vtable_rva) kind = owned::Kind::alliance;
    else if (table == base + lifecycle_royal_vtable_rva) kind = owned::Kind::royal_marriage;
    else if (table == base + lifecycle_military_access_vtable_rva) kind = owned::Kind::military_access;
    else if (table == base + lifecycle_guarantee_vtable_rva) kind = owned::Kind::guarantee;
    else if (table == base + lifecycle_support_vtable_rva) kind = owned::Kind::support_independence;
    else if (table == base + lifecycle_vassalization_vtable_rva) kind = owned::Kind::subject;
    else return false;
    return true;
}

static bool family_matches(owned::Kind kind, ActionFamily family) noexcept {
    switch (kind) {
    case owned::Kind::alliance: return family == ActionFamily::alliance;
    case owned::Kind::royal_marriage: return family == ActionFamily::royal_marriage;
    case owned::Kind::military_access: return family == ActionFamily::military_access;
    case owned::Kind::guarantee: return family == ActionFamily::guarantee;
    case owned::Kind::support_independence: return family == ActionFamily::support_independence;
    case owned::Kind::subject: return family == ActionFamily::vassalization;
    }
    return false;
}

static bool guarantee_direction(uint64_t actor, uint64_t recipient, bool& granted) noexcept {
    uintptr_t country = 0, relations = 0, owner = 0, begin = 0;
    uint64_t other = 0;
    int32_t count = 0;
    const auto slot = static_cast<int16_t>((recipient >> 32) & 0xffffu);
    if (!insult_query_country(actor, country) || !read(country + 0x1510, relations) || !relations) return false;
    const auto row = relations + static_cast<uintptr_t>(static_cast<uint16_t>(slot)) * 0x48;
    if (!read(row + 0x10, other) || other != recipient || !read(row, owner) || !owner
        || !read(owner + 0x1a0, begin) || !read(owner + 0x1ac, count)
        || count < 0 || count > 4096 || (count && !begin)) return false;
    uintptr_t first = 0;
    bool found = false;
    for (int32_t index = 0; index < count; ++index) {
        unsigned char item[16]{};
        if (!read(begin + static_cast<uintptr_t>(index) * 16, item)) return false;
        int32_t item_slot = 0;
        memcpy(&item_slot, item, sizeof(item_slot));
        if (!found && item_slot == slot) { memcpy(&first, item + 8, sizeof(first)); found = true; }
    }
    granted = false;
    if (!first) return true;
    uint64_t reference = 0;
    if (!read(first + 0x18, reference)) return false;
    granted = static_cast<int16_t>((reference >> 32) & 0xffffu) == slot;
    return true;
}

static bool snapshot(const AlliancePayload& payload, owned::Kind kind, owned::Snapshot& result) noexcept {
    result = {};
    if (kind == owned::Kind::guarantee) {
        // The accepted directed-relation profile pins this exact B23 leaf.
        static constexpr unsigned char expected[] = {
            0x48,0x8b,0x11,0x4c,0x8b,0x49,0x10,0x49,0xc1,0xe9,0x20,0x41,0x0f,0xbf,0xc1,
            0x48,0x8b,0x8a,0xa0,0x01,0x00,0x00,0x4c,0x63,0x82,0xac,0x01,0x00,0x00,0x49,
            0xc1,0xe0,0x04,0x4c,0x03,0xc1,0x49,0x3b,0xc8,0x74,0x14,0x0f,0x1f,0x80,0x00,
            0x00,0x00,0x00,0x39,0x01,0x74,0x0c,0x48,0x83,0xc1,0x10,0x49,0x3b,0xc8,0x75,
            0xf3,0x32,0xc0,0xc3,0x48,0x8b,0x41,0x08,0x48,0x85,0xc0,0x74,0xf4,0x48,0x8b,
            0x40,0x18,0x48,0xc1,0xe8,0x20,0x66,0x41,0x3b,0xc1,0x75,0xe6,0xb0,0x01,0xc3};
        unsigned char bytes[sizeof(expected)]{};
        if (!read(base + 0xa69e00, bytes) || memcmp(bytes, expected, sizeof(expected))
            || !guarantee_direction(payload.actor10, payload.recipient20, result.guarantee_actor_grants)
            || !guarantee_direction(payload.recipient20, payload.actor10, result.guarantee_recipient_grants)) return false;
        result.active = result.guarantee_actor_grants || result.guarantee_recipient_grants;
    } else if (kind == owned::Kind::subject) {
        VassalQueryState value{};
        if (!vassal_query_relation(payload.actor10, payload.recipient20, value)) return false;
        result.active = value.active;
        result.subject_actor_is_overlord = value.actor_is_overlord;
        result.subject_actor_is_subject = value.actor_is_subject;
        if (value.active) {
            const size_t length = strnlen(value.subject_type_json, sizeof(value.subject_type_json));
            if (length < 3 || length > 66 || value.subject_type_json[0] != '"'
                || value.subject_type_json[length - 1] != '"') return false;
            memcpy(result.subject_type, value.subject_type_json + 1, length - 2);
        }
    } else {
        if (!execution_read_after(payload, result.active)) return false;
        if (kind == owned::Kind::support_independence) {
            const auto roles = support_role_capture(payload.actor10, payload.recipient20);
            if (!roles.readable) return false;
            result.support_actor_is_subject = roles.actor_is_subject;
            result.support_recipient_is_subject = roles.recipient_is_subject;
        }
    }
    result.complete = true;
    return owned::valid(kind, result);
}

static void enqueue(const Value& value) noexcept {
    if (!TryAcquireSRWLockExclusive(&queue_lock)) { note_drop(); return; }
    for (const uint64_t observer : {value.actor, value.recipient}) {
        if (!observation_information_country_handle(observer)) continue;
        Event event{value, static_cast<uint64_t>(InterlockedIncrement64(&sequence))};
        event.value.observer=observer;
        if (size < kCapacity) { events[(head + size) % kCapacity] = event; ++size; }
        else note_drop();
    }
    ReleaseSRWLockExclusive(&queue_lock);
}

#ifdef BRIDGE_ALLIANCE_RECORD_OBSERVATION
static bool record_snapshot_equal(owned::Kind kind,const owned::Snapshot& left,
                                  const owned::Snapshot& right) noexcept {
    if (owned::classify(kind,left,right) != owned::Outcome::unchanged) return false;
    // Even an inactive support relation reports the endpoints' subject roles.
    // A record can only cover the command when that reported metadata agrees.
    return kind != owned::Kind::support_independence
        || (left.support_actor_is_subject == right.support_actor_is_subject
            && left.support_recipient_is_subject == right.support_recipient_is_subject);
}

static void record_result(const Value& value) noexcept {
    for (unsigned index = 0; index < active_pair_count; ++index) {
        auto& active = active_pairs[index];
        const bool forward = active.actor == value.actor && active.recipient == value.recipient;
        const bool symmetric = value.kind == owned::Kind::alliance
            || value.kind == owned::Kind::royal_marriage || value.kind == owned::Kind::guarantee
            || value.kind == owned::Kind::subject || value.kind == owned::Kind::support_independence;
        const bool reverse = active.actor == value.recipient && active.recipient == value.actor;
        if (active.kind != value.kind || (!forward && !(symmetric && reverse))) continue;
        auto before = value.before;
        auto after = value.after;
        if (!forward && value.kind == owned::Kind::guarantee) {
            std::swap(before.guarantee_actor_grants, before.guarantee_recipient_grants);
            std::swap(after.guarantee_actor_grants, after.guarantee_recipient_grants);
        } else if (!forward && value.kind == owned::Kind::subject) {
            std::swap(before.subject_actor_is_overlord, before.subject_actor_is_subject);
            std::swap(after.subject_actor_is_overlord, after.subject_actor_is_subject);
        } else if (!forward && value.kind == owned::Kind::support_independence) {
            std::swap(before.support_actor_is_subject, before.support_recipient_is_subject);
            std::swap(after.support_actor_is_subject, after.support_recipient_is_subject);
        }
        if (!active.record_observed) active.record_before = before;
        active.record_after = after;
        active.record_observed = true;
    }
}
#endif

static Pending begin_payload(uintptr_t action, const AlliancePayload& payload) noexcept {
    Pending pending{};
    if (!installed || transport_fault) return pending;
    uintptr_t table = 0;
    if (action < 0x10000 || action > UINT64_C(0x00007fffffffffa7)
        || !read(action, table)
        || !kind_for_table(table, pending.value.kind)) return pending;
    if (!date_now(pending.value.date)) { note_drop(); return pending; }
    // Read the existing canonical payload only for these six action classes.
    if (!family_matches(pending.value.kind, payload.family)
        || payload.actor10 == payload.recipient20 || payload.state34 > 2 || payload.variant38 > 1
        || (!observation_information_country_handle(payload.actor10)
            && !observation_information_country_handle(payload.recipient20))) return pending;
    for (unsigned index = 0; index < active_pair_count; ++index) {
        const auto& active = active_pairs[index];
        const bool symmetric = pending.value.kind == owned::Kind::alliance
            || pending.value.kind == owned::Kind::royal_marriage || pending.value.kind == owned::Kind::subject
            || pending.value.kind == owned::Kind::guarantee;
        if (active.kind == pending.value.kind
            && ((active.actor == payload.actor10 && active.recipient == payload.recipient20)
                || (symmetric && active.actor == payload.recipient20 && active.recipient == payload.actor10))) return pending;
    }
    if (active_pair_count == 16) { note_drop(); return pending; }
    active_pairs[active_pair_count++] = {pending.value.kind, payload.actor10, payload.recipient20};
    pending.observed = true;
    auto& value = pending.value;
    value.actor = payload.actor10;
    value.recipient = payload.recipient20;
    value.state = static_cast<unsigned>(payload.state34);
    value.mode = static_cast<unsigned>(payload.variant38);
    pending.payload = payload;
    pending.ready = insult_query_country(value.actor, pending.actor_country)
        && insult_query_country(value.recipient, pending.recipient_country)
        && snapshot(payload, value.kind, value.before);
    return pending;
}

static Pending begin(void* wrapper) noexcept {
    const auto address = reinterpret_cast<uintptr_t>(wrapper);
    uintptr_t action = 0, table = 0;
    owned::Kind kind{};
    if (!installed || transport_fault || address < 0x10000
        || address > UINT64_C(0x00007fffffffffa7)
        || !read(address + 0x50, action) || !read(action, table)
        || !kind_for_table(table, kind)) return {};
    int32_t date = 0;
    if (!date_now(date)) { note_drop(); return {}; }
    const auto entry = protocol_capture(wrapper);
    if (!entry.identity || !entry.readable || entry.action != action) return {};
    AlliancePayload payload{};
    if (!execution_payload(entry.payload, payload)) return {};
    return begin_payload(action, payload);
}

static void finish(Pending& pending) noexcept {
    if (!pending.observed) return;
    pending.observed = false;
    // begin/finish follow the original command's synchronous call stack.
    const auto active = active_pairs[--active_pair_count];
#ifndef BRIDGE_ALLIANCE_RECORD_OBSERVATION
    (void)active;
#endif
    auto& value = pending.value;
    uintptr_t actor = 0, recipient = 0;
    int32_t date = 0;
    if (!pending.ready || transport_fault || !date_now(date) || date != value.date
        || !insult_query_country(value.actor, actor) || actor != pending.actor_country
        || !insult_query_country(value.recipient, recipient) || recipient != pending.recipient_country
        || !snapshot(pending.payload, value.kind, value.after)) { note_drop(); return; }
    const auto outcome = owned::classify(value.kind, value.before, value.after);
    if (outcome == owned::Outcome::unchanged) return;
    if (outcome == owned::Outcome::unreadable) { note_drop(); return; }
#ifdef BRIDGE_ALLIANCE_RECORD_OBSERVATION
    // Retain command fallback unless the record observations cover exactly
    // this command's before/after state, including any synchronous nesting.
    if (active.record_observed
        && record_snapshot_equal(value.kind,active.record_before,value.before)
        && record_snapshot_equal(value.kind,active.record_after,value.after)) return;
#endif
    enqueue(value);
}

static bool append(const char* message, size_t bytes) noexcept {
    if (transport_fault || log_file == INVALID_HANDLE_VALUE) { transport_fault = true; return false; }
    DWORD written = 0;
    if (!WriteFile(log_file, message, static_cast<DWORD>(bytes), &written, nullptr)
        || written != bytes || !FlushFileBuffers(log_file)) { transport_fault = true; return false; }
    return true;
}

static void snapshot_json(owned::Kind kind, const owned::Snapshot& value, char* output, size_t capacity) noexcept {
    char guarantee[128] = "null", support[128] = "null", subject[192] = "null";
    if (kind == owned::Kind::guarantee)
        snprintf(guarantee, sizeof(guarantee), "{\"actor_grants\":%s,\"recipient_grants\":%s}",
            value.guarantee_actor_grants ? "true" : "false", value.guarantee_recipient_grants ? "true" : "false");
    if (kind == owned::Kind::support_independence)
        snprintf(support, sizeof(support), "{\"actor_is_subject\":%s,\"recipient_is_subject\":%s}",
            value.support_actor_is_subject ? "true" : "false", value.support_recipient_is_subject ? "true" : "false");
    if (kind == owned::Kind::subject) {
        char type[68] = "null";
        if (value.active) snprintf(type, sizeof(type), "\"%s\"", value.subject_type);
        snprintf(subject, sizeof(subject), "{\"actor_is_overlord\":%s,\"actor_is_subject\":%s,\"type\":%s}",
            value.subject_actor_is_overlord ? "true" : "false", value.subject_actor_is_subject ? "true" : "false", type);
    }
    snprintf(output, capacity, "{\"active\":%s,\"guarantee\":%s,\"support_roles\":%s,\"subject\":%s}",
        value.active ? "true" : "false", guarantee, support, subject);
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
        char actor[4]{}, recipient[4]{}, before[384]{}, after[384]{}, message[1600]{};
        for (unsigned byte = 0; byte < 3; ++byte) {
            actor[byte] = static_cast<char>(value.actor >> (byte * 8));
            recipient[byte] = static_cast<char>(value.recipient >> (byte * 8));
        }
        snapshot_json(value.kind, value.before, before, sizeof(before));
        snapshot_json(value.kind, value.after, after, sizeof(after));
#ifdef BRIDGE_ALLIANCE_RECORD_OBSERVATION
#ifdef BRIDGE_SUPPORT_SUBJECT_RECORD_OBSERVATION
        const char* path = nullptr;
        switch (value.path) {
        case Path::command_return: path = "command_return"; break;
        case Path::alliance_record_enable: path = "alliance_record_enable"; break;
        case Path::alliance_record_disable: path = "alliance_record_disable"; break;
        case Path::royal_record_enable: path = "royal_record_enable"; break;
        case Path::royal_record_disable: path = "royal_record_disable"; break;
        case Path::guarantee_record_enable: path = "guarantee_record_enable"; break;
        case Path::guarantee_record_disable: path = "guarantee_record_disable"; break;
        case Path::military_record_enable: path = "military_record_enable"; break;
        case Path::military_record_disable: path = "military_record_disable"; break;
        case Path::support_record_enable: path = "support_record_enable"; break;
        case Path::support_record_disable: path = "support_record_disable"; break;
        case Path::subject_record_enable: path = "subject_record_enable"; break;
        case Path::subject_record_disable: path = "subject_record_disable"; break;
        }
        constexpr unsigned wire =
#ifdef BRIDGE_NATIVE_COUNTRY_CONTROL
            6;
#else
            5;
#endif
        constexpr const char* source = "relation_command_or_six_family_record_return_actual_pair_state";
#elif defined(BRIDGE_DIRECTED_RECORD_OBSERVATION)
        const char* path = nullptr;
        switch (value.path) {
        case Path::command_return: path = "command_return"; break;
        case Path::alliance_record_enable: path = "alliance_record_enable"; break;
        case Path::alliance_record_disable: path = "alliance_record_disable"; break;
        case Path::royal_record_enable: path = "royal_record_enable"; break;
        case Path::royal_record_disable: path = "royal_record_disable"; break;
        case Path::guarantee_record_enable: path = "guarantee_record_enable"; break;
        case Path::guarantee_record_disable: path = "guarantee_record_disable"; break;
        case Path::military_record_enable: path = "military_record_enable"; break;
        case Path::military_record_disable: path = "military_record_disable"; break;
        }
        constexpr unsigned wire = 4;
        constexpr const char* source = "relation_command_or_alliance_or_royal_or_directed_record_return_actual_pair_state";
#elif defined(BRIDGE_ROYAL_RECORD_OBSERVATION)
        const char* path = nullptr;
        switch (value.path) {
        case Path::command_return: path = "command_return"; break;
        case Path::alliance_record_enable: path = "alliance_record_enable"; break;
        case Path::alliance_record_disable: path = "alliance_record_disable"; break;
        case Path::royal_record_enable: path = "royal_record_enable"; break;
        case Path::royal_record_disable: path = "royal_record_disable"; break;
        }
        constexpr unsigned wire = 3;
        constexpr const char* source = "relation_command_or_alliance_or_royal_record_return_actual_pair_state";
#else
        const char* path = value.path == Path::command_return ? "command_return"
            : value.path == Path::alliance_record_enable ? "alliance_record_enable" : "alliance_record_disable";
        constexpr unsigned wire = 2;
        constexpr const char* source = "relation_command_or_alliance_record_return_actual_pair_state";
#endif
        char state[12] = "null", mode[12] = "null";
        if (value.path == Path::command_return) {
            snprintf(state,sizeof(state),"%u",value.state);
            snprintf(mode,sizeof(mode),"%u",value.mode);
        }
        const int bytes = snprintf(message,sizeof(message),
            "{\"event\":\"native_relation_changed\",\"schema_version\":%u,\"session_id\":\"%lu-%llx\","
            "\"sequence\":%llu,\"country\":\"%.3s\",\"actor\":\"%s\",\"recipient\":\"%s\","
            "\"actor_fullref\":\"0x%llx\",\"recipient_fullref\":\"0x%llx\",\"date_raw\":%d,"
            "\"relation_kind\":\"%s\",\"command_state\":%s,\"command_mode\":%s,\"before\":%s,\"after\":%s,"
            "\"observation_path\":\"%s\",\"source\":\"%s\",\"complete\":true}\n",
            wire,static_cast<unsigned long>(GetCurrentProcessId()),static_cast<unsigned long long>(observation_creation),
            static_cast<unsigned long long>(event.sequence),
            value.observer==value.actor?actor:recipient,actor,recipient,
            static_cast<unsigned long long>(value.actor),static_cast<unsigned long long>(value.recipient),
            value.date,owned::name(value.kind),state,mode,before,after,path,source);
#else
        const int bytes = snprintf(message, sizeof(message),
            "{\"event\":\"native_relation_changed\",\"schema_version\":1,\"session_id\":\"%lu-%llx\","
            "\"sequence\":%llu,\"country\":\"FRA\",\"actor\":\"%s\",\"recipient\":\"%s\","
            "\"actor_fullref\":\"0x%llx\",\"recipient_fullref\":\"0x%llx\",\"date_raw\":%d,"
            "\"relation_kind\":\"%s\",\"command_state\":%u,\"command_mode\":%u,\"before\":%s,\"after\":%s,"
            "\"source\":\"relation_command_return_actual_pair_state\",\"complete\":true}\n",
            static_cast<unsigned long>(GetCurrentProcessId()), static_cast<unsigned long long>(observation_creation),
            static_cast<unsigned long long>(event.sequence), actor, recipient,
            static_cast<unsigned long long>(value.actor), static_cast<unsigned long long>(value.recipient),
            value.date, owned::name(value.kind), value.state, value.mode, before, after);
#endif
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
            "{\"event\":\"native_relation_capture_gap\",\"session_id\":\"%lu-%llx\",\"dropped\":%ld,\"complete\":false}\n",
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
        ",\"relation_source\":{\"installed\":%s,\"transport_fault\":%s,\"total_dropped\":%ld,"
        "\"queue_readable\":%s,\"queued\":%u}}\n", installed.load() ? "true" : "false",
        transport_fault.load() ? "true" : "false", static_cast<long>(InterlockedCompareExchange(&total_dropped, 0, 0)),
        readable ? "true" : "false", queued);
}

} // namespace relation_change_observer
