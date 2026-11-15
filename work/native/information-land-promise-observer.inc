// Included in alliance_execution_detail before the declaration observer.
// Uses the existing command calls and war registry. No additional entry patch.
namespace land_promise_observer {

namespace owned = ::information::land_promise;
struct Event final { owned::Value value{}; uint64_t sequence = 0; };
struct Pending final {
    owned::Kind kind = owned::Kind::none;
    uint64_t actor = 0, recipient = 0;
    uintptr_t actor_country = 0, recipient_country = 0;
    owned::References actor_before{}, recipient_before{};
    std::array<uint64_t, owned::kMaxPromises> promises{};
    unsigned count = 0;
    uint64_t birth_sequence_before = 0;
    int32_t date = 0;
    bool ready = false;
};
struct LastError final {
    DWORD value = GetLastError();
    ~LastError() noexcept { SetLastError(value); }
};
static std::atomic<bool> installed{false}, transport_fault{false};
static SRWLOCK queue_lock = SRWLOCK_INIT;
static Event events[owned::kCapacity]{};
static unsigned head = 0, size = 0;
static volatile LONG64 sequence = 0;
static volatile LONG dropped = 0, total_dropped = 0;
constexpr uintptr_t kCallVtable = 0x1c800b0;

static void note_drop() noexcept {
    InterlockedIncrement(&dropped);
    InterlockedIncrement(&total_dropped);
}

static bool date_now(int32_t& date) noexcept {
    uintptr_t game = 0;
    return !thread_changed && frame_thread == GetCurrentThreadId()
        && read(base + 0x233fe58, game) && read(game + 0x1dd0, date) && date > 0;
}

static bool canonical_country(uint64_t reference, uintptr_t& country) noexcept {
    if (((reference >> 32) & 0xffffu) >= 4096) return false;
    for (unsigned index = 0; index < 3; ++index) {
        const auto value = static_cast<unsigned char>(reference >> (index * 8));
        if (!((value >= 'A' && value <= 'Z') || (value >= '0' && value <= '9'))) return false;
    }
    return peace_query_country_pointer(reference, country);
}

static bool pair_snapshot(Pending& pending, owned::References& output) noexcept {
    PeaceWarReferenceList left{}, right{};
    uintptr_t actor = 0, recipient = 0;
    if (!canonical_country(pending.actor, actor) || !canonical_country(pending.recipient, recipient)
        || actor != pending.actor_country || recipient != pending.recipient_country
        || !peace_query_pair_references(actor, static_cast<unsigned>((pending.recipient >> 32) & 0xffffu), left)
        || !peace_query_pair_references(recipient, static_cast<unsigned>((pending.actor >> 32) & 0xffffu), right)
        || !peace_query_reference_sets_equal(left, right)
        || !peace_query_context_state_stable(pending.actor, pending.recipient, actor, recipient, left, right)) return false;
    output = owned::References{};
    output.count = left.count;
    for (unsigned index = 0; index < left.count; ++index) {
        output.values[index] = left.references[index];
        output.births[index] = peace_war_registry_lifetimes.birth(left.references[index]).sequence;
    }
    output.complete = true;
    return information::war_declaration::valid(output);
}

static bool country_references(uint64_t reference, uintptr_t expected,
                               owned::References& output) noexcept {
    uintptr_t country = 0, rows = 0;
    int32_t count = 0;
    if (!canonical_country(reference, country) || country != expected
        || !read(country + 0x1548, rows) || !read(country + 0x1554, count)
        || count < 0 || count > 256 || (count && rows < 0x10000)) return false;
    struct Row final { int32_t slot = 0, unused = 0; uintptr_t war = 0; };
    static_assert(sizeof(Row) == 16);
    std::array<Row, 256> captured{};
    output = owned::References{};
    for (int32_t index = 0; index < count; ++index) {
        auto& row = captured[static_cast<unsigned>(index)];
        if (!read(rows + static_cast<uintptr_t>(index) * 16, row)
            || row.slot < 0 || row.slot >= 4096 || row.war < 0x10000) return false;
        bool duplicate = false;
        for (unsigned prior = 0; prior < output.count; ++prior)
            duplicate = duplicate || output.values[prior] == row.war;
        if (duplicate) continue;
        if (output.count == output.values.size()) return false;
        output.values[output.count] = row.war;
        output.births[output.count] = peace_war_registry_lifetimes.birth(row.war).sequence;
        ++output.count;
    }
    for (int32_t index = 0; index < count; ++index) {
        Row after{};
        if (!read(rows + static_cast<uintptr_t>(index) * 16, after)
            || after.slot != captured[static_cast<unsigned>(index)].slot
            || after.war != captured[static_cast<unsigned>(index)].war) return false;
    }
    uintptr_t after_country = 0, after_rows = 0;
    int32_t after_count = 0;
    if (!canonical_country(reference, after_country) || after_country != country
        || !read(country + 0x1548, after_rows) || after_rows != rows
        || !read(country + 0x1554, after_count) || after_count != count) return false;
    output.complete = true;
    return information::war_declaration::valid(output);
}

enum class PromiseRecord : unsigned char { unreadable, absent, promised };
static PromiseRecord promised_record(uintptr_t war, uint64_t beneficiary) noexcept {
    std::array<uintptr_t, 3> vector{}, after{};
    if (!read(war + 0xc0, vector) || vector[1] < vector[0] || vector[2] < vector[1]
        || (vector[1] - vector[0]) % 0x90 || (vector[2] - vector[0]) % 0x90
        || (vector[1] - vector[0]) / 0x90 > 4096) return PromiseRecord::unreadable;
    unsigned matches = 0;
    unsigned char flag = 1;
    for (uintptr_t row = vector[0]; row < vector[1]; row += 0x90) {
        uintptr_t table = 0;
        uint64_t reference = 0;
        if (!read(row, table) || table != base + 0x1d1f6b0 || !read(row + 0x10, reference)) return PromiseRecord::unreadable;
        if (reference != beneficiary) continue;
        if (++matches != 1 || !read(row + 0x1c, flag) || flag > 1) return PromiseRecord::unreadable;
    }
    if (matches != 1 || !read(war + 0xc0, after) || after != vector) return PromiseRecord::unreadable;
    return flag == 0 ? PromiseRecord::promised : PromiseRecord::absent;
}

static bool value_for_war(const Pending& pending, uintptr_t war, uint64_t beneficiary,
                          owned::Value& value) noexcept {
    PeaceWarSideMembers first_a{}, first_b{}, side_a{}, side_b{};
    const char* reason = nullptr;
    if (!peace_war_capture_vectors_stable(war, 0x48, 0x50, 0x58, 0x78, 0x80, 0x88,
                                         first_a, first_b, reason)) return false;
    const unsigned first_side = peace_war_side_for_handle(first_a, first_b, pending.actor);
    const auto& opponents = first_side == 1 ? first_b : first_a;
    if (!first_side || !opponents.count
        || !peace_war_capture_participant_sides(war, pending.actor, opponents.handles[0], side_a, side_b, reason)) return false;
    const unsigned actor_side = peace_war_side_for_handle(side_a, side_b, pending.actor);
    value = owned::Value{};
    if (peace_war_side_for_handle(side_a, side_b, beneficiary) != actor_side) return true;
    const auto record = promised_record(war, beneficiary);
    if (record == PromiseRecord::unreadable) return false;
    if (record == PromiseRecord::absent) return true;
    for (const auto* side : {&side_a, &side_b})
        for (unsigned index = 0; index < side->count; ++index)
            if ((side->handles[index] & 0xffffffu) == 0x415246u) value.observer = side->handles[index];
    if (!value.observer) return true;
    const auto registered = peace_query_register_war(war);
    if (!registered || !peace_war_registry_lifetimes.current(*registered)) return false;
    value.promisor = pending.actor;
    value.beneficiary = beneficiary;
    value.date = pending.date;
    value.kind = pending.kind;
    std::memcpy(value.war_id, registered->public_id, sizeof(value.war_id));
    return true;
}

static void enqueue(const owned::Value& value) noexcept {
    if (!value.observer) return;
    if (!TryAcquireSRWLockExclusive(&queue_lock)) { note_drop(); return; }
    bool duplicate = false;
    for (unsigned index = 0; index < size; ++index)
        duplicate = duplicate || owned::same(events[(head + index) % owned::kCapacity].value, value);
    if (!duplicate) {
        if (size < owned::kCapacity) {
            events[(head + size) % owned::kCapacity] = {value, static_cast<uint64_t>(InterlockedIncrement64(&sequence))};
            ++size;
        } else note_drop();
    }
    ReleaseSRWLockExclusive(&queue_lock);
}

static Pending begin_action(uintptr_t action) noexcept {
    LastError preserve{};
    Pending pending{};
    uintptr_t table = 0;
    if (!installed || transport_fault || !read(action, table)) return pending;
    if (table == base + lifecycle_declarewar_vtable_rva) {
        const auto shape = lifecycle_capture_shape(reinterpret_cast<void*>(action));
        AlliancePayload payload{};
        if (!execution_payload(shape, payload) || payload.family != ActionFamily::declare_war
            || payload.state34 != 0 || payload.variant38 != 1 || !payload.war.container68.count) return pending;
        pending.kind = owned::Kind::declaration;
        pending.actor = payload.actor10;
        pending.recipient = payload.recipient20;
        pending.count = payload.war.container68.count;
        if (pending.count > owned::kMaxPromises) return pending;
        for (unsigned index = 0; index < pending.count; ++index) {
            const uint64_t beneficiary = payload.war.container68.values[index];
            uintptr_t country = 0;
            bool selected = false;
            for (unsigned called = 0; called < payload.war.container50.count; ++called)
                selected = selected || payload.war.container50.values[called] == beneficiary;
            if (!selected || beneficiary == pending.actor || beneficiary == pending.recipient
                || !canonical_country(beneficiary, country)) return pending;
            for (unsigned prior = 0; prior < index; ++prior)
                if (pending.promises[prior] == beneficiary) return pending;
            pending.promises[index] = beneficiary;
        }
    } else if (table == base + kCallVtable) {
        int32_t marker = 0, state = 0;
        unsigned char promise = 1;
        if (!read(action + 8, marker) || marker != 0x165 || !read(action + 0x34, state)
            || (state != 0 && state != 2) || !read(action + 0x53, promise) || promise != 0) return pending;
        pending.kind = owned::Kind::call;
        if (!read(action + 0x10, pending.actor) || !read(action + 0x20, pending.recipient)) return pending;
    } else return pending;
    if (pending.actor == pending.recipient || !date_now(pending.date)
        || !canonical_country(pending.actor, pending.actor_country)
        || !canonical_country(pending.recipient, pending.recipient_country)) return pending;
    pending.birth_sequence_before = peace_war_registry_lifetimes.sequence();
    if (pending.kind == owned::Kind::declaration)
        pending.ready = pair_snapshot(pending, pending.actor_before);
    else pending.ready = country_references(pending.actor, pending.actor_country, pending.actor_before)
        && country_references(pending.recipient, pending.recipient_country, pending.recipient_before);
    return pending;
}

static Pending begin(void* wrapper) noexcept {
    LastError preserve{};
    uintptr_t action = 0;
    const auto address = reinterpret_cast<uintptr_t>(wrapper);
    if (!installed || transport_fault || address < 0x10000 || !read(address + 0x50, action)) return {};
    return begin_action(action);
}

static void finish(Pending& pending) noexcept {
    LastError preserve{};
    if (pending.kind == owned::Kind::none) return;
    const auto kind = pending.kind;
    int32_t date = 0;
    if (!pending.ready || transport_fault || !date_now(date) || date != pending.date) {
        pending.kind = owned::Kind::none;
        note_drop();
        return;
    }
    if (kind == owned::Kind::declaration) {
        owned::References after{};
        if (!pair_snapshot(pending, after)) { note_drop(); pending.kind = owned::Kind::none; return; }
        const auto difference = information::war_declaration::difference(pending.actor_before, after);
        if (difference.outcome == information::war_declaration::Outcome::single_added) {
            const auto birth = peace_war_registry_lifetimes.birth(difference.reference);
            if (birth.sequence <= pending.birth_sequence_before || birth.sequence != difference.birth
                || birth.state != information::war_registry::BirthState::complete
                || birth.actor != pending.actor || birth.recipient != pending.recipient) note_drop();
            else for (unsigned index = 0; index < pending.count; ++index) {
                owned::Value value{};
                if (value_for_war(pending, difference.reference, pending.promises[index], value)) enqueue(value);
                else note_drop();
            }
        } else if (difference.outcome != information::war_declaration::Outcome::unchanged) note_drop();
    } else {
        owned::References actor_after{}, recipient_after{};
        if (!country_references(pending.actor, pending.actor_country, actor_after)
            || !country_references(pending.recipient, pending.recipient_country, recipient_after)) note_drop();
        else for (unsigned index = 0; index < recipient_after.count; ++index) {
            if (!owned::joined(pending.actor_before, actor_after, pending.recipient_before, recipient_after, index)) continue;
            owned::Value value{};
            if (value_for_war(pending, recipient_after.values[index], pending.recipient, value)) enqueue(value);
            else note_drop();
        }
    }
    pending.kind = owned::Kind::none;
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
        const auto& value = event.value;
        const char* source = value.kind == owned::Kind::declaration
            ? "declare_war_return_promised_participant" : "call_action_return_new_promised_participant";
        char message[1024]{};
        const int bytes = snprintf(message, sizeof(message),
            "{\"event\":\"native_land_promise_established\",\"session_id\":\"%lu-%llx\","
            "\"sequence\":%llu,\"date_raw\":%d,\"promisor_ref\":\"0x%llx\","
            "\"beneficiary_ref\":\"0x%llx\",\"observer_ref\":\"0x%llx\",\"war_id\":\"%s\","
            "\"source\":\"%s\",\"wire\":1}\n",
            static_cast<unsigned long>(GetCurrentProcessId()), static_cast<unsigned long long>(observation_creation),
            static_cast<unsigned long long>(event.sequence), value.date, static_cast<unsigned long long>(value.promisor),
            static_cast<unsigned long long>(value.beneficiary), static_cast<unsigned long long>(value.observer),
            value.war_id, source);
        if (bytes <= 0 || static_cast<size_t>(bytes) >= sizeof(message)) { transport_fault = true; return; }
        if (!append(message, static_cast<size_t>(bytes))) return;
        AcquireSRWLockExclusive(&queue_lock);
        head = (head + 1) % owned::kCapacity;
        --size;
        ReleaseSRWLockExclusive(&queue_lock);
    }
    const LONG count = InterlockedCompareExchange(&dropped, 0, 0);
    if (count) {
        char message[256]{};
        const int bytes = snprintf(message, sizeof(message),
            "{\"event\":\"native_land_promise_capture_gap\",\"session_id\":\"%lu-%llx\","
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
    const bool readable = TryAcquireSRWLockExclusive(&queue_lock) != FALSE;
    if (readable) { queued = size; ReleaseSRWLockExclusive(&queue_lock); }
    snprintf(end, capacity - static_cast<size_t>(end - message),
        ",\"land_promise_source\":{\"installed\":%s,\"transport_fault\":%s,\"total_dropped\":%ld,"
        "\"queue_readable\":%s,\"queued\":%u}}\n", installed.load() ? "true" : "false",
        transport_fault.load() ? "true" : "false", static_cast<long>(InterlockedCompareExchange(&total_dropped, 0, 0)),
        readable ? "true" : "false", queued);
}

static bool install() noexcept {
    LastError preserve{};
    if (installed) return false;
    const auto reader = [](uintptr_t address, auto& value) { return read(address, value); };
    uintptr_t call_handler = 0;
    if (!read(base + kCallVtable + 0x48, call_handler) || call_handler != base + 0x53e130
        || !information::land_promise::native_guards::verify(reader, base)) return false;
    installed = true;
    return true;
}

static bool rollback() noexcept {
    installed = false;
    return true;
}

} // namespace land_promise_observer
