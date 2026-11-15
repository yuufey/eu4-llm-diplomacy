#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <type_traits>

static constexpr uintptr_t kImageBase = UINT64_C(0x140000000);
static constexpr uintptr_t kFakeGame = UINT64_C(0x21000000);
static constexpr size_t kArenaBytes = 0x4000;
static uintptr_t base = kImageBase;
static DWORD frame_thread = 0;
static bool thread_changed = false;
static uint64_t observation_creation = UINT64_C(0x321001);
static HANDLE log_file = INVALID_HANDLE_VALUE;
static unsigned read_calls = 0, country_calls = 0, membership_calls = 0;

struct RivalQueryState {
    bool state_verified = false;
    bool active = false;
    int32_t since_date_raw = -1;
    int32_t count = -1;
    int32_t max_rivals = -1;
    int32_t diplomatic_power_raw = -1;
    bool at_war = false;
};

struct FixtureArena {
    int32_t date_raw = 100;
    uint64_t actor_ref = 0, target_ref = 0, old_ref = 0;
    uintptr_t actor_country = 0, target_country = 0, old_country = 0;
    int32_t count = 0;
    bool target_readable = true, target_verified = true;
    bool old_readable = true, old_verified = true;
    bool actor_resolvable = true, target_resolvable = true, old_resolvable = true;
    bool membership_readable = true;
    bool target_active = false, old_active = false;
    int32_t target_since = -1, old_since = -1;
};

static FixtureArena* arena = nullptr;

template<class Value>
static bool read(uintptr_t address, Value& value) noexcept {
    ++read_calls;
    if constexpr (std::is_same_v<Value, uintptr_t>) {
        if (address == base + 0x233fe58) {
            value = kFakeGame;
            return true;
        }
    } else if constexpr (std::is_same_v<Value, int32_t>) {
        if (address == kFakeGame + 0x1dd0 && arena) {
            value = arena->date_raw;
            return true;
        }
    }
    return false;
}

static bool insult_query_country(uint64_t reference, uintptr_t& country) noexcept {
    ++country_calls;
    if (!arena) return false;
    if (reference == arena->actor_ref && arena->actor_resolvable) {
        country = arena->actor_country;
        return country != 0;
    }
    if (reference == arena->target_ref && arena->target_resolvable) {
        country = arena->target_country;
        return country != 0;
    }
    if (reference == arena->old_ref && arena->old_resolvable) {
        country = arena->old_country;
        return country != 0;
    }
    return false;
}

static bool rival_query_membership(uintptr_t owner, uint64_t recipient,
    RivalQueryState& state) noexcept {
    ++membership_calls;
    state = RivalQueryState{};
    if (!arena || owner != arena->actor_country || !arena->membership_readable) return false;
    state.count = arena->count;
    state.max_rivals = 5;
    state.diplomatic_power_raw = 100;
    if (recipient == arena->target_ref) {
        if (!arena->target_readable) return false;
        state.state_verified = arena->target_verified;
        state.active = arena->target_active;
        state.since_date_raw = state.active ? arena->target_since : -1;
        return true;
    }
    if (recipient == arena->old_ref) {
        if (!arena->old_readable) return false;
        state.state_verified = arena->old_verified;
        state.active = arena->old_active;
        state.since_date_raw = state.active ? arena->old_since : -1;
        return true;
    }
    return false;
}

#include "../information-rival-observer.inc"

namespace source = rival_change_observer;
namespace owned = information::rival_change;

static unsigned checks = 0, failures = 0, scenarios = 0;

static void check(bool okay, const char* name) {
    ++checks;
    if (!okay) {
        ++failures;
        std::printf("FAIL %s\n", name);
    }
}

#define CHECK_ONE(expression) check((expression), #expression)
#define CHECK_TWO(expression, name) check((expression), name)
#define CHECK_SELECT(_1, _2, NAME, ...) NAME
#define CHECK(...) CHECK_SELECT(__VA_ARGS__, CHECK_TWO, CHECK_ONE)(__VA_ARGS__)

static uint64_t make_reference(const char* tag, uint16_t slot) {
    const uint64_t code = static_cast<unsigned char>(tag[0])
        | (static_cast<uint64_t>(static_cast<unsigned char>(tag[1])) << 8)
        | (static_cast<uint64_t>(static_cast<unsigned char>(tag[2])) << 16);
    return (static_cast<uint64_t>(slot) << 32) | code;
}

static void reset_observer() {
    source::installed.store(true);
    source::transport_fault.store(false);
    source::sequence = 0;
    source::dropped = 0;
    source::total_dropped = 0;
    source::head = 0;
    source::size = 0;
    for (auto& event : source::events) event = source::Event{};
}

static void reset_fixture(bool target_active = false, int32_t target_since = -1,
    bool old_active = false, int32_t old_since = -1, int32_t count = 0) {
    *arena = FixtureArena{};
    arena->actor_ref = make_reference("FRA", 1);
    arena->target_ref = make_reference("ENG", 2);
    arena->old_ref = make_reference("ARA", 3);
    const auto memory = reinterpret_cast<uintptr_t>(arena);
    arena->actor_country = memory + 0x800;
    arena->target_country = memory + 0x1000;
    arena->old_country = memory + 0x1800;
    arena->target_active = target_active;
    arena->target_since = target_active ? target_since : -1;
    arena->old_active = old_active;
    arena->old_since = old_active ? old_since : -1;
    arena->count = count;
    base = kImageBase;
    frame_thread = GetCurrentThreadId();
    thread_changed = false;
    read_calls = country_calls = membership_calls = 0;
    reset_observer();
}

static source::Pending begin(unsigned kind, bool command_verified = true) {
    return source::begin(kind, arena->actor_ref, arena->target_ref, arena->old_ref,
        command_verified);
}

static void clear_log() {
    LARGE_INTEGER zero{};
    CHECK(log_file != INVALID_HANDLE_VALUE);
    CHECK(SetFilePointerEx(log_file, zero, nullptr, FILE_BEGIN) != FALSE);
    CHECK(SetEndOfFile(log_file) != FALSE);
}

static wchar_t log_path[32768]{};

static bool open_log_reader(char* output, DWORD capacity, DWORD& bytes) {
    HANDLE input = CreateFileW(log_path, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (input == INVALID_HANDLE_VALUE) return false;
    const bool okay = ReadFile(input, output, capacity - 1, &bytes, nullptr) != FALSE;
    CloseHandle(input);
    if (okay) output[bytes] = '\0';
    return okay;
}

static void test_set_event_owned_copy_and_json() {
    ++scenarios;
    clear_log();
    reset_fixture();
    auto pending = begin(1);
    CHECK(pending.ready);
    arena->target_active = true;
    arena->target_since = arena->date_raw;
    arena->count = 1;
    source::finish(pending);
    CHECK(source::size == 1 && source::total_dropped == 0);
    const auto saved = source::events[source::head];
    CHECK(saved.value.kind == owned::Kind::set);
    CHECK(saved.value.actor == arena->actor_ref && saved.value.target == arena->target_ref);
    CHECK(!saved.value.before.target.active && saved.value.after.target.active);
    CHECK(saved.value.before.count == 0 && saved.value.after.count == 1);
    arena->target_active = false;
    arena->target_since = -1;
    arena->count = 0;
    CHECK(saved.value.after.target.active && saved.value.after.count == 1,
        "queued event is an owned copy");
    source::finish(pending);
    CHECK(source::size == 1 && source::total_dropped == 0, "successful finish is idempotent");
    source::flush();
    CHECK(source::size == 0 && !source::transport_fault);
    char output[4096]{};
    DWORD bytes = 0;
    CHECK(open_log_reader(output, sizeof(output), bytes));
    CHECK(std::strstr(output, "\"event\":\"native_rival_changed\"") != nullptr);
    CHECK(std::strstr(output, "\"operation\":\"set\"") != nullptr);
    CHECK(std::strstr(output, "\"actor\":\"FRA\",\"target\":\"ENG\"") != nullptr);
    CHECK(std::strstr(output, "\"complete\":true") != nullptr);
}

static void test_remove_and_noop() {
    ++scenarios;
    reset_fixture(true, 90, false, -1, 1);
    auto pending = begin(3);
    CHECK(pending.ready);
    arena->target_active = false;
    arena->target_since = -1;
    arena->count = 0;
    source::finish(pending);
    CHECK(source::size == 1 && source::events[source::head].value.kind == owned::Kind::remove);

    reset_fixture();
    pending = begin(1);
    CHECK(pending.ready);
    source::finish(pending);
    CHECK(source::size == 0 && source::total_dropped == 0, "no-op emits no event");
    source::finish(pending);
    CHECK(source::size == 0 && source::total_dropped == 0, "no-op finish is idempotent");
}

static void test_replace_full_and_partial_results() {
    ++scenarios;
    reset_fixture(false, -1, true, 80, 1);
    auto pending = begin(2);
    CHECK(pending.ready);
    arena->target_active = true;
    arena->target_since = 100;
    arena->old_active = false;
    arena->old_since = -1;
    source::finish(pending);
    CHECK(source::size == 1 && source::events[source::head].value.kind == owned::Kind::replace);
    CHECK(source::events[source::head].value.before.old_rival.active
        && source::events[source::head].value.after.target.active
        && !source::events[source::head].value.after.old_rival.active);

    reset_fixture(false, -1, true, 80, 1);
    pending = begin(2);
    arena->target_active = true;
    arena->target_since = 100;
    arena->count = 2;
    source::finish(pending);
    CHECK(source::size == 1 && source::events[source::head].value.after.target.active
        && source::events[source::head].value.after.old_rival.active,
        "partial replace with only new rival changed");

    reset_fixture(true, 80, true, 70, 2);
    pending = begin(2);
    arena->old_active = false;
    arena->old_since = -1;
    arena->count = 1;
    source::finish(pending);
    CHECK(source::size == 1 && source::events[source::head].value.after.target.active
        && !source::events[source::head].value.after.old_rival.active,
        "partial replace with only old rival changed");
}

static void expect_one_capture_gap(const char* label) {
    CHECK(source::size == 0 && source::total_dropped == 1 && source::dropped == 1, label);
    auto pending = source::Pending{};
    const auto before = source::total_dropped;
    source::finish(pending);
    CHECK(source::total_dropped == before, "failed pending finish remains idempotent");
}

static void test_unreadable_and_count_mismatch() {
    ++scenarios;
    reset_fixture();
    arena->target_verified = false;
    auto pending = begin(1);
    CHECK(!pending.ready);
    source::finish(pending);
    expect_one_capture_gap("unverified membership produces a gap");

    reset_fixture();
    pending = begin(1);
    CHECK(pending.ready);
    arena->target_active = true;
    arena->target_since = 100;
    // Membership changed but count did not, so classify refuses the event.
    source::finish(pending);
    expect_one_capture_gap("inconsistent count produces a gap");
}

static void test_date_thread_and_identity_filters() {
    ++scenarios;
    reset_fixture();
    auto pending = begin(1);
    arena->target_active = true;
    arena->target_since = 100;
    arena->count = 1;
    arena->date_raw = 101;
    source::finish(pending);
    expect_one_capture_gap("changed frame date produces a gap");

    reset_fixture();
    pending = begin(1);
    arena->target_active = true;
    arena->target_since = 100;
    arena->count = 1;
    thread_changed = true;
    source::finish(pending);
    expect_one_capture_gap("changed frame thread produces a gap");

    reset_fixture();
    pending = begin(1);
    arena->target_active = true;
    arena->target_since = 100;
    arena->count = 1;
    arena->actor_country += 0x100;
    source::finish(pending);
    expect_one_capture_gap("changed actor identity produces a gap");
}

static void test_early_filters_do_not_read() {
    ++scenarios;
    reset_fixture();
    auto pending = begin(1, false);
    CHECK(pending.relevant && !pending.ready);
    CHECK(read_calls == 0 && country_calls == 0 && membership_calls == 0,
        "unverified command begin performs no reads");
    source::finish(pending);
    CHECK(read_calls == 0 && country_calls == 0 && membership_calls == 0);
    CHECK(source::size == 0 && source::total_dropped == 1);

    reset_fixture();
    arena->actor_ref = make_reference("GER", 1);
    pending = begin(1);
    CHECK(!pending.relevant && !pending.ready);
    source::finish(pending);
    CHECK(read_calls == 0 && country_calls == 0 && membership_calls == 0,
        "irrelevant non-FRA command performs no reads");
    CHECK(source::size == 0 && source::total_dropped == 0);
}

static void test_bounded_queue_overflow_and_flush() {
    ++scenarios;
    clear_log();
    reset_fixture();
    for (unsigned index = 0; index < 65; ++index) {
        arena->target_active = false;
        arena->target_since = -1;
        arena->count = 0;
        auto pending = begin(1);
        arena->target_active = true;
        arena->target_since = 100;
        arena->count = 1;
        source::finish(pending);
    }
    CHECK(source::size == source::kCapacity && source::total_dropped == 1
        && source::dropped == 1, "64 queued and one overflow gap");
    source::flush();
    CHECK(source::size == 32 && source::dropped == 0 && source::total_dropped == 1,
        "first bounded flush writes 32 events and the gap");
    source::flush();
    CHECK(source::size == 0 && source::total_dropped == 1 && !source::transport_fault);
    char output[65536]{};
    DWORD bytes = 0;
    CHECK(open_log_reader(output, sizeof(output), bytes));
    unsigned lines = 0;
    for (DWORD index = 0; index < bytes; ++index) if (output[index] == '\n') ++lines;
    CHECK(lines == 65, "64 event records plus one capture-gap record");
    CHECK(std::strstr(output, "\"event\":\"native_rival_changed\"") != nullptr);
    CHECK(std::strstr(output, "\"event\":\"native_rival_capture_gap\"") != nullptr);
}

static void test_read_only_handle_fault_retains_queue_head() {
    ++scenarios;
    clear_log();
    reset_fixture();
    auto pending = begin(1);
    arena->target_active = true;
    arena->target_since = 100;
    arena->count = 1;
    source::finish(pending);
    CHECK(source::size == 1 && source::head == 0);
    CloseHandle(log_file);
    log_file = CreateFileW(log_path, GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    CHECK(log_file != INVALID_HANDLE_VALUE);
    source::flush();
    CHECK(source::transport_fault && source::size == 1 && source::head == 0,
        "read-only write failure latches fault and retains queue head");
    source::flush();
    CHECK(source::transport_fault && source::size == 1 && source::head == 0,
        "latched write fault does not consume or retry queue head");
    char health[640] = "{\"event\":\"fixture_health\"}\n";
    source::append_health(health, sizeof(health));
    CHECK(std::strstr(health, "\"transport_fault\":true") != nullptr);
    CHECK(std::strstr(health, "\"queued\":1") != nullptr);
}

int main() {
    static_assert(sizeof(uintptr_t) == 8, "EU4 fixture requires x64");
    auto memory = VirtualAlloc(nullptr, kArenaBytes, MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);
    if (!memory) return 2;
    arena = static_cast<FixtureArena*>(memory);
    const DWORD path_chars = GetEnvironmentVariableW(L"RIVAL_FIXTURE_LOG", log_path,
        static_cast<DWORD>(sizeof(log_path) / sizeof(log_path[0])));
    if (!path_chars || path_chars >= sizeof(log_path) / sizeof(log_path[0])) return 3;
    log_file = CreateFileW(log_path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (log_file == INVALID_HANDLE_VALUE) return 4;

    test_set_event_owned_copy_and_json();
    test_remove_and_noop();
    test_replace_full_and_partial_results();
    test_unreadable_and_count_mismatch();
    test_date_thread_and_identity_filters();
    test_early_filters_do_not_read();
    test_bounded_queue_overflow_and_flush();
    test_read_only_handle_fault_retains_queue_head();

    if (log_file != INVALID_HANDLE_VALUE) CloseHandle(log_file);
    source::installed.store(false);
    CHECK(VirtualFree(memory, 0, MEM_RELEASE) != FALSE);
    std::printf("rival production observer: %s (%u checks, %u scenarios)\n",
        failures ? "FAIL" : "PASS", checks, scenarios);
    return failures ? 1 : 0;
}
