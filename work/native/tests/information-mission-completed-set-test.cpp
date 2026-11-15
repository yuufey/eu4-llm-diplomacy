#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "../information-mission-completion.h"
#include "../information-mission-completed-set-entry-plan.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>

namespace owned = information::mission_completion;
namespace plan = information::mission_completed_set::entry;

static constexpr SIZE_T kArenaBytes = 0x2400000;
static constexpr uint64_t kFraTag = UINT64_C(0x415246);
static constexpr uint64_t kEngTag = UINT64_C(0x474e45);
static constexpr uint64_t kFraReference = UINT64_C(0x1200000100415246);
static constexpr uint64_t kEngReference = UINT64_C(0x1200000200474e45);
static constexpr uint32_t kCommandReturn = 0x8d7b16;
static constexpr uint32_t kEffectReturn = 0x6b94a6;
static constexpr uint32_t kExcludedReturn = 0x8d72c8;
static constexpr DWORD kIncomingError = ERROR_INVALID_FUNCTION;
static constexpr DWORD kReturnedError = ERROR_ACCESS_DENIED;

static uintptr_t base = 0;
static uintptr_t fra_country = 0;
static uintptr_t eng_country = 0;
static uintptr_t fake_country = 0;
static uintptr_t game_date_address = 0;
static uintptr_t fixture_return_pc = 0;
static DWORD frame_thread = 0;
static bool thread_changed = false;
static bool identity_shift_after_original = false;
static bool lifecycle_rollback_incomplete = false;
static uint64_t observation_creation = UINT64_C(0x330001);
static HANDLE log_file = INVALID_HANDLE_VALUE;

namespace bridge_entry_patch {
struct PatchTarget final {
    void* address = nullptr;
    unsigned size = 0;
    const unsigned char* expected = nullptr;
    const unsigned char* replacement = nullptr;
    const void* original_trampoline = nullptr;
    SIZE_T original_trampoline_size = 0;
};
struct PatchPlan final { unsigned count = 0; PatchTarget targets[1]{}; };
struct PatchResult final {
    bool published = false;
    bool success = false;
    bool threads_resumed = false;
    bool protection_restored = false;
};
static PatchResult guarded_patch_apply(const PatchPlan&) { return {}; }
static PatchResult guarded_patch_rollback(const PatchPlan&) { return {}; }
} // namespace bridge_entry_patch

static unsigned reads = 0;
static bool read(uintptr_t address, void* output, size_t bytes) noexcept {
    ++reads;
    SIZE_T copied = 0;
    return ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<void*>(address),
        output, bytes, &copied) != FALSE && copied == bytes;
}

template<class T>
static bool read(uintptr_t address, T& value) noexcept {
    return read(address, &value, sizeof(value));
}

static bool insult_query_country(uint64_t reference, uintptr_t& country) noexcept {
    if (reference == kFraReference) {
        country = fra_country + (identity_shift_after_original ? 0x20 : 0);
        return true;
    }
    if (reference == kEngReference) {
        country = eng_country;
        return true;
    }
    return false;
}

static void* fixture_return_address(unsigned) noexcept {
    return reinterpret_cast<void*>(fixture_return_pc);
}
#define __builtin_return_address(level) fixture_return_address(level)
#include "../information-mission-completed-set-observer.inc"
#undef __builtin_return_address

namespace Observer = mission_completion_observer;

static unsigned checks = 0;
static unsigned failures = 0;
static unsigned scenarios = 0;

#define CHECK(condition, label) do { \
    ++checks; \
    if (!(condition)) { ++failures; std::fprintf(stderr, "FAIL: %s\n", label); } \
} while (0)

struct Task final {
    uintptr_t country = 0;
    uintptr_t container = 0;
    uintptr_t definition = 0;
    uintptr_t key = 0;
    uintptr_t output = 0;
};

enum class Mode {
    insert,
    duplicate,
    throw_cpp,
    mutate_date,
    mutate_name,
    mutate_identity,
    invalid_flag,
    return_mismatch,
    nested_different,
    nested_same,
};

struct CallRecord final {
    unsigned reads_at_entry = 0;
    uintptr_t args[4]{};
    DWORD incoming_error = 0;
};

static Task primary_task{};
static Task nested_task{};
static Mode mode = Mode::insert;
static unsigned original_calls = 0;
static unsigned original_depth = 0;
static unsigned node_count = 0;
static CallRecord call_records[128]{};
static std::string mutated_name = "mutated_after_return";

static uintptr_t arena_at(size_t offset) {
    return base + offset;
}

static void put_u64(uintptr_t address, uint64_t value) noexcept {
    std::memcpy(reinterpret_cast<void*>(address), &value, sizeof(value));
}

static uint64_t get_u64(uintptr_t address) noexcept {
    uint64_t value = 0;
    std::memcpy(&value, reinterpret_cast<void*>(address), sizeof(value));
    return value;
}

static void put_string32(uintptr_t address, const std::string& text, uintptr_t heap_address) {
    std::memset(reinterpret_cast<void*>(address), 0, 32);
    const uint64_t length = text.size();
    uint64_t capacity = 15;
    if (text.size() <= 15) {
        std::memcpy(reinterpret_cast<void*>(address), text.data(), text.size());
        reinterpret_cast<char*>(address)[text.size()] = '\0';
    } else {
        capacity = text.size();
        std::memcpy(reinterpret_cast<void*>(heap_address), text.data(), text.size());
        reinterpret_cast<char*>(heap_address)[text.size()] = '\0';
        put_u64(address, heap_address);
    }
    put_u64(address + 16, length);
    put_u64(address + 24, capacity);
}

static uintptr_t sentinel_for(uintptr_t country) noexcept {
    return country + 0x9fc0;
}

static void initialize_country(uintptr_t country, uint64_t reference) noexcept {
    std::memset(reinterpret_cast<void*>(country), 0, 0xa000);
    put_u64(country + 0x20, reference);
    const uintptr_t sentinel = sentinel_for(country);
    put_u64(country + 0x99a0, sentinel);
    put_u64(sentinel, sentinel);
    put_u64(country + 0x99a8, 0);
}

static void reset_observer() noexcept {
    Observer::installed = true;
    Observer::transport_fault = false;
    Observer::head = Observer::size = 0;
    std::memset(Observer::events, 0, sizeof(Observer::events));
    InterlockedExchange64(&Observer::sequence, 0);
    InterlockedExchange(&Observer::dropped, 0);
    InterlockedExchange(&Observer::total_dropped, 0);
    Observer::original = nullptr;
    original_calls = original_depth = node_count = 0;
    std::memset(call_records, 0, sizeof(call_records));
    mode = Mode::insert;
    identity_shift_after_original = false;
    fixture_return_pc = base + kCommandReturn;
}

static void reset_world() {
    initialize_country(fra_country, kFraReference);
    initialize_country(eng_country, kEngReference);
    initialize_country(fake_country, kFraReference);
    uintptr_t game = base + 0x4000;
    put_u64(base + 0x233fe58, game);
    game_date_address = game + 0x1dd0;
    const int32_t date = 56700000;
    std::memcpy(reinterpret_cast<void*>(game_date_address), &date, sizeof(date));
    reset_observer();
    Observer::original = nullptr;
}

static Task make_task(const std::string& name, unsigned slot, uintptr_t country = 0) {
    if (!country) country = fra_country;
    const uintptr_t definition = arena_at(0x900000 + static_cast<size_t>(slot) * 0x500);
    put_string32(definition + 0x10, name, definition + 0x210);
    const uintptr_t key = arena_at(0xa10000 + static_cast<size_t>(slot) * 8);
    put_u64(key, definition);
    const uintptr_t output = arena_at(0xa20000 + static_cast<size_t>(slot) * 0x20);
    std::memset(reinterpret_cast<void*>(output), 0, 16);
    return {country, country + 0x9998, definition, key, output};
}

static void reset_case(const std::string& name) {
    reset_world();
    primary_task = make_task(name, 0);
    nested_task = {};
    frame_thread = GetCurrentThreadId();
    thread_changed = false;
    Observer::original = nullptr;
}

static uintptr_t find_node(uintptr_t country, uintptr_t definition) noexcept {
    const uintptr_t sentinel = static_cast<uintptr_t>(get_u64(country + 0x99a0));
    uintptr_t node = static_cast<uintptr_t>(get_u64(sentinel));
    for (unsigned index = 0; index <= owned::kMaxCompleted && node != sentinel; ++index) {
        if (get_u64(node + 0x10) == definition) return node;
        node = static_cast<uintptr_t>(get_u64(node));
    }
    return 0;
}

static uintptr_t insert_definition(uintptr_t country, uintptr_t definition) noexcept {
    uintptr_t existing = find_node(country, definition);
    if (existing) return existing;
    const uintptr_t sentinel = static_cast<uintptr_t>(get_u64(country + 0x99a0));
    const uintptr_t old_head = static_cast<uintptr_t>(get_u64(sentinel));
    const uintptr_t node = arena_at(0xc00000 + static_cast<size_t>(node_count++) * 0x20);
    put_u64(node, old_head);
    put_u64(node + 8, 0);
    put_u64(node + 0x10, definition);
    put_u64(sentinel, node);
    put_u64(country + 0x99a8, get_u64(country + 0x99a8) + 1);
    return node;
}

static bool write_output(uintptr_t output, uintptr_t node, unsigned char inserted) noexcept {
    if (!owned::range(output, 16)) return false;
    put_u64(output, node);
    std::memcpy(reinterpret_cast<void*>(output + 8), &inserted, sizeof(inserted));
    return true;
}

static uintptr_t do_insert(uintptr_t container, uintptr_t output, uintptr_t key) noexcept {
    const uintptr_t country = container - 0x9998;
    const uintptr_t definition = static_cast<uintptr_t>(get_u64(key));
    const uintptr_t node = insert_definition(country, definition);
    write_output(output, node, 1);
    return output;
}

static uintptr_t do_duplicate(uintptr_t container, uintptr_t output, uintptr_t key) noexcept {
    const uintptr_t country = container - 0x9998;
    const uintptr_t definition = static_cast<uintptr_t>(get_u64(key));
    const uintptr_t node = find_node(country, definition);
    write_output(output, node ? node : sentinel_for(country), 0);
    return output;
}

static uintptr_t fixture_original(uintptr_t container, uintptr_t output,
                                  uintptr_t key, uintptr_t fourth) {
    if (original_calls < sizeof(call_records)/sizeof(call_records[0])) {
        auto& record = call_records[original_calls];
        record.reads_at_entry = reads;
        record.args[0] = container;
        record.args[1] = output;
        record.args[2] = key;
        record.args[3] = fourth;
        record.incoming_error = GetLastError();
    }
    ++original_calls;

    const auto set_return_error = [] { SetLastError(kReturnedError); };
    if (mode == Mode::throw_cpp) {
        set_return_error();
        throw 0x330;
    }
    if (mode == Mode::nested_same && original_depth == 0) {
        const Mode saved_mode = mode;
        const uintptr_t saved_pc = fixture_return_pc;
        ++original_depth;
        mode = Mode::insert;
        fixture_return_pc = base + kEffectReturn;
        const uintptr_t inner_result = Observer::observe(container, nested_task.output,
            key, fourth ^ UINT64_C(0x1111000000000000));
        mode = Mode::duplicate;
        fixture_return_pc = saved_pc;
        do_duplicate(container, output, key);
        mode = saved_mode;
        --original_depth;
        set_return_error();
        return output;
    }
    if (mode == Mode::nested_different && original_depth == 0) {
        const Mode saved_mode = mode;
        const uintptr_t saved_pc = fixture_return_pc;
        ++original_depth;
        mode = Mode::insert;
        fixture_return_pc = base + kEffectReturn;
        (void)Observer::observe(nested_task.container, nested_task.output,
            nested_task.key, fourth ^ UINT64_C(0x2222000000000000));
        mode = Mode::insert;
        fixture_return_pc = saved_pc;
        const uintptr_t result = do_insert(container, output, key);
        mode = saved_mode;
        --original_depth;
        set_return_error();
        return result;
    }

    if (mode == Mode::mutate_date) {
        const int32_t changed_date = 56700001;
        std::memcpy(reinterpret_cast<void*>(game_date_address), &changed_date, sizeof(changed_date));
    } else if (mode == Mode::mutate_name) {
        const uintptr_t definition = static_cast<uintptr_t>(get_u64(key));
        put_string32(definition + 0x10, mutated_name, definition + 0x210);
    } else if (mode == Mode::mutate_identity) {
        identity_shift_after_original = true;
    }

    uintptr_t result = mode == Mode::duplicate ? do_duplicate(container, output, key)
                                               : do_insert(container, output, key);
    if (mode == Mode::invalid_flag && owned::range(output, 16)) {
        const unsigned char invalid = 2;
        std::memcpy(reinterpret_cast<void*>(output + 8), &invalid, sizeof(invalid));
    }
    if (mode == Mode::return_mismatch) result = UINT64_C(0xfedcba9876543210);
    set_return_error();
    return result;
}

static uintptr_t call_observer(const Task& task, uintptr_t fourth = UINT64_C(0x8877665544332211)) {
    Observer::original = &fixture_original;
    return Observer::observe(task.container, task.output, task.key, fourth);
}

static void test_plan_and_caller_guards() {
    ++scenarios;
    std::array<unsigned char, 5> call{};
    auto install_call = [&](uint32_t return_rva) {
        call.fill(0);
        call[0] = 0xe8;
        const int32_t displacement = static_cast<int32_t>(plan::kEntryRva)
                                   - static_cast<int32_t>(return_rva);
        std::memcpy(call.data() + 1, &displacement, sizeof(displacement));
        std::memcpy(reinterpret_cast<void*>(base + return_rva - 5), call.data(), call.size());
    };
    install_call(kCommandReturn);
    install_call(kEffectReturn);
    CHECK(Observer::caller_guard(kCommandReturn), "command return has the audited five-byte call guard");
    CHECK(Observer::caller_guard(kEffectReturn), "effect return has the audited five-byte call guard");
    CHECK(!Observer::caller_guard(kExcludedReturn), "bulk initializer has no whitelisted call guard");

    plan::Plan image{};
    CHECK(plan::prepare(plan::kPrefix, plan::kSourceUnwind, base + plan::kEntryRva,
        reinterpret_cast<uintptr_t>(&Observer::observe), image), "exact 32-byte original metadata prepares the entry plan");
    auto changed_metadata = plan::kSourceUnwind;
    changed_metadata[31] ^= 1;
    CHECK(!plan::prepare(plan::kPrefix, changed_metadata, base + plan::kEntryRva,
        reinterpret_cast<uintptr_t>(&Observer::observe), image), "any changed original metadata byte is rejected");
    CHECK(plan::kPatchBytes == 15 && plan::kSourceUnwind.size() == 32,
        "candidate uses the bounded 15-byte entry and 32-byte metadata contract");
    CHECK(plan::classify(base, base + kCommandReturn) == plan::Path::command
        && plan::classify(base, base + kEffectReturn) == plan::Path::effect
        && plan::classify(base, base + kExcludedReturn) == plan::Path::none,
        "only the two approved caller returns are classified");
}

static void test_real_observe_insert_and_original_transparency() {
    ++scenarios;
    reset_case("mission_command_insert");
    fixture_return_pc = base + kCommandReturn;
    SetLastError(kIncomingError);
    const uintptr_t returned = call_observer(primary_task);
    CHECK(returned == primary_task.output && returned > UINT32_MAX,
        "observe returns the original full-width iterator pointer unchanged");
    CHECK(original_calls == 1 && call_records[0].args[0] == primary_task.container
        && call_records[0].args[1] == primary_task.output && call_records[0].args[2] == primary_task.key
        && call_records[0].args[3] == UINT64_C(0x8877665544332211),
        "the original four uintptr arguments are forwarded exactly once");
    CHECK(call_records[0].incoming_error == kIncomingError && GetLastError() == kReturnedError,
        "incoming and returned LastError values survive observation");
    CHECK(Observer::size == 1 && Observer::events[0].sequence == 1
        && Observer::events[0].value.path == plan::Path::command
        && Observer::events[0].value.mission.length == std::strlen("mission_command_insert"),
        "an inserted member emits its validated command-handler result");
}

static void test_duplicate_and_caller_identity_filters() {
    ++scenarios;
    reset_case("already_completed");
    insert_definition(primary_task.country, primary_task.definition);
    mode = Mode::duplicate;
    fixture_return_pc = base + kCommandReturn;
    (void)call_observer(primary_task);
    CHECK(original_calls == 1 && Observer::size == 0 && Observer::dropped == 0,
        "duplicate membership with inserted=false emits no event or gap");

    reset_case("unlisted_initializer");
    fixture_return_pc = base + kExcludedReturn;
    const unsigned reads_before = reads;
    (void)call_observer(primary_task);
    CHECK(original_calls == 1 && Observer::size == 0 && Observer::dropped == 0,
        "the unlisted bulk initializer call is forwarded but not observed");
    CHECK(call_records[0].reads_at_entry == reads_before,
        "unlisted calls reach the original without observer memory reads");

    reset_case("foreign_country");
    Task foreign = make_task("foreign_mission", 1, eng_country);
    fixture_return_pc = base + kCommandReturn;
    (void)call_observer(foreign);
    CHECK(original_calls == 1 && Observer::size == 0,
        "non-FRA completion is isolated while the original still runs");

    reset_case("fake_container");
    Task fake = make_task("fake_container_mission", 1, fake_country);
    fixture_return_pc = base + kEffectReturn;
    (void)call_observer(fake);
    CHECK(original_calls == 1 && Observer::size == 0 && Observer::dropped == 1,
        "a FRA tag on a noncanonical container cannot create an observation");
}

static void test_post_return_consistency_rejections() {
    ++scenarios;
    for (const auto failure_mode : {Mode::mutate_date, Mode::mutate_name,
                                    Mode::mutate_identity, Mode::invalid_flag,
                                    Mode::return_mismatch}) {
        reset_case("consistency_guard_mission");
        mode = failure_mode;
        fixture_return_pc = base + kCommandReturn;
        const uintptr_t returned = call_observer(primary_task);
        CHECK(original_calls == 1 && Observer::size == 0 && Observer::dropped == 1,
            "post-return date/name/identity/flag/return inconsistencies become gaps, not events");
        if (failure_mode == Mode::return_mismatch)
            CHECK(returned == UINT64_C(0xfedcba9876543210) && returned > UINT32_MAX,
                "a noncanonical full-width original return is still passed through unchanged");
    }

    reset_case("invalid_output_mission");
    uintptr_t invalid_output = 0x1234;
    Observer::original = &fixture_original;
    fixture_return_pc = base + kEffectReturn;
    const uintptr_t returned = Observer::observe(primary_task.container, invalid_output,
        primary_task.key, UINT64_C(0x8877665544332211));
    CHECK(original_calls == 1 && returned == invalid_output && Observer::size == 0
        && Observer::dropped == 1,
        "an invalid output pointer is forwarded without dereference and produces no event");
}

static void test_cpp_exception_cleanup_and_recovery() {
    ++scenarios;
    reset_case("throwing_mission");
    mode = Mode::throw_cpp;
    fixture_return_pc = base + kCommandReturn;
    bool caught = false;
    try { (void)call_observer(primary_task); }
    catch (int code) { caught = code == 0x330; }
    CHECK(caught && original_calls == 1 && Observer::size == 0 && Observer::dropped == 1,
        "the original C++ throw propagates and cleanup records a gap without inventing an event");
    reset_case("after_throw_recovers");
    fixture_return_pc = base + kCommandReturn;
    (void)call_observer(primary_task);
    CHECK(original_calls == 1 && Observer::size == 1,
        "the next normal original call works after the C++ throw");
}

static void test_nested_insertions() {
    ++scenarios;
    reset_case("outer_duplicate_after_inner");
    nested_task = primary_task;
    nested_task.output = arena_at(0xa20080);
    std::memset(reinterpret_cast<void*>(nested_task.output), 0, 16);
    mode = Mode::nested_same;
    fixture_return_pc = base + kCommandReturn;
    (void)call_observer(primary_task);
    CHECK(original_calls == 2 && Observer::size == 1 && Observer::events[0].sequence == 1
        && Observer::events[0].value.path == plan::Path::effect,
        "same-task inner insert emits once while the outer duplicate is suppressed");

    reset_case("outer_different_task");
    nested_task = make_task("nested_inner_task", 1);
    mode = Mode::nested_different;
    fixture_return_pc = base + kCommandReturn;
    (void)call_observer(primary_task);
    CHECK(original_calls == 2 && Observer::size == 2
        && Observer::events[0].value.path == plan::Path::effect
        && Observer::events[1].value.path == plan::Path::command,
        "nested insertions for different task keys both produce their own event");
    CHECK(std::string(Observer::events[0].value.mission.text, Observer::events[0].value.mission.length)
            == "nested_inner_task"
        && std::string(Observer::events[1].value.mission.text, Observer::events[1].value.mission.length)
            == "outer_different_task",
        "nested event snapshots retain each task name independently");
}

static void test_queue_capacity_flush_limit_and_fault_head() {
    ++scenarios;
    reset_case("queue_seed");
    for (unsigned index = 0; index < 65; ++index) {
        const std::string name = "queue_task_" + std::to_string(index);
        Task task = make_task(name, index + 10);
        fixture_return_pc = base + (index % 2 ? kEffectReturn : kCommandReturn);
        (void)call_observer(task);
    }
    CHECK(Observer::size == 64 && Observer::dropped == 1 && Observer::total_dropped == 1,
        "the 64-entry queue is bounded and a 65th insertion increments drop counters");
    Observer::flush();
    CHECK(Observer::size == 32,
        "one flush call writes at most 32 rows and leaves the remaining queue intact");
    Observer::flush();
    CHECK(Observer::size == 0 && Observer::dropped == 0 && !Observer::transport_fault,
        "the second flush drains the remaining rows and the pending gap");

    reset_case("fault_head_retained");
    fixture_return_pc = base + kCommandReturn;
    (void)call_observer(primary_task);
    const unsigned before_head = Observer::head;
    const unsigned before_size = Observer::size;
    const HANDLE saved_log = log_file;
    log_file = INVALID_HANDLE_VALUE;
    Observer::flush();
    CHECK(Observer::transport_fault && Observer::head == before_head && Observer::size == before_size,
        "a writer fault retains the uncommitted queue head");
    char health[256] = "{\"event\":\"fixture_health\"}";
    Observer::append_health(health, sizeof(health));
    CHECK(std::strstr(health, "\"transport_fault\":true")
        && std::strstr(health, "\"queued\":1"),
        "health reports the active writer fault and retained head");
    log_file = saved_log;
}

static void test_clean_contract_log(const char* output_path) {
    ++scenarios;
    reset_case("contract_log_seed");
    HANDLE handle = CreateFileA(output_path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
        nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    CHECK(handle != INVALID_HANDLE_VALUE, "open a real Windows file for contract JSONL");
    if (handle == INVALID_HANDLE_VALUE) return;
    log_file = handle;
    observation_creation = UINT64_C(0x330001);
    const std::string command_name = "command_handler_completed_set";
    const std::string effect_name = "script_effect_completed_set";
    const std::string maximum_name(owned::kMaxName, 'm');
    Task command = make_task(command_name, 100);
    Task effect = make_task(effect_name, 101);
    Task maximum = make_task(maximum_name, 102);
    fixture_return_pc = base + kCommandReturn;
    (void)call_observer(command);
    fixture_return_pc = base + kEffectReturn;
    (void)call_observer(effect);
    fixture_return_pc = base + kCommandReturn;
    (void)call_observer(maximum);
    CHECK(Observer::size == 3 && Observer::sequence == 3,
        "clean writer fixture starts at sequence one and contains three inserted tasks");
    Observer::flush();
    CHECK(Observer::size == 0 && !Observer::transport_fault,
        "real writer flushes the clean contract rows successfully");
    CHECK(CloseHandle(handle) != FALSE, "close the real contract JSONL file");
    log_file = INVALID_HANDLE_VALUE;
}

int main(int argc, char** argv) {
    static_assert(sizeof(uintptr_t) == 8, "completed-set fixture requires x64");
    if (argc != 3) {
        std::fprintf(stderr, "usage: fixture.exe <native-log.jsonl> <diagnostic-log.jsonl>\n");
        return 2;
    }
    auto* memory = static_cast<unsigned char*>(VirtualAlloc(nullptr, kArenaBytes,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!memory) return 2;
    base = reinterpret_cast<uintptr_t>(memory);
    fra_country = base + 0x100000;
    eng_country = base + 0x300000;
    fake_country = base + 0x500000;
    frame_thread = GetCurrentThreadId();
    reset_world();

    HANDLE diagnostic = CreateFileA(argv[2], GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
        nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (diagnostic == INVALID_HANDLE_VALUE) return 2;
    log_file = diagnostic;

    test_plan_and_caller_guards();
    test_real_observe_insert_and_original_transparency();
    test_duplicate_and_caller_identity_filters();
    test_post_return_consistency_rejections();
    test_cpp_exception_cleanup_and_recovery();
    test_nested_insertions();
    test_queue_capacity_flush_limit_and_fault_head();
    test_clean_contract_log(argv[1]);

    Observer::installed = false;
    if (log_file != INVALID_HANDLE_VALUE) CloseHandle(log_file);
    if (log_file != diagnostic) CloseHandle(diagnostic);
    log_file = INVALID_HANDLE_VALUE;
    CHECK(VirtualFree(memory, 0, MEM_RELEASE) != FALSE, "release the private fixture arena");
    std::printf("FIXTURE_RESULT: %s (%u checks, %u scenarios)\n",
        failures ? "FAIL" : "PASS", checks, scenarios);
    std::printf("SCOPE: owned private-memory fixture with self-authored country, game-date, and original-call stubs; no live game access\n");
    std::printf("EXCEPTION: C++ exception propagation tested; foreign MSVC SEH behavior unknown\n");
    return failures ? 1 : 0;
}
