#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "../information-mission-completion.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <type_traits>

static constexpr uint64_t kFra = UINT64_C(0x1200000100415246);
static constexpr uint64_t kEng = UINT64_C(0x12340000474e45);
static constexpr size_t kModuleBytes = 0x2400000;
static uintptr_t base = 0;
static uintptr_t game_address = 0;
static DWORD frame_thread = 0;
static bool thread_changed = false;
static bool fixture_date_read_failed = false;
static bool identity_shift_after_original = false;
static bool original_has_returned = false;
static bool lifecycle_rollback_incomplete = false;
static uint64_t observation_creation = UINT64_C(0x326001);
static HANDLE log_file = INVALID_HANDLE_VALUE;
static wchar_t log_path[32768]{};
static uintptr_t g_fra_country = 0;
static uintptr_t g_other_country = 0;
static unsigned char* g_fra_memory = nullptr;
static unsigned char* g_other_memory = nullptr;
static int32_t g_date = 14671001;
static int32_t* date_pointer = nullptr;
static unsigned total_original_calls = 0;
static bool fixture_fra_is_player = false;
static unsigned checks = 0;
static unsigned failures = 0;
static unsigned scenarios = 0;
static unsigned virtual_protect_calls = 0;
static unsigned fail_virtual_protect_call = 0;

#define CHECK(condition, message) do { \
    ++checks; \
    if (!(condition)) { ++failures; std::fprintf(stderr, "FAIL: %s\n", message); } \
} while (0)

static BOOL WINAPI fixture_virtual_protect(LPVOID address, SIZE_T bytes,
    DWORD protection, PDWORD previous) {
    ++virtual_protect_calls;
    if (fail_virtual_protect_call && virtual_protect_calls == fail_virtual_protect_call) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return VirtualProtect(address, bytes, protection, previous);
}

template<class Value>
static bool read(uintptr_t address, Value& value) noexcept {
    if (fixture_date_read_failed && address == game_address + 0x1dd0) return false;
    SIZE_T copied = 0;
    return ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<void*>(address),
        &value, sizeof(value), &copied) != FALSE && copied == sizeof(value);
}

static bool insult_query_country(uint64_t reference, uintptr_t& country) noexcept {
    if (reference == kFra) {
        if (!g_fra_country) return false;
        country = g_fra_country + ((identity_shift_after_original && original_has_returned) ? 0x20 : 0);
        return true;
    }
    if (reference == kEng) {
        if (!g_other_country) return false;
        country = g_other_country;
        return true;
    }
    return false;
}

#define VirtualProtect fixture_virtual_protect
#include "../information-mission-observer.inc"
#undef VirtualProtect

namespace Observer = mission_completion_observer;
namespace owned = information::mission_completion;

struct MissionStore final {
    uintptr_t country = 0, sentinel = 0, node = 0, definition = 0, heap = 0;
    uint64_t fullref = kFra;
    std::string id;
    bool completed = false;
};

struct Command final {
    unsigned char* memory = nullptr;
    uintptr_t address = 0;
};

struct Plan final {
    Command* command = nullptr;
    MissionStore* store = nullptr;
    bool set_completed_after = false;
    bool corrupt_membership_after = false;
    bool advance_date_after = false;
    bool fail_date_read_after = false;
    bool destroy_command = true;
    bool nested_done = false;
    Command* nested_command = nullptr;
    DWORD expected_incoming_error = ERROR_SUCCESS;
    DWORD returned_error = ERROR_SUCCESS;
    DWORD nested_incoming_error = ERROR_SUCCESS;
    DWORD nested_returned_error = ERROR_SUCCESS;
    unsigned calls = 0;
    bool validate_errors = false;
};

static MissionStore stores[256]{};
static unsigned store_count = 0;
static Command commands[256]{};
static unsigned command_count = 0;
static Plan plans[256]{};
static unsigned plan_count = 0;

static void put_u64(uintptr_t address, uint64_t value) noexcept {
    std::memcpy(reinterpret_cast<void*>(address), &value, sizeof(value));
}

static void put_string32(uintptr_t address, const std::string& text,
    uintptr_t heap_address) noexcept {
    std::memset(reinterpret_cast<void*>(address), 0, 32);
    const uint64_t length = text.size();
    uint64_t capacity = 15;
    if (text.size() <= 15) {
        std::memcpy(reinterpret_cast<void*>(address), text.data(), text.size());
        reinterpret_cast<char*>(address)[text.size()] = 0;
    } else {
        capacity = text.size();
        std::memcpy(reinterpret_cast<void*>(heap_address), text.data(), text.size());
        reinterpret_cast<char*>(heap_address)[text.size()] = 0;
        put_u64(address, heap_address);
    }
    put_u64(address + 16, length);
    put_u64(address + 24, capacity);
}

static void rebuild_completed_list() noexcept {
    if (!g_fra_country) return;
    const uintptr_t sentinel = g_fra_country + 0xa000;
    uintptr_t next = sentinel;
    for (unsigned index = 0; index < store_count; ++index) {
        auto& store = stores[index];
        if (store.fullref != kFra || !store.completed) continue;
        put_u64(store.node, next);
        next = store.node;
    }
    put_u64(sentinel, next);
}

static MissionStore* make_store(const std::string& id, bool completed = false,
    uint64_t fullref = kFra) {
    if (store_count >= sizeof(stores) / sizeof(stores[0])) return nullptr;
    auto& store = stores[store_count];
    store = MissionStore{};
    store.fullref = fullref;
    store.id = id;
    store.completed = completed;
    if (fullref == kFra) {
        if (!g_fra_memory) {
            g_fra_memory = static_cast<unsigned char*>(VirtualAlloc(nullptr, 0x50000,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
            if (!g_fra_memory) return nullptr;
            g_fra_country = reinterpret_cast<uintptr_t>(g_fra_memory);
            put_u64(g_fra_country + 0x99a0, g_fra_country + 0xa000);
            put_u64(g_fra_country + 0xa000, g_fra_country + 0xa000);
        }
        store.country = g_fra_country;
        store.sentinel = g_fra_country + 0xa000;
        store.node = g_fra_country + 0xa020 + store_count * 0x20;
        store.definition = g_fra_country + 0x10000 + store_count * 0x180;
        store.heap = store.definition + 0x50;
        put_string32(store.definition + 0x10, id, store.heap);
        put_u64(store.node, store.sentinel);
        put_u64(store.node + 16, store.definition);
    } else if (fullref == kEng) {
        if (!g_other_memory) {
            g_other_memory = static_cast<unsigned char*>(VirtualAlloc(nullptr, 0xc000,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
            if (!g_other_memory) return nullptr;
            g_other_country = reinterpret_cast<uintptr_t>(g_other_memory);
            put_u64(g_other_country + 0x99a0, g_other_country + 0xa000);
            put_u64(g_other_country + 0xa000, g_other_country + 0xa000);
        }
        store.country = g_other_country;
        store.sentinel = g_other_country + 0xa000;
    }
    ++store_count;
    rebuild_completed_list();
    return &store;
}

static Command* make_command(const std::string& id, uint64_t country = kFra) {
    if (command_count >= sizeof(commands) / sizeof(commands[0])) return nullptr;
    auto* command = &commands[command_count++];
    *command = Command{};
    command->memory = static_cast<unsigned char*>(VirtualAlloc(nullptr, 0x1000,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!command->memory) return nullptr;
    command->address = reinterpret_cast<uintptr_t>(command->memory);
    put_u64(command->address, base + Observer::kVtableRva);
    const uint32_t discriminator = 0x165;
    std::memcpy(command->memory + 8, &discriminator, sizeof(discriminator));
    put_string32(command->address + 0x50, id, command->address + 0x200);
    put_u64(command->address + 0x70, country);
    return command;
}

static Plan* add_plan(Command* command, MissionStore* store,
    bool set_completed_after, DWORD incoming_error = ERROR_SUCCESS,
    DWORD returned_error = ERROR_SUCCESS) {
    if (!command || plan_count >= sizeof(plans) / sizeof(plans[0])) return nullptr;
    auto& plan = plans[plan_count++];
    plan = Plan{};
    plan.command = command;
    plan.store = store;
    plan.set_completed_after = set_completed_after;
    plan.expected_incoming_error = incoming_error;
    plan.returned_error = returned_error;
    return &plan;
}

static Plan* find_plan(void* command) noexcept {
    for (unsigned index = plan_count; index > 0; --index) {
        auto& plan = plans[index - 1];
        if (plan.command && plan.command->address == reinterpret_cast<uintptr_t>(command))
            return &plan;
    }
    return nullptr;
}

static void set_completed(MissionStore& store, bool completed) noexcept {
    store.completed = completed;
    rebuild_completed_list();
}

static void invoke_hook(Command* command) {
    auto* slot = reinterpret_cast<void* volatile*>(base + Observer::kVtableRva + 0x48);
    const auto call = reinterpret_cast<Observer::Original>(*slot);
    CHECK(reinterpret_cast<void*>(call) == reinterpret_cast<void*>(&Observer::observe),
        "fixture invokes the published mission vtable hook");
    call(command->memory);
}

static void test_original(void* command) {
    auto* plan = find_plan(command);
    CHECK(plan != nullptr, "fixture original is called with its own command");
    if (!plan) return;
    ++plan->calls;
    ++total_original_calls;
    if (plan->validate_errors)
        CHECK(GetLastError() == plan->expected_incoming_error,
            "observe restores incoming GetLastError before forwarding");

    if (plan->nested_command && !plan->nested_done) {
        plan->nested_done = true;
        SetLastError(plan->nested_incoming_error);
        invoke_hook(plan->nested_command);
        CHECK(GetLastError() == plan->nested_returned_error,
            "nested observe preserves the nested original's returned GetLastError");
    }

    if (plan->store && plan->set_completed_after)
        set_completed(*plan->store, true);
    if (plan->store && plan->corrupt_membership_after) {
        set_completed(*plan->store, true);
        put_u64(plan->store->node + 16, UINT64_C(0x10000));
    }
    if (plan->advance_date_after && date_pointer) ++*date_pointer;
    if (plan->fail_date_read_after) fixture_date_read_failed = true;
    original_has_returned = true;

    if (plan->destroy_command && plan->command && plan->command->memory) {
        CHECK(VirtualFree(plan->command->memory, 0, MEM_RELEASE) != FALSE,
            "original destroys the mission command before observer finish");
        plan->command->memory = nullptr;
    }
    SetLastError(plan->returned_error);
}

static void reset_plans() noexcept {
    plan_count = 0;
    original_has_returned = false;
    identity_shift_after_original = false;
    fixture_date_read_failed = false;
    thread_changed = false;
    frame_thread = GetCurrentThreadId();
}

static bool readable_page(uintptr_t address, DWORD expected) noexcept {
    MEMORY_BASIC_INFORMATION info{};
    return VirtualQuery(reinterpret_cast<void*>(address), &info, sizeof(info)) == sizeof(info)
        && info.State == MEM_COMMIT && info.Protect == expected;
}

static bool replace_private_slot(void* volatile* slot, void* value) noexcept {
    DWORD previous = 0, ignored = 0;
    if (!VirtualProtect(const_cast<void**>(slot), 8, PAGE_READWRITE, &previous)) return false;
    InterlockedExchangePointer(slot, value);
    return VirtualProtect(const_cast<void**>(slot), 8, previous, &ignored) != FALSE;
}

static bool write_private_bytes(void* address, const void* bytes, size_t length) noexcept {
    DWORD previous = 0, ignored = 0;
    if (!VirtualProtect(address, 0x1000, PAGE_EXECUTE_READWRITE, &previous)) return false;
    std::memcpy(address, bytes, length);
    return VirtualProtect(address, 0x1000, previous, &ignored) != FALSE;
}

static void test_install_guard_publish_and_rollback() {
    ++scenarios;
    auto* slot = reinterpret_cast<void* volatile*>(base + Observer::kVtableRva + 0x48);
    auto* method = reinterpret_cast<unsigned char*>(base + Observer::kMethodRva);
    void* expected = reinterpret_cast<void*>(base + Observer::kMethodRva);
    static constexpr unsigned char guard[] = {0xe9, 0x4b, 0x62, 0x81, 0x00};

    const unsigned char wrong_guard[] = {0x90};
    CHECK(write_private_bytes(method, wrong_guard, sizeof(wrong_guard)),
        "fixture can change the private method guard page temporarily");
    CHECK(!Observer::install() && *slot == expected
            && Observer::original.load() == nullptr,
        "install rejects a method whose five-byte entry guard differs");
    CHECK(write_private_bytes(method, guard, sizeof(guard)),
        "fixture restores the exact private method guard");

    void* foreign = reinterpret_cast<void*>(base + 0x123450);
    CHECK(replace_private_slot(slot, foreign), "fixture installs a foreign private slot value");
    CHECK(!Observer::install() && *slot == foreign,
        "install leaves an unexpected vtable occupant untouched");
    CHECK(replace_private_slot(slot, expected), "fixture restores the expected native slot");

    Observer::original.store(nullptr);
    virtual_protect_calls = 0;
    fail_virtual_protect_call = 1;
    CHECK(!Observer::install() && *slot == expected
            && readable_page(reinterpret_cast<uintptr_t>(slot), PAGE_READONLY),
        "initial VirtualProtect failure leaves the slot and its original protection intact");
    Observer::original.store(nullptr);

    virtual_protect_calls = 0;
    fail_virtual_protect_call = 2;
    lifecycle_rollback_incomplete = false;
    CHECK(!Observer::install() && *slot == expected
            && readable_page(reinterpret_cast<uintptr_t>(slot), PAGE_READONLY)
            && !lifecycle_rollback_incomplete,
        "restore-protection failure rolls back the slot and restores its original page protection");
    Observer::original.store(nullptr);
    fail_virtual_protect_call = 0;
    virtual_protect_calls = 0;

    CHECK(Observer::install() && *slot == reinterpret_cast<void*>(&Observer::observe),
        "install publishes the hook after exact slot and guard validation");
    CHECK(!Observer::installed.load(),
        "install does not mark the source installed before the main family commit");
    CHECK(Observer::original.load() == reinterpret_cast<Observer::Original>(expected),
        "successful install retains the original native method pointer");
    CHECK(readable_page(reinterpret_cast<uintptr_t>(slot), PAGE_READONLY),
        "successful install restores the vtable page's original protection");

    // This is the main observer family's post-commit publication point.
    Observer::installed.store(true);
}

static void check_command_destroyed(const Command* command, const char* message) {
    MEMORY_BASIC_INFORMATION info{};
    const SIZE_T queried = VirtualQuery(reinterpret_cast<void*>(command->address), &info, sizeof(info));
    CHECK(queried == sizeof(info) && info.State == MEM_FREE, message);
}

static void test_transition_forwarding_and_error_contract() {
    ++scenarios;
    reset_plans();
    Observer::original.store(&test_original);
    const unsigned queued_start = Observer::size;
    const LONG dropped_start = Observer::total_dropped;

    const std::string quoted_id = "claim \"A\\B\"";
    auto* store = make_store(quoted_id, false, kFra);
    auto* command = make_command(quoted_id, kFra);
    auto* plan = add_plan(command, store, true, 0x1234, 0x4567);
    plan->validate_errors = true;
    const unsigned calls_before = total_original_calls;
    SetLastError(0x1234);
    invoke_hook(command);
    CHECK(GetLastError() == 0x4567,
        "observe preserves the original function's returned GetLastError after finish");
    CHECK(plan->calls == 1 && total_original_calls == calls_before + 1,
        "the original function is forwarded exactly once for a FRA completion");
    CHECK(Observer::size == queued_start + 1 && Observer::total_dropped == dropped_start,
        "an observed false-to-true completed-membership transition is queued");
    CHECK(!fixture_fra_is_player,
        "the captured FRA observer fixture is explicitly a non-player country");
    check_command_destroyed(command,
        "finish succeeds after the original has destroyed the command allocation");

    reset_plans();
    std::string maximum_id(owned::kMaxName, 'x');
    maximum_id[254] = '"';
    maximum_id[255] = '\\';
    auto* maximum_store = make_store(maximum_id, false, kFra);
    auto* maximum_command = make_command(maximum_id, kFra);
    auto* maximum_plan = add_plan(maximum_command, maximum_store, true);
    const unsigned before_maximum = Observer::size;
    invoke_hook(maximum_command);
    CHECK(maximum_plan->calls == 1 && Observer::size == before_maximum + 1,
        "the longest heap-backed mission ID survives command capture and queueing");
    check_command_destroyed(maximum_command,
        "the maximum-length event also finishes after command destruction");

    reset_plans();
    auto* already_store = make_store("already_done", true, kFra);
    auto* already_command = make_command("already_done", kFra);
    auto* already = add_plan(already_command, already_store, true);
    const unsigned before_already = Observer::size;
    invoke_hook(already_command);
    CHECK(already->calls == 1 && Observer::size == before_already,
        "a mission already completed before the command does not emit again");

    reset_plans();
    auto* nochange_store = make_store("still_pending", false, kFra);
    auto* nochange_command = make_command("still_pending", kFra);
    auto* nochange = add_plan(nochange_command, nochange_store, false);
    const unsigned before_nochange = Observer::size;
    invoke_hook(nochange_command);
    CHECK(nochange->calls == 1 && Observer::size == before_nochange,
        "a mission that remains incomplete after the command does not emit");

    reset_plans();
    auto* other_store = make_store("forward_only", false, kEng);
    auto* other_command = make_command("forward_only", kEng);
    auto* other = add_plan(other_command, other_store, false);
    const unsigned before_other = Observer::size;
    const LONG drops_before_other = Observer::total_dropped;
    invoke_hook(other_command);
    CHECK(other->calls == 1 && Observer::size == before_other
            && Observer::total_dropped == drops_before_other,
        "a non-FRA command is forwarded once without capture or a gap");

    CHECK(CloseHandle(log_file) != FALSE,
        "close the output handle before flushing the first transition fixture");
    log_file = CreateFileW(log_path, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    CHECK(log_file != INVALID_HANDLE_VALUE,
        "reopen transition output for bounded observer flush");
    Observer::flush();
    CHECK(Observer::size == 0,
        "transition and no-op fixtures leave the observer queue drained");
}

static void test_date_thread_identity_and_read_gaps() {
    ++scenarios;
    Observer::original.store(&test_original);
    const LONG dropped_start = Observer::total_dropped;

    reset_plans();
    auto* date_store = make_store("date_crossing", false);
    auto* date_command = make_command("date_crossing");
    auto* date_plan = add_plan(date_command, date_store, true);
    date_plan->advance_date_after = true;
    invoke_hook(date_command);
    CHECK(date_plan->calls == 1 && Observer::size == 0,
        "a completion that crosses the observed game date is not assigned to either day");

    reset_plans();
    auto* thread_store = make_store("wrong_thread", false);
    auto* thread_command = make_command("wrong_thread");
    auto* thread_plan = add_plan(thread_command, thread_store, true);
    frame_thread = GetCurrentThreadId() + 1;
    invoke_hook(thread_command);
    CHECK(thread_plan->calls == 1 && Observer::size == 0,
        "wrong-frame-thread execution is forwarded but not captured");

    reset_plans();
    identity_shift_after_original = true;
    auto* identity_store = make_store("identity_shift", false);
    auto* identity_command = make_command("identity_shift");
    auto* identity_plan = add_plan(identity_command, identity_store, true);
    invoke_hook(identity_command);
    CHECK(identity_plan->calls == 1 && Observer::size == 0,
        "country pointer identity changes across the original call create a capture gap");

    reset_plans();
    auto* broken_store = make_store("unreadable_after", false);
    auto* broken_command = make_command("unreadable_after");
    auto* broken_plan = add_plan(broken_command, broken_store, false);
    broken_plan->corrupt_membership_after = true;
    invoke_hook(broken_command);
    CHECK(broken_plan->calls == 1 && Observer::size == 0,
        "a failed post-call completed-list read is not emitted as a transition");
    put_u64(broken_store->node + 16, broken_store->definition);
    rebuild_completed_list();

    reset_plans();
    auto* date_read_store = make_store("date_read_failed", false);
    auto* date_read_command = make_command("date_read_failed");
    auto* date_read_plan = add_plan(date_read_command, date_read_store, true);
    date_read_plan->fail_date_read_after = true;
    invoke_hook(date_read_command);
    CHECK(date_read_plan->calls == 1 && Observer::size == 0,
        "a failed post-call date read becomes a capture gap");
    fixture_date_read_failed = false;

    CHECK(Observer::total_dropped == dropped_start + 5,
        "date, thread, identity, membership, and date-read failures are counted as five gaps");
    Observer::flush();
    CHECK(Observer::dropped == 0 && Observer::size == 0,
        "the bounded gap diagnostic flush clears only the reported drop count");
}

static void test_nested_same_and_distinct_missions() {
    ++scenarios;
    reset_plans();
    Observer::original.store(&test_original);
    const LONG dropped_start = Observer::total_dropped;

    auto* same_store = make_store("nested_same", false);
    auto* same_outer = make_command("nested_same");
    auto* same_inner = make_command("nested_same");
    auto* outer_plan = add_plan(same_outer, same_store, true);
    auto* inner_plan = add_plan(same_inner, same_store, false);
    outer_plan->nested_command = same_inner;
    outer_plan->nested_incoming_error = 0x7001;
    outer_plan->nested_returned_error = 0x7002;
    inner_plan->expected_incoming_error = 0x7001;
    inner_plan->returned_error = 0x7002;
    inner_plan->validate_errors = true;
    const unsigned same_before = Observer::size;
    invoke_hook(same_outer);
    CHECK(outer_plan->calls == 1 && inner_plan->calls == 1
            && Observer::size == same_before + 1,
        "nested execution of the same country and mission is suppressed once");

    reset_plans();
    auto* first_store = make_store("task_A", false);
    auto* second_store = make_store("task_B", false);
    auto* first_command = make_command("task_A");
    auto* second_command = make_command("task_B");
    auto* first_plan = add_plan(first_command, first_store, true);
    auto* second_plan = add_plan(second_command, second_store, true);
    first_plan->nested_command = second_command;
    first_plan->nested_incoming_error = 0x7101;
    first_plan->nested_returned_error = 0x7102;
    second_plan->expected_incoming_error = 0x7101;
    second_plan->returned_error = 0x7102;
    second_plan->validate_errors = true;
    const unsigned distinct_before = Observer::size;
    invoke_hook(first_command);
    CHECK(first_plan->calls == 1 && second_plan->calls == 1
            && Observer::size == distinct_before + 2,
        "nested execution of a different mission retains both completion transitions");
    CHECK(Observer::total_dropped == dropped_start,
        "nested duplicate suppression and distinct missions do not create gaps");
    Observer::flush();
    CHECK(Observer::size == 0,
        "nested mission events are drained before the queue-capacity scenario");
}

static void test_queue_limits_overflow_and_fault_retention() {
    ++scenarios;
    reset_plans();
    Observer::original.store(&test_original);
    const LONG drops_before = Observer::total_dropped;

    auto* lock_store = make_store("lock_fault_head", false);
    auto* lock_command = make_command("lock_fault_head");
    auto* lock_plan = add_plan(lock_command, lock_store, true);
    invoke_hook(lock_command);
    const unsigned lock_head = Observer::head;
    AcquireSRWLockExclusive(&Observer::queue_lock);
    Observer::flush();
    ReleaseSRWLockExclusive(&Observer::queue_lock);
    CHECK(lock_plan->calls == 1 && Observer::size == 1 && Observer::head == lock_head,
        "a queue-lock acquisition fault leaves the queued head in place");
    CHECK(!Observer::transport_fault.load(),
        "a transient lock fault does not latch the transport as failed");
    Observer::flush();
    CHECK(Observer::size == 0,
        "the retained lock-fault head is written before the capacity scenario");
    const unsigned calls_before = total_original_calls;

    for (unsigned index = 0; index < 65; ++index) {
        char id[32]{};
        std::snprintf(id, sizeof(id), "queue_%02u", index);
        auto* store = make_store(id, false);
        auto* command = make_command(id);
        auto* plan = add_plan(command, store, true);
        invoke_hook(command);
        CHECK(plan->calls == 1,
            "queue-capacity fixture forwards each native command exactly once");
    }
    CHECK(total_original_calls == calls_before + 65,
        "all 65 queue-capacity commands reach the original exactly once");
    CHECK(Observer::size == Observer::kCapacity,
        "mission observer queue retains exactly 64 events");
    CHECK(Observer::total_dropped == drops_before + 1 && Observer::dropped == 1,
        "the 65th event beyond capacity increments the gap counter once");

    Observer::flush();
    CHECK(Observer::size == 32 && Observer::dropped == 0,
        "a single flush drains at most 32 events and reports the overflow gap");
    Observer::flush();
    CHECK(Observer::size == 0,
        "a second flush drains the remaining 32 queued mission events");

    auto* write_store = make_store("write_fault_head", false);
    auto* write_command = make_command("write_fault_head");
    auto* write_plan = add_plan(write_command, write_store, true);
    invoke_hook(write_command);
    const unsigned write_head = Observer::head;
    CHECK(CloseHandle(log_file) != FALSE,
        "close the writable mission log before forcing the write failure");
    log_file = CreateFileW(log_path, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    CHECK(log_file != INVALID_HANDLE_VALUE,
        "reopen the mission log read-only for the write-failure fixture");
    Observer::flush();
    CHECK(write_plan->calls == 1 && Observer::transport_fault.load(),
        "a failed WriteFile latches mission transport fault");
    CHECK(Observer::size == 1 && Observer::head == write_head,
        "write failure retains the uncommitted event at the queue head");

    char health[640] = "{\"event\":\"fixture_health\"}";
    Observer::append_health(health, sizeof(health));
    CHECK(std::strstr(health, "\"installed\":true") != nullptr
            && std::strstr(health, "\"transport_fault\":true") != nullptr
            && std::strstr(health, "\"queue_readable\":true") != nullptr
            && std::strstr(health, "\"queued\":1") != nullptr,
        "health exposes the installed source, transport fault, and retained queue head");
    std::printf("HEALTH_JSON:%s", health);
}

static void test_final_rollback_retains_original() {
    auto* slot = reinterpret_cast<void* volatile*>(base + Observer::kVtableRva + 0x48);
    void* expected = reinterpret_cast<void*>(base + Observer::kMethodRva);
    Observer::installed.store(false);
    Observer::original.store(reinterpret_cast<Observer::Original>(expected));
    CHECK(Observer::rollback() && *slot == expected,
        "rollback restores the original native slot after the fixture family completes");
    CHECK(Observer::original.load() == reinterpret_cast<Observer::Original>(expected),
        "rollback retains the original method pointer for ownership and recovery");
    CHECK(readable_page(reinterpret_cast<uintptr_t>(slot), PAGE_READONLY),
        "rollback restores the original vtable page protection");

    void* foreign = reinterpret_cast<void*>(base + 0x135790);
    CHECK(replace_private_slot(slot, foreign), "fixture changes the rolled-back slot to a foreign value");
    CHECK(!Observer::rollback() && *slot == foreign,
        "rollback does not overwrite a foreign slot value");
    CHECK(Observer::original.load() == reinterpret_cast<Observer::Original>(expected),
        "foreign-slot rollback failure still retains the original method pointer");
    CHECK(replace_private_slot(slot, expected), "fixture restores the original slot after foreign-value check");
}

int main() {
    static_assert(sizeof(uintptr_t) == 8, "EU4 mission observer fixture requires x64");
    auto* module = static_cast<unsigned char*>(VirtualAlloc(nullptr, kModuleBytes,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!module) return 2;
    base = reinterpret_cast<uintptr_t>(module);
    game_address = base + 0x2350000;
    date_pointer = reinterpret_cast<int32_t*>(game_address + 0x1dd0);
    *date_pointer = g_date;
    put_u64(base + 0x233fe58, game_address);

    auto* slot = reinterpret_cast<void* volatile*>(base + Observer::kVtableRva + 0x48);
    void* expected = reinterpret_cast<void*>(base + Observer::kMethodRva);
    InterlockedExchangePointer(slot, expected);
    static constexpr unsigned char guard[] = {0xe9, 0x4b, 0x62, 0x81, 0x00};
    std::memcpy(reinterpret_cast<void*>(base + Observer::kMethodRva), guard, sizeof(guard));
    DWORD old_protection = 0;
    if (!VirtualProtect(reinterpret_cast<void*>(base + Observer::kVtableRva + 0x48),
            0x1000, PAGE_READONLY, &old_protection)
        || !VirtualProtect(reinterpret_cast<void*>(base + Observer::kMethodRva),
            0x1000, PAGE_EXECUTE_READ, &old_protection)) return 3;

    const DWORD path_chars = GetEnvironmentVariableW(L"INFORMATION_MISSION_FIXTURE_LOG",
        log_path, static_cast<DWORD>(sizeof(log_path) / sizeof(log_path[0])));
    if (!path_chars || path_chars >= sizeof(log_path) / sizeof(log_path[0])) return 4;
    log_file = CreateFileW(log_path, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (log_file == INVALID_HANDLE_VALUE) return 5;

    // Seed stable private-memory country fixtures for native query substitutes.
    auto* fra_seed = make_store("seed_fra", false, kFra);
    auto* other_seed = make_store("seed_eng", false, kEng);
    (void)fra_seed;
    (void)other_seed;

    test_install_guard_publish_and_rollback();
    test_transition_forwarding_and_error_contract();
    test_date_thread_identity_and_read_gaps();
    test_nested_same_and_distinct_missions();
    test_queue_limits_overflow_and_fault_retention();
    test_final_rollback_retains_original();

    Observer::installed.store(false);
    if (log_file != INVALID_HANDLE_VALUE) {
        CHECK(CloseHandle(log_file) != FALSE, "close final mission fixture log handle");
        log_file = INVALID_HANDLE_VALUE;
    }
    if (g_other_memory)
        CHECK(VirtualFree(g_other_memory, 0, MEM_RELEASE) != FALSE,
            "release private non-FRA country fixture memory");
    if (g_fra_memory)
        CHECK(VirtualFree(g_fra_memory, 0, MEM_RELEASE) != FALSE,
            "release private completed-list fixture memory");
    CHECK(VirtualFree(module, 0, MEM_RELEASE) != FALSE,
        "release private vtable and date fixture memory");
    std::printf("information mission production observer: %s (%u checks, %u scenarios)\n",
        failures ? "FAIL" : "PASS", checks, scenarios);
    return failures ? 1 : 0;
}
