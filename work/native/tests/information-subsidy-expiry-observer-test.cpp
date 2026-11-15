#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "../entry-patch-transaction.inc"

static uintptr_t base = 0, test_caller = 0;
static DWORD frame_thread = 0;
static bool thread_changed = false;
static uint64_t observation_creation = 1;
static HANDLE log_file = INVALID_HANDLE_VALUE;
template<class Value> static bool read(uintptr_t address, Value& value) {
    SIZE_T count = 0;
    return ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<void*>(address), &value,
        sizeof(value), &count) && count == sizeof(value);
}
#define __builtin_return_address(level) reinterpret_cast<void*>(test_caller)
#include "../information-subsidy-expiry-observer.inc"
#undef __builtin_return_address
namespace source = subsidy_expiry_observer;
namespace owned = information::subsidy_expiry;
static unsigned checks = 0, calls = 0;
static uintptr_t instance = 0;
static bool remove_record = true, change_amount = false;
static constexpr uint64_t fra = UINT64_C(0x100000100415246), sav = UINT64_C(0x100000200564153);
static constexpr uintptr_t returned = 0x12345678;
#define CHECK(expression) do { ++checks; if (!(expression)) { std::printf("FAIL line %u %s\n", __LINE__, #expression); std::exit(1); } } while (false)
template<class Value> static void put(uintptr_t address, Value value) {
    std::memcpy(reinterpret_cast<void*>(address), &value, sizeof(value));
}
static uintptr_t original(uintptr_t item) {
    CHECK(item == instance);
    ++calls;
    if (remove_record) put(item + 0x28, static_cast<unsigned char>(1));
    if (change_amount) put(item + 0x40, int32_t{2500});
    return returned;
}
static void reset(bool reverse = false) {
    source::installed = true;
    source::transport_fault = false;
    source::dropped = source::total_dropped = 0;
    source::sequence = 0;
    source::size = source::head = calls = 0;
    source::original = &original;
    frame_thread = GetCurrentThreadId();
    thread_changed = false;
    test_caller = base + owned::kCleanupReturnRva;
    remove_record = true;
    change_amount = false;
    put(base + 0x233d8b0, base + 0x20000);
    put(base + 0x20118, base + 0x22000);
    put(base + 0x22008, base + 0x24000);
    put(base + 0x22010, base + 0x26000);
    put(base + 0x24020, fra);
    put(base + 0x26020, sav);
    put(base + 0x233fe58, base + 0x28000);
    put(base + 0x29dd0, int32_t{8861});
    std::memset(reinterpret_cast<void*>(instance), 0, 0x48);
    put(instance, base + owned::kRecordTableRva);
    put(instance + 0x10, reverse ? sav : fra);
    put(instance + 0x18, reverse ? fra : sav);
    put(instance + 0x20, int32_t{100});
    put(instance + 0x40, int32_t{1250});
    put(instance + 0x44, int32_t{1});
}
static void invoke(unsigned queued, unsigned dropped = 0) {
    CHECK(source::subsidy_remove_observe(instance) == returned);
    CHECK(calls == 1 && source::size == queued);
    CHECK(static_cast<unsigned>(source::total_dropped) == dropped);
}
int main() {
    base = reinterpret_cast<uintptr_t>(VirtualAlloc(nullptr, 0x2341000,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    CHECK(base != 0);
    instance = base + 0x30000;
    for (bool reverse : {false, true}) {
        for (uintptr_t caller : {owned::kCleanupReturnRva, owned::kMonthlyCleanupReturnRva}) {
            reset(reverse);
            test_caller = base + caller;
            invoke(1);
            const auto value = source::events[source::head].value;
            CHECK(value.payer == (reverse ? sav : fra) && value.recipient == (reverse ? fra : sav));
            CHECK(value.observer == fra && value.start == 100 && value.end == 8860);
            CHECK(value.date == 8861 && value.amount == 1250);
        }
    }
    for (uintptr_t caller : {owned::kCleanupReturnRva, owned::kMonthlyCleanupReturnRva}) {
        for (int32_t date : {8859, 8860}) {
            reset();
            test_caller = base + caller;
            put(base + 0x29dd0, date);
            invoke(0);
        }
    }
    reset(); test_caller = base + 0x5487a3; invoke(0);
    reset(); put(instance + 0x10, sav); invoke(0);
    reset(); put(base + 0x26020, sav + 1); invoke(0, 1);
    reset(); put(instance + 0x28, static_cast<unsigned char>(1)); invoke(0);
    reset(); remove_record = false; invoke(0, 1);
    reset(); change_amount = true; invoke(0, 1);
    reset(); thread_changed = true; invoke(0, 1);
    reset(); source::installed = false; invoke(0);
    reset(); source::transport_fault = true; invoke(0);
    reset();
    const uint64_t other_generation = UINT64_C(0x10000100415246);
    put(instance + 0x10, other_generation);
    put(base + 0x24020, other_generation);
    invoke(1);
    reset();
    source::Reader reader;
    owned::Pending pending{};
    CHECK(owned::begin(reader, {0, 8861, true}, instance, owned::kCleanupReturnRva, pending)
        == owned::Decision::ignored);
    CHECK(!owned::guards(reader, 0));
    // Match native wrapping signed arithmetic across the i32 deadline boundary.
    put(instance + 0x20, INT32_MAX - 100);
    CHECK(owned::begin(reader, {base, 8861, true}, instance, test_caller, pending) == owned::Decision::ready);
    CHECK(pending.value.end == INT32_MIN + 8659);
    reset();
    std::memcpy(reinterpret_cast<void*>(base + owned::kPredicateRva), owned::kPredicateBytes.data(), owned::kPredicateBytes.size());
    std::memcpy(reinterpret_cast<void*>(base + owned::kCleanupRva), owned::kCleanupBytes.data(), owned::kCleanupBytes.size());
    std::memcpy(reinterpret_cast<void*>(base + owned::kMonthlyCleanupRva), owned::kMonthlyCleanupBytes.data(), owned::kMonthlyCleanupBytes.size());
    CHECK(owned::guards(reader, base));
    put(base + owned::kMonthlyCleanupRva + 12, static_cast<unsigned char>(0));
    CHECK(!owned::guards(reader, base));
    std::memcpy(reinterpret_cast<void*>(base + owned::kMonthlyCleanupRva), owned::kMonthlyCleanupBytes.data(), owned::kMonthlyCleanupBytes.size());
    put(base + owned::kCleanupRva + 100, static_cast<unsigned char>(0));
    CHECK(!owned::guards(reader, base));
    reset(); invoke(1);
    const char* path = std::getenv("SUBSIDY_EXPIRY_FIXTURE_LOG");
    CHECK(path != nullptr);
    log_file = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, 0, nullptr);
    CHECK(log_file != INVALID_HANDLE_VALUE);
    source::flush();
    CHECK(source::size == 0 && !source::transport_fault);
    for (unsigned index = 0; index < 65; ++index) source::queue(source::events[0].value);
    CHECK(source::size == 64 && source::dropped == 1);
    source::flush(); source::flush();
    CHECK(source::size == 0 && source::dropped == 0 && source::total_dropped == 1);
    char health[512] = "{\"event\":\"diplomacy_observer_health\"}";
    source::append_health(health, sizeof(health));
    CHECK(std::strstr(health, "\"queue_readable\":true") && std::strstr(health, "\"total_dropped\":1"));
    CloseHandle(log_file);
    log_file = INVALID_HANDLE_VALUE;
    source::queue(source::events[0].value);
    source::flush();
    CHECK(source::size == 1);
    CHECK(VirtualFree(reinterpret_cast<void*>(base), 0, MEM_RELEASE));
    std::printf("%u subsidy capture, forwarding and queue checks passed\n", checks);
}
