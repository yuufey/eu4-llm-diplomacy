#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "../entry-patch-transaction.inc"

static uintptr_t base = 0;
static DWORD frame_thread = 0;
static bool thread_changed = false;
static uint64_t observation_creation = 1;
static HANDLE log_file = INVALID_HANDLE_VALUE;
template<class Value> static bool read(uintptr_t address, Value& value) {
    SIZE_T count = 0;
    return ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<void*>(address), &value,
        sizeof(value), &count) && count == sizeof(value);
}
#include "../information-truce-expiry-observer.inc"
namespace source = truce_expiry_observer;
namespace owned = information::truce_expiry;
static unsigned checks = 0, calls = 0;
static uintptr_t instance = 0;
static bool clear_record = true, change_input = false, advance_date = false;
static constexpr uint64_t fra = UINT64_C(0x10000100415246), sav = UINT64_C(0x10000200564153);
static constexpr int32_t input_date = 56064000, end_date = 56108544;
static constexpr uintptr_t returned = 0x12345678;
#define CHECK(expression) do { ++checks; if (!(expression)) { std::printf("FAIL line %u %s\n", __LINE__, #expression); std::exit(1); } } while (false)
template<class Value> static void put(uintptr_t address, Value value) {
    std::memcpy(reinterpret_cast<void*>(address), &value, sizeof(value));
}
static uintptr_t original(uintptr_t item) {
    CHECK(item == instance);
    ++calls;
    if (clear_record) {
        put(item + 0x44, static_cast<unsigned char>(2));
        put(item + 0x45, static_cast<unsigned char>(0xa0));
    }
    if (change_input) put(item + 0x34, input_date + 24);
    if (advance_date) put(base + 0x29dd0, end_date + 24);
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
    clear_record = true;
    change_input = advance_date = false;
    put(base + 0x233d8b0, base + 0x20000);
    put(base + 0x20118, base + 0x22000);
    put(base + 0x22008, base + 0x24000);
    put(base + 0x22010, base + 0x26000);
    put(base + 0x24020, fra);
    put(base + 0x26020, sav);
    put(base + 0x233fe58, base + 0x28000);
    put(base + 0x29dd0, end_date);
    put(base + 0x29dd4, int32_t{43800000});
    put(base + 0x1fd13c4, int32_t{-1});
    put(base + 0x233dc88, int32_t{10});
    put(base + 0x233dd8c, int32_t{5});
    put(base + 0x30050, base + 0x34000);
    put(base + 0x3005c, int32_t{0});
    put(base + (reverse ? 0x27510 : 0x25510), base + 0x32000);
    instance = base + 0x32000 + (reverse ? 1 : 2) * 0x48;
    std::memset(reinterpret_cast<void*>(instance), 0, 0x48);
    put(instance, base + 0x30000);
    put(instance + 8, reverse ? sav : fra);
    put(instance + 0x10, reverse ? fra : sav);
    put(instance + 0x34, input_date);
    put(instance + 0x45, static_cast<unsigned char>(0xa1));
}
static void invoke(unsigned queued, unsigned dropped = 0) {
    CHECK(source::truce_maintenance_observe(instance) == returned);
    CHECK(calls == 1 && source::size == queued);
    CHECK(static_cast<unsigned>(source::total_dropped) == dropped);
}
static void check_date_projection() {
    const char* path = std::getenv("TRUCE_EXPIRY_MATH_LOG");
    CHECK(path != nullptr);
    HANDLE output = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, 0, nullptr);
    CHECK(output != INVALID_HANDLE_VALUE);
    for (int32_t input : {43800000, 43800023, 43800696, 56064000, INT32_MAX}) {
        for (int adjustment : {-128, -1, 0, 127}) {
            for (int32_t first : {INT32_MIN, -1, 0, 10, INT32_MAX}) {
                for (int32_t second : {INT32_MIN, -1, 0, 5, INT32_MAX}) {
                    owned::Value value{};
                    value.input = input;
                    value.adjustment = static_cast<int8_t>(adjustment);
                    value.configuration_a = first;
                    value.configuration_b = second;
                    const bool supported = owned::detail::expiry(value);
                    char line[128]{};
                    const int bytes = std::snprintf(line, sizeof(line), "%d,%d,%d,%d,%d,%d\n",
                        input, adjustment, first, second, supported, value.end);
                    DWORD written = 0;
                    CHECK(bytes > 0 && static_cast<size_t>(bytes) < sizeof(line));
                    CHECK(WriteFile(output, line, bytes, &written, nullptr) && written == static_cast<DWORD>(bytes));
                }
            }
        }
    }
    CHECK(CloseHandle(output));
}
int main() {
    check_date_projection();
    base = reinterpret_cast<uintptr_t>(VirtualAlloc(nullptr, 0x2341000,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    CHECK(base != 0);
    for (bool reverse : {false, true}) {
        reset(reverse);
        invoke(1);
        const auto value = source::events[source::head].value;
        CHECK(value.actor == (reverse ? sav : fra) && value.recipient == (reverse ? fra : sav));
        CHECK(value.observer == fra && value.input == input_date && value.end == end_date);
        CHECK(value.date == end_date && value.adjustment == 0);
    }
    reset(); put(base + 0x29dd0, end_date - 1); invoke(0);
    reset(); put(base + 0x29dd4, input_date); invoke(0);
    reset(); put(base + 0x1fd13c4, end_date); invoke(0);
    reset(); put(instance + 0x34, end_date + 1); invoke(0);
    reset(); put(instance + 0x45, static_cast<unsigned char>(0xa0)); invoke(0);
    reset(); put(instance + 8, sav); invoke(0);
    reset(); put(base + 0x3005c, int32_t{1}); put(base + 0x34000, int32_t{2}); invoke(0);
    reset(); put(base + 0x3005c, int32_t{-1}); invoke(0, 1);
    reset(); put(base + 0x3005c, int32_t{4097}); invoke(0, 1);
    reset(); put(base + 0x30050, uintptr_t{0}); put(base + 0x3005c, int32_t{1}); invoke(0, 1);
    reset(); put(base + 0x26020, sav + 1); invoke(0, 1);
    reset(); put(base + 0x25510, base + 0x32008); invoke(0, 1);
    reset(); put(instance + 0x34, int32_t{43800000 - 1}); put(base + 0x29dd4, int32_t{-1}); invoke(0, 1);
    reset(); clear_record = false; invoke(0, 1);
    reset(); change_input = true; invoke(0, 1);
    reset(); advance_date = true; invoke(0, 1);
    reset(); thread_changed = true; invoke(0, 1);
    reset(); source::installed = false; invoke(0);
    reset(); source::transport_fault = true; invoke(0);
    reset();
    source::Reader reader;
    owned::Pending pending{};
    CHECK(owned::begin(reader, {base, end_date, true}, instance, pending) == owned::Decision::ready);
    owned::Value value{};
    CHECK(!owned::finish(reader, pending, value));
    CHECK(!owned::finish(reader, pending, value));
    CHECK(owned::begin(reader, {0, end_date, true}, instance, pending) == owned::Decision::ignored);
    CHECK(!owned::guards(reader, 0));
    // Native duplicate invocations see the cleared input flag and forward once.
    reset(); invoke(1);
    CHECK(source::truce_maintenance_observe(instance) == returned);
    CHECK(calls == 2 && source::size == 1 && source::total_dropped == 0);
    reset();
    std::memcpy(reinterpret_cast<void*>(base + owned::kMaintenanceRva), owned::kMaintenanceBytes.data(), owned::kMaintenanceBytes.size());
    std::memcpy(reinterpret_cast<void*>(base + owned::kDateMathRva), owned::kDateMathBytes.data(), owned::kDateMathBytes.size());
    CHECK(owned::guards(reader, base));
    put(base + owned::kMaintenanceRva + 100, static_cast<unsigned char>(0));
    CHECK(!owned::guards(reader, base));
    reset(); invoke(1);
    const char* path = std::getenv("TRUCE_EXPIRY_FIXTURE_LOG");
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
    std::printf("%u truce capture, forwarding and queue checks passed\n", checks);
}
