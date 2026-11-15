#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include "../entry-patch-transaction.inc"

static uintptr_t base = 0, test_caller = 0;
static DWORD frame_thread = 0;
static bool thread_changed = false;
static uint64_t observation_creation = 1;
static HANDLE log_file = INVALID_HANDLE_VALUE;
template<class Value>
static bool read(uintptr_t address, Value& value) {
    SIZE_T bytes = 0;
    return ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<void*>(address),
        &value, sizeof(value), &bytes) && bytes == sizeof(value);
}
// Include the production observer and replace only the compiler return-PC
// intrinsic. All fixture mutations below target this test process's own arena.
#define __builtin_return_address(level) reinterpret_cast<void*>(test_caller)
#include "../information-country-modifier-observer.inc"
#undef __builtin_return_address

namespace source = country_modifier_observer;
static unsigned calls = 0, failures = 0;
static uintptr_t country = 0, instance = 0, node = 0;
static constexpr uint64_t reference = (UINT64_C(1) << 32) | 0x415246;

static void check(bool okay, const char* name) {
    if (!okay) { ++failures; std::printf("FAIL %s\n", name); }
}

template<class Value>
static void put(uintptr_t address, const Value& value) {
    std::memcpy(reinterpret_cast<void*>(address), &value, sizeof(value));
}

static void fake_original(void* owner, void* item, unsigned char flag) {
    ++calls;
    check(reinterpret_cast<uintptr_t>(owner) == country
        && reinterpret_cast<uintptr_t>(item) == instance && flag == 0x5a, "native arguments");
    put(country + 0x1f0, node);
    put(country + 0x1f8, node);
    put(country + 0x200, uint32_t{1});
    put(node, instance);
    put(node + 0x10, uintptr_t{0});
}

static void reset() {
    calls = 0;
    frame_thread = GetCurrentThreadId();
    thread_changed = false;
    test_caller = base + source::owned::kCreatorReturnRva;
    source::installed = true;
    source::transport_fault = false;
    source::dropped = source::total_dropped = 0;
    source::sequence = 0;
    source::head = source::size = 0;
    source::original = &fake_original;
    put(country + 0x1f0, uintptr_t{0});
    put(country + 0x1f8, uintptr_t{0});
    put(country + 0x200, uint32_t{0});
}

int main() {
    auto memory = VirtualAlloc(nullptr, 0x2340000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!memory) return 2;
    base = reinterpret_cast<uintptr_t>(memory);
    country = base + 0x100000;
    const uintptr_t game = base + 0x140000, database = base + 0x180000;
    const uintptr_t countries = base + 0x1a0000, definition = base + 0x1c0000;
    instance = base + 0x1e0000;
    node = base + 0x200000;
    put(base + 0x233d8b0, database);
    put(database + 0x118, countries);
    put(countries + 8, country);
    put(country + 0x20, reference);
    put(base + 0x233fe58, game);
    put(game + 0x1dd0, int32_t{56658312});
    put(instance, base + 0x1ce7f08);
    put(instance + 0x30, definition);
    put(instance + 0x40, int32_t{43808760});
    put(instance + 0x44, int32_t{56660000});
    put(definition, base + 0x1c42ae0);
    std::memcpy(reinterpret_cast<void*>(definition + 0x158), "test_modifier", 14);
    put(definition + 0x168, uint64_t{13});
    put(definition + 0x170, uint64_t{15});
    const unsigned char call[]{0xe8, 0xd8, 0xf5, 0xff, 0xff};
    std::memcpy(reinterpret_cast<void*>(base + 0x328e13), call, sizeof(call));

    reset();
    source::country_modifier_insert_observe(reinterpret_cast<void*>(country),
        reinterpret_cast<void*>(instance), 0x5a);
    check(calls == 1 && source::size == 1, "successful native return queues once");
    check(std::strcmp(source::events[source::head].value.key.data(), "test_modifier") == 0,
        "owned modifier identity");
    reset();
    test_caller = base + 0x2d414a;
    source::country_modifier_insert_observe(reinterpret_cast<void*>(country),
        reinterpret_cast<void*>(instance), 0x5a);
    check(calls == 1 && source::size == 0 && source::total_dropped == 0, "noncreator call only forwards");
    reset();
    thread_changed = true;
    source::country_modifier_insert_observe(reinterpret_cast<void*>(country),
        reinterpret_cast<void*>(instance), 0x5a);
    check(calls == 1 && source::size == 0 && source::total_dropped == 1,
        "rejected capture still forwards exactly once and records gap");

    wchar_t path[32768]{};
    if (!GetEnvironmentVariableW(L"MODIFIER_TEST_LOG", path, 32768)) return 3;
    log_file = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (log_file == INVALID_HANDLE_VALUE) return 4;
    reset();
    source::owned::Added value{};
    value.country = reference;
    value.date = 56658312;
    std::memcpy(value.key.data(), "test_modifier", 14);
    for (unsigned index = 0; index < 65; ++index) source::queue(value);
    check(source::size == 64 && source::total_dropped == 1, "bounded queue overflow gap");
    source::flush();
    check(source::size == 32 && source::dropped == 0 && source::total_dropped == 1,
        "bounded flush acknowledges gap and retains total");
    source::flush();
    check(source::size == 0 && !source::transport_fault, "second flush drains remaining values");
    CloseHandle(log_file);
    log_file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (log_file == INVALID_HANDLE_VALUE) return 5;
    char output[65536]{};
    DWORD bytes = 0;
    check(ReadFile(log_file, output, sizeof(output) - 1, &bytes, nullptr) != FALSE, "read generated stream");
    unsigned lines = 0;
    for (DWORD index = 0; index < bytes; ++index) if (output[index] == '\n') ++lines;
    check(lines == 65 && std::strstr(output, "native_country_modifier_added")
        && std::strstr(output, "native_country_modifier_capture_gap"), "64 records and one gap");

    reset();
    source::queue(value);
    source::flush(); // Deliberately use the read-only fixture handle.
    check(source::transport_fault && source::size == 1 && source::head == 0,
        "write failure latches and retains owned head");
    source::flush();
    check(source::transport_fault && source::size == 1 && source::head == 0,
        "latched write is not retried");
    char health[640] = "{\"event\":\"fixture_health\"}\n";
    source::append_health(health, sizeof(health));
    check(std::strstr(health, "\"transport_fault\":true") && std::strstr(health, "\"queued\":1"),
        "health exposes transport failure and retained record");
    CloseHandle(log_file);
    log_file = INVALID_HANDLE_VALUE;
    check(VirtualFree(memory, 0, MEM_RELEASE) != FALSE, "release fixture arena");
    std::printf("observer wrapper and transport regression %s\n", failures ? "FAIL" : "PASS");
    return failures ? 1 : 0;
}
