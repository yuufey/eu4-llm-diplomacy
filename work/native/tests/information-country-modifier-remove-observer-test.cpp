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
static wchar_t log_path[32768]{};

template<class Value>
static bool read(uintptr_t address, Value& value) {
    SIZE_T bytes = 0;
    return ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<void*>(address),
        &value, sizeof(value), &bytes) && bytes == sizeof(value);
}

// Include the shipping observer and replace only the return-PC intrinsic.
#define BRIDGE_COUNTRY_MODIFIER_REMOVAL 1
#define __builtin_return_address(level) reinterpret_cast<void*>(test_caller)
#include "../information-country-modifier-observer.inc"
#undef __builtin_return_address
#undef BRIDGE_COUNTRY_MODIFIER_REMOVAL

namespace source = country_modifier_observer;
namespace removal = information::country_modifier::removal;

namespace {

enum class NativeResult { unlink, deferred };
static unsigned checks = 0, failures = 0, native_calls = 0;
static uintptr_t country = 0, instance = 0, definition = 0, node = 0;
static constexpr uint64_t reference = (UINT64_C(1) << 32) | 0x415246;
static constexpr int32_t date = 56658312;
static constexpr int32_t start_date = 56658000;
static constexpr int32_t end_date = 56662000;
static constexpr char modifier_key[] = "test_remove";
static NativeResult native_result = NativeResult::unlink;
static bool destroyed = false;

static void check(bool okay, const char* name) {
    ++checks;
    if (!okay) {
        ++failures;
        std::printf("FAIL %s\n", name);
    }
}

#define CHECK(expression) check((expression), #expression)

template<class Value>
static void put(uintptr_t address, const Value& value) {
    std::memcpy(reinterpret_cast<void*>(address), &value, sizeof(value));
}

static bool protect_lifetime_pages(DWORD protection) {
    DWORD previous = 0;
    const bool instance_ok = VirtualProtect(reinterpret_cast<void*>(instance), 0x1000,
        protection, &previous) != FALSE;
    const bool definition_ok = VirtualProtect(reinterpret_cast<void*>(definition), 0x1000,
        protection, &previous) != FALSE;
    return instance_ok && definition_ok;
}

static void fake_remove(void* owner, void* item) {
    ++native_calls;
    CHECK(reinterpret_cast<uintptr_t>(owner) == country);
    CHECK(reinterpret_cast<uintptr_t>(item) == instance);
    if (native_result == NativeResult::unlink) {
        put(country + 0x1f0, uintptr_t{0});
        put(country + 0x1f8, uintptr_t{0});
        put(country + 0x200, uint32_t{0});
    } else {
        put(node + 0x18, static_cast<unsigned char>(1));
        put(country + 0x204, static_cast<unsigned char>(1));
    }
    destroyed = true;
    CHECK(protect_lifetime_pages(PAGE_NOACCESS));
}

static void reset(NativeResult result, uintptr_t caller) {
    CHECK(protect_lifetime_pages(PAGE_READWRITE));
    destroyed = false;
    native_calls = 0;
    native_result = result;
    frame_thread = GetCurrentThreadId();
    thread_changed = false;
    test_caller = caller;
    source::installed = true;
    source::transport_fault = false;
    source::dropped = source::total_dropped = 0;
    source::sequence = 0;
    source::head = source::size = 0;
    source::remove_original = &fake_remove;

    put(base + 0x233d8b0, base + 0x180000);
    put(base + 0x180000 + 0x118, base + 0x1a0000);
    put(base + 0x1a0000 + 8, country);
    put(country + 0x20, reference);
    put(country + 0x1f0, node);
    put(country + 0x1f8, node);
    put(country + 0x200, uint32_t{1});
    put(country + 0x204, static_cast<unsigned char>(result == NativeResult::deferred));
    put(base + 0x233fe58, base + 0x140000);
    put(base + 0x140000 + 0x1dd0, date);

    put(instance, base + 0x1ce7f08);
    put(instance + 0x30, definition);
    put(instance + 0x40, start_date);
    put(instance + 0x44, end_date);
    const unsigned char flags[4]{1, 0, 1, 0};
    std::memcpy(reinterpret_cast<void*>(instance + 0x48), flags, sizeof(flags));
    put(definition, base + 0x1c42ae0);
    std::memset(reinterpret_cast<void*>(definition + 0x158), 0, 32);
    std::memcpy(reinterpret_cast<void*>(definition + 0x158), modifier_key, sizeof(modifier_key));
    put(definition + 0x168, static_cast<uint64_t>(sizeof(modifier_key) - 1));
    put(definition + 0x170, uint64_t{15});

    put(node, instance);
    put(node + 8, uintptr_t{0});
    put(node + 0x10, uintptr_t{0});
    put(node + 0x18, static_cast<unsigned char>(0));
    if (caller == base + removal::kPredicateReturnRva) {
        const unsigned char call[5]{0xe8, 0xa0, 0xfc, 0xff, 0xff};
        std::memcpy(reinterpret_cast<void*>(caller - 5), call, sizeof(call));
    } else if (caller == base + removal::kReligionReturnRva) {
        const unsigned char call[5]{0xe8, 0x15, 0xa5, 0x02, 0x00};
        std::memcpy(reinterpret_cast<void*>(caller - 5), call, sizeof(call));
    }
}

static void check_owned_value(const source::Event& event) {
    CHECK(event.removed);
    CHECK(event.value.country == reference);
    CHECK(event.value.date == date);
    CHECK(event.value.start_date == start_date);
    CHECK(event.value.end_date == end_date);
    CHECK((event.value.flags == std::array<unsigned char, 4>{{1, 0, 1, 0}}));
    CHECK(std::strcmp(event.value.key.data(), modifier_key) == 0);
}

static bool read_stream(char* output, DWORD capacity, DWORD& bytes) {
    log_file = CreateFileW(log_path, GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (log_file == INVALID_HANDLE_VALUE) return false;
    const bool okay = ReadFile(log_file, output, capacity - 1, &bytes, nullptr) != FALSE
        && bytes < capacity;
    if (okay) output[bytes] = '\0';
    CloseHandle(log_file);
    log_file = INVALID_HANDLE_VALUE;
    return okay;
}

static void test_normal_and_deferred_removal() {
    reset(NativeResult::unlink, base + removal::kPredicateReturnRva);
    source::country_modifier_remove_observe(reinterpret_cast<void*>(country),
        reinterpret_cast<void*>(instance));
    CHECK(native_calls == 1 && source::size == 1 && source::total_dropped == 0);
    if (source::size == 1) check_owned_value(source::events[source::head]);
    CHECK(destroyed);

    source::flush();
    CHECK(source::size == 0 && !source::transport_fault);

    source::owned::Added value{};
    value.country = reference;
    value.date = date;
    std::memcpy(value.key.data(), modifier_key, sizeof(modifier_key));
    for (unsigned index = 0; index < 65; ++index) source::queue(value, true);
    CHECK(source::size == 64 && source::dropped == 1 && source::total_dropped == 1);
    source::flush();
    CHECK(source::size == 32 && source::dropped == 0 && source::total_dropped == 1);
    source::flush();
    CHECK(source::size == 0 && !source::transport_fault);

    CloseHandle(log_file);
    log_file = INVALID_HANDLE_VALUE;
    char output[65536]{};
    DWORD bytes = 0;
    CHECK(read_stream(output, sizeof(output), bytes));
    unsigned lines = 0;
    for (DWORD index = 0; index < bytes; ++index) if (output[index] == '\n') ++lines;
    CHECK(lines == 66);
    CHECK(std::strstr(output, "\"event\":\"native_country_modifier_removed\""));
    CHECK(std::strstr(output, "\"source\":\"temporary_country_modifier_remove_return\""));
    CHECK(std::strstr(output, "\"modifier_id\":\"test_remove\""));
    CHECK(std::strstr(output, "\"event\":\"native_country_modifier_capture_gap\""));
    CHECK(std::strstr(output, "\"dropped\":1"));

    reset(NativeResult::deferred, base + removal::kReligionReturnRva);
    source::country_modifier_remove_observe(reinterpret_cast<void*>(country),
        reinterpret_cast<void*>(instance));
    CHECK(native_calls == 1 && source::size == 1 && source::total_dropped == 0);
    if (source::size == 1) check_owned_value(source::events[source::head]);
    CHECK(destroyed);
}

static void test_wrong_caller_forwards_once() {
    reset(NativeResult::unlink, base + 0x2d414a);
    source::country_modifier_remove_observe(reinterpret_cast<void*>(country),
        reinterpret_cast<void*>(instance));
    CHECK(native_calls == 1);
    CHECK(source::size == 0 && source::total_dropped == 0);
    CHECK(destroyed);
}

static void test_wrong_frame_forwards_once_and_records_gap() {
    reset(NativeResult::unlink, base + removal::kPredicateReturnRva);
    thread_changed = true;
    source::country_modifier_remove_observe(reinterpret_cast<void*>(country),
        reinterpret_cast<void*>(instance));
    CHECK(native_calls == 1);
    CHECK(source::size == 0 && source::total_dropped == 1 && source::dropped == 1);
    CHECK(destroyed);
}

static void test_write_failure_latches_without_consuming_owned_event() {
    reset(NativeResult::unlink, base + removal::kPredicateReturnRva);
    log_file = CreateFileW(log_path, GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    CHECK(log_file != INVALID_HANDLE_VALUE);
    source::country_modifier_remove_observe(reinterpret_cast<void*>(country),
        reinterpret_cast<void*>(instance));
    CHECK(native_calls == 1 && source::size == 1 && source::events[source::head].removed);
    CHECK(destroyed);

    source::flush();
    CHECK(source::transport_fault && source::size == 1 && source::head == 0);
    source::flush();
    CHECK(source::transport_fault && source::size == 1 && source::head == 0);
    char health[640] = "{\"event\":\"fixture_health\"}";
    source::append_health(health, sizeof(health));
    CHECK(std::strstr(health, "\"transport_fault\":true"));
    CHECK(std::strstr(health, "\"queued\":1"));
    CloseHandle(log_file);
    log_file = INVALID_HANDLE_VALUE;
}

} // namespace

int main() {
    auto memory = VirtualAlloc(nullptr, 0x2340000,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!memory) return 2;
    base = reinterpret_cast<uintptr_t>(memory);
    country = base + 0x100000;
    definition = base + 0x1c0000;
    instance = base + 0x1e0000;
    node = base + 0x200000;

    if (!GetEnvironmentVariableW(L"MODIFIER_TEST_LOG", log_path,
        static_cast<DWORD>(sizeof(log_path) / sizeof(log_path[0])))) return 3;
    log_file = CreateFileW(log_path, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (log_file == INVALID_HANDLE_VALUE) return 4;

    test_normal_and_deferred_removal();
    test_wrong_caller_forwards_once();
    test_wrong_frame_forwards_once_and_records_gap();
    test_write_failure_latches_without_consuming_owned_event();

    if (log_file != INVALID_HANDLE_VALUE) CloseHandle(log_file);
    DWORD previous = 0;
    VirtualProtect(reinterpret_cast<void*>(instance), 0x1000, PAGE_READWRITE, &previous);
    VirtualProtect(reinterpret_cast<void*>(definition), 0x1000, PAGE_READWRITE, &previous);
    CHECK(VirtualFree(memory, 0, MEM_RELEASE) != FALSE);
    std::printf("observer removal regression: %s (%u checks, 5 scenarios)\n",
        failures ? "FAIL" : "PASS", checks);
    return failures ? 1 : 0;
}
