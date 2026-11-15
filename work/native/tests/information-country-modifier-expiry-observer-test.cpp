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

template<class Value>
static void put(uintptr_t address, const Value& value) {
    std::memcpy(reinterpret_cast<void*>(address), &value, sizeof(value));
}

static bool protect_lifetime_pages(uintptr_t instance, uintptr_t definition, DWORD protection) {
    DWORD previous = 0;
    const bool instance_ok = VirtualProtect(reinterpret_cast<void*>(instance), 0x1000,
        protection, &previous) != FALSE;
    const bool definition_ok = VirtualProtect(reinterpret_cast<void*>(definition), 0x1000,
        protection, &previous) != FALSE;
    return instance_ok && definition_ok;
}

// Include the shipping observer and replace only the return-PC intrinsic.
#define BRIDGE_COUNTRY_MODIFIER_REMOVAL 1
#define BRIDGE_COUNTRY_MODIFIER_EXPIRY 1
#define __builtin_return_address(level) reinterpret_cast<void*>(test_caller)
#include "../information-country-modifier-observer.inc"
#undef __builtin_return_address
#undef BRIDGE_COUNTRY_MODIFIER_EXPIRY
#undef BRIDGE_COUNTRY_MODIFIER_REMOVAL

namespace source = country_modifier_observer;
namespace removal = information::country_modifier::removal;
namespace expiry = information::country_modifier::expiry;

namespace {

enum class NativeResult { unlink };
static unsigned checks = 0, failures = 0, native_calls = 0;
static uintptr_t country = 0, instance = 0, definition = 0, node = 0, function = 0;
static constexpr uint64_t reference = (UINT64_C(7) << 32) | 0x415246u;
static constexpr int32_t date = 56658312;
static constexpr int32_t start_date = 56657000;
static constexpr int32_t end_date = 56658000;
static constexpr char modifier_key[] = "expiry_fixture";
static NativeResult native_result = NativeResult::unlink;
static bool destroyed = false;

void check(bool okay, const char* name) {
    ++checks;
    if (!okay) {
        ++failures;
        std::printf("FAIL %s\n", name);
    }
}

#define CHECK(expression) check((expression), #expression)

static bool protect_lifetime_pages(DWORD protection) {
    return ::protect_lifetime_pages(instance, definition, protection);
}

static void fake_remove(void* owner, void* item) {
    ++native_calls;
    CHECK(reinterpret_cast<uintptr_t>(owner) == country);
    CHECK(reinterpret_cast<uintptr_t>(item) == instance);
    CHECK(native_result == NativeResult::unlink);
    put(country + 0x1f0, uintptr_t{0});
    put(country + 0x1f8, uintptr_t{0});
    put(country + 0x200, uint32_t{0});
    destroyed = true;
    CHECK(protect_lifetime_pages(PAGE_NOACCESS));
}

static void clear_file() {
    CHECK(SetFilePointer(log_file, 0, nullptr, FILE_BEGIN) != INVALID_SET_FILE_POINTER);
    CHECK(SetEndOfFile(log_file) != FALSE);
}

static void reset(bool wrong_vtable, bool corrupt_predicate_guard) {
    CHECK(protect_lifetime_pages(PAGE_READWRITE));
    destroyed = false;
    native_calls = 0;
    native_result = NativeResult::unlink;
    frame_thread = GetCurrentThreadId();
    thread_changed = false;
    test_caller = base + removal::kPredicateReturnRva;
    source::installed = true;
    source::transport_fault = false;
    source::dropped = source::total_dropped = 0;
    source::sequence = 0;
    source::head = source::size = 0;
    source::remove_original = &fake_remove;
    clear_file();

    put(base + 0x233d8b0, base + 0x180000);
    put(base + 0x180000 + 0x118, base + 0x1a0000);
    const uintptr_t country_slot = static_cast<uintptr_t>((reference >> 32) & 0xffffu);
    put(base + 0x1a0000 + country_slot * sizeof(uintptr_t), country);
    put(country + 0x20, reference);
    put(country + 0x1f0, node);
    put(country + 0x1f8, node);
    put(country + 0x200, uint32_t{1});
    put(country + 0x204, static_cast<unsigned char>(0));
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

    const uintptr_t table = base + 0x1c56ba8;
    put(function, wrong_vtable ? table + 0x80 : table);
    put(function + 8, base + 0x140000 + 0x1dd0);
    put(function + 0x10, country);
    put(function + 0x38, function);
    put(table + 0x10, base + 0x42f360);
    const unsigned char caller_call[5]{0xe8, 0xa0, 0xfc, 0xff, 0xff};
    std::memcpy(reinterpret_cast<void*>(base + removal::kPredicateReturnRva - 5),
        caller_call, sizeof(caller_call));
    const unsigned char bind[3]{0x4c, 0x8b, 0xea};
    const unsigned char dispatch[4]{0x49, 0x8b, 0x4d, 0x38};
    const unsigned char adapter[12]{
        0x48, 0x8b, 0x12, 0x48, 0x83, 0xc1, 0x08, 0xe9, 0x84, 0xdf, 0xeb, 0xff};
    std::memcpy(reinterpret_cast<void*>(base + 0x328904), bind, sizeof(bind));
    std::memcpy(reinterpret_cast<void*>(base + 0x328954), dispatch, sizeof(dispatch));
    std::memcpy(reinterpret_cast<void*>(base + 0x42f360), adapter, sizeof(adapter));
    std::memcpy(reinterpret_cast<void*>(base + 0x2ed2f0), expiry::kPredicatePrefix.data(),
        expiry::kPredicatePrefix.size());
    if (corrupt_predicate_guard)
        *reinterpret_cast<unsigned char*>(base + 0x2ed2f0) ^= 0x01;
}

static void check_owned_event(const source::Event& event, bool expired) {
    CHECK(event.removed);
    CHECK(event.expired == expired);
    CHECK(event.value.country == reference);
    CHECK(event.value.date == date);
    CHECK(event.value.start_date == start_date);
    CHECK(event.value.end_date == end_date);
    CHECK((event.value.flags == std::array<unsigned char, 4>{{1, 0, 1, 0}}));
    CHECK(std::strcmp(event.value.key.data(), modifier_key) == 0);
}

static void check_owned_value(const information::country_modifier::Added& value) {
    CHECK(value.country == reference);
    CHECK(value.date == date);
    CHECK(value.start_date == start_date);
    CHECK(value.end_date == end_date);
    CHECK((value.flags == std::array<unsigned char, 4>{{1, 0, 1, 0}}));
    CHECK(std::strcmp(value.key.data(), modifier_key) == 0);
}

static void check_native_pipeline(expiry::Reason expected_reason) {
    source::Reader reader;
    const information::country_modifier::Context context{
        base, country, reference, date, true};
    removal::Pending pending{};
    CHECK(removal::begin(reader, context, instance, test_caller, pending));
    CHECK(pending.ready);
    CHECK(expiry::classify(reader, context, pending.value, test_caller, function)
        == expected_reason);

    fake_remove(reinterpret_cast<void*>(country), reinterpret_cast<void*>(instance));
    CHECK(native_calls == 1 && destroyed);
    information::country_modifier::Added value{};
    CHECK(removal::finish(reader, pending, value));
    CHECK(!pending.ready);
    check_owned_value(value);
}

static bool read_file(char* output, DWORD capacity, DWORD& bytes) {
    HANDLE file = CreateFileW(log_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    const bool okay = ReadFile(file, output, capacity - 1, &bytes, nullptr) != FALSE;
    CloseHandle(file);
    if (okay) output[bytes] = '\0';
    return okay;
}

static void test_expired_removal_emits_expiry_event_once() {
    reset(false, false);
    check_native_pipeline(expiry::Reason::expired);
    reset(false, false);
    source::country_modifier_remove_observe(reinterpret_cast<void*>(country),
        reinterpret_cast<void*>(instance), reinterpret_cast<void*>(function));
    CHECK(native_calls == 1);
    CHECK(source::size == 1 && source::total_dropped == 0);
    check_owned_event(source::events[source::head], true);
    CHECK(destroyed);
    source::flush();
    char output[2048]{};
    DWORD bytes = 0;
    CHECK(read_file(output, sizeof(output), bytes));
    CHECK(std::strstr(output, "\"event\":\"native_country_modifier_expired\""));
    CHECK(std::strstr(output, "\"source\":\"temporary_country_modifier_expiry_remove_return\""));
    CHECK(!std::strstr(output, "native_country_modifier_capture_gap"));
}

static void test_other_vtable_remains_removed_without_expiry() {
    reset(true, false);
    check_native_pipeline(expiry::Reason::other);
    reset(true, false);
    source::country_modifier_remove_observe(reinterpret_cast<void*>(country),
        reinterpret_cast<void*>(instance), reinterpret_cast<void*>(function));
    CHECK(native_calls == 1);
    CHECK(source::size == 1 && source::total_dropped == 0);
    check_owned_event(source::events[source::head], false);
    CHECK(destroyed);
    source::flush();
    char output[2048]{};
    DWORD bytes = 0;
    CHECK(read_file(output, sizeof(output), bytes));
    CHECK(std::strstr(output, "\"event\":\"native_country_modifier_removed\""));
    CHECK(std::strstr(output, "\"source\":\"temporary_country_modifier_remove_return\""));
    CHECK(!std::strstr(output, "native_country_modifier_expired"));
    CHECK(!std::strstr(output, "native_country_modifier_capture_gap"));
}

static void test_unreadable_reason_keeps_removed_and_records_gap() {
    reset(false, true);
    check_native_pipeline(expiry::Reason::unreadable);
    reset(false, true);
    source::country_modifier_remove_observe(reinterpret_cast<void*>(country),
        reinterpret_cast<void*>(instance), reinterpret_cast<void*>(function));
    CHECK(native_calls == 1);
    CHECK(source::size == 1 && source::total_dropped == 1 && source::dropped == 1);
    check_owned_event(source::events[source::head], false);
    CHECK(destroyed);
    source::flush();
    CHECK(source::size == 0 && source::dropped == 0);
    char output[2048]{};
    DWORD bytes = 0;
    CHECK(read_file(output, sizeof(output), bytes));
    CHECK(std::strstr(output, "\"event\":\"native_country_modifier_removed\""));
    CHECK(std::strstr(output, "\"source\":\"temporary_country_modifier_remove_return\""));
    CHECK(std::strstr(output, "\"event\":\"native_country_modifier_capture_gap\""));
    CHECK(std::strstr(output, "\"dropped\":1"));
    CHECK(!std::strstr(output, "native_country_modifier_expired"));
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
    function = base + 0x210000;

    if (!GetEnvironmentVariableW(L"MODIFIER_EXPIRY_TEST_LOG", log_path,
        static_cast<DWORD>(sizeof(log_path) / sizeof(log_path[0])))) return 3;
    log_file = CreateFileW(log_path, GENERIC_WRITE, FILE_SHARE_READ,
        nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (log_file == INVALID_HANDLE_VALUE) return 4;

    test_expired_removal_emits_expiry_event_once();
    test_other_vtable_remains_removed_without_expiry();
    test_unreadable_reason_keeps_removed_and_records_gap();

    if (log_file != INVALID_HANDLE_VALUE) CloseHandle(log_file);
    DWORD previous = 0;
    VirtualProtect(reinterpret_cast<void*>(instance), 0x1000, PAGE_READWRITE, &previous);
    VirtualProtect(reinterpret_cast<void*>(definition), 0x1000, PAGE_READWRITE, &previous);
    CHECK(VirtualFree(memory, 0, MEM_RELEASE) != FALSE);
    std::printf("expiry observer regression: %s (%u checks, 3 scenarios)\n",
        failures ? "FAIL" : "PASS", checks);
    return failures ? 1 : 0;
}
