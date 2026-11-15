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
#include "../information-claim-expiry-observer.inc"
#undef __builtin_return_address
namespace source = claim_expiry_observer;
namespace owned = information::claim_expiry;
static unsigned checks = 0, calls = 0;
static uintptr_t instance = 0;
static uint64_t claimant = 0;
static bool remove_claim = true, change_other = false, change_owner = false, advance_date = false;
static constexpr uint64_t fra = UINT64_C(0x100007a00415246), sav = UINT64_C(0x10000d200564153);
static constexpr uint64_t bur = UINT64_C(0x100004200525542), por = UINT64_C(0x10000bd00524f50);
static constexpr uint64_t empty = UINT64_C(0x1000000002d2d2d);
static constexpr int32_t date = 56692920, province = 186;
static constexpr uintptr_t returned = 0x12345678;
#define CHECK(expression) do { ++checks; if (!(expression)) { std::printf("FAIL line %u %s\n", __LINE__, #expression); std::exit(1); } } while (false)
template<class Value> static void put(uintptr_t address, Value value) {
    std::memcpy(reinterpret_cast<void*>(address), &value, sizeof(value));
}
static uintptr_t original(uintptr_t item, uint64_t country, unsigned char record_history) {
    CHECK(item == instance && country == claimant && record_history == 0xa5);
    ++calls;
    if (remove_claim) put(base + 0x3a010, base + 0x3a040);
    if (change_other) put(base + 0x3a000, por);
    if (change_owner) put(item + 0x468, fra);
    if (advance_date) put(base + 0x31dd0, date + 24);
    return returned;
}
static void reset(bool foreign_claimant = false) {
    source::installed = true;
    source::transport_fault = false;
    source::dropped = source::total_dropped = 0;
    source::sequence = 0;
    source::size = source::head = calls = 0;
    source::original = &original;
    frame_thread = GetCurrentThreadId();
    thread_changed = false;
    test_caller = base + owned::kExpiryReturnRva;
    remove_claim = true;
    change_other = change_owner = advance_date = false;
    claimant = foreign_claimant ? sav : fra;
    instance = base + 0x40000 + province * 0x2e10;
    put(base + 0x233d8b0, base + 0x20000);
    put(base + 0x20118, base + 0x22000);
    put(base + 0x20124, uint32_t{256});
    put(base + 0x22000 + 122 * 8, base + 0x25000);
    put(base + 0x22000 + 210 * 8, base + 0x28000);
    put(base + 0x22000, base + 0x2b000);
    put(base + 0x25020, fra);
    put(base + 0x28020, sav);
    put(base + 0x2b020, empty);
    put(base + 0x233fe58, base + 0x30000);
    put(base + 0x31dd0, date);
    put(base + 0x31c90, base + 0x35000);
    put(base + 0x31c98, base + 0x35000 + 300 * 8);
    put(base + 0x31ca8, base + 0x40000);
    put(instance + 0x20, province);
    put(instance + 0x468, foreign_claimant ? fra : sav);
    put(instance + 0x5e0, base + 0x38000);
    put(base + 0x3800c, uint32_t{1u << 26});
    put(instance + 0x4c0, base + 0x3a000);
    put(base + 0x3a000, bur);
    put(base + 0x3a010, base + 0x3a020);
    put(base + 0x3a020, claimant);
    put(base + 0x3a030, base + 0x3a040);
    put(base + 0x3a040, por);
    put(base + 0x3a050, uintptr_t{0});
}
static void invoke(unsigned queued, unsigned dropped = 0) {
    CHECK(source::claim_remove_observe(instance, claimant, 0xa5) == returned);
    CHECK(calls == 1 && source::size == queued);
    CHECK(static_cast<unsigned>(source::total_dropped) == dropped);
}
struct TrackingReader final {
    unsigned calls = 0, bytes = 0, max_size = 0;
    bool opaque_read = false;
    bool read(uintptr_t address, unsigned char* destination, size_t size) noexcept {
        ++calls;
        bytes += size;
        max_size = size > max_size ? size : max_size;
        for (auto node : {base + 0x3a000, base + 0x3a020, base + 0x3a040}) {
            if (address < node + 0x10 && node + 8 < address + size) opaque_read = true;
        }
        source::Reader reader;
        return reader.read(address, destination, size);
    }
};
int main() {
    base = reinterpret_cast<uintptr_t>(VirtualAlloc(nullptr, 0x2341000,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    CHECK(base != 0);
    for (bool foreign_claimant : {false, true}) {
        reset(foreign_claimant);
        invoke(1);
        const auto value = source::events[source::head].value;
        CHECK(value.claimant == (foreign_claimant ? sav : fra));
        CHECK(value.owner == (foreign_claimant ? fra : sav));
        CHECK(value.observer == fra && value.province == province && value.date == date);
    }
    reset(); test_caller = base + 0x9fe52f; invoke(0);
    reset(); test_caller = base + 0xd8bb1e; invoke(0);
    reset(); put(instance + 0x468, sav); claimant = bur; invoke(0);
    reset(); put(base + 0x28020, sav + 1); invoke(0, 1);
    reset(); put(base + 0x20124, uint32_t{100}); invoke(0, 1);
    reset(); put(base + 0x31ca8, base + 0x40008); invoke(0, 1);
    reset(); put(instance + 0x20, province + 1); invoke(0, 1);
    reset(); put(base + 0x31c98, base + 0x35000 + 7); invoke(0, 1);
    reset(); put(base + 0x3800c, uint32_t{0}); invoke(0, 1);
    reset(); put(base + 0x3a010, base + 0x3a040); invoke(0);
    reset(); put(base + 0x3a040, claimant); invoke(0, 1);
    reset(); put(base + 0x3a020, claimant ^ (UINT64_C(1) << 48)); invoke(0, 1);
    reset(); put(base + 0x3a050, base + 0x3a000); invoke(0, 1);
    reset(); put(base + 0x3a010, base + 0x3a008); invoke(0, 1);
    reset(); remove_claim = false; invoke(0, 1);
    reset(); change_other = true; invoke(0, 1);
    reset(); change_owner = true; invoke(0, 1);
    reset(); advance_date = true; invoke(0, 1);
    reset(); thread_changed = true; invoke(0, 1);
    reset(); source::installed = false; invoke(0);
    reset(); source::transport_fault = true; invoke(0);
    reset(); put(instance + 0x468, empty); invoke(1);
    reset(); put(instance + 0x468, fra); invoke(1);
    // Canonical equality admits the same tag/slot with another high-bit encoding.
    reset(); claimant = fra ^ (UINT64_C(1) << 60); put(base + 0x25020, claimant);
    put(base + 0x3a020, claimant); invoke(1);
    reset();
    TrackingReader tracked;
    owned::Pending pending{};
    CHECK(owned::begin(tracked, {base, date, true}, instance, claimant, test_caller, pending) == owned::Decision::ready);
    original(instance, claimant, 0xa5);
    owned::Value value{};
    CHECK(owned::finish(tracked, pending, value));
    CHECK(!owned::finish(tracked, pending, value));
    CHECK(!tracked.opaque_read && tracked.bytes < 32768 && tracked.calls < 600 && tracked.max_size <= 128);
    TrackingReader manual;
    CHECK(owned::begin(manual, {base, date, true}, instance, claimant, base + 0xd8bb1e, pending) == owned::Decision::ignored);
    CHECK(manual.calls == 0);
    CHECK(owned::begin(manual, {0, date, true}, instance, claimant, owned::kExpiryReturnRva, pending) == owned::Decision::ignored);
    source::Reader reader;
    reset();
    std::memcpy(reinterpret_cast<void*>(base + owned::kRemovalRva), owned::kRemovalBytes.data(), owned::kRemovalBytes.size());
    std::memcpy(reinterpret_cast<void*>(base + owned::kNaturalCallerRva), owned::kNaturalCallerBytes.data(), owned::kNaturalCallerBytes.size());
    CHECK(owned::guards(reader, base));
    put(base + owned::kNaturalCallerRva + 100, static_cast<unsigned char>(0));
    CHECK(!owned::guards(reader, base));
    reset(); invoke(1);
    CHECK(source::claim_remove_observe(instance, claimant, 0xa5) == returned);
    CHECK(calls == 2 && source::size == 1 && source::total_dropped == 0);
    const char* path = std::getenv("CLAIM_EXPIRY_FIXTURE_LOG");
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
    std::printf("%u claim capture, forwarding and queue checks passed\n", checks);
}
