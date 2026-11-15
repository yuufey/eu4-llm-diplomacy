#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "../information-mission-completion.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

namespace owned = information::mission_completion;

struct MemoryReader final {
    bool read(uintptr_t address, void* output, size_t bytes) noexcept {
        SIZE_T copied = 0;
        return ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<void*>(address),
            output, bytes, &copied) != FALSE && copied == bytes;
    }
};

static unsigned checks = 0;
static unsigned failures = 0;
static unsigned scenarios = 0;

#define CHECK(condition, message) do { \
    ++checks; \
    if (!(condition)) { ++failures; std::fprintf(stderr, "FAIL: %s\n", message); } \
} while (0)

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

static void test_name_layouts_and_ascii_bounds(uintptr_t memory) {
    ++scenarios;
    MemoryReader reader;
    const uintptr_t inlined = memory + 0x100;
    const uintptr_t heap = memory + 0x200;
    const uintptr_t heap_text = memory + 0x300;
    const uintptr_t longest = memory + 0x600;
    const uintptr_t longest_text = memory + 0x700;

    put_string32(inlined, "mission", heap_text);
    owned::Name short_name{};
    CHECK(owned::name(reader, inlined, short_name)
            && std::string(short_name.text, short_name.length) == "mission",
        "String32 inline name decodes with its terminator and length");

    const std::string quoted = "claim \"A\\B\"";
    put_string32(heap, quoted, heap_text);
    owned::Name quoted_name{};
    CHECK(owned::name(reader, heap, quoted_name)
            && std::string(quoted_name.text, quoted_name.length) == quoted,
        "ASCII quotes and backslashes survive heap String32 decoding");

    std::string maximum(owned::kMaxName, 'x');
    maximum[254] = '"';
    maximum[255] = '\\';
    put_string32(longest, maximum, longest_text);
    owned::Name maximum_name{};
    CHECK(owned::name(reader, longest, maximum_name)
            && maximum_name.length == owned::kMaxName
            && std::memcmp(maximum_name.text, maximum.data(), maximum.size()) == 0,
        "the maximum 256-byte ASCII mission ID is preserved exactly");

    put_u64(longest + 16, owned::kMaxName + 1);
    owned::Name rejected{};
    CHECK(!owned::name(reader, longest, rejected),
        "String32 names above the 256-byte cap are rejected");
    CHECK(owned::range(memory, 0) && !owned::range(0xffff, 1)
            && !owned::range(UINT64_C(0x800000000000), 1),
        "native reads use the documented bounded address range");
}

static void test_completed_membership_and_cycle_bound(uintptr_t memory) {
    ++scenarios;
    MemoryReader reader;
    const uintptr_t country = memory;
    const uintptr_t sentinel = memory + 0xa000;
    const uintptr_t first = memory + 0xa020;
    const uintptr_t second = memory + 0xa040;
    const uintptr_t definition_a = memory + 0xa100;
    const uintptr_t definition_b = memory + 0xa180;
    const uintptr_t name_a = definition_a + 0x10;
    const uintptr_t name_b = definition_b + 0x10;
    const uintptr_t name_heap = memory + 0xa300;
    const uintptr_t sentinel_slot = country + 0x99a0;
    const owned::Name wanted = [] {
        owned::Name value{};
        constexpr char id[] = "mission_a";
        std::memcpy(value.text, id, sizeof(id));
        value.length = sizeof(id) - 1;
        return value;
    }();

    put_u64(sentinel_slot, sentinel);
    put_u64(sentinel, sentinel);
    bool found = true;
    CHECK(owned::membership(reader, country, wanted, found) && !found,
        "an empty sentinel list reports no completed target");

    put_u64(sentinel, first);
    put_u64(first, sentinel);
    put_u64(first + 16, definition_a);
    put_string32(name_a, "mission_a", name_heap);
    CHECK(owned::membership(reader, country, wanted, found) && found,
        "a completed linked-list target is found");

    put_string32(name_a, "other_mission", name_heap);
    CHECK(owned::membership(reader, country, wanted, found) && !found,
        "a well-formed completed list without the target returns false");

    put_u64(first, second);
    put_u64(second, first);
    put_u64(second + 16, definition_b);
    put_string32(name_b, "another_mission", name_heap);
    CHECK(!owned::membership(reader, country, wanted, found) && !found,
        "a non-sentinel cycle terminates at the completed-list traversal bound");
}

int main() {
    static_assert(sizeof(uintptr_t) == 8, "EU4 mission fixture requires x64");
    auto* memory = static_cast<unsigned char*>(VirtualAlloc(nullptr, 0xc000,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!memory) return 2;

    test_name_layouts_and_ascii_bounds(reinterpret_cast<uintptr_t>(memory));
    test_completed_membership_and_cycle_bound(reinterpret_cast<uintptr_t>(memory));

    CHECK(VirtualFree(memory, 0, MEM_RELEASE) != FALSE,
        "release the bounded owned-memory fixture");
    std::printf("information mission completion values: %s (%u checks, %u scenarios)\n",
        failures ? "FAIL" : "PASS", checks, scenarios);
    return failures ? 1 : 0;
}
