#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

#include "information-country-modifier-add.h"
#include "information-country-modifier-entry-plan.h"

using information::country_modifier::Added;
using information::country_modifier::Address;
using information::country_modifier::Context;
using information::country_modifier::Pending;

namespace {

constexpr std::size_t kReaderMemoryLimit = 50u * 1024u * 1024u;
constexpr Address kModule = 0x140000000ull;
constexpr Address kDatabase = 0x240000000ull;
constexpr Address kCountries = 0x250000000ull;
constexpr Address kCountry = 0x260000000ull;
constexpr Address kGame = 0x270000000ull;
constexpr Address kInstance = 0x280000000ull;
constexpr Address kDefinition = 0x290000000ull;
constexpr Address kNode = 0x2a0000000ull;
constexpr Address kKeyText = 0x2b0000000ull;
constexpr std::uint64_t kObserver = (std::uint64_t{7} << 32u) | 0x90123400u;
constexpr std::int32_t kDate = 56658312;
constexpr Address kCaller = kModule + information::country_modifier::kCreatorReturnRva;
constexpr Address kItemVtable = kModule + 0x1ce7f08u;
constexpr Address kDefinitionVtable = kModule + 0x1c42ae0u;
constexpr Address kWrongInstance = 0x2c0000000ull;
constexpr std::array<unsigned char, 5> kCreatorCall{{0xe8, 0xd8, 0xf5, 0xff, 0xff}};

void check(bool condition, const char* expression, int line) {
    if (condition) return;
    std::cerr << "FAIL line " << line << ": " << expression << '\n';
    std::exit(1);
}

#define CHECK(expression) check((expression), #expression, __LINE__)

struct Region final {
    Address begin = 0;
    std::vector<unsigned char> bytes;
};

class Reader final {
public:
    void add(Address begin, std::size_t size) {
        CHECK(size != 0);
        CHECK(stored_bytes_ + size < kReaderMemoryLimit);
        regions_.push_back(Region{begin, std::vector<unsigned char>(size, 0)});
        stored_bytes_ += size;
    }

    bool write(Address address, const void* source, std::size_t size) {
        if (source == nullptr || size == 0 || address > UINT64_MAX - size) return false;
        for (auto& region : regions_) {
            if (address < region.begin) continue;
            const Address offset = address - region.begin;
            if (offset <= region.bytes.size() && size <= region.bytes.size() - offset) {
                std::memcpy(region.bytes.data() + static_cast<std::size_t>(offset), source, size);
                return true;
            }
        }
        return false;
    }

    template<class Value>
    bool write_value(Address address, const Value& value) {
        return write(address, &value, sizeof(value));
    }

    bool read(Address address, unsigned char* destination, std::size_t size) noexcept {
        requested_bytes_ += size;
        ++read_calls_;
        if (!destination || size == 0 || address > UINT64_MAX - size) return false;
        if (fail_enabled_ && address <= fail_address_ && fail_address_ < address + size) {
            fail_enabled_ = false;
            return false;
        }
        for (const auto& region : regions_) {
            if (address < region.begin) continue;
            const Address offset = address - region.begin;
            if (offset <= region.bytes.size() && size <= region.bytes.size() - offset) {
                std::memcpy(destination, region.bytes.data() + static_cast<std::size_t>(offset), size);
                return true;
            }
        }
        return false;
    }

    void fail_once_at(Address address) noexcept {
        fail_address_ = address;
        fail_enabled_ = true;
    }

    std::size_t stored_bytes() const noexcept { return stored_bytes_; }
    std::size_t requested_bytes() const noexcept { return requested_bytes_; }
    std::size_t read_calls() const noexcept { return read_calls_; }

private:
    std::vector<Region> regions_;
    std::size_t stored_bytes_ = 0;
    std::size_t requested_bytes_ = 0;
    std::size_t read_calls_ = 0;
    Address fail_address_ = 0;
    bool fail_enabled_ = false;
};

struct Fixture final {
    Reader reader;
    Context context{};

    Fixture() {
        constexpr Address slot = (kObserver >> 32u) & 0xffffu;
        reader.add(kModule + 0x233d8b0u, sizeof(Address));
        reader.add(kDatabase + 0x118u, sizeof(Address));
        reader.add(kCountries + slot * sizeof(Address), sizeof(Address));
        reader.add(kCountry, 0x210u);
        reader.add(kModule + 0x233fe58u, sizeof(Address));
        reader.add(kGame + 0x1dd0u, sizeof(kDate));
        reader.add(kCaller - kCreatorCall.size(), kCreatorCall.size());
        reader.add(kInstance, 0x50u);
        reader.add(kDefinition, 0x178u);
        reader.add(kNode, 24u);
        reader.add(kKeyText, 64u);

        context = Context{kModule, kCountry, kObserver, kDate, true};
        CHECK(reader.write_value(kModule + 0x233d8b0u, kDatabase));
        CHECK(reader.write_value(kDatabase + 0x118u, kCountries));
        CHECK(reader.write_value(kCountries + slot * sizeof(Address), kCountry));
        CHECK(reader.write_value(kCountry + 0x20u, kObserver));
        CHECK(reader.write_value(kCountry + 0x200u, std::uint32_t{0}));
        const std::array<Address, 2> empty_ends{{0, 0}};
        CHECK(reader.write(kCountry + 0x1f0u, empty_ends.data(), sizeof(empty_ends)));
        CHECK(reader.write_value(kModule + 0x233fe58u, kGame));
        CHECK(reader.write_value(kGame + 0x1dd0u, kDate));
        CHECK(reader.write(kCaller - kCreatorCall.size(), kCreatorCall.data(), kCreatorCall.size()));

        CHECK(reader.write_value(kInstance, kItemVtable));
        CHECK(reader.write_value(kInstance + 0x30u, kDefinition));
        CHECK(reader.write_value(kInstance + 0x40u, std::int32_t{56658000}));
        CHECK(reader.write_value(kInstance + 0x44u, std::int32_t{56662000}));
        const std::array<unsigned char, 4> flags{{0, 1, 0, 1}};
        CHECK(reader.write(kInstance + 0x48u, flags.data(), flags.size()));
        CHECK(reader.write_value(kDefinition, kDefinitionVtable));
        set_inline_key("temp_example");
        CHECK(reader.stored_bytes() < kReaderMemoryLimit);
    }

    void set_inline_key(const std::string& key) {
        CHECK(!key.empty() && key.size() <= 15u);
        std::array<unsigned char, 32> sso{};
        std::memcpy(sso.data(), key.c_str(), key.size() + 1u);
        const std::uint64_t length = key.size();
        const std::uint64_t capacity = 15u;
        std::memcpy(sso.data() + 0x10u, &length, sizeof(length));
        std::memcpy(sso.data() + 0x18u, &capacity, sizeof(capacity));
        CHECK(reader.write(kDefinition + 0x158u, sso.data(), sso.size()));
    }

    void set_external_key(const std::string& key, std::uint64_t capacity = 31u) {
        CHECK(!key.empty() && key.size() < information::country_modifier::kKeyCapacity);
        CHECK(capacity >= 16u && key.size() <= capacity);
        CHECK(reader.write(kKeyText, key.c_str(), key.size() + 1u));
        std::array<unsigned char, 32> sso{};
        const Address pointer = kKeyText;
        const std::uint64_t length = key.size();
        std::memcpy(sso.data(), &pointer, sizeof(pointer));
        std::memcpy(sso.data() + 0x10u, &length, sizeof(length));
        std::memcpy(sso.data() + 0x18u, &capacity, sizeof(capacity));
        CHECK(reader.write(kDefinition + 0x158u, sso.data(), sso.size()));
    }

    void insert(Address item = kInstance, Address next = 0) {
        CHECK(reader.write_value(kNode, item));
        CHECK(reader.write_value(kNode + 0x10u, next));
        const std::array<Address, 2> ends{{kNode, kNode}};
        CHECK(reader.write(kCountry + 0x1f0u, ends.data(), sizeof(ends)));
        CHECK(reader.write_value(kCountry + 0x200u, std::uint32_t{1}));
    }

    void poison_external_key(std::size_t size) {
        std::array<unsigned char, 64> bytes{};
        bytes.fill(static_cast<unsigned char>('x'));
        CHECK(size <= bytes.size());
        CHECK(reader.write(kKeyText, bytes.data(), size));
    }

    void check_bounded() const {
        CHECK(reader.stored_bytes() < kReaderMemoryLimit);
        CHECK(reader.requested_bytes() < kReaderMemoryLimit);
    }
};

void test_begin_insert_finish_and_single_consumption() {
    Fixture f;
    Pending pending{};
    Added output{};
    CHECK(information::country_modifier::begin(f.reader, f.context, kInstance,
        kCaller, pending));
    CHECK(pending.ready);
    CHECK(pending.count_before == 0u);
    f.insert();
    CHECK(information::country_modifier::finish(f.reader, pending, output));
    CHECK(!pending.ready);
    CHECK(output.country == kObserver);
    CHECK(output.date == kDate);
    CHECK(output.start_date == 56658000);
    CHECK(output.end_date == 56662000);
    CHECK((output.flags == std::array<unsigned char, 4>{{0, 1, 0, 1}}));
    CHECK(std::string(output.key.data()) == "temp_example");
    const std::size_t reads_after_finish = f.reader.read_calls();
    Added second{};
    CHECK(!information::country_modifier::finish(f.reader, pending, second));
    CHECK(f.reader.read_calls() == reads_after_finish);
    f.check_bounded();
}

void test_wrong_caller_and_load_do_not_sample() {
    Fixture f;
    Pending pending{};
    pending.ready = true;
    CHECK(!information::country_modifier::begin(f.reader, f.context, kInstance,
        kModule + 0x2d2ff0u, pending));
    CHECK(!pending.ready);
    CHECK(f.reader.read_calls() == 0u);
    f.check_bounded();
}

void test_context_country_session_date_and_frame_gates() {
    {
        Fixture f;
        Context wrong_country = f.context;
        wrong_country.country += 0x1000u;
        Pending pending{};
        CHECK(!information::country_modifier::begin(f.reader, wrong_country,
            kInstance, kCaller, pending));
        f.check_bounded();
    }
    {
        Fixture f;
        Context unbound = f.context;
        unbound.bound_frame_thread = false;
        Pending pending{};
        CHECK(!information::country_modifier::begin(f.reader, unbound,
            kInstance, kCaller, pending));
        CHECK(f.reader.read_calls() == 0u);
        f.check_bounded();
    }
    {
        Fixture f;
        Pending pending{};
        Added output{};
        CHECK(information::country_modifier::begin(f.reader, f.context,
            kInstance, kCaller, pending));
        f.insert();
        pending.context.bound_frame_thread = false;
        CHECK(!information::country_modifier::finish(f.reader, pending, output));
        CHECK(!pending.ready);
        f.check_bounded();
    }
    {
        Fixture f;
        Pending pending{};
        Added output{};
        CHECK(information::country_modifier::begin(f.reader, f.context,
            kInstance, kCaller, pending));
        f.insert();
        CHECK(f.reader.write_value(kGame + 0x1dd0u, std::int32_t{kDate + 1}));
        CHECK(!information::country_modifier::finish(f.reader, pending, output));
        f.check_bounded();
    }
    {
        Fixture f;
        Pending pending{};
        Added output{};
        CHECK(information::country_modifier::begin(f.reader, f.context,
            kInstance, kCaller, pending));
        f.insert();
        CHECK(f.reader.write_value(kCountry + 0x20u, kObserver + 1u));
        CHECK(!information::country_modifier::finish(f.reader, pending, output));
        f.check_bounded();
    }
    {
        Fixture f;
        Pending pending{};
        Added output{};
        CHECK(information::country_modifier::begin(f.reader, f.context,
            kInstance, kCaller, pending));
        f.insert();
        constexpr Address slot = (kObserver >> 32u) & 0xffffu;
        CHECK(f.reader.write_value(kCountries + slot * sizeof(Address), kWrongInstance));
        CHECK(!information::country_modifier::finish(f.reader, pending, output));
        f.check_bounded();
    }
}

void test_invalid_vtable_sso_and_partial_reads_fail_closed() {
    {
        Fixture f;
        CHECK(f.reader.write_value(kInstance, kItemVtable + 8u));
        Pending pending{};
        CHECK(!information::country_modifier::begin(f.reader, f.context,
            kInstance, kCaller, pending));
        CHECK(!pending.ready);
        f.check_bounded();
    }
    {
        Fixture f;
        const std::uint64_t invalid_capacity = 14u;
        CHECK(f.reader.write_value(kDefinition + 0x170u, invalid_capacity));
        Pending pending{};
        CHECK(!information::country_modifier::begin(f.reader, f.context,
            kInstance, kCaller, pending));
        CHECK(!pending.ready);
        f.check_bounded();
    }
    {
        Fixture f;
        f.reader.fail_once_at(kDefinition + 0x158u);
        Pending pending{};
        CHECK(!information::country_modifier::begin(f.reader, f.context,
            kInstance, kCaller, pending));
        CHECK(!pending.ready);
        f.check_bounded();
    }
}

void test_finish_requires_added_count_and_exact_single_membership() {
    {
        Fixture f;
        Pending pending{};
        Added output{};
        CHECK(information::country_modifier::begin(f.reader, f.context,
            kInstance, kCaller, pending));
        CHECK(!information::country_modifier::finish(f.reader, pending, output));
        CHECK(!pending.ready);
        f.check_bounded();
    }
    {
        Fixture f;
        Pending pending{};
        Added output{};
        CHECK(information::country_modifier::begin(f.reader, f.context,
            kInstance, kCaller, pending));
        f.insert(kWrongInstance);
        CHECK(!information::country_modifier::finish(f.reader, pending, output));
        f.check_bounded();
    }
    {
        Fixture f;
        Pending pending{};
        Added output{};
        CHECK(information::country_modifier::begin(f.reader, f.context,
            kInstance, kCaller, pending));
        f.insert(kInstance, kNode);
        CHECK(!information::country_modifier::finish(f.reader, pending, output));
        f.check_bounded();
    }
}

void test_instance_count_limit() {
    {
        Fixture f;
        CHECK(f.reader.write_value(kCountry + 0x200u,
            information::country_modifier::kMaxInstances));
        Pending pending{};
        CHECK(!information::country_modifier::begin(f.reader, f.context,
            kInstance, kCaller, pending));
        f.check_bounded();
    }
    {
        Fixture f;
        CHECK(f.reader.write_value(kCountry + 0x200u,
            information::country_modifier::kMaxInstances + 1u));
        Pending pending{};
        CHECK(!information::country_modifier::begin(f.reader, f.context,
            kInstance, kCaller, pending));
        f.check_bounded();
    }
}

void test_external_key_is_copied_into_owned_payload() {
    Fixture f;
    const std::string key = "external_temporary_modifier_long_name";
    f.set_external_key(key, 63u);
    Pending pending{};
    CHECK(information::country_modifier::begin(f.reader, f.context,
        kInstance, kCaller, pending));
    CHECK(std::string(pending.value.key.data()) == key);
    f.poison_external_key(key.size() + 1u);
    CHECK(std::string(pending.value.key.data()) == key);

    CHECK(f.reader.write(kKeyText, key.c_str(), key.size() + 1u));
    f.insert();
    Added output{};
    CHECK(information::country_modifier::finish(f.reader, pending, output));
    f.poison_external_key(key.size() + 1u);
    CHECK(std::string(output.key.data()) == key);
    f.check_bounded();
}

void test_entry_plan_pins_prefix_unwind_and_jump_bytes() {
    namespace entry = information::country_modifier::entry;
    constexpr std::array<unsigned char, entry::kPatchBytes> expected_prefix{{
        0x40,0x56,0x41,0x56,0x48,0x83,0xec,0x28,
        0x48,0x8b,0x42,0x30,0x48,0x8b,0xf2,
    }};
    constexpr std::array<unsigned char, 12> expected_unwind{{
        0x01,0x08,0x03,0x00,0x08,0x42,0x04,0xe0,0x02,0x60,0x00,0x00,
    }};
    static_assert(entry::kEntryRva == 0x3283f0u);
    static_assert(entry::kSourceEndRva == 0x3283ffu);
    static_assert(entry::kUnwindRva == 0x1df67a8u);
    static_assert(entry::kPatchBytes == 15u);
    CHECK(entry::kPrefix == expected_prefix);
    CHECK(entry::kUnwind == expected_unwind);

    const Address image_base = 0x140000000ull;
    const Address original_entry = image_base + entry::kEntryRva;
    const Address hook = 0x7fff12345678ull;
    auto prefix = expected_prefix;
    auto unwind = expected_unwind;
    entry::Plan plan{};
    CHECK(entry::prepare(prefix, unwind, original_entry, hook, plan));
    CHECK(prefix == expected_prefix);
    CHECK(unwind == expected_unwind);
    CHECK(std::memcmp(plan.image.data(), expected_prefix.data(), expected_prefix.size()) == 0);
    CHECK(std::memcmp(plan.image.data() + entry::kUnwindOffset,
        expected_unwind.data(), expected_unwind.size()) == 0);
    CHECK(plan.runtime.begin == 0u);
    CHECK(plan.runtime.end == entry::kPatchBytes
        + information::battle::message_entry::kHomeSlotJumpBytes);
    CHECK(plan.runtime.unwind == entry::kUnwindOffset);

    constexpr std::array<unsigned char, 29> expected_home_jump{{
        0xc7,0x84,0x24,0x40,0x00,0x00,0x00,0xff,0x83,0x32,0x40,
        0xc7,0x84,0x24,0x44,0x00,0x00,0x00,0x01,0x00,0x00,0x00,
        0xff,0xa4,0x24,0x40,0x00,0x00,0x00,
    }};
    CHECK(std::memcmp(plan.image.data() + entry::kPatchBytes,
        expected_home_jump.data(), expected_home_jump.size()) == 0);

    std::array<unsigned char, entry::kPatchBytes> expected_patch{};
    expected_patch.fill(0x90);
    expected_patch[0] = 0xff;
    expected_patch[1] = 0x25;
    expected_patch[2] = 0;
    expected_patch[3] = 0;
    expected_patch[4] = 0;
    expected_patch[5] = 0;
    for (unsigned index = 0; index < 8; ++index)
        expected_patch[6 + index] = static_cast<unsigned char>(hook >> (index * 8u));
    CHECK(plan.patch == expected_patch);

    entry::Plan unchanged{};
    unchanged.image.fill(0xa5);
    unchanged.patch.fill(0x5a);
    unchanged.runtime = {0x1234u, 0x5678u, 0x9abcu};
    const entry::Plan before = unchanged;
    const auto unchanged_output = [&]() {
        return unchanged.image == before.image && unchanged.patch == before.patch
            && unchanged.runtime.begin == before.runtime.begin
            && unchanged.runtime.end == before.runtime.end
            && unchanged.runtime.unwind == before.runtime.unwind;
    };
    auto bad_prefix = expected_prefix;
    bad_prefix[0] ^= 1u;
    CHECK(!entry::prepare(bad_prefix, unwind, original_entry, hook, unchanged));
    CHECK(unchanged_output());
    auto bad_unwind = expected_unwind;
    bad_unwind[0] ^= 1u;
    CHECK(!entry::prepare(prefix, bad_unwind, original_entry, hook, unchanged));
    CHECK(unchanged_output());
}

} // namespace

int main() {
    test_begin_insert_finish_and_single_consumption();
    test_wrong_caller_and_load_do_not_sample();
    test_context_country_session_date_and_frame_gates();
    test_invalid_vtable_sso_and_partial_reads_fail_closed();
    test_finish_requires_added_count_and_exact_single_membership();
    test_instance_count_limit();
    test_external_key_is_copied_into_owned_payload();
    test_entry_plan_pins_prefix_unwind_and_jump_bytes();
    std::cout << "country modifier add regression: PASS\n";
    return 0;
}
