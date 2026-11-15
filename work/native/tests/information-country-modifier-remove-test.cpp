#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

#include "../information-country-modifier-remove.h"
#include "../information-country-modifier-remove-entry-plan.h"

using information::country_modifier::Added;
using information::country_modifier::Address;
using information::country_modifier::Context;
using information::country_modifier::removal::Pending;

namespace {

constexpr std::size_t kReaderMemoryLimit = 8u * 1024u * 1024u;
constexpr Address kModule = 0x140000000ull;
constexpr Address kDatabase = 0x240000000ull;
constexpr Address kCountries = 0x250000000ull;
constexpr Address kCountry = 0x260000000ull;
constexpr Address kGame = 0x270000000ull;
constexpr Address kInstance = 0x280000000ull;
constexpr Address kDefinition = 0x290000000ull;
constexpr Address kNodes = 0x2a0000000ull;
constexpr Address kWrongInstance = 0x2c0000000ull;
constexpr Address kObserver = (std::uint64_t{7} << 32u) | 0x90123400u;
constexpr std::int32_t kDate = 56658312;
constexpr std::size_t kNodeStride = 32;
constexpr std::size_t kNodeBytes = 25;
constexpr auto kPredicateCaller = kModule + information::country_modifier::removal::kPredicateReturnRva;
constexpr auto kReligionCaller = kModule + information::country_modifier::removal::kReligionReturnRva;
constexpr Address kItemVtable = kModule + 0x1ce7f08u;
constexpr Address kDefinitionVtable = kModule + 0x1c42ae0u;
constexpr std::array<unsigned char, 5> kPredicateCall{{0xe8, 0xa0, 0xfc, 0xff, 0xff}};
constexpr std::array<unsigned char, 5> kReligionCall{{0xe8, 0x15, 0xa5, 0x02, 0x00}};

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
        if (!source || size == 0 || address > UINT64_MAX - size) return false;
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
        ++read_calls_;
        requested_bytes_ += size;
        if (size > max_read_size_) max_read_size_ = size;
        if (!destination || size == 0 || address > UINT64_MAX - size) return false;
        if (size > information::country_modifier::kMaxSingleRead) {
            ++oversized_reads_;
            return false;
        }
        if (fail_enabled_ && address < fail_address_ + fail_size_
            && fail_address_ < address + size) {
            fail_enabled_ = false;
            return false;
        }
        for (const auto& banned : banned_) {
            if (address < banned.second && banned.first < address + size) {
                ++banned_reads_;
                return false;
            }
        }
        for (auto& region : regions_) {
            if (address < region.begin) continue;
            const Address offset = address - region.begin;
            if (offset <= region.bytes.size() && size <= region.bytes.size() - offset) {
                std::memcpy(destination, region.bytes.data() + static_cast<std::size_t>(offset), size);
                if (mutation_pending_ && address == mutation_trigger_) {
                    mutation_pending_ = false;
                    CHECK(write(mutation_address_, mutation_bytes_.data(), mutation_size_));
                }
                return true;
            }
        }
        return false;
    }

    void fail_once_at(Address address, std::size_t size = 1) noexcept {
        fail_address_ = address;
        fail_size_ = size;
        fail_enabled_ = true;
    }

    void ban_range(Address begin, std::size_t size) {
        CHECK(size != 0 && begin <= UINT64_MAX - size);
        banned_.push_back({begin, begin + size});
    }

    void mutate_after_read(Address trigger, Address address, const void* value, std::size_t size) {
        CHECK(value && size != 0 && size <= mutation_bytes_.size());
        mutation_trigger_ = trigger;
        mutation_address_ = address;
        mutation_size_ = size;
        std::memcpy(mutation_bytes_.data(), value, size);
        mutation_pending_ = true;
    }

    std::size_t stored_bytes() const noexcept { return stored_bytes_; }
    std::size_t requested_bytes() const noexcept { return requested_bytes_; }
    std::size_t read_calls() const noexcept { return read_calls_; }
    std::size_t max_read_size() const noexcept { return max_read_size_; }
    std::size_t oversized_reads() const noexcept { return oversized_reads_; }
    std::size_t banned_reads() const noexcept { return banned_reads_; }

private:
    std::vector<Region> regions_;
    std::vector<std::pair<Address, Address>> banned_;
    std::size_t stored_bytes_ = 0;
    std::size_t requested_bytes_ = 0;
    std::size_t read_calls_ = 0;
    std::size_t max_read_size_ = 0;
    std::size_t oversized_reads_ = 0;
    std::size_t banned_reads_ = 0;
    Address fail_address_ = 0;
    std::size_t fail_size_ = 0;
    bool fail_enabled_ = false;
    Address mutation_trigger_ = 0;
    Address mutation_address_ = 0;
    std::array<unsigned char, information::country_modifier::kMaxSingleRead> mutation_bytes_{};
    std::size_t mutation_size_ = 0;
    bool mutation_pending_ = false;
};

struct Fixture final {
    Reader reader;
    Context context{};
    std::vector<Address> list_items;

    Fixture() {
        constexpr Address slot = (kObserver >> 32u) & 0xffffu;
        reader.add(kModule + 0x233d8b0u, sizeof(Address));
        reader.add(kDatabase + 0x118u, sizeof(Address));
        reader.add(kCountries + slot * sizeof(Address), sizeof(Address));
        reader.add(kCountry, 0x210u);
        reader.add(kModule + 0x233fe58u, sizeof(Address));
        reader.add(kGame + 0x1dd0u, sizeof(kDate));
        reader.add(kModule + information::country_modifier::removal::kPredicateReturnRva - 5,
            kPredicateCall.size());
        reader.add(kModule + information::country_modifier::removal::kReligionReturnRva - 5,
            kReligionCall.size());
        reader.add(kInstance, 0x50u);
        reader.add(kDefinition, 0x178u);
        reader.add(kNodes, information::country_modifier::kMaxInstances * kNodeStride);

        context = Context{kModule, kCountry, kObserver, kDate, true};
        CHECK(reader.write_value(kModule + 0x233d8b0u, kDatabase));
        CHECK(reader.write_value(kDatabase + 0x118u, kCountries));
        CHECK(reader.write_value(kCountries + slot * sizeof(Address), kCountry));
        CHECK(reader.write_value(kCountry + 0x20u, kObserver));
        CHECK(reader.write_value(kCountry + 0x200u, std::uint32_t{0}));
        CHECK(reader.write_value(kCountry + 0x204u, static_cast<unsigned char>(0)));
        CHECK(reader.write_value(kModule + 0x233fe58u, kGame));
        CHECK(reader.write_value(kGame + 0x1dd0u, kDate));
        CHECK(reader.write(kModule + information::country_modifier::removal::kPredicateReturnRva - 5,
            kPredicateCall.data(), kPredicateCall.size()));
        CHECK(reader.write(kModule + information::country_modifier::removal::kReligionReturnRva - 5,
            kReligionCall.data(), kReligionCall.size()));

        CHECK(reader.write_value(kInstance, kItemVtable));
        CHECK(reader.write_value(kInstance + 0x30u, kDefinition));
        CHECK(reader.write_value(kInstance + 0x40u, std::int32_t{56658000}));
        CHECK(reader.write_value(kInstance + 0x44u, std::int32_t{56662000}));
        const std::array<unsigned char, 4> flags{{1, 0, 1, 0}};
        CHECK(reader.write(kInstance + 0x48u, flags.data(), flags.size()));
        CHECK(reader.write_value(kDefinition, kDefinitionVtable));
        set_inline_key("temp_remove");
        set_list({kInstance});
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

    Address node_at(std::size_t index) const noexcept {
        return kNodes + index * kNodeStride;
    }

    void set_list(const std::vector<Address>& items, unsigned char deferred = 0) {
        CHECK(items.size() <= information::country_modifier::kMaxInstances);
        list_items = items;
        for (std::size_t index = 0; index < items.size(); ++index) {
            std::array<unsigned char, kNodeBytes> bytes{};
            const Address previous = index == 0 ? 0 : node_at(index - 1);
            const Address next = index + 1 == items.size() ? 0 : node_at(index + 1);
            std::memcpy(bytes.data(), &items[index], sizeof(Address));
            std::memcpy(bytes.data() + 8, &previous, sizeof(Address));
            std::memcpy(bytes.data() + 16, &next, sizeof(Address));
            bytes[24] = 0;
            CHECK(reader.write(node_at(index), bytes.data(), bytes.size()));
        }
        const std::array<Address, 2> ends{{items.empty() ? 0 : node_at(0),
            items.empty() ? 0 : node_at(items.size() - 1)}};
        CHECK(reader.write(kCountry + 0x1f0u, ends.data(), sizeof(ends)));
        CHECK(reader.write_value(kCountry + 0x200u, static_cast<std::uint32_t>(items.size())));
        CHECK(reader.write_value(kCountry + 0x204u, deferred));
    }

    void unlink_first() {
        CHECK(!list_items.empty() && list_items[0] == kInstance);
        std::vector<Address> remaining(list_items.begin() + 1, list_items.end());
        set_list(remaining, 0);
    }

    void mark_first_deferred() {
        CHECK(!list_items.empty() && list_items[0] == kInstance);
        CHECK(reader.write_value(node_at(0) + 24u, static_cast<unsigned char>(1)));
        CHECK(reader.write_value(kCountry + 0x204u, static_cast<unsigned char>(1)));
    }

    void mark_destroyed() {
        reader.ban_range(kInstance, 0x50u);
        reader.ban_range(kDefinition, 0x178u);
    }

    void check_bounded(std::size_t allowed_banned_reads = 0) const {
        CHECK(reader.stored_bytes() < kReaderMemoryLimit);
        CHECK(reader.requested_bytes() < kReaderMemoryLimit);
        CHECK(reader.read_calls() < 4096u);
        CHECK(reader.max_read_size() <= information::country_modifier::kMaxSingleRead);
        CHECK(reader.oversized_reads() == 0u);
        CHECK(reader.banned_reads() == allowed_banned_reads);
    }
};

bool begin(Fixture& fixture, Pending& pending, Address caller = kPredicateCaller) {
    return information::country_modifier::removal::begin(
        fixture.reader, fixture.context, kInstance, caller, pending);
}

void check_owned_value(const Added& value) {
    CHECK(value.country == kObserver);
    CHECK(value.date == kDate);
    CHECK(value.start_date == 56658000);
    CHECK(value.end_date == 56662000);
    CHECK((value.flags == std::array<unsigned char, 4>{{1, 0, 1, 0}}));
    CHECK(std::string(value.key.data()) == "temp_remove");
}

void test_unlinked_and_deferred_success_copy_only_owned_values() {
    for (const Address caller : {kPredicateCaller, kReligionCaller}) {
        Fixture f;
        Pending pending{};
        CHECK(begin(f, pending, caller));
        CHECK(pending.ready && pending.count_before == 1u && pending.deferred == 0);
        f.unlink_first();
        f.mark_destroyed();
        Added output{};
        CHECK(information::country_modifier::removal::finish(f.reader, pending, output));
        CHECK(!pending.ready);
        check_owned_value(output);
        CHECK(f.reader.banned_reads() == 0u);
        const auto reads = f.reader.read_calls();
        Added second{};
        CHECK(!information::country_modifier::removal::finish(f.reader, pending, second));
        CHECK(f.reader.read_calls() == reads);
        f.check_bounded();
    }

    Fixture f;
    f.set_list({kInstance}, 1);
    Pending pending{};
    CHECK(begin(f, pending));
    CHECK(pending.ready && pending.deferred == 1);
    f.mark_first_deferred();
    f.mark_destroyed();
    Added output{};
    CHECK(information::country_modifier::removal::finish(f.reader, pending, output));
    check_owned_value(output);
    CHECK(f.reader.banned_reads() == 0u);
    f.check_bounded();
}

void test_rejects_noop_and_wrong_count_after_destroy_without_dereference() {
    {
        Fixture f;
        Pending pending{};
        CHECK(begin(f, pending));
        f.mark_destroyed();
        Added output{};
        CHECK(!information::country_modifier::removal::finish(f.reader, pending, output));
        CHECK(!pending.ready && f.reader.banned_reads() == 0u);
        f.check_bounded();
    }
    {
        Fixture f;
        Pending pending{};
        CHECK(begin(f, pending));
        f.unlink_first();
        CHECK(f.reader.write_value(kCountry + 0x200u, std::uint32_t{1}));
        f.mark_destroyed();
        Added output{};
        CHECK(!information::country_modifier::removal::finish(f.reader, pending, output));
        CHECK(f.reader.banned_reads() == 0u);
        f.check_bounded();
    }
}

void test_rejects_bad_links_duplicates_and_marks() {
    {
        Fixture f;
        f.set_list({kInstance, kWrongInstance});
        Pending pending{};
        CHECK(begin(f, pending));
        f.unlink_first();
        const Address broken_previous = kNodes;
        CHECK(f.reader.write_value(f.node_at(0) + 8u, broken_previous));
        f.mark_destroyed();
        Added output{};
        CHECK(!information::country_modifier::removal::finish(f.reader, pending, output));
        CHECK(f.reader.banned_reads() == 0u);
        f.check_bounded();
    }
    {
        Fixture f;
        f.set_list({kInstance, kWrongInstance});
        Pending pending{};
        CHECK(begin(f, pending));
        f.unlink_first();
        const std::array<Address, 2> bad_ends{{f.node_at(0), kNodes + 2 * kNodeStride}};
        CHECK(f.reader.write(kCountry + 0x1f0u, bad_ends.data(), sizeof(bad_ends)));
        f.mark_destroyed();
        Added output{};
        CHECK(!information::country_modifier::removal::finish(f.reader, pending, output));
        CHECK(f.reader.banned_reads() == 0u);
        f.check_bounded();
    }
    {
        Fixture f;
        f.set_list({kInstance, kWrongInstance});
        Pending pending{};
        CHECK(begin(f, pending));
        f.unlink_first();
        CHECK(f.reader.write_value(f.node_at(0) + 16u, f.node_at(0)));
        f.mark_destroyed();
        Added output{};
        CHECK(!information::country_modifier::removal::finish(f.reader, pending, output));
        CHECK(f.reader.banned_reads() == 0u);
        f.check_bounded();
    }
    {
        Fixture f;
        f.set_list({kInstance, kInstance});
        Pending pending{};
        CHECK(!begin(f, pending));
        CHECK(!pending.ready);
        f.check_bounded();
    }
    {
        Fixture f;
        CHECK(f.reader.write_value(f.node_at(0) + 24u, static_cast<unsigned char>(2)));
        Pending pending{};
        CHECK(!begin(f, pending));
        f.check_bounded();
    }
    {
        Fixture f;
        f.set_list({kInstance}, 1);
        Pending pending{};
        CHECK(begin(f, pending));
        CHECK(f.reader.write_value(f.node_at(0) + 24u, static_cast<unsigned char>(2)));
        f.mark_destroyed();
        Added output{};
        CHECK(!information::country_modifier::removal::finish(f.reader, pending, output));
        CHECK(f.reader.banned_reads() == 0u);
        f.check_bounded();
    }
    {
        Fixture f;
        f.set_list({kInstance, kWrongInstance});
        Pending pending{};
        CHECK(begin(f, pending));
        f.unlink_first();
        f.mark_destroyed();
        f.reader.fail_once_at(f.node_at(0), kNodeBytes);
        Added output{};
        CHECK(!information::country_modifier::removal::finish(f.reader, pending, output));
        CHECK(f.reader.banned_reads() == 0u);
        f.check_bounded();
    }
}

void test_frame_caller_copy_and_dead_object_gates() {
    {
        Fixture f;
        Pending pending{};
        pending.ready = true;
        CHECK(!begin(f, pending, kModule + 0x2d2ff0u));
        CHECK(!pending.ready && f.reader.read_calls() == 0u);
        f.check_bounded();
    }
    {
        Fixture f;
        f.context.bound_frame_thread = false;
        Pending pending{};
        CHECK(!begin(f, pending));
        CHECK(f.reader.read_calls() == 0u);
        f.check_bounded();
    }
    {
        Fixture f;
        const std::array<unsigned char, 5> wrong{{0xe8, 0, 0, 0, 0}};
        CHECK(f.reader.write(kPredicateCaller - 5, wrong.data(), wrong.size()));
        Pending pending{};
        CHECK(!begin(f, pending));
        CHECK(!pending.ready);
        f.check_bounded();
    }
    {
        Fixture f;
        f.reader.fail_once_at(kPredicateCaller - 5, 5);
        Pending pending{};
        CHECK(!begin(f, pending));
        CHECK(!pending.ready);
        f.check_bounded();
    }
    {
        Fixture f;
        f.reader.ban_range(kInstance, 0x50u);
        Pending pending{};
        CHECK(!begin(f, pending));
        CHECK(f.reader.banned_reads() == 1u);
        f.check_bounded(1u);
    }
    {
        Fixture f;
        f.reader.ban_range(kDefinition, 0x178u);
        Pending pending{};
        CHECK(!begin(f, pending));
        CHECK(f.reader.banned_reads() == 1u);
        f.check_bounded(1u);
    }
}

void test_double_pass_and_post_delete_identity_changes_fail_closed() {
    {
        Fixture f;
        const std::int32_t changed_start = 56658001;
        f.reader.mutate_after_read(kInstance, kInstance + 0x40u,
            &changed_start, sizeof(changed_start));
        Pending pending{};
        CHECK(!begin(f, pending));
        CHECK(!pending.ready);
        f.check_bounded();
    }
    {
        Fixture f;
        const std::uint32_t changed_count = 2;
        f.reader.mutate_after_read(kCountry + 0x200u, kCountry + 0x200u,
            &changed_count, sizeof(changed_count));
        Pending pending{};
        CHECK(!begin(f, pending));
        CHECK(!pending.ready);
        f.check_bounded();
    }
    {
        Fixture f;
        Pending pending{};
        CHECK(begin(f, pending));
        f.unlink_first();
        f.mark_destroyed();
        CHECK(f.reader.write_value(kGame + 0x1dd0u, std::int32_t{kDate + 1}));
        Added output{};
        CHECK(!information::country_modifier::removal::finish(f.reader, pending, output));
        CHECK(f.reader.banned_reads() == 0u);
        f.check_bounded();
    }
    {
        Fixture f;
        Pending pending{};
        CHECK(begin(f, pending));
        f.unlink_first();
        f.mark_destroyed();
        CHECK(f.reader.write_value(kCountry + 0x20u, kObserver + 1u));
        Added output{};
        CHECK(!information::country_modifier::removal::finish(f.reader, pending, output));
        CHECK(f.reader.banned_reads() == 0u);
        f.check_bounded();
    }
    {
        Fixture f;
        Pending pending{};
        CHECK(begin(f, pending));
        f.unlink_first();
        f.mark_destroyed();
        pending.context.bound_frame_thread = false;
        const auto reads = f.reader.read_calls();
        Added output{};
        CHECK(!information::country_modifier::removal::finish(f.reader, pending, output));
        CHECK(f.reader.read_calls() == reads && f.reader.banned_reads() == 0u);
        f.check_bounded();
    }
    {
        Fixture f;
        Pending pending{};
        CHECK(begin(f, pending));
        f.unlink_first();
        f.mark_destroyed();
        f.reader.fail_once_at(kCountry + 0x1f0u, sizeof(Address) * 2u);
        Added output{};
        CHECK(!information::country_modifier::removal::finish(f.reader, pending, output));
        CHECK(f.reader.banned_reads() == 0u);
        f.check_bounded();
    }
}

void test_instance_limit_is_bounded_and_over_limit_rejected() {
    {
        Fixture f;
        std::vector<Address> items(information::country_modifier::kMaxInstances, kWrongInstance);
        items[0] = kInstance;
        f.set_list(items);
        Pending pending{};
        CHECK(begin(f, pending));
        CHECK(pending.count_before == information::country_modifier::kMaxInstances);
        f.unlink_first();
        f.mark_destroyed();
        Added output{};
        CHECK(information::country_modifier::removal::finish(f.reader, pending, output));
        check_owned_value(output);
        CHECK(f.reader.banned_reads() == 0u);
        f.check_bounded();
    }
    {
        Fixture f;
        CHECK(f.reader.write_value(kCountry + 0x200u,
            information::country_modifier::kMaxInstances + 1u));
        Pending pending{};
        CHECK(!begin(f, pending));
        CHECK(!pending.ready);
        f.check_bounded();
    }
}

void test_removal_entry_plan_pins_bytes_and_continuation_slot() {
    namespace entry = information::country_modifier::removal_entry;
    constexpr std::array<unsigned char, entry::kPatchBytes> expected_prefix{{
        0x48,0x89,0x5c,0x24,0x08,0x57,0x48,0x83,0xec,0x20,0x48,0x8b,0x42,0x30,
    }};
    constexpr std::array<unsigned char, 12> expected_unwind{{
        0x01,0x0a,0x04,0x00,0x0a,0x34,0x06,0x00,0x0a,0x32,0x06,0x70,
    }};
    static_assert(entry::kEntryRva == 0x328710u);
    static_assert(entry::kSourceEndRva == 0x32885du);
    static_assert(entry::kUnwindRva == 0x1dc9798u);
    static_assert(entry::kPatchBytes == 14u);
    CHECK(entry::kPrefix == expected_prefix);
    CHECK(entry::kUnwind == expected_unwind);

    const Address image_base = 0x140000000ull;
    const Address original_entry = image_base + entry::kEntryRva;
    const Address hook = 0x7fff12345678ull;
    entry::Plan plan{};
    CHECK(entry::prepare(expected_prefix, expected_unwind, original_entry, hook, plan));
    CHECK(std::memcmp(plan.image.data(), expected_prefix.data(), expected_prefix.size()) == 0);
    CHECK(std::memcmp(plan.image.data() + entry::kUnwindOffset,
        expected_unwind.data(), expected_unwind.size()) == 0);
    CHECK(plan.runtime.begin == 0u);
    CHECK(plan.runtime.end == entry::kPatchBytes
        + information::battle::message_entry::kHomeSlotJumpBytes);
    CHECK(plan.runtime.unwind == entry::kUnwindOffset);

    constexpr std::array<unsigned char, 29> expected_home_jump{{
        0xc7,0x84,0x24,0x38,0x00,0x00,0x00,0x1e,0x87,0x32,0x40,
        0xc7,0x84,0x24,0x3c,0x00,0x00,0x00,0x01,0x00,0x00,0x00,
        0xff,0xa4,0x24,0x38,0x00,0x00,0x00,
    }};
    CHECK(std::memcmp(plan.image.data() + entry::kPatchBytes,
        expected_home_jump.data(), expected_home_jump.size()) == 0);
    CHECK(plan.image[entry::kPatchBytes + 3] == 0x38
        && plan.image[entry::kPatchBytes + 4] == 0
        && plan.image[entry::kPatchBytes + 5] == 0
        && plan.image[entry::kPatchBytes + 6] == 0);

    std::array<unsigned char, entry::kPatchBytes> expected_patch{};
    expected_patch.fill(0x90);
    expected_patch[0] = 0xff;
    expected_patch[1] = 0x25;
    expected_patch[2] = expected_patch[3] = expected_patch[4] = expected_patch[5] = 0;
    for (unsigned index = 0; index < 8; ++index)
        expected_patch[6 + index] = static_cast<unsigned char>(hook >> (index * 8u));
    CHECK(plan.patch == expected_patch);

    entry::Plan unchanged{};
    unchanged.image.fill(0xa5);
    unchanged.patch.fill(0x5a);
    unchanged.runtime = {0x1234u, 0x5678u, 0x9abcu};
    const entry::Plan before = unchanged;
    auto unchanged_output = [&]() {
        return unchanged.image == before.image && unchanged.patch == before.patch
            && unchanged.runtime.begin == before.runtime.begin
            && unchanged.runtime.end == before.runtime.end
            && unchanged.runtime.unwind == before.runtime.unwind;
    };
    auto bad_prefix = expected_prefix;
    bad_prefix[0] ^= 1u;
    CHECK(!entry::prepare(bad_prefix, expected_unwind, original_entry, hook, unchanged));
    CHECK(unchanged_output());
    auto bad_unwind = expected_unwind;
    bad_unwind[0] ^= 1u;
    CHECK(!entry::prepare(expected_prefix, bad_unwind, original_entry, hook, unchanged));
    CHECK(unchanged_output());
}

} // namespace

int main() {
    test_unlinked_and_deferred_success_copy_only_owned_values();
    test_rejects_noop_and_wrong_count_after_destroy_without_dereference();
    test_rejects_bad_links_duplicates_and_marks();
    test_frame_caller_copy_and_dead_object_gates();
    test_double_pass_and_post_delete_identity_changes_fail_closed();
    test_instance_limit_is_bounded_and_over_limit_rejected();
    test_removal_entry_plan_pins_bytes_and_continuation_slot();
    std::cout << "country modifier removal regression: PASS\n";
    return 0;
}
