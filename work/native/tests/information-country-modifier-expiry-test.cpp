#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <utility>
#include <vector>

#include "../information-country-modifier-expiry.h"

namespace expiry = information::country_modifier::expiry;
using information::country_modifier::Added;
using information::country_modifier::Address;
using information::country_modifier::Context;

namespace {

constexpr Address kModule = 0x140000000ull;
constexpr Address kCountry = 0x260000000ull;
constexpr Address kFunction = 0x270000000ull;
constexpr Address kTable = kModule + 0x1c56ba8u;
constexpr Address kDateAddress = 0x290000000ull;
constexpr Address kAdapter = kModule + 0x42f360u;
constexpr Address kPredicateCaller = kModule
    + information::country_modifier::removal::kPredicateReturnRva;
constexpr std::uint64_t kObserver = (std::uint64_t{7} << 32u) | 0x90123400u;
constexpr std::int32_t kDate = 56658312;
constexpr std::int32_t kEndDate = 56658000;

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
        regions_.push_back(Region{begin, std::vector<unsigned char>(size, 0)});
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
        max_read_size_ = size > max_read_size_ ? size : max_read_size_;
        if (!destination || size == 0 || address > UINT64_MAX - size) return false;
        if (fail_enabled_ && address < fail_address_ + fail_size_
            && fail_address_ < address + size) {
            fail_enabled_ = false;
            return false;
        }
        for (auto& region : regions_) {
            if (address < region.begin) continue;
            const Address offset = address - region.begin;
            if (offset > region.bytes.size() || size > region.bytes.size() - offset) continue;
            std::memcpy(destination, region.bytes.data() + static_cast<std::size_t>(offset), size);
            if (mutation_enabled_ && address == mutation_trigger_
                && size == mutation_trigger_size_) {
                mutation_enabled_ = false;
                CHECK(write(mutation_address_, mutation_bytes_.data(), mutation_size_));
            }
            return true;
        }
        return false;
    }

    void fail_once_at(Address address, std::size_t size) noexcept {
        fail_address_ = address;
        fail_size_ = size;
        fail_enabled_ = true;
    }

    void mutate_after_read(Address trigger, std::size_t trigger_size,
                          Address address, const void* value, std::size_t size) {
        CHECK(value && size != 0 && size <= mutation_bytes_.size());
        mutation_trigger_ = trigger;
        mutation_trigger_size_ = trigger_size;
        mutation_address_ = address;
        mutation_size_ = size;
        std::memcpy(mutation_bytes_.data(), value, size);
        mutation_enabled_ = true;
    }

    std::size_t read_calls() const noexcept { return read_calls_; }
    std::size_t requested_bytes() const noexcept { return requested_bytes_; }
    std::size_t max_read_size() const noexcept { return max_read_size_; }

private:
    std::vector<Region> regions_;
    std::size_t read_calls_ = 0;
    std::size_t requested_bytes_ = 0;
    std::size_t max_read_size_ = 0;
    Address fail_address_ = 0;
    std::size_t fail_size_ = 0;
    bool fail_enabled_ = false;
    Address mutation_trigger_ = 0;
    std::size_t mutation_trigger_size_ = 0;
    Address mutation_address_ = 0;
    std::array<unsigned char, 128> mutation_bytes_{};
    std::size_t mutation_size_ = 0;
    bool mutation_enabled_ = false;
};

struct Fixture final {
    Reader reader;
    Context context{kModule, kCountry, kObserver, kDate, true};
    Added value{};

    Fixture() {
        reader.add(kFunction, 64);
        reader.add(kTable, 0x18);
        reader.add(kDateAddress, sizeof(kDate));
        reader.add(kModule + 0x328904u, 3);
        reader.add(kModule + 0x328954u, 4);
        reader.add(kAdapter, 12);
        reader.add(kModule + 0x2ed2f0u, expiry::kPredicatePrefix.size());

        CHECK(reader.write_value(kFunction, kTable));
        CHECK(reader.write_value(kFunction + 8u, kDateAddress));
        CHECK(reader.write_value(kFunction + 0x10u, kCountry));
        CHECK(reader.write_value(kFunction + 0x38u, kFunction));
        CHECK(reader.write_value(kTable + 0x10u, kAdapter));
        const std::array<unsigned char, 3> bind{{0x4c, 0x8b, 0xea}};
        const std::array<unsigned char, 4> dispatch{{0x49, 0x8b, 0x4d, 0x38}};
        const std::array<unsigned char, 12> adapter{{
            0x48, 0x8b, 0x12, 0x48, 0x83, 0xc1, 0x08, 0xe9, 0x84, 0xdf, 0xeb, 0xff}};
        CHECK(reader.write(kModule + 0x328904u, bind.data(), bind.size()));
        CHECK(reader.write(kModule + 0x328954u, dispatch.data(), dispatch.size()));
        CHECK(reader.write(kAdapter, adapter.data(), adapter.size()));
        CHECK(reader.write(kModule + 0x2ed2f0u,
            expiry::kPredicatePrefix.data(), expiry::kPredicatePrefix.size()));
        CHECK(reader.write_value(kDateAddress, kDate));

        value.country = kObserver;
        value.date = kDate;
        value.start_date = 56657000;
        value.end_date = kEndDate;
        value.key[0] = 'x';
    }

    expiry::Reason classify(Address caller = kPredicateCaller,
                            Address function = kFunction) {
        return expiry::classify(reader, context, value, caller, function);
    }

    void check_bounded() const {
        CHECK(reader.requested_bytes() < 64u * 1024u);
        CHECK(reader.read_calls() < 128u);
        CHECK(reader.max_read_size() <= information::country_modifier::kMaxSingleRead);
    }
};

void test_correct_inline_descriptor_and_guards_expire() {
    Fixture f;
    CHECK(f.classify() == expiry::Reason::expired);
    CHECK(f.reader.read_calls() == 10u);
    f.check_bounded();
}

void test_other_caller_returns_other_without_reading() {
    Fixture f;
    CHECK(f.classify(kPredicateCaller + 1u) == expiry::Reason::other);
    CHECK(f.reader.read_calls() == 0u);
    f.check_bounded();
}

void test_wrong_frame_returns_unreadable_without_reading() {
    Fixture f;
    f.context.bound_frame_thread = false;
    CHECK(f.classify() == expiry::Reason::unreadable);
    CHECK(f.reader.read_calls() == 0u);
    f.check_bounded();
}

void test_other_vtable_returns_other() {
    Fixture f;
    CHECK(f.reader.write_value(kFunction, kTable + 0x100u));
    CHECK(f.classify() == expiry::Reason::other);
    CHECK(f.reader.read_calls() == 1u);
    f.check_bounded();
}

void test_wrong_self_and_country_are_unreadable() {
    {
        Fixture f;
        CHECK(f.reader.write_value(kFunction + 0x38u, kFunction + 8u));
        CHECK(f.classify() == expiry::Reason::unreadable);
        f.check_bounded();
    }
    {
        Fixture f;
        CHECK(f.reader.write_value(kFunction + 0x10u, kCountry + 8u));
        CHECK(f.classify() == expiry::Reason::unreadable);
        f.check_bounded();
    }
    {
        Fixture f;
        f.value.country += 1u;
        CHECK(f.classify() == expiry::Reason::unreadable);
        CHECK(f.reader.read_calls() == 0u);
        f.check_bounded();
    }
}

void test_wrong_date_target_and_code_guards_are_unreadable() {
    {
        Fixture f;
        f.value.date += 1;
        CHECK(f.classify() == expiry::Reason::unreadable);
        CHECK(f.reader.read_calls() == 0u);
    }
    {
        Fixture f;
        CHECK(f.reader.write_value(kTable + 0x10u, kAdapter + 1u));
        CHECK(f.classify() == expiry::Reason::unreadable);
    }
    {
        Fixture f;
        const unsigned char bad = 0;
        CHECK(f.reader.write(kModule + 0x328904u, &bad, sizeof(bad)));
        CHECK(f.classify() == expiry::Reason::unreadable);
    }
    {
        Fixture f;
        const unsigned char bad = 0;
        CHECK(f.reader.write(kModule + 0x2ed2f0u + 20u, &bad, sizeof(bad)));
        CHECK(f.classify() == expiry::Reason::unreadable);
    }
    {
        Fixture f;
        const std::int32_t before_expiry = kEndDate - 1;
        CHECK(f.reader.write_value(kDateAddress, before_expiry));
        CHECK(f.classify() == expiry::Reason::unreadable);
    }
}

void test_double_pass_descriptor_or_date_change_is_unreadable() {
    {
        Fixture f;
        const Address changed_country = kCountry + 8u;
        f.reader.mutate_after_read(kFunction, 64u, kFunction + 0x10u,
            &changed_country, sizeof(changed_country));
        CHECK(f.classify() == expiry::Reason::unreadable);
    }
    {
        Fixture f;
        const std::int32_t changed_date = kDate + 1;
        f.reader.mutate_after_read(kDateAddress, sizeof(kDate), kDateAddress,
            &changed_date, sizeof(changed_date));
        CHECK(f.classify() == expiry::Reason::unreadable);
    }
}

void test_reader_failure_is_unreadable_and_bounded() {
    Fixture f;
    f.reader.fail_once_at(kTable + 0x10u, sizeof(Address));
    CHECK(f.classify() == expiry::Reason::unreadable);
    f.check_bounded();
}

} // namespace

int main() {
    test_correct_inline_descriptor_and_guards_expire();
    test_other_caller_returns_other_without_reading();
    test_wrong_frame_returns_unreadable_without_reading();
    test_other_vtable_returns_other();
    test_wrong_self_and_country_are_unreadable();
    test_wrong_date_target_and_code_guards_are_unreadable();
    test_double_pass_descriptor_or_date_change_is_unreadable();
    test_reader_failure_is_unreadable_and_bounded();
    std::cout << "expiry value regression: PASS (8 scenarios)\n";
    return 0;
}
