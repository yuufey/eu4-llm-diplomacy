#ifndef INFORMATION_COUNTRY_MODIFIER_ADD_H
#define INFORMATION_COUNTRY_MODIFIER_ADD_H

// B23 temporary-country-modifier insertion. The caller owns the original
// native invocation. No allocation, logging, native call or write occurs here.
// begin/finish straddle a normal return from RVA3283f0, entered only from
// AddTemporaryModifier at return RVA328e18. The other direct call at
// RVA2d4145 is excluded without assigning it an unverified lifecycle meaning.
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace information::country_modifier {

using Address = std::uintptr_t;
inline constexpr std::size_t kKeyCapacity = 128;
inline constexpr std::uint32_t kMaxInstances = 1024;
inline constexpr std::size_t kMaxSingleRead = 128;
inline constexpr std::size_t kMaxReadBytes = 32768;
inline constexpr Address kEntryRva = 0x3283f0;
inline constexpr Address kCreatorReturnRva = 0x328e18;

struct Context final {
    Address module = 0;
    Address country = 0;
    std::uint64_t observer = 0;
    std::int32_t date = 0;
    bool bound_frame_thread = false;
};

// A complete, owned added-record payload. Dates retain native units and flags
// retain their storage meaning. They do not establish a future expiry event.
struct Added final {
    std::uint64_t country = 0;
    std::int32_t date = 0;
    std::int32_t start_date = 0;
    std::int32_t end_date = 0;
    std::array<unsigned char, 4> flags{};
    std::array<char, kKeyCapacity> key{};
};

// Only this short-lived scope contains native addresses. It is never queued
// or serialized. A new default-initialized scope is required for each call.
struct Pending final {
    Context context{};
    Address instance = 0;
    Address definition = 0;
    std::uint32_t count_before = 0;
    Added value{};
    bool ready = false;
};

namespace detail {

inline bool range(Address address, std::size_t size) noexcept {
    constexpr Address end = UINT64_C(0x0000800000000000);
    return address >= 0x10000 && address < end && size != 0 && size <= end - address;
}

template<class Reader>
class Copy final {
public:
    explicit Copy(Reader& reader) noexcept : reader_(reader) {}

    bool bytes(Address address, void* destination, std::size_t size) noexcept {
        if (!range(address, size) || size > kMaxSingleRead || size > kMaxReadBytes - used_) return false;
        used_ += size;
        return reader_.read(address, static_cast<unsigned char*>(destination), size);
    }

    template<class Value>
    bool value(Address address, Value& output) noexcept {
        return bytes(address, &output, sizeof(output));
    }

private:
    Reader& reader_;
    std::size_t used_ = 0;
};

template<class Value, std::size_t Size>
Value field(const std::array<unsigned char, Size>& bytes, std::size_t offset) noexcept {
    Value value{};
    std::memcpy(&value, bytes.data() + offset, sizeof(value));
    return value;
}

inline bool same(const Added& left, const Added& right) noexcept {
    return left.country == right.country && left.date == right.date
        && left.start_date == right.start_date && left.end_date == right.end_date
        && left.flags == right.flags && left.key == right.key;
}

template<class Reader>
bool identity(Copy<Reader>& copy, const Context& context, std::uint32_t& count) noexcept {
    if (!context.bound_frame_thread || !range(context.module, 0x233fe60)
        || !range(context.country, 0x204) || context.observer == 0 || context.date < 0) return false;
    Address game = 0, database = 0, countries = 0, country = 0;
    std::uint64_t actual = 0;
    std::int32_t date = 0;
    const auto slot = static_cast<std::uint32_t>((context.observer >> 32) & 0xffff);
    return slot < 4096
        && copy.value(context.module + 0x233d8b0, database) && range(database, 0x120)
        && copy.value(database + 0x118, countries) && range(countries, (slot + 1) * 8)
        && copy.value(countries + slot * 8, country) && country == context.country
        && copy.value(country + 0x20, actual) && actual == context.observer
        && copy.value(context.module + 0x233fe58, game) && range(game, 0x1dd4)
        && copy.value(game + 0x1dd0, date) && date == context.date
        && copy.value(country + 0x200, count) && count <= kMaxInstances;
}

template<class Reader>
bool snapshot(Copy<Reader>& copy, const Context& context, Address instance,
              Address& definition, Added& output) noexcept {
    std::array<unsigned char, 0x50> prefix{};
    if (!copy.bytes(instance, prefix.data(), prefix.size())
        || field<Address>(prefix, 0) != context.module + 0x1ce7f08) return false;
    definition = field<Address>(prefix, 0x30);
    Address table = 0;
    std::array<unsigned char, 32> sso{};
    if (!range(definition, 0x178) || !copy.value(definition, table)
        || table != context.module + 0x1c42ae0
        || !copy.bytes(definition + 0x158, sso.data(), sso.size())) return false;
    const auto length = field<std::uint64_t>(sso, 0x10);
    const auto capacity = field<std::uint64_t>(sso, 0x18);
    if (length == 0 || length >= kKeyCapacity || length > capacity
        || (capacity < 16 && capacity != 15)) return false;
    Added candidate{};
    if (capacity == 15) {
        std::memcpy(candidate.key.data(), sso.data(), static_cast<std::size_t>(length + 1));
    } else {
        const Address text = field<Address>(sso, 0);
        if (!copy.bytes(text, candidate.key.data(), static_cast<std::size_t>(length + 1))) return false;
    }
    if (candidate.key[length] != '\0') return false;
    for (std::size_t index = 0; index < length; ++index) {
        const char ch = candidate.key[index];
        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
            || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '.')) return false;
    }
    candidate.country = context.observer;
    candidate.date = context.date;
    candidate.start_date = field<std::int32_t>(prefix, 0x40);
    candidate.end_date = field<std::int32_t>(prefix, 0x44);
    std::memcpy(candidate.flags.data(), prefix.data() + 0x48, candidate.flags.size());
    if (candidate.flags[0] > 1 || candidate.flags[1] > 1
        || candidate.flags[2] > 1 || candidate.flags[3] > 1) return false;
    output = candidate;
    return true;
}

template<class Reader>
bool membership(Copy<Reader>& copy, const Pending& pending, std::uint32_t count) noexcept {
    std::array<Address, 2> ends{};
    if (!copy.value(pending.context.country + 0x1f0, ends)) return false;
    Address node = ends[0], last = 0;
    unsigned matches = 0;
    for (std::uint32_t index = 0; index < count; ++index) {
        std::array<unsigned char, 24> bytes{};
        if (!copy.bytes(node, bytes.data(), bytes.size())) return false;
        if (field<Address>(bytes, 0) == pending.instance) ++matches;
        last = node;
        node = field<Address>(bytes, 0x10);
    }
    return node == 0 && last == ends[1] && matches == 1;
}

} // namespace detail

template<class Reader>
bool begin(Reader& reader, const Context& context, Address instance,
           Address caller_return, Pending& output) noexcept {
    output = Pending{};
    if (!context.bound_frame_thread || !detail::range(context.module, 0x233fe60)
        || caller_return != context.module + kCreatorReturnRva) return false;
    detail::Copy<Reader> copy(reader);
    constexpr std::array<unsigned char, 5> expected{{0xe8, 0xd8, 0xf5, 0xff, 0xff}};
    std::array<unsigned char, 5> call{};
    Pending candidate{};
    candidate.context = context;
    candidate.instance = instance;
    Added repeated{};
    Address second_definition = 0;
    if (!copy.bytes(caller_return - 5, call.data(), call.size()) || call != expected
        || !detail::identity(copy, context, candidate.count_before)
        || candidate.count_before == kMaxInstances
        || !detail::snapshot(copy, context, instance, candidate.definition, candidate.value)
        || !detail::snapshot(copy, context, instance, second_definition, repeated)
        || candidate.definition != second_definition || !detail::same(candidate.value, repeated)) return false;
    candidate.ready = true;
    output = candidate;
    return true;
}

template<class Reader>
bool finish(Reader& reader, Pending& pending, Added& output) noexcept {
    const bool ready = pending.ready;
    pending.ready = false;
    if (!ready) return false;
    detail::Copy<Reader> copy(reader);
    std::uint32_t count = 0, repeated_count = 0;
    Address definition = 0;
    Added current{};
    if (!detail::identity(copy, pending.context, count) || count != pending.count_before + 1
        || !detail::snapshot(copy, pending.context, pending.instance, definition, current)
        || definition != pending.definition || !detail::same(current, pending.value)
        || !detail::membership(copy, pending, count)
        || !detail::identity(copy, pending.context, repeated_count) || repeated_count != count) return false;
    output = pending.value;
    return true;
}

} // namespace information::country_modifier
#endif
