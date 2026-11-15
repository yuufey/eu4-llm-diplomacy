#ifndef INFORMATION_COUNTRY_MODIFIER_REMOVE_H
#define INFORMATION_COUNTRY_MODIFIER_REMOVE_H

#include "information-country-modifier-add.h"

// B23 RVA328710 destroys the instance after unlinking its list node, or
// marking that node for deferred removal. Copy before calling the original.
// The two admitted callers establish removal, without establishing expiry.
namespace information::country_modifier::removal {

inline constexpr Address kEntryRva = 0x328710;
inline constexpr Address kPredicateReturnRva = 0x328a70;
inline constexpr Address kReligionReturnRva = 0x2fe1fb;

struct Pending final {
    Context context{};
    Address instance = 0;
    std::uint32_t count_before = 0;
    unsigned char deferred = 0;
    Added value{};
    bool ready = false;
};

namespace detail {

template<class Reader>
bool caller(country_modifier::detail::Copy<Reader>& copy, const Context& context,
            Address return_address) noexcept {
    std::array<unsigned char, 5> expected{};
    if (return_address == context.module + kPredicateReturnRva) {
        expected = {{0xe8, 0xa0, 0xfc, 0xff, 0xff}};
    } else if (return_address == context.module + kReligionReturnRva) {
        expected = {{0xe8, 0x15, 0xa5, 0x02, 0x00}};
    } else {
        return false;
    }
    std::array<unsigned char, 5> actual{};
    return copy.bytes(return_address - 5, actual.data(), actual.size()) && actual == expected;
}

// Only node bytes are read. An item pointer in a marked node can already
// refer to a destroyed instance and must never be dereferenced here.
template<class Reader>
bool membership(country_modifier::detail::Copy<Reader>& copy, const Pending& pending,
                std::uint32_t count, unsigned expected_matches, unsigned char expected_mark) noexcept {
    std::array<Address, 2> ends{};
    if (!copy.value(pending.context.country + 0x1f0, ends)) return false;
    Address node = ends[0], previous = 0;
    unsigned matches = 0;
    for (std::uint32_t index = 0; index < count; ++index) {
        std::array<unsigned char, 25> bytes{};
        if (!copy.bytes(node, bytes.data(), bytes.size())
            || country_modifier::detail::field<Address>(bytes, 8) != previous
            || bytes[24] > 1) return false;
        if (country_modifier::detail::field<Address>(bytes, 0) == pending.instance) {
            if (bytes[24] != expected_mark) return false;
            ++matches;
        }
        previous = node;
        node = country_modifier::detail::field<Address>(bytes, 16);
    }
    return node == 0 && previous == ends[1] && matches == expected_matches;
}

} // namespace detail

template<class Reader>
bool begin(Reader& reader, const Context& context, Address instance,
           Address caller_return, Pending& output) noexcept {
    output = Pending{};
    if (!context.bound_frame_thread || !country_modifier::detail::range(context.module, 0x233fe60)
        || (caller_return != context.module + kPredicateReturnRva
            && caller_return != context.module + kReligionReturnRva)) return false;
    country_modifier::detail::Copy<Reader> copy(reader);
    Pending candidate{};
    candidate.context = context;
    candidate.instance = instance;
    Address definition = 0, repeated_definition = 0;
    Added repeated{};
    std::uint32_t repeated_count = 0;
    unsigned char repeated_deferred = 0;
    if (!detail::caller(copy, context, caller_return)
        || !country_modifier::detail::identity(copy, context, candidate.count_before)
        || candidate.count_before == 0
        || !copy.value(context.country + 0x204, candidate.deferred) || candidate.deferred > 1
        || !country_modifier::detail::snapshot(copy, context, instance, definition, candidate.value)
        || !detail::membership(copy, candidate, candidate.count_before, 1, 0)
        || !country_modifier::detail::snapshot(copy, context, instance, repeated_definition, repeated)
        || definition != repeated_definition || !country_modifier::detail::same(candidate.value, repeated)
        || !country_modifier::detail::identity(copy, context, repeated_count)
        || repeated_count != candidate.count_before
        || !copy.value(context.country + 0x204, repeated_deferred)
        || repeated_deferred != candidate.deferred) return false;
    candidate.ready = true;
    output = candidate;
    return true;
}

template<class Reader>
bool finish(Reader& reader, Pending& pending, Added& output) noexcept {
    const bool ready = pending.ready;
    pending.ready = false;
    if (!ready) return false;
    country_modifier::detail::Copy<Reader> copy(reader);
    std::uint32_t count = 0, repeated_count = 0;
    unsigned char deferred = 0;
    const auto expected_count = pending.count_before - (pending.deferred == 0 ? 1u : 0u);
    const unsigned expected_matches = pending.deferred == 0 ? 0u : 1u;
    if (!country_modifier::detail::identity(copy, pending.context, count) || count != expected_count
        || !copy.value(pending.context.country + 0x204, deferred) || deferred != pending.deferred
        || !detail::membership(copy, pending, count, expected_matches, 1)
        || !country_modifier::detail::identity(copy, pending.context, repeated_count)
        || repeated_count != count) return false;
    output = pending.value;
    return true;
}

} // namespace information::country_modifier::removal
#endif
