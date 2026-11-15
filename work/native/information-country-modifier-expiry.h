#ifndef INFORMATION_COUNTRY_MODIFIER_EXPIRY_H
#define INFORMATION_COUNTRY_MODIFIER_EXPIRY_H

#include "information-country-modifier-remove.h"

// B23 date predicate2ed2f0 is invoked through42f360 by the functor at1c56ba8.
// It selects only date>=end and native_date_year(end)>1. All remaining code
// prepares an optional player message and ends with true. A completed328710
// removal selected by this predicate establishes expiry for NPCs as well.
// R13 retains the std::function argument of3288e0 until after its removal loop.
namespace information::country_modifier::expiry {

enum class Reason : unsigned char { other, expired, unreadable };

inline constexpr std::array<unsigned char, 76> kPredicatePrefix{{
    0x48,0x89,0x5c,0x24,0x10,0x48,0x89,0x74,0x24,0x18,0x48,0x89,0x7c,0x24,0x20,
    0x55,0x41,0x56,0x41,0x57,0x48,0x8d,0x6c,0x24,0xc0,0x48,0x81,0xec,0x40,0x01,0x00,0x00,
    0x48,0x8b,0xfa,0x48,0x8b,0xd9,0x48,0x8b,0x01,0x44,0x8b,0x42,0x44,0x44,0x39,0x00,
    0x0f,0x8c,0x7b,0x03,0x00,0x00,0x44,0x89,0x45,0x60,0x48,0x8d,0x4d,0x60,
    0xe8,0x3d,0x2a,0xde,0xff,0x83,0xf8,0x01,0x0f,0x8e,0x65,0x03,0x00,0x00,
}};

namespace detail {

template<class Reader, std::size_t Size>
bool guard(country_modifier::detail::Copy<Reader>& copy, Address address,
           const std::array<unsigned char, Size>& expected) noexcept {
    std::array<unsigned char, Size> actual{};
    return copy.bytes(address, actual.data(), actual.size()) && actual == expected;
}

} // namespace detail

template<class Reader>
Reason classify(Reader& reader, const Context& context, const Added& value,
                Address caller_return, Address function) noexcept {
    if (caller_return != context.module + removal::kPredicateReturnRva) return Reason::other;
    if (!context.bound_frame_thread || !country_modifier::detail::range(context.module, 0x233fe60)
        || value.country != context.observer || value.date != context.date) return Reason::unreadable;
    country_modifier::detail::Copy<Reader> copy(reader);
    Address table = 0;
    if (!copy.value(function, table)) return Reason::unreadable;
    if (table != context.module + 0x1c56ba8) return Reason::other;
    std::array<unsigned char, 64> descriptor{}, repeated{};
    constexpr std::array<unsigned char, 3> bind{{0x4c,0x8b,0xea}};
    constexpr std::array<unsigned char, 4> dispatch{{0x49,0x8b,0x4d,0x38}};
    constexpr std::array<unsigned char, 12> adapter{{
        0x48,0x8b,0x12,0x48,0x83,0xc1,0x08,0xe9,0x84,0xdf,0xeb,0xff}};
    Address target = 0;
    std::int32_t date = 0, repeated_date = 0;
    if (!copy.bytes(function, descriptor.data(), descriptor.size())
        || country_modifier::detail::field<Address>(descriptor, 0) != table
        || country_modifier::detail::field<Address>(descriptor, 0x10) != context.country
        || country_modifier::detail::field<Address>(descriptor, 0x38) != function
        || !copy.value(table + 0x10, target) || target != context.module + 0x42f360
        || !detail::guard(copy, context.module + 0x328904, bind)
        || !detail::guard(copy, context.module + 0x328954, dispatch)
        || !detail::guard(copy, target, adapter)
        || !detail::guard(copy, context.module + 0x2ed2f0, kPredicatePrefix)) return Reason::unreadable;
    const Address date_address = country_modifier::detail::field<Address>(descriptor, 8);
    if (!copy.value(date_address, date) || date != context.date || date < value.end_date
        || !copy.bytes(function, repeated.data(), repeated.size()) || descriptor != repeated
        || !copy.value(date_address, repeated_date) || repeated_date != date) return Reason::unreadable;
    // This classification becomes an event only after removal::finish confirms
    // the native deletion. The observer never calls or substitutes the predicate.
    return Reason::expired;
}

} // namespace information::country_modifier::expiry
#endif
