#pragma once

#include "information-country-modifier-add.h"
#include "information-truce-expiry-native-guards.h"

namespace information::truce_expiry {

using Address = std::uintptr_t;
inline constexpr Address kMaintenanceRva = 0xa67420;
inline constexpr std::int32_t kDateReference = 43800000;

struct Context final {
    Address module = 0;
    std::int32_t date = 0;
    bool bound_frame_thread = false;
};

struct Value final {
    std::uint64_t actor = 0, recipient = 0, observer = 0;
    std::int32_t date = 0, input = 0, end = 0, configuration_a = 0, configuration_b = 0;
    std::int8_t adjustment = 0;
};

struct Pending final {
    Context context{};
    Address instance = 0, root = 0, game = 0;
    std::int32_t date_floor = 0, sentinel = 0;
    unsigned char flags = 0;
    Value value{};
    bool ready = false;
};

enum class Decision : unsigned char { ignored, ready, unreadable };

namespace detail {
namespace shared = information::country_modifier::detail;
inline constexpr std::array<int, 12> kMonthDays{{31,28,31,30,31,30,31,31,30,31,30,31}};

inline std::int32_t signed_bits(std::uint32_t value) noexcept {
    std::int32_t result = 0;
    std::memcpy(&result, &value, sizeof(result));
    return result;
}

inline bool expiry(Value& value) noexcept {
    if (value.input < kDateReference) return false;
    const std::int32_t scaled = signed_bits(static_cast<std::uint32_t>(value.adjustment)
        * static_cast<std::uint32_t>(value.configuration_a) * 1000u);
    const std::int32_t combined = signed_bits(static_cast<std::uint32_t>(value.configuration_b) * 1000u
        + static_cast<std::uint32_t>(scaled / 100));
    const std::int32_t numerator = signed_bits(static_cast<std::uint32_t>(combined) * 12u + 1000u);
    const std::int32_t months = numerator / 1000 + (numerator > 0 && numerator % 1000 != 0);
    const std::int32_t offset = value.input - kDateReference;
    const std::int32_t days = offset / 24;
    int month = 0, ordinal = days % 365;
    while (ordinal >= kMonthDays[month]) ordinal -= kMonthDays[month++];
    const std::int64_t month_index = static_cast<std::int64_t>(days / 365) * 12 + month + months;
    if (month_index < 0) return false;
    const std::int64_t year = month_index / 12;
    month = static_cast<int>(month_index % 12);
    std::int64_t result = kDateReference + year * 8760 + offset % 24;
    for (int index = 0; index < month; ++index) result += kMonthDays[index] * 24;
    if (result > INT32_MAX) return false;
    value.end = static_cast<std::int32_t>(result);
    return true;
}

inline Value value(const std::array<unsigned char, 0x48>& bytes, const Context& context) noexcept {
    Value result{};
    result.actor = shared::field<std::uint64_t>(bytes, 8);
    result.recipient = shared::field<std::uint64_t>(bytes, 0x10);
    result.observer = (result.actor & 0xffffff) == 0x415246 ? result.actor : result.recipient;
    result.date = context.date;
    result.input = shared::field<std::int32_t>(bytes, 0x34);
    result.adjustment = shared::field<std::int8_t>(bytes, 0x24);
    return result;
}

template<class Reader>
bool canonical(shared::Copy<Reader>& copy, Address module, std::uint64_t reference,
               Address& country) noexcept {
    const auto slot = static_cast<std::uint32_t>((reference >> 32) & 0xffff);
    Address database = 0, table = 0;
    std::uint64_t actual = 0;
    return slot < 4096
        && copy.value(module + 0x233d8b0, database) && copy.value(database + 0x118, table)
        && copy.value(table + slot * 8, country)
        && copy.value(country + 0x20, actual) && actual == reference;
}

template<class Reader>
bool ownership(shared::Copy<Reader>& copy, const Pending& pending) noexcept {
    Address actor = 0, recipient = 0, table = 0;
    const auto slot = static_cast<std::uint32_t>((pending.value.recipient >> 32) & 0xffff);
    return canonical(copy, pending.context.module, pending.value.actor, actor)
        && canonical(copy, pending.context.module, pending.value.recipient, recipient)
        && copy.value(actor + 0x1510, table) && shared::range(table, (slot + 1) * 0x48)
        && table + slot * 0x48 == pending.instance;
}

template<class Reader>
Decision branch(shared::Copy<Reader>& copy, const Pending& pending) noexcept {
    Address entries = 0;
    std::int32_t count = 0;
    if (!copy.value(pending.root + 0x50, entries) || !copy.value(pending.root + 0x5c, count)
        || count < 0 || count > 4096) return Decision::unreadable;
    const auto slot = static_cast<std::int32_t>((pending.value.recipient >> 32) & 0xffff);
    for (std::int32_t index = 0; index < count; ++index) {
        std::int32_t excluded = 0;
        if (!copy.value(entries + static_cast<Address>(index) * 16, excluded)) return Decision::unreadable;
        if (excluded == slot) return Decision::ignored;
    }
    return Decision::ready;
}

template<class Reader, std::size_t Size>
bool guard(shared::Copy<Reader>& copy, Address address,
           const std::array<unsigned char, Size>& expected) noexcept {
    std::array<unsigned char, 128> bytes{};
    for (std::size_t offset = 0; offset < Size; offset += bytes.size()) {
        const std::size_t size = (Size - offset < bytes.size()) ? Size - offset : bytes.size();
        if (!copy.bytes(address + offset, bytes.data(), size)
            || std::memcmp(bytes.data(), expected.data() + offset, size)) return false;
    }
    return true;
}
} // namespace detail

template<class Reader>
bool guards(Reader& reader, Address module) noexcept {
    detail::shared::Copy<Reader> copy(reader);
    return detail::guard(copy, module + kMaintenanceRva, kMaintenanceBytes)
        && detail::guard(copy, module + kDateMathRva, kDateMathBytes);
}

template<class Reader>
Decision begin(Reader& reader, const Context& context, Address instance, Pending& pending) noexcept {
    pending = {};
    if (!context.bound_frame_thread || context.date < 0
        || !detail::shared::range(context.module, 0x233fe60)) return Decision::ignored;
    detail::shared::Copy<Reader> copy(reader);
    std::array<unsigned char, 0x48> bytes{};
    if (!copy.bytes(instance, bytes.data(), bytes.size())) return Decision::unreadable;
    Pending candidate{};
    candidate.value = detail::value(bytes, context);
    candidate.flags = bytes[0x45];
    if (!(candidate.flags & 1) || (candidate.value.observer & 0xffffff) != 0x415246
        || candidate.value.actor == candidate.value.recipient) return Decision::ignored;
    candidate.context = context;
    candidate.instance = instance;
    candidate.root = detail::shared::field<Address>(bytes, 0);
    std::int32_t actual_date = 0;
    if (!copy.value(context.module + 0x233fe58, candidate.game)
        || !copy.value(candidate.game + 0x1dd0, actual_date) || actual_date != context.date
        || !copy.value(candidate.game + 0x1dd4, candidate.date_floor)
        || !copy.value(context.module + 0x1fd13c4, candidate.sentinel)
        || !copy.value(context.module + 0x233dc88, candidate.value.configuration_a)
        || !copy.value(context.module + 0x233dd8c, candidate.value.configuration_b)) return Decision::unreadable;
    if (context.date == candidate.sentinel || candidate.value.input > context.date
        || candidate.value.input <= candidate.date_floor) return Decision::ignored;
    if (!detail::expiry(candidate.value)) return Decision::unreadable;
    if (candidate.value.end > context.date) return Decision::ignored;
    if (!detail::ownership(copy, candidate)) return Decision::unreadable;
    const auto decision = detail::branch(copy, candidate);
    if (decision != Decision::ready) return decision;
    candidate.ready = true;
    pending = candidate;
    return Decision::ready;
}

template<class Reader>
bool finish(Reader& reader, Pending& pending, Value& output) noexcept {
    const bool ready = pending.ready;
    pending.ready = false;
    if (!ready) return false;
    detail::shared::Copy<Reader> copy(reader);
    std::array<unsigned char, 0x48> bytes{};
    Address game = 0;
    std::int32_t date = 0, floor = 0, sentinel = 0, configuration_a = 0, configuration_b = 0;
    if (!copy.bytes(pending.instance, bytes.data(), bytes.size())
        || detail::shared::field<Address>(bytes, 0) != pending.root
        || detail::shared::field<std::uint64_t>(bytes, 8) != pending.value.actor
        || detail::shared::field<std::uint64_t>(bytes, 0x10) != pending.value.recipient
        || detail::shared::field<std::int32_t>(bytes, 0x34) != pending.value.input
        || detail::shared::field<std::int8_t>(bytes, 0x24) != pending.value.adjustment
        || bytes[0x44] != 2 || bytes[0x45] != (pending.flags & 0xfe)
        || !detail::ownership(copy, pending)
        || !copy.value(pending.context.module + 0x233fe58, game) || game != pending.game
        || !copy.value(game + 0x1dd0, date) || date != pending.context.date
        || !copy.value(game + 0x1dd4, floor) || floor != pending.date_floor
        || !copy.value(pending.context.module + 0x1fd13c4, sentinel) || sentinel != pending.sentinel
        || !copy.value(pending.context.module + 0x233dc88, configuration_a)
        || configuration_a != pending.value.configuration_a
        || !copy.value(pending.context.module + 0x233dd8c, configuration_b)
        || configuration_b != pending.value.configuration_b) return false;
    output = pending.value;
    return true;
}
} // namespace information::truce_expiry
