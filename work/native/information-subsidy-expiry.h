#pragma once

#include "information-country-modifier-add.h"
#include "information-subsidy-expiry-native-guards.h"

namespace information::subsidy_expiry {

using Address = std::uintptr_t;
inline constexpr Address kRemovalRva = 0xa62df0;
inline constexpr Address kCleanupReturnRva = 0x4e1adb;
inline constexpr Address kMonthlyCleanupReturnRva = 0xa6c9dc;
inline constexpr Address kRecordTableRva = 0x1c815d8;

inline bool is_cleanup_return(Address module, Address caller) noexcept {
    return caller == module + kCleanupReturnRva || caller == module + kMonthlyCleanupReturnRva;
}

struct Context final {
    Address module = 0;
    std::int32_t date = 0;
    bool bound_frame_thread = false;
};

struct Value final {
    std::uint64_t payer = 0, recipient = 0, observer = 0;
    std::int32_t date = 0, start = 0, end = 0, amount = 0, years = 0;
};

struct Pending final {
    Context context{};
    Address instance = 0;
    Value value{};
    bool ready = false;
};

enum class Decision : unsigned char { ignored, ready, unreadable };

namespace detail {
namespace shared = information::country_modifier::detail;

template<class Reader>
bool canonical(shared::Copy<Reader>& copy, Address module, std::uint64_t reference) noexcept {
    const auto slot = static_cast<std::uint32_t>((reference >> 32) & 0xffff);
    Address database = 0, table = 0, country = 0;
    std::uint64_t actual = 0;
    return slot < 4096
        && copy.value(module + 0x233d8b0, database)
        && shared::range(database, 0x120)
        && copy.value(database + 0x118, table)
        && shared::range(table, (slot + 1) * 8)
        && copy.value(table + slot * 8, country)
        && shared::range(country, 0x28)
        && copy.value(country + 0x20, actual) && actual == reference;
}

inline Value value(const std::array<unsigned char, 0x48>& bytes, const Context& context) noexcept {
    Value result{};
    result.payer = shared::field<std::uint64_t>(bytes, 0x10);
    result.recipient = shared::field<std::uint64_t>(bytes, 0x18);
    result.observer = (result.payer & 0xffffff) == 0x415246 ? result.payer : result.recipient;
    result.date = context.date;
    result.start = shared::field<std::int32_t>(bytes, 0x20);
    result.amount = shared::field<std::int32_t>(bytes, 0x40);
    result.years = shared::field<std::int32_t>(bytes, 0x44);
    const std::uint32_t end = static_cast<std::uint32_t>(result.start)
        + static_cast<std::uint32_t>(result.years) * 8760u;
    std::memcpy(&result.end, &end, sizeof(end));
    return result;
}

inline bool same(const Value& first, const Value& second) noexcept {
    return first.payer == second.payer && first.recipient == second.recipient
        && first.observer == second.observer && first.start == second.start
        && first.end == second.end && first.amount == second.amount && first.years == second.years;
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
    return detail::shared::range(module, 0x233fe60)
        && detail::guard(copy, module + kPredicateRva, kPredicateBytes)
        && detail::guard(copy, module + kCleanupRva, kCleanupBytes)
        && detail::guard(copy, module + kMonthlyCleanupRva, kMonthlyCleanupBytes);
}

template<class Reader>
Decision begin(Reader& reader, const Context& context, Address instance,
               Address caller_return, Pending& pending) noexcept {
    pending = {};
    if (!context.bound_frame_thread || context.date < 0
        || !detail::shared::range(context.module, 0x233fe60)
        || !is_cleanup_return(context.module, caller_return)) return Decision::ignored;
    detail::shared::Copy<Reader> copy(reader);
    std::array<unsigned char, 0x48> bytes{};
    if (!copy.bytes(instance, bytes.data(), bytes.size())) return Decision::unreadable;
    if (detail::shared::field<Address>(bytes, 0) != context.module + kRecordTableRva)
        return Decision::ignored;
    const Value value = detail::value(bytes, context);
    if ((value.observer & 0xffffff) != 0x415246 || value.payer == value.recipient
        || bytes[0x28] != 0 || context.date <= value.end) return Decision::ignored;
    if (!detail::canonical(copy, context.module, value.payer)
        || !detail::canonical(copy, context.module, value.recipient)) return Decision::unreadable;
    pending = {context, instance, value, true};
    return Decision::ready;
}

template<class Reader>
bool finish(Reader& reader, const Pending& pending, Value& output) noexcept {
    if (!pending.ready) return false;
    detail::shared::Copy<Reader> copy(reader);
    std::array<unsigned char, 0x48> bytes{};
    Address game = 0;
    std::int32_t date = 0;
    if (!copy.bytes(pending.instance, bytes.data(), bytes.size())
        || detail::shared::field<Address>(bytes, 0) != pending.context.module + kRecordTableRva
        || bytes[0x28] != 1 || !detail::same(pending.value, detail::value(bytes, pending.context))
        || !detail::canonical(copy, pending.context.module, pending.value.payer)
        || !detail::canonical(copy, pending.context.module, pending.value.recipient)
        || !copy.value(pending.context.module + 0x233fe58, game)
        || !detail::shared::range(game, 0x1dd4)
        || !copy.value(game + 0x1dd0, date) || date != pending.context.date) return false;
    output = pending.value;
    return true;
}
} // namespace information::subsidy_expiry
