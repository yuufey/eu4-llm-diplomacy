#ifndef INFORMATION_BATTLE_INDEPENDENT_LINE_WIRE_H
#define INFORMATION_BATTLE_INDEPENDENT_LINE_WIRE_H

// IBOW14 carries an independently requested formatter output. The embedded
// battle record and its actual popup/Line1 observations retain their meaning.
#include "information-battle-outcome-tail-wire.h"

namespace information::battle::independent_line_wire {
namespace previous = outcome_tail_wire;
namespace bytes = previous::bytes;
using EncodeResult = previous::EncodeResult;
using Text = previous::Text;
using State = previous::State;
inline constexpr std::size_t kFieldCount = 5;
inline constexpr std::size_t kFixedBodyBytes = 17;
inline constexpr std::size_t kMaxWireBytes = previous::kMaxWireBytes;
enum Field : std::size_t { language, definition_key, body_template, name_input, output };
struct Snapshot final {
    std::uint64_t sequence = 0;
    std::int32_t raw_date = 0;
    std::uint8_t kind = 0;
    State state = State::unknown;
    std::uint8_t failure = 1;
    std::uint8_t transform_mode = 0;
    std::uint8_t flags = 0;
    std::array<Text, kFieldCount> fields{};
};
static_assert(std::is_trivially_copyable_v<Snapshot>);

namespace detail {
using Identity = previous::detail::BaseIdentity;
inline bool base_identity(const unsigned char* base, std::size_t size, Identity& identity) noexcept {
    return previous::validate(base, size)
        && previous::detail::base_identity(base + 10, bytes::get_u32(base + 6), identity);
}
inline std::size_t field_limit(std::size_t index) noexcept {
    return index == language ? 256 : index == definition_key ? 64 : 8192;
}
inline bool valid_fields(const Snapshot& value) noexcept {
    const bool known = value.state == State::known;
    if ((!known && value.state != State::unknown) || value.failure > 12 || value.flags > 15
            || ((value.flags & 6) && !(value.flags & 1))) return false;
    if (known ? (value.failure != 0 || value.flags != 15
                    || (value.transform_mode != 1 && value.transform_mode != 2))
              : (value.failure == 0 || value.transform_mode != 0)) return false;
    for (std::size_t index = 0; index < kFieldCount; ++index) {
        const auto& field = value.fields[index];
        if (field.state != (known ? State::known : State::unknown)
                || field.length > field_limit(index)
                || (!known && field.length)
                || std::memchr(field.bytes.data(), 0, field.length)) return false;
    }
    if (!known) return true;
    const auto& lang = value.fields[language];
    const auto& key = value.fields[definition_key];
    const auto& text = value.fields[body_template];
    const char* expected = value.kind == 1 ? "LANDBATTLEOVER" : "NAVALBATTLEOVER";
    return previous::detail::language_valid(lang.bytes.data(), lang.length)
        && key.length == std::strlen(expected)
        && !std::memcmp(key.bytes.data(), expected, key.length)
        && text.length == 6 && !std::memcmp(text.bytes.data(), "$NAME$", 6);
}
inline bool valid_snapshot(const Snapshot& value, const Identity& identity) noexcept {
    return identity.sequence && identity.raw_date >= 0 && (identity.kind == 1 || identity.kind == 2)
        && value.sequence == identity.sequence && value.raw_date == identity.raw_date
        && value.kind == identity.kind && valid_fields(value);
}
inline std::size_t body_size(const Snapshot& value) noexcept {
    std::size_t size = kFixedBodyBytes + 3 * kFieldCount;
    for (const auto& field : value.fields) size += field.length;
    return size;
}
inline bool disjoint(const unsigned char* base, std::size_t base_size,
                     const Snapshot& snapshot, unsigned char* result, std::size_t size) noexcept {
    previous::Address b = 0, be = 0, s = 0, se = 0, r = 0, re = 0;
    return previous::detail::pointer_range(base, base_size, b, be)
        && previous::detail::pointer_range(&snapshot, sizeof(snapshot), s, se)
        && previous::detail::pointer_range(result, size, r, re)
        && !previous::detail::overlaps(b, be, s, se)
        && !previous::detail::overlaps(b, be, r, re)
        && !previous::detail::overlaps(s, se, r, re);
}
} // namespace detail

inline EncodeResult encode(const unsigned char* base, std::size_t base_size,
                           const Snapshot& snapshot, unsigned char* result,
                           std::size_t capacity) noexcept {
    detail::Identity identity{};
    if (!detail::base_identity(base, base_size, identity)
            || !detail::valid_snapshot(snapshot, identity)) return {};
    const auto body_size = detail::body_size(snapshot);
    const auto total = 20 + base_size + body_size;
    if (total > kMaxWireBytes || capacity < total || !result
            || !detail::disjoint(base, base_size, snapshot, result, total)) return {};
    auto* cursor = result;
    std::memcpy(cursor, "IBOW", 4); cursor += 4;
    bytes::put_u16(cursor, 14);
    bytes::put_u32(cursor, static_cast<std::uint32_t>(base_size));
    std::memcpy(cursor, base, base_size); cursor += base_size;
    std::memcpy(cursor, "IFMT", 4); cursor += 4;
    bytes::put_u16(cursor, 1);
    bytes::put_u32(cursor, static_cast<std::uint32_t>(body_size));
    bytes::put_u64(cursor, snapshot.sequence);
    bytes::put_u32(cursor, static_cast<std::uint32_t>(snapshot.raw_date));
    *cursor++ = snapshot.kind;
    *cursor++ = static_cast<unsigned char>(snapshot.state);
    *cursor++ = snapshot.failure;
    *cursor++ = snapshot.transform_mode;
    *cursor++ = snapshot.flags;
    for (const auto& field : snapshot.fields) {
        *cursor++ = static_cast<unsigned char>(field.state);
        bytes::put_u16(cursor, static_cast<std::uint16_t>(field.length));
        std::memcpy(cursor, field.bytes.data(), field.length); cursor += field.length;
    }
    return {total};
}

inline bool validate(const unsigned char* frame, std::size_t size) noexcept {
    if (!frame || size > kMaxWireBytes || size < 20 + kFixedBodyBytes + 3 * kFieldCount
            || std::memcmp(frame, "IBOW", 4) || bytes::get_u16(frame + 4) != 14) return false;
    const auto base_size = bytes::get_u32(frame + 6);
    if (base_size > size - 20) return false;
    detail::Identity identity{};
    if (!detail::base_identity(frame + 10, base_size, identity)) return false;
    const auto* extension = frame + 10 + base_size;
    if (std::memcmp(extension, "IFMT", 4) || bytes::get_u16(extension + 4) != 1
            || bytes::get_u32(extension + 6) != size - base_size - 20) return false;
    const auto* cursor = extension + 10;
    const auto* end = frame + size;
    if (end - cursor < static_cast<std::ptrdiff_t>(kFixedBodyBytes)) return false;
    Snapshot value{};
    value.sequence = bytes::get_u64(cursor); cursor += 8;
    value.raw_date = static_cast<std::int32_t>(bytes::get_u32(cursor)); cursor += 4;
    value.kind = *cursor++;
    value.state = static_cast<State>(*cursor++);
    value.failure = *cursor++;
    value.transform_mode = *cursor++;
    value.flags = *cursor++;
    for (std::size_t index = 0; index < kFieldCount; ++index) {
        if (end - cursor < 3) return false;
        auto& field = value.fields[index];
        field.state = static_cast<State>(*cursor++);
        field.length = bytes::get_u16(cursor); cursor += 2;
        if (field.length > detail::field_limit(index)
                || end - cursor < static_cast<std::ptrdiff_t>(field.length)) return false;
        std::memcpy(field.bytes.data(), cursor, field.length); cursor += field.length;
    }
    return cursor == end && detail::valid_snapshot(value, identity);
}
} // namespace information::battle::independent_line_wire
#endif
