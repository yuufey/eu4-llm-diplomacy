#ifndef INFORMATION_BATTLE_FLAG_INPUT_WIRE_H
#define INFORMATION_BATTLE_FLAG_INPUT_WIRE_H
#include "information-battle-independent-line-wire.h"

namespace information::battle::flag_input_wire {
namespace previous = independent_line_wire;
namespace bytes = previous::bytes;
namespace ranges = previous::previous::detail;
using EncodeResult = previous::EncodeResult;
inline constexpr std::size_t kMaxEntries = 128;
inline constexpr std::size_t kFixedBodyBytes = 17;
inline constexpr std::size_t kEntryBytes = 16;
inline constexpr std::size_t kMaxWireBytes = previous::kMaxWireBytes;
enum class State : std::uint8_t { unknown = 0, known = 1, not_applicable = 2 };
enum class Mode : std::uint8_t { numeric = 1, country = 2, rebel = 3 };
struct Entry final {
    std::uint16_t pair_index = 0;
    std::uint8_t side = 0;
    Mode mode = Mode::numeric;
    std::uint64_t country_ref = 0;
    std::uint32_t rebel_raw = 0;
};
struct Snapshot final {
    std::uint64_t sequence = 0;
    std::int32_t raw_date = 0;
    std::uint8_t kind = 0;
    State state = State::unknown;
    std::uint8_t failure = 1;
    std::uint16_t entry_count = 0;
    std::array<Entry, kMaxEntries> entries{};
};
static_assert(std::is_trivially_copyable_v<Snapshot>);
namespace detail {
using Identity = previous::detail::Identity;
inline bool country_ref(std::uint64_t value) noexcept {
    if (!(value >> 56) || ((value >> 24) & 255)) return false;
    for (unsigned shift = 0; shift < 24; shift += 8) {
        const auto byte = static_cast<unsigned char>(value >> shift);
        if (!((byte >= 'A' && byte <= 'Z') || (byte >= '0' && byte <= '9'))) return false;
    }
    return true;
}
inline bool valid_fields(const Snapshot& value) noexcept {
    if (value.failure > 8 || value.entry_count > kMaxEntries) return false;
    if (value.state == State::unknown) return value.failure && !value.entry_count;
    if (value.failure) return false;
    if (value.state == State::not_applicable) return value.kind == 2 && !value.entry_count;
    if (value.state != State::known || value.kind != 1) return false;
    for (std::size_t index = 0; index < value.entry_count; ++index) {
        const auto& item = value.entries[index];
        if (item.pair_index >= kMaxEntries || item.side > 1
                || (index && item.pair_index <= value.entries[index - 1].pair_index)) return false;
        if (item.mode == Mode::country) {
            if (!country_ref(item.country_ref) || item.rebel_raw) return false;
        } else if (item.mode == Mode::rebel) {
            if (item.country_ref) return false;
        } else if (item.mode != Mode::numeric || item.country_ref || item.rebel_raw) return false;
    }
    return true;
}
inline bool base_identity(const unsigned char* base, std::size_t size, Identity& identity) noexcept {
    return previous::validate(base, size)
        && previous::detail::base_identity(base + 10, bytes::get_u32(base + 6), identity);
}
inline bool valid_snapshot(const Snapshot& value, const Identity& identity) noexcept {
    return identity.sequence && identity.raw_date >= 0 && (identity.kind == 1 || identity.kind == 2)
        && value.sequence == identity.sequence && value.raw_date == identity.raw_date
        && value.kind == identity.kind && valid_fields(value);
}
inline bool disjoint(const unsigned char* base, std::size_t base_size,
                     const Snapshot& snapshot, unsigned char* output, std::size_t size) noexcept {
    previous::previous::Address b = 0, be = 0, s = 0, se = 0, o = 0, oe = 0;
    return ranges::pointer_range(base, base_size, b, be)
        && ranges::pointer_range(&snapshot, sizeof(snapshot), s, se)
        && ranges::pointer_range(output, size, o, oe)
        && !ranges::overlaps(b, be, s, se) && !ranges::overlaps(b, be, o, oe)
        && !ranges::overlaps(s, se, o, oe);
}
} // namespace detail
inline bool validate(const unsigned char* frame, std::size_t size) noexcept;
inline EncodeResult encode(const unsigned char* base, std::size_t base_size, const Snapshot& snapshot,
                           unsigned char* output, std::size_t capacity) noexcept {
    detail::Identity identity{};
    if (!detail::base_identity(base, base_size, identity) || !detail::valid_snapshot(snapshot, identity)) return {};
    const std::size_t body_size = kFixedBodyBytes + kEntryBytes * snapshot.entry_count;
    const std::size_t total = 20 + base_size + body_size;
    if (total > kMaxWireBytes || capacity < total || !output
            || !detail::disjoint(base, base_size, snapshot, output, total)) return {};
    auto* cursor = output;
    std::memcpy(cursor, "IBOW", 4); cursor += 4;
    bytes::put_u16(cursor, 15); bytes::put_u32(cursor, static_cast<std::uint32_t>(base_size));
    std::memcpy(cursor, base, base_size); cursor += base_size;
    std::memcpy(cursor, "FLAG", 4); cursor += 4;
    bytes::put_u16(cursor, 1); bytes::put_u32(cursor, static_cast<std::uint32_t>(body_size));
    bytes::put_u64(cursor, snapshot.sequence); bytes::put_u32(cursor, static_cast<std::uint32_t>(snapshot.raw_date));
    *cursor++ = snapshot.kind; *cursor++ = static_cast<unsigned char>(snapshot.state); *cursor++ = snapshot.failure;
    bytes::put_u16(cursor, snapshot.entry_count);
    for (std::size_t index = 0; index < snapshot.entry_count; ++index) {
        const auto& entry = snapshot.entries[index];
        bytes::put_u16(cursor, entry.pair_index); *cursor++ = entry.side; *cursor++ = static_cast<unsigned char>(entry.mode);
        bytes::put_u64(cursor, entry.country_ref); bytes::put_u32(cursor, entry.rebel_raw);
    }
    return {total};
}
inline bool validate(const unsigned char* frame, std::size_t size) noexcept {
    if (!frame || size < 20 + kFixedBodyBytes || size > kMaxWireBytes
            || std::memcmp(frame, "IBOW", 4) || bytes::get_u16(frame + 4) != 15) return false;
    const auto base_size = bytes::get_u32(frame + 6);
    if (base_size > size - 20 - kFixedBodyBytes) return false;
    detail::Identity identity{};
    if (!detail::base_identity(frame + 10, base_size, identity)) return false;
    const auto* cursor = frame + 10 + base_size;
    if (std::memcmp(cursor, "FLAG", 4) || bytes::get_u16(cursor + 4) != 1
            || bytes::get_u32(cursor + 6) != size - base_size - 20) return false;
    cursor += 10;
    Snapshot value{};
    value.sequence = bytes::get_u64(cursor); cursor += 8;
    value.raw_date = static_cast<std::int32_t>(bytes::get_u32(cursor)); cursor += 4;
    value.kind = *cursor++; value.state = static_cast<State>(*cursor++); value.failure = *cursor++;
    value.entry_count = bytes::get_u16(cursor); cursor += 2;
    if (value.entry_count > kMaxEntries || size - base_size - 20 != kFixedBodyBytes + kEntryBytes * value.entry_count) return false;
    for (std::size_t index = 0; index < value.entry_count; ++index) {
        auto& entry = value.entries[index];
        entry.pair_index = bytes::get_u16(cursor); cursor += 2;
        entry.side = *cursor++; entry.mode = static_cast<Mode>(*cursor++);
        entry.country_ref = bytes::get_u64(cursor); cursor += 8;
        entry.rebel_raw = bytes::get_u32(cursor); cursor += 4;
    }
    return detail::valid_snapshot(value, identity);
}
} // namespace information::battle::flag_input_wire
#endif
