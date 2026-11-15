#ifndef INFORMATION_BATTLE_DISPLAY_CONTEXT_LAYOUT_H
#define INFORMATION_BATTLE_DISPLAY_CONTEXT_LAYOUT_H

// Pointer-free, event-bound copies. A copied client definition/cache is not a
// rendered window or a country knowledge decision. Raw popup kind is dynamic.
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <type_traits>

namespace information::battle::display_context {

inline constexpr std::size_t kFieldCount = 7;
inline constexpr std::size_t kArenaBytes = 32768;
inline constexpr std::size_t kMaxTextBytes = 8192;
inline constexpr std::size_t kMaxDefinitionKeyBytes = 64;
inline constexpr std::size_t kMaxLanguageBytes = 256;
inline constexpr std::uint8_t kRouterScopeExit = 3;

enum class State : std::uint8_t { unknown = 0, observed = 1, absent = 2 };
enum class Failure : std::uint16_t {
    none = 0, not_captured = 1, invalid_input = 2, read_failed = 3,
    definition_missing = 4, cache_invalid = 5, budget = 6,
    source_changed = 7, guard = 8, ambiguous_scope = 9,
};
enum class Field : std::uint8_t {
    definition_key = 1, language = 2, body_template = 3,
    button1 = 4, button2 = 5, button3 = 6, compact_losses_template = 7,
};
struct Text final {
    State state = State::unknown;
    std::uint32_t offset = 0;
    std::uint32_t length = 0;
};
struct Identity final {
    std::uint64_t sequence = 0;
    std::int32_t date = 0;
    std::uint8_t kind = 0;
    std::uint8_t stage = 0;
};
struct Snapshot final {
    State state = State::unknown; // only unknown/observed at context level
    Failure failure = Failure::not_captured;
    Identity identity{};
    std::int32_t popup_kind_raw = 0;
    std::int32_t layout_raw = 0;
    std::uint8_t button_flag_raw = 0;
    std::array<Text, kFieldCount> fields{};
    std::uint32_t arena_used = 0;
    std::array<unsigned char, kArenaBytes> arena{};
};
static_assert(std::is_trivially_copyable_v<Snapshot>);

inline void clear(Snapshot& value, Failure failure = Failure::not_captured) noexcept {
    value = Snapshot{};
    value.identity = Identity{};
    value.identity.stage = 0;
    value.failure = failure;
}
inline std::size_t field_limit(std::size_t index) noexcept {
    return index == 0 ? kMaxDefinitionKeyBytes
        : index == 1 ? kMaxLanguageBytes : kMaxTextBytes;
}
inline bool valid(const Snapshot& value) noexcept {
    const auto failure = static_cast<std::uint16_t>(value.failure);
    if (failure > static_cast<std::uint16_t>(Failure::ambiguous_scope)
            || value.arena_used > kArenaBytes) return false;
    if (value.state == State::unknown) {
        if (failure == 0 || value.identity.sequence || value.identity.date
                || value.identity.kind || value.identity.stage
                || value.popup_kind_raw || value.layout_raw || value.button_flag_raw
                || value.arena_used) return false;
        for (const auto& text : value.fields)
            if (text.state != State::unknown || text.offset || text.length) return false;
        return true;
    }
    if (value.state != State::observed || value.failure != Failure::none
            || value.identity.sequence == 0
            || (value.identity.kind != 1 && value.identity.kind != 2)
            || value.identity.stage < 1 || value.identity.stage > kRouterScopeExit) return false;
    std::size_t cursor = 0;
    for (std::size_t index = 0; index < kFieldCount; ++index) {
        const auto& text = value.fields[index];
        if (text.state != State::observed) {
            if (text.state != State::unknown && text.state != State::absent) return false;
            if (text.offset || text.length) return false;
            continue;
        }
        if (text.offset != cursor || text.length > field_limit(index)
                || text.length > value.arena_used - cursor) return false;
        if (std::memchr(value.arena.data() + cursor, 0, text.length)) return false;
        cursor += text.length;
    }
    if (cursor != value.arena_used || value.fields[0].state != State::observed
            || value.fields[1].state != State::observed) return false;
    const char* expected = value.identity.kind == 1 ? "LANDBATTLEOVER" : "NAVALBATTLEOVER";
    const auto& key = value.fields[0];
    if (key.length != std::strlen(expected)
            || std::memcmp(value.arena.data() + key.offset, expected, key.length)) return false;
    const auto& language = value.fields[1];
    if (language.length < 3 || value.arena[language.offset] != 'l'
            || value.arena[language.offset + 1] != '_') return false;
    for (std::size_t i = 2; i < language.length; ++i) {
        const auto byte = value.arena[language.offset + i];
        if (!((byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z')
                || (byte >= '0' && byte <= '9') || byte == '_')) return false;
    }
    return true;
}

} // namespace information::battle::display_context
#endif
