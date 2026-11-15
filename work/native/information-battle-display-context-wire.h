#ifndef INFORMATION_BATTLE_DISPLAY_CONTEXT_WIRE_H
#define INFORMATION_BATTLE_DISPLAY_CONTEXT_WIRE_H

// IBOW v7 value-only extension. The complete v6 frame is embedded byte-for-
// byte; DCTX contains only the bounded same-event display-context snapshot.
// This encoder does not call engine code, allocate, perform I/O, or retain
// pointers into the source snapshot.

#include "information-battle-display-context-layout.h"
#include "information-battle-native-text-wire.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <type_traits>

namespace information::battle::display_context_wire {

namespace layout = information::battle::display_context;
namespace native_text = information::battle::native_text_wire;
using Address = std::uintptr_t;

inline constexpr std::array<unsigned char, 4> kMagic{{'I', 'B', 'O', 'W'}};
inline constexpr std::array<unsigned char, 4> kExtensionMagic{{'D', 'C', 'T', 'X'}};
inline constexpr std::uint16_t kVersion = 7u;
inline constexpr std::uint16_t kExtensionVersion = 1u;
inline constexpr std::size_t kMaxWireBytes = 512u * 1024u;
inline constexpr std::size_t kMaxExtensionArenaBytes = layout::kArenaBytes;
inline constexpr std::size_t kOuterHeaderBytes = 4u + 2u + 4u;
inline constexpr std::size_t kExtensionHeaderBytes = 4u + 2u + 4u;
inline constexpr std::size_t kFixedBodyBytes = 27u;
inline constexpr std::size_t kEntryHeaderBytes = 8u;
inline constexpr std::size_t kEntryCount = layout::kFieldCount;

// Build metadata only; these values are not emitted as wire fields.
inline constexpr char kTargetGameVersion[] = "1.37.4";
inline constexpr char kTargetExecutableSha256[] =
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77";

enum class FieldId : std::uint8_t {
    definition_key = 1u,
    language = 2u,
    body_template = 3u,
    button1 = 4u,
    button2 = 5u,
    button3 = 6u,
    compact_losses_template = 7u,
};

struct EncodeResult final {
    std::size_t written_bytes = 0u;

    bool succeeded() const noexcept { return written_bytes != 0u; }
};

static_assert(std::is_trivially_copyable<EncodeResult>::value,
              "encode result must be a value type");
static_assert(kEntryCount == 7u, "wire v7 has exactly seven fields");

namespace detail {

inline bool checked_add(std::size_t left, std::size_t right,
                        std::size_t& result) noexcept {
    if (left > (std::numeric_limits<std::size_t>::max)() - right) {
        return false;
    }
    result = left + right;
    return true;
}

inline bool pointer_range(const void* pointer, std::size_t size,
                          Address& begin, Address& end) noexcept {
    if (pointer == nullptr || size == 0u) {
        return false;
    }
    begin = reinterpret_cast<Address>(pointer);
    if (begin > (std::numeric_limits<Address>::max)()
            - static_cast<Address>(size)) {
        return false;
    }
    end = begin + static_cast<Address>(size);
    return end > begin;
}

inline bool overlaps(Address left_begin, Address left_end,
                     Address right_begin, Address right_end) noexcept {
    return left_begin < right_end && right_begin < left_end;
}

inline void put_u8(unsigned char*& output, std::uint8_t value) noexcept {
    *output++ = value;
}

inline void put_u16(unsigned char*& output, std::uint16_t value) noexcept {
    output[0] = static_cast<unsigned char>(value & 0xffu);
    output[1] = static_cast<unsigned char>((value >> 8u) & 0xffu);
    output += 2u;
}

inline void put_u32(unsigned char*& output, std::uint32_t value) noexcept {
    for (unsigned index = 0u; index < 4u; ++index) {
        output[index] = static_cast<unsigned char>(
            (value >> (index * 8u)) & 0xffu);
    }
    output += 4u;
}

inline void put_u64(unsigned char*& output, std::uint64_t value) noexcept {
    for (unsigned index = 0u; index < 8u; ++index) {
        output[index] = static_cast<unsigned char>(
            (value >> (index * 8u)) & 0xffu);
    }
    output += 8u;
}

inline void put_i32(unsigned char*& output, std::int32_t value) noexcept {
    put_u32(output, static_cast<std::uint32_t>(value));
}

inline bool valid_base6(const unsigned char* base6,
                        std::size_t base6_bytes) noexcept {
    return base6 != nullptr && base6_bytes != 0u
        && base6_bytes <= kMaxWireBytes
        && native_text::validate(base6, base6_bytes);
}

inline bool extension_body_size(const layout::Snapshot& snapshot,
                                std::size_t& body_bytes) noexcept {
    if (!layout::valid(snapshot)
            || snapshot.arena_used > kMaxExtensionArenaBytes) {
        return false;
    }
    std::size_t headers = 0u;
    if (kEntryCount > (std::numeric_limits<std::size_t>::max)()
            / kEntryHeaderBytes) {
        return false;
    }
    headers = kEntryCount * kEntryHeaderBytes;
    body_bytes = kFixedBodyBytes;
    return checked_add(body_bytes, headers, body_bytes)
        && checked_add(body_bytes, snapshot.arena_used, body_bytes)
        && body_bytes <= static_cast<std::size_t>(
            (std::numeric_limits<std::uint32_t>::max)());
}

inline bool total_size(const unsigned char* base6,
                       std::size_t base6_bytes,
                       const layout::Snapshot& snapshot,
                       std::size_t& required,
                       std::size_t& body_bytes) noexcept {
    if (!valid_base6(base6, base6_bytes)
            || !extension_body_size(snapshot, body_bytes)) {
        return false;
    }
    required = kOuterHeaderBytes;
    if (!checked_add(required, base6_bytes, required)
            || !checked_add(required, kExtensionHeaderBytes, required)
            || !checked_add(required, body_bytes, required)
            || required > kMaxWireBytes) {
        return false;
    }
    return true;
}

inline bool disjoint_ranges(const unsigned char* base6,
                            std::size_t base6_bytes,
                            const layout::Snapshot& snapshot,
                            unsigned char* output,
                            std::size_t output_bytes) noexcept {
    Address base_begin = 0u, base_end = 0u;
    Address snapshot_begin = 0u, snapshot_end = 0u;
    Address output_begin = 0u, output_end = 0u;
    if (!pointer_range(base6, base6_bytes, base_begin, base_end)
            || !pointer_range(&snapshot, sizeof(snapshot),
                              snapshot_begin, snapshot_end)
            || !pointer_range(output, output_bytes, output_begin, output_end)) {
        return false;
    }
    return !overlaps(base_begin, base_end, snapshot_begin, snapshot_end)
        && !overlaps(base_begin, base_end, output_begin, output_end)
        && !overlaps(snapshot_begin, snapshot_end, output_begin, output_end);
}

inline void write_entry(unsigned char*& cursor, std::size_t index,
                        const layout::Text& field,
                        const layout::Snapshot& snapshot) noexcept {
    put_u8(cursor, static_cast<std::uint8_t>(index + 1u));
    put_u8(cursor, static_cast<std::uint8_t>(field.state));
    put_u16(cursor, 0u);
    put_u32(cursor, field.length);
    if (field.state == layout::State::observed && field.length != 0u) {
        std::memcpy(cursor, snapshot.arena.data() + field.offset, field.length);
        cursor += field.length;
    }
}

}  // namespace detail

inline std::size_t encoded_size(const unsigned char* base6,
                                std::size_t base6_bytes,
                                const layout::Snapshot& snapshot) noexcept {
    std::size_t required = 0u;
    std::size_t body_bytes = 0u;
    return detail::total_size(base6, base6_bytes, snapshot, required,
                              body_bytes)
        ? required : 0u;
}

inline EncodeResult encode(const unsigned char* base6,
                           std::size_t base6_bytes,
                           const layout::Snapshot& snapshot,
                           unsigned char* output,
                           std::size_t capacity) noexcept {
    // Validate all input, output capacity and alias ranges before touching a
    // byte. The serializer has no remaining failure branch after this point.
    std::size_t required = 0u;
    std::size_t body_bytes = 0u;
    if (output == nullptr
            || !detail::total_size(base6, base6_bytes, snapshot, required,
                                   body_bytes)
            || capacity < required
            || !detail::disjoint_ranges(base6, base6_bytes, snapshot,
                                        output, required)) {
        return {};
    }

    unsigned char* cursor = output;
    std::memcpy(cursor, kMagic.data(), kMagic.size());
    cursor += kMagic.size();
    detail::put_u16(cursor, kVersion);
    detail::put_u32(cursor, static_cast<std::uint32_t>(base6_bytes));
    std::memcpy(cursor, base6, base6_bytes);
    cursor += base6_bytes;
    std::memcpy(cursor, kExtensionMagic.data(), kExtensionMagic.size());
    cursor += kExtensionMagic.size();
    detail::put_u16(cursor, kExtensionVersion);
    detail::put_u32(cursor, static_cast<std::uint32_t>(body_bytes));

    detail::put_u8(cursor, static_cast<std::uint8_t>(snapshot.state));
    detail::put_u8(cursor, snapshot.identity.stage);
    detail::put_u16(cursor, static_cast<std::uint16_t>(snapshot.failure));
    detail::put_u64(cursor, snapshot.identity.sequence);
    detail::put_i32(cursor, snapshot.identity.date);
    detail::put_u8(cursor, snapshot.identity.kind);
    detail::put_i32(cursor, snapshot.popup_kind_raw);
    detail::put_i32(cursor, snapshot.layout_raw);
    detail::put_u8(cursor, snapshot.button_flag_raw);
    detail::put_u8(cursor, static_cast<std::uint8_t>(kEntryCount));

    for (std::size_t index = 0u; index < kEntryCount; ++index) {
        detail::write_entry(cursor, index, snapshot.fields[index], snapshot);
    }
    return EncodeResult{required};
}

}  // namespace information::battle::display_context_wire

#endif  // INFORMATION_BATTLE_DISPLAY_CONTEXT_WIRE_H
