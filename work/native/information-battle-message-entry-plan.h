#ifndef INFORMATION_BATTLE_MESSAGE_ENTRY_PLAN_H
#define INFORMATION_BATTLE_MESSAGE_ENTRY_PLAN_H

// Fixed-build, value-only plans for the three already-scoped 1.37.4 entries.
// This component only validates copied PE bytes and builds an owned image.  It
// does not allocate executable memory, install a patch, register a runtime
// function, or retain any source pointer.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>

namespace information::battle::message_entry {

using Address = std::uintptr_t;

inline constexpr Address kStaticImageBase = UINT64_C(0x0000000140000000);
inline constexpr Address kMaxUserAddress = UINT64_C(0x0000800000000000);
inline constexpr std::size_t kMaxImageBytes = 128u;
inline constexpr std::size_t kMaxPrefixBytes = 32u;
inline constexpr std::size_t kMaxUnwindBytes = 32u;
inline constexpr std::size_t kMaxPatchBytes = 26u;
inline constexpr std::size_t kAbsoluteJumpBytes = 14u;
inline constexpr std::size_t kHomeSlotJumpBytes = 29u;
inline constexpr std::size_t kUnwindOffset = 64u;
inline constexpr std::uint32_t kHomeSlotOffset = 0x18u;

enum class EntryKind : std::uint8_t {
    router = 0,
    message = 1,
    cleanup = 2,
};

struct Spec final {
    EntryKind kind = EntryKind::router;
    std::uint32_t rva = 0u;
    std::uint32_t end_rva = 0u;
    std::uint32_t unwind_rva = 0u;
    std::uint32_t stack_delta = 0u;
    std::uint32_t prefix_bytes = 0u;
    std::uint32_t unwind_bytes = 0u;
    std::uint32_t projected_unwind_bytes = 0u;
    std::uint32_t unwind_code_count = 0u;
    std::array<unsigned char, kMaxPrefixBytes> prefix{};
    std::array<unsigned char, kMaxUnwindBytes> unwind_expected{};
};

struct RuntimeFunction final {
    // All fields are image-relative PE RUNTIME_FUNCTION values.
    std::uint32_t begin = 0u;
    std::uint32_t end = 0u;
    std::uint32_t unwind = 0u;
};
static_assert(sizeof(RuntimeFunction) == 12u,
              "runtime row must match PE RUNTIME_FUNCTION");

struct Plan final {
    std::array<unsigned char, kMaxImageBytes> image{};
    std::array<unsigned char, kMaxPatchBytes> patch{};
    RuntimeFunction runtime{};
    EntryKind kind = EntryKind::router;
    std::size_t image_bytes = 0u;
    std::size_t patch_bytes = 0u;
    std::size_t prologue_bytes = 0u;
    std::size_t unwind_bytes = 0u;
    Address original_entry = 0u;
    Address continuation = 0u;
    Address hook = 0u;
};

enum class Status : std::uint8_t {
    prepared,
    invalid_kind,
    invalid_address,
    invalid_identity,
    invalid_buffer,
    input_alias,
    output_alias,
    prologue_mismatch,
    unwind_mismatch,
    image_overflow,
};

namespace detail {

constexpr std::array<unsigned char, kMaxPrefixBytes> router_prefix() noexcept {
    return {{
        0x48u,0x89u,0x5cu,0x24u,0x10u,0x55u,0x56u,0x57u,
        0x41u,0x54u,0x41u,0x55u,0x41u,0x56u,0x41u,0x57u,
        0x48u,0x8bu,0xecu,0x48u,0x81u,0xecu,0x80u,0x00u,
        0x00u,0x00u,
    }};
}

constexpr std::array<unsigned char, kMaxPrefixBytes> message_prefix() noexcept {
    // The ordinary PE window is exact and contiguous.  MOV RBX,RDX occupies
    // bytes 13..15; TEST R8,R8 starts at RVA 0x244643 and is outside this
    // 16-byte prefix.
    return {{
        0x48u,0x89u,0x54u,0x24u,0x10u,0x53u,0x48u,0x81u,
        0xecu,0x00u,0x01u,0x00u,0x00u,0x48u,0x8bu,0xdau,
    }};
}

constexpr std::array<unsigned char, kMaxUnwindBytes> router_unwind() noexcept {
    return {{
        0x11u,0x1au,0x0au,0x00u,
        0x1au,0x34u,0x19u,0x00u,0x1au,0xf2u,0x10u,0xf0u,
        0x0eu,0xe0u,0x0cu,0xd0u,0x0au,0xc0u,0x08u,0x70u,
        0x07u,0x60u,0x06u,0x50u,0x9cu,0x4du,0xa3u,0x01u,
    }};
}

constexpr std::array<unsigned char, kMaxUnwindBytes> message_unwind() noexcept {
    return {{
        0x11u,0x0du,0x03u,0x00u,
        0x0du,0x01u,0x20u,0x00u,0x06u,0x30u,0x00u,0x00u,
        0x9cu,0x4du,0xa3u,0x01u,
    }};
}

constexpr std::array<unsigned char, kMaxPrefixBytes> cleanup_prefix() noexcept {
    // The cleanup PE ledger pins the complete 16-byte patch window.  The
    // unwind prologue is 10 bytes; the remaining MOV RSI,RCX is copied as
    // part of the fixed prefix so the native continuation starts at TEST.
    return {{
        0x48u,0x89u,0x5cu,0x24u,0x10u,0x56u,0x48u,0x83u,
        0xecu,0x20u,0x48u,0x8bu,0x19u,0x48u,0x8bu,0xf1u,
    }};
}

constexpr std::array<unsigned char, kMaxUnwindBytes> cleanup_unwind() noexcept {
    return {{
        0x01u,0x0au,0x04u,0x00u,
        0x0au,0x34u,0x07u,0x00u,0x0au,0x32u,0x06u,0x60u,
    }};
}

inline constexpr Spec kRouterSpec{
    EntryKind::router, 0x23a020u, 0x23a6b8u, 0x1de6d8cu,
    184u, 26u, 28u, 24u, 10u,
    router_prefix(), router_unwind(),
};

inline constexpr Spec kMessageSpec{
    EntryKind::message, 0x244630u, 0x2446eeu, 0x1de7940u,
    264u, 16u, 16u, 12u, 3u,
    message_prefix(), message_unwind(),
};

inline constexpr Spec kCleanupSpec{
    EntryKind::cleanup, 0x1af740u, 0x1af755u, 0x1dcad04u,
    40u, 16u, 12u, 12u, 4u,
    cleanup_prefix(), cleanup_unwind(),
};

inline bool valid_kind(EntryKind kind) noexcept {
    return kind == EntryKind::router || kind == EntryKind::message
        || kind == EntryKind::cleanup;
}

inline const Spec* try_spec(EntryKind kind) noexcept {
    if (kind == EntryKind::router) return &kRouterSpec;
    if (kind == EntryKind::message) return &kMessageSpec;
    if (kind == EntryKind::cleanup) return &kCleanupSpec;
    return nullptr;
}

inline bool valid_code_address(Address value, std::size_t extent = 1u) noexcept {
    return value >= UINT64_C(0x10000) && value < kMaxUserAddress
        && extent != 0u
        && static_cast<Address>(extent) <= kMaxUserAddress - value;
}

inline bool range_end(Address begin, std::size_t size,
                      Address& end) noexcept {
    if (size == 0u
            || begin > (std::numeric_limits<Address>::max)()
                - static_cast<Address>(size)) {
        return false;
    }
    end = begin + static_cast<Address>(size);
    return end > begin;
}

inline bool input_range(const unsigned char* pointer, std::size_t size,
                        Address& begin, Address& end) noexcept {
    if (pointer == nullptr || !range_end(
            reinterpret_cast<Address>(pointer), size, end)) {
        return false;
    }
    begin = reinterpret_cast<Address>(pointer);
    return true;
}

inline bool overlaps(Address left_begin, Address left_end,
                     Address right_begin, Address right_end) noexcept {
    return left_begin < right_end && right_begin < left_end;
}

inline void write_u32(unsigned char* output, std::uint32_t value) noexcept {
    for (unsigned shift = 0u; shift != 32u; shift += 8u) {
        output[shift / 8u] = static_cast<unsigned char>(value >> shift);
    }
}

inline void write_u64(unsigned char* output, std::uint64_t value) noexcept {
    for (unsigned shift = 0u; shift != 64u; shift += 8u) {
        output[shift / 8u] = static_cast<unsigned char>(value >> shift);
    }
}

inline void absolute_jump(unsigned char* output, Address target) noexcept {
    output[0] = 0xffu;
    output[1] = 0x25u;
    output[2] = output[3] = output[4] = output[5] = 0u;
    write_u64(output + 6u, static_cast<std::uint64_t>(target));
}

inline void home_slot_jump(unsigned char* output, std::uint32_t displacement,
                           Address target) noexcept {
    // C7 84 24 disp32 imm32 (11 bytes), twice, followed by
    // FF A4 24 disp32 (7 bytes).  The full sequence is 29 bytes and changes
    // only the third caller-owned home slot; it does not touch GPRs or flags.
    output[0] = 0xc7u; output[1] = 0x84u; output[2] = 0x24u;
    write_u32(output + 3u, displacement);
    write_u32(output + 7u, static_cast<std::uint32_t>(target));
    output[11] = 0xc7u; output[12] = 0x84u; output[13] = 0x24u;
    write_u32(output + 14u, displacement + 4u);
    write_u32(output + 18u,
              static_cast<std::uint32_t>(static_cast<std::uint64_t>(target)
                                          >> 32u));
    output[22] = 0xffu; output[23] = 0xa4u; output[24] = 0x24u;
    write_u32(output + 25u, displacement);
}

inline bool make_projected_unwind(const Spec& source,
                                   unsigned char* destination,
                                   std::size_t capacity) noexcept {
    if (destination == nullptr
            || source.projected_unwind_bytes > capacity
            || source.projected_unwind_bytes > source.unwind_bytes
            || source.projected_unwind_bytes > kMaxUnwindBytes) {
        return false;
    }
    std::memset(destination, 0, capacity);
    std::memcpy(destination, source.unwind_expected.data(),
                source.projected_unwind_bytes);
    destination[0] = static_cast<unsigned char>(destination[0] & 0x07u);
    return true;
}

}  // namespace detail

inline const Spec& spec(EntryKind kind) noexcept {
    const Spec* selected = detail::try_spec(kind);
    return selected != nullptr ? *selected : detail::kRouterSpec;
}

// Builds an owned 128-byte image and a complete prefix-length patch.  The
// input buffers are copied only after all identity, alias, and byte checks
// pass; output is unchanged on every failure.
inline Status prepare(EntryKind kind,
                      const unsigned char* readprefix,
                      std::size_t readprefix_size,
                      const unsigned char* readunwind,
                      std::size_t readunwind_size,
                      Address originalentry,
                      Address hook,
                      Plan& output) noexcept {
    const Spec* selected = detail::try_spec(kind);
    if (selected == nullptr) return Status::invalid_kind;
    const Spec& selected_spec = *selected;
    if (!detail::valid_code_address(originalentry, selected_spec.prefix_bytes)
            || !detail::valid_code_address(hook)
            || originalentry == hook) {
        return originalentry == hook ? Status::invalid_identity
                                     : Status::invalid_address;
    }
    if (readprefix == nullptr || readunwind == nullptr
            || readprefix_size != selected_spec.prefix_bytes
            || readunwind_size != selected_spec.unwind_bytes) {
        return Status::invalid_buffer;
    }

    Address prefix_begin = 0u;
    Address prefix_end = 0u;
    Address unwind_begin = 0u;
    Address unwind_end = 0u;
    if (!detail::input_range(readprefix, readprefix_size,
                             prefix_begin, prefix_end)
            || !detail::input_range(readunwind, readunwind_size,
                                    unwind_begin, unwind_end)) {
        return Status::invalid_buffer;
    }
    const Address output_begin = reinterpret_cast<Address>(&output);
    Address output_end = 0u;
    if (!detail::range_end(output_begin, sizeof(output), output_end)) {
        return Status::invalid_buffer;
    }
    if (detail::overlaps(prefix_begin, prefix_end, unwind_begin, unwind_end)) {
        return Status::input_alias;
    }
    if (detail::overlaps(output_begin, output_end, prefix_begin, prefix_end)
            || detail::overlaps(output_begin, output_end,
                                 unwind_begin, unwind_end)) {
        return Status::output_alias;
    }
    if (std::memcmp(readprefix, selected_spec.prefix.data(),
                    selected_spec.prefix_bytes) != 0) {
        return Status::prologue_mismatch;
    }
    if (std::memcmp(readunwind, selected_spec.unwind_expected.data(),
                    selected_spec.unwind_bytes) != 0) {
        return Status::unwind_mismatch;
    }
    const std::size_t code_bytes = selected_spec.prefix_bytes
        + kHomeSlotJumpBytes;
    const std::size_t image_bytes = kUnwindOffset
        + selected_spec.projected_unwind_bytes;
    if (selected_spec.prefix_bytes > kMaxPatchBytes
            || code_bytes > kMaxImageBytes
            || image_bytes > kMaxImageBytes
            || selected_spec.stack_delta
                > (std::numeric_limits<std::uint32_t>::max)()
                    - kHomeSlotOffset - 4u) {
        return Status::image_overflow;
    }

    Plan candidate{};
    candidate.kind = kind;
    candidate.image_bytes = image_bytes;
    candidate.patch_bytes = selected_spec.prefix_bytes;
    // The unwind header keeps the original prologue length.  The message and
    // cleanup entries both copy a 16-byte patch window; their unwind
    // prologues remain 13 and 10 bytes respectively, so any trailing copied
    // instruction belongs to the body for unwind purposes.
    candidate.prologue_bytes = selected_spec.unwind_expected[1];
    candidate.unwind_bytes = selected_spec.projected_unwind_bytes;
    candidate.original_entry = originalentry;
    candidate.continuation = originalentry + selected_spec.prefix_bytes;
    candidate.hook = hook;
    candidate.runtime.begin = 0u;
    candidate.runtime.end = static_cast<std::uint32_t>(code_bytes);
    candidate.runtime.unwind = static_cast<std::uint32_t>(kUnwindOffset);

    std::memcpy(candidate.image.data(), readprefix,
                selected_spec.prefix_bytes);
    detail::home_slot_jump(
        candidate.image.data() + selected_spec.prefix_bytes,
        selected_spec.stack_delta + kHomeSlotOffset,
        candidate.continuation);
    if (!detail::make_projected_unwind(
            selected_spec, candidate.image.data() + kUnwindOffset,
            candidate.image.size() - kUnwindOffset)) {
        return Status::image_overflow;
    }
    candidate.patch.fill(0x90u);
    detail::absolute_jump(candidate.patch.data(), hook);
    output = candidate;
    return Status::prepared;
}

}  // namespace information::battle::message_entry

#endif  // INFORMATION_BATTLE_MESSAGE_ENTRY_PLAN_H
