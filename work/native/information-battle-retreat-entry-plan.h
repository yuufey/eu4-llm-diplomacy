#ifndef INFORMATION_BATTLE_RETREAT_ENTRY_PLAN_H
#define INFORMATION_BATTLE_RETREAT_ENTRY_PLAN_H

// Fixed-build, value-only plans for the scoped retreat entries.
// This component validates copied PE bytes and builds an owned image. It does
// not allocate executable memory, install a patch, register a runtime
// function, or retain any source pointer.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>

#include "information-battle-message-entry-plan.h"

namespace information::battle::retreat_entry {

using Address = std::uintptr_t;

inline constexpr std::size_t kMaxImageBytes = 128u;
inline constexpr std::size_t kMaxPrefixBytes = 28u;
inline constexpr std::size_t kMaxUnwindBytes = 32u;
inline constexpr std::size_t kPrefixBytes = kMaxPrefixBytes;
inline constexpr std::size_t kUnwindBytes = kMaxUnwindBytes;
inline constexpr std::size_t kProjectedUnwindBytes = 28u;
inline constexpr std::size_t kPatchBytes = kPrefixBytes;
inline constexpr std::size_t kUnwindOffset = 64u;
inline constexpr std::uint32_t kHomeSlotOffset = 0x08u;

enum class Kind : std::uint8_t {
    outcome = 0,
    unit_path = 1,
    unit_removal = 2,
};

struct Spec final {
    Kind kind = Kind::outcome;
    std::uint32_t rva = 0u;
    std::uint32_t end_rva = 0u;
    std::uint32_t unwind_rva = 0u;
    std::uint32_t prefix_bytes = 0u;
    std::uint32_t unwind_bytes = 0u;
    std::uint32_t projected_unwind_bytes = 0u;
    std::uint32_t stack_delta = 0u;
    std::array<unsigned char, kPrefixBytes> prefix{};
    std::array<unsigned char, kUnwindBytes> unwind_expected{};
    std::uint32_t home_slot_offset = kHomeSlotOffset;
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
    std::array<unsigned char, kPatchBytes> patch{};
    RuntimeFunction runtime{};
    std::size_t image_bytes = 0u;
    std::size_t patch_bytes = 0u;
    std::size_t prologue_bytes = 0u;
    std::size_t unwind_bytes = 0u;
    Address original_entry = 0u;
    Address continuation = 0u;
    Address hook = 0u;
    Kind kind = Kind::outcome;
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

constexpr std::array<unsigned char, kPrefixBytes> outcome_prefix() noexcept {
    return {{
        0x48u,0x89u,0x5cu,0x24u,0x10u,0x48u,0x89u,0x6cu,
        0x24u,0x18u,0x48u,0x89u,0x74u,0x24u,0x20u,0x57u,
        0x41u,0x54u,0x41u,0x55u,0x41u,0x56u,0x41u,0x57u,
        0x48u,0x83u,0xecu,0x20u,
    }};
}

constexpr std::array<unsigned char, kPrefixBytes> unit_path_prefix() noexcept {
    return {{
        0x48u,0x89u,0x5cu,0x24u,0x10u,0x55u,0x56u,0x57u,
        0x41u,0x54u,0x41u,0x55u,0x41u,0x56u,0x41u,0x57u,
        0x48u,0x8du,0x6cu,0x24u,0xd9u,0x48u,0x81u,0xecu,
        0xe0u,0x00u,0x00u,0x00u,
    }};
}

constexpr std::array<unsigned char, kPrefixBytes> unit_removal_prefix() noexcept {
    return {{
        0x48u,0x89u,0x5cu,0x24u,0x08u,0x48u,0x89u,0x6cu,
        0x24u,0x10u,0x48u,0x89u,0x74u,0x24u,0x20u,0x57u,
        0x48u,0x83u,0xecu,0x20u,0x41u,0x0fu,0xb6u,0xe8u,
        0x48u,0x8bu,0xfau,
    }};
}

constexpr std::array<unsigned char, kUnwindBytes> outcome_unwind() noexcept {
    return {{
        0x11u,0x1cu,0x0cu,0x00u,
        0x1cu,0x64u,0x0du,0x00u,0x1cu,0x54u,0x0cu,0x00u,
        0x1cu,0x34u,0x0bu,0x00u,0x1cu,0x32u,0x18u,0xf0u,
        0x16u,0xe0u,0x14u,0xd0u,0x12u,0xc0u,0x10u,0x70u,
        0x9cu,0x4du,0xa3u,0x01u,
    }};
}

constexpr std::array<unsigned char, kUnwindBytes> unit_path_unwind() noexcept {
    return {{
        0x11u,0x1cu,0x0bu,0x00u,
        0x1cu,0x34u,0x25u,0x00u,0x1cu,0x01u,0x1cu,0x00u,
        0x10u,0xf0u,0x0eu,0xe0u,0x0cu,0xd0u,0x0au,0xc0u,
        0x08u,0x70u,0x07u,0x60u,0x06u,0x50u,0x00u,0x00u,
        0x9cu,0x4du,0xa3u,0x01u,
    }};
}

constexpr std::array<unsigned char, kUnwindBytes> unit_removal_unwind() noexcept {
    return {{
        0x11u,0x14u,0x08u,0x00u,0x14u,0x64u,0x09u,0x00u,
        0x14u,0x54u,0x07u,0x00u,0x14u,0x34u,0x06u,0x00u,
        0x14u,0x32u,0x10u,0x70u,0x9cu,0x4du,0xa3u,0x01u,
        0x3cu,0x6fu,0xdeu,0x01u,0x28u,0xddu,0x9au,0xddu,
    }};
}

inline constexpr Spec kOutcomeSpec{
    Kind::outcome, 0x22bed0u, 0x22c0a6u, 0x1de6084u,
    28u, 32u, 28u, 0x48u,
    outcome_prefix(), outcome_unwind(),
};

inline constexpr Spec kUnitPathSpec{
    Kind::unit_path, 0xd4fb20u, 0xd501a3u, 0x1ebb0a4u,
    28u, 32u, 28u, 0x118u,
    unit_path_prefix(), unit_path_unwind(),
};

// The native prologue saves RBX at original RSP+8. The jump instead uses
// RSP+0x18, a volatile home slot written by the native body before its use.
inline constexpr Spec kUnitRemovalSpec{
    Kind::unit_removal, 0x23b200u, 0x23b397u, 0x1de6f20u,
    27u, 32u, 20u, 0x28u,
    unit_removal_prefix(), unit_removal_unwind(), 0x18u,
};

inline const Spec* try_spec(Kind kind) noexcept {
    if (kind == Kind::outcome) return &kOutcomeSpec;
    if (kind == Kind::unit_path) return &kUnitPathSpec;
    if (kind == Kind::unit_removal) return &kUnitRemovalSpec;
    return nullptr;
}

}  // namespace detail

inline const Spec& spec(Kind kind) noexcept {
    const Spec* selected = detail::try_spec(kind);
    return selected != nullptr ? *selected : detail::kOutcomeSpec;
}

// Builds an owned 128-byte image and 28-byte patch from a complete copied
// entry prefix and source UNWIND_INFO. All failures leave output unchanged.
// The caller binds original_entry to the selected module/base identity.
inline Status prepare(Kind kind,
                      const unsigned char* readprefix,
                      std::size_t readprefix_size,
                      const unsigned char* readunwind,
                      std::size_t readunwind_size,
                      Address original_entry,
                      Address hook,
                      Plan& output) noexcept {
    const Spec* selected = detail::try_spec(kind);
    if (selected == nullptr) return Status::invalid_kind;
    const Spec& selected_spec = *selected;

    if (!message_entry::detail::valid_code_address(
                original_entry, selected_spec.prefix_bytes)
            || !message_entry::detail::valid_code_address(hook)
            || original_entry == hook) {
        return original_entry == hook ? Status::invalid_identity
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
    if (!message_entry::detail::input_range(
                readprefix, readprefix_size, prefix_begin, prefix_end)
            || !message_entry::detail::input_range(
                readunwind, readunwind_size, unwind_begin, unwind_end)) {
        return Status::invalid_buffer;
    }
    const Address output_begin = reinterpret_cast<Address>(&output);
    Address output_end = 0u;
    if (!message_entry::detail::range_end(
                output_begin, sizeof(output), output_end)) {
        return Status::invalid_buffer;
    }
    if (message_entry::detail::overlaps(
                prefix_begin, prefix_end, unwind_begin, unwind_end)) {
        return Status::input_alias;
    }
    if (message_entry::detail::overlaps(
                output_begin, output_end, prefix_begin, prefix_end)
            || message_entry::detail::overlaps(
                output_begin, output_end, unwind_begin, unwind_end)) {
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
        + message_entry::kHomeSlotJumpBytes;
    const std::size_t image_bytes = kUnwindOffset
        + selected_spec.projected_unwind_bytes;
    if (selected_spec.prefix_bytes > kPatchBytes
            || code_bytes > kMaxImageBytes
            || image_bytes > kMaxImageBytes
            || selected_spec.stack_delta
                > (std::numeric_limits<std::uint32_t>::max)()
                    - selected_spec.home_slot_offset - 4u) {
        return Status::image_overflow;
    }

    Plan candidate{};
    candidate.kind = kind;
    candidate.image_bytes = image_bytes;
    candidate.patch_bytes = selected_spec.prefix_bytes;
    candidate.prologue_bytes = selected_spec.unwind_expected[1];
    candidate.unwind_bytes = selected_spec.projected_unwind_bytes;
    candidate.original_entry = original_entry;
    candidate.continuation = original_entry + selected_spec.prefix_bytes;
    candidate.hook = hook;
    candidate.runtime = {
        0u,
        static_cast<std::uint32_t>(code_bytes),
        static_cast<std::uint32_t>(kUnwindOffset),
    };

    std::memcpy(candidate.image.data(), readprefix,
                selected_spec.prefix_bytes);
    message_entry::detail::home_slot_jump(
        candidate.image.data() + selected_spec.prefix_bytes,
        selected_spec.stack_delta + selected_spec.home_slot_offset,
        candidate.continuation);
    std::memset(candidate.image.data() + kUnwindOffset, 0,
                candidate.image.size() - kUnwindOffset);
    std::memcpy(candidate.image.data() + kUnwindOffset, readunwind,
                selected_spec.projected_unwind_bytes);
    candidate.image[kUnwindOffset] &= 0x07u;

    candidate.patch.fill(0x90u);
    message_entry::detail::absolute_jump(candidate.patch.data(), hook);
    output = candidate;
    return Status::prepared;
}

}  // namespace information::battle::retreat_entry

#endif  // INFORMATION_BATTLE_RETREAT_ENTRY_PLAN_H
