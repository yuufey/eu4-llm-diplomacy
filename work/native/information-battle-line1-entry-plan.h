#ifndef INFORMATION_BATTLE_LINE1_ENTRY_PLAN_H
#define INFORMATION_BATTLE_LINE1_ENTRY_PLAN_H

// Fixed-build, value-only preparation for the 1.37.4 Line1 setter entry.
// This header validates bounded ordinary-PE bytes and constructs an owned
// trampoline image.  It does not install a patch, call the game, or retain a
// pointer into the source executable.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>

namespace information::battle::line1_entry {

using Address = std::uintptr_t;

inline constexpr char kTargetExeSha256[] =
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77";
inline constexpr Address kStaticImageBase = UINT64_C(0x0000000140000000);
inline constexpr Address kMaxUserAddress = UINT64_C(0x0000800000000000);

inline constexpr std::uint32_t kEntryRva = 0x152ad10u;
inline constexpr std::uint32_t kContinuationRva = 0x152ad24u;
inline constexpr std::uint32_t kFunctionEndRva = 0x152ad92u;
inline constexpr std::uint32_t kUnwindRva = 0x1dca66cu;
inline constexpr std::uint32_t kPdataRva = 0x2465000u;
inline constexpr std::uint32_t kPdataFileOffset = 0x2333000u;
inline constexpr std::uint32_t kPdataRowFileOffset = 0x23b3cb8u;
inline constexpr std::uint32_t kUnwindFileOffset = 0x1dc986cu;
inline constexpr std::uint32_t kStackDelta = 0x28u;
inline constexpr std::size_t kPrefixBytes = 20u;
inline constexpr std::size_t kUnwindBytes = 20u;
inline constexpr std::size_t kProjectedUnwindBytes = 20u;
inline constexpr std::size_t kMaxImageBytes = 128u;
inline constexpr std::size_t kMaxPatchBytes = 32u;
inline constexpr std::size_t kAbsoluteJumpBytes = 14u;
inline constexpr std::size_t kUnwindOffset = 64u;

struct RuntimeFunction final {
    // PE RUNTIME_FUNCTION fields are image-relative RVAs.
    std::uint32_t begin = 0u;
    std::uint32_t end = 0u;
    std::uint32_t unwind = 0u;
};
static_assert(sizeof(RuntimeFunction) == 12u,
              "runtime row must match PE RUNTIME_FUNCTION");

struct Spec final {
    std::uint32_t entry_rva = kEntryRva;
    std::uint32_t continuation_rva = kContinuationRva;
    std::uint32_t function_end_rva = kFunctionEndRva;
    std::uint32_t unwind_rva = kUnwindRva;
    std::uint32_t pdata_rva = kPdataRva;
    std::uint32_t stack_delta = kStackDelta;
    std::uint32_t prologue_bytes = static_cast<std::uint32_t>(kPrefixBytes);
    std::uint32_t prefix_bytes = static_cast<std::uint32_t>(kPrefixBytes);
    std::uint32_t unwind_bytes = static_cast<std::uint32_t>(kUnwindBytes);
    std::uint32_t projected_unwind_bytes =
        static_cast<std::uint32_t>(kProjectedUnwindBytes);
    std::uint32_t unwind_code_count = 8u;
    std::array<unsigned char, kPrefixBytes> prefix{};
    std::array<unsigned char, kUnwindBytes> unwind_expected{};
    std::array<unsigned char, sizeof(RuntimeFunction)> pdata_row{};
};

struct Plan final {
    std::array<unsigned char, kMaxImageBytes> image{};
    std::array<unsigned char, kMaxPatchBytes> patch{};
    RuntimeFunction runtime{};
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

constexpr std::array<unsigned char, kPrefixBytes> fixed_prefix() noexcept {
    // MOV [RSP+08],RBX; MOV [RSP+10],RBP; MOV [RSP+18],RSI;
    // PUSH RDI; SUB RSP,20.  Continuation starts at RVA 0x152ad24.
    return {{
        0x48u, 0x89u, 0x5cu, 0x24u, 0x08u,
        0x48u, 0x89u, 0x6cu, 0x24u, 0x10u,
        0x48u, 0x89u, 0x74u, 0x24u, 0x18u,
        0x57u,
        0x48u, 0x83u, 0xecu, 0x20u,
    }};
}

constexpr std::array<unsigned char, kUnwindBytes> fixed_unwind() noexcept {
    // .pdata points to UNWIND_INFO with version 1, prologue size 0x14,
    // eight unwind-code slots, and no handler.  The three SAVE_NONVOL rows,
    // ALLOC_SMALL, and PUSH_NONVOL RDI are retained exactly as ordinary PE
    // bytes; no synthetic unwind row is inferred here.
    return {{
        0x01u, 0x14u, 0x08u, 0x00u,
        0x14u, 0x64u, 0x08u, 0x00u,
        0x14u, 0x54u, 0x07u, 0x00u,
        0x14u, 0x34u, 0x06u, 0x00u,
        0x14u, 0x32u, 0x10u, 0x70u,
    }};
}

constexpr std::array<unsigned char, sizeof(RuntimeFunction)> fixed_pdata_row()
    noexcept {
    // begin=0x152ad10, end=0x152ad92, unwind=0x1dca66c, little-endian.
    return {{
        0x10u, 0xadu, 0x52u, 0x01u,
        0x92u, 0xadu, 0x52u, 0x01u,
        0x6cu, 0xa6u, 0xdcu, 0x01u,
    }};
}

inline constexpr Spec kSpec{
    kEntryRva, kContinuationRva, kFunctionEndRva, kUnwindRva, kPdataRva,
    kStackDelta, static_cast<std::uint32_t>(kPrefixBytes),
    static_cast<std::uint32_t>(kPrefixBytes),
    static_cast<std::uint32_t>(kUnwindBytes),
    static_cast<std::uint32_t>(kProjectedUnwindBytes), 8u,
    fixed_prefix(), fixed_unwind(), fixed_pdata_row(),
};

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
    if (pointer == nullptr
            || !range_end(reinterpret_cast<Address>(pointer), size, end)) {
        return false;
    }
    begin = reinterpret_cast<Address>(pointer);
    return true;
}

inline bool overlaps(Address left_begin, Address left_end,
                     Address right_begin, Address right_end) noexcept {
    return left_begin < right_end && right_begin < left_end;
}

inline void write_u64(unsigned char* output, std::uint64_t value) noexcept {
    for (unsigned shift = 0u; shift != 64u; shift += 8u) {
        output[shift / 8u] = static_cast<unsigned char>(value >> shift);
    }
}

inline void absolute_jump(unsigned char* output, Address target) noexcept {
    // FF 25 00000000 followed by an inline absolute 64-bit target.  This
    // tail does not consume a GPR or alter flags, so the original three
    // setter arguments remain intact for the native continuation.
    output[0] = 0xffu;
    output[1] = 0x25u;
    output[2] = output[3] = output[4] = output[5] = 0u;
    write_u64(output + 6u, static_cast<std::uint64_t>(target));
}

}  // namespace detail

inline const Spec& spec() noexcept { return detail::kSpec; }

// Builds an owned RX-ready image and an exact 20-byte patch.  The caller
// supplies ordinary PE windows from the fixed build; output is unchanged on
// every failure.
inline Status prepare(const unsigned char* readprefix,
                      std::size_t readprefix_size,
                      const unsigned char* readunwind,
                      std::size_t readunwind_size,
                      Address originalentry,
                      Address hook,
                      Plan& output) noexcept {
    const Spec& selected = detail::kSpec;
    if (!detail::valid_code_address(originalentry, selected.prefix_bytes)
            || !detail::valid_code_address(hook)
            || originalentry == hook) {
        return originalentry == hook ? Status::invalid_identity
                                     : Status::invalid_address;
    }
    if (readprefix == nullptr || readunwind == nullptr
            || readprefix_size != selected.prefix_bytes
            || readunwind_size != selected.unwind_bytes) {
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
    if (std::memcmp(readprefix, selected.prefix.data(), selected.prefix_bytes)
            != 0) {
        return Status::prologue_mismatch;
    }
    if (std::memcmp(readunwind, selected.unwind_expected.data(),
                    selected.unwind_bytes) != 0) {
        return Status::unwind_mismatch;
    }
    const std::size_t code_bytes = selected.prefix_bytes + kAbsoluteJumpBytes;
    const std::size_t image_bytes = kUnwindOffset
        + selected.projected_unwind_bytes;
    if (code_bytes > kMaxImageBytes || image_bytes > kMaxImageBytes) {
        return Status::image_overflow;
    }

    Plan candidate{};
    candidate.image_bytes = image_bytes;
    candidate.patch_bytes = selected.prefix_bytes;
    candidate.prologue_bytes = selected.prologue_bytes;
    candidate.unwind_bytes = selected.projected_unwind_bytes;
    candidate.original_entry = originalentry;
    candidate.continuation = originalentry + selected.prefix_bytes;
    candidate.hook = hook;
    candidate.runtime.begin = 0u;
    candidate.runtime.end = static_cast<std::uint32_t>(code_bytes);
    candidate.runtime.unwind = static_cast<std::uint32_t>(kUnwindOffset);

    std::memcpy(candidate.image.data(), readprefix, selected.prefix_bytes);
    detail::absolute_jump(candidate.image.data() + selected.prefix_bytes,
                          candidate.continuation);
    std::memcpy(candidate.image.data() + kUnwindOffset,
                readunwind, selected.projected_unwind_bytes);
    candidate.patch.fill(0x90u);
    detail::absolute_jump(candidate.patch.data(), hook);
    output = candidate;
    return Status::prepared;
}

}  // namespace information::battle::line1_entry

#endif  // INFORMATION_BATTLE_LINE1_ENTRY_PLAN_H
