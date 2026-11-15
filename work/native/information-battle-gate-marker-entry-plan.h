#ifndef INFORMATION_BATTLE_GATE_MARKER_ENTRY_PLAN_H
#define INFORMATION_BATTLE_GATE_MARKER_ENTRY_PLAN_H

// Fixed-build, value-only plan for the 1.37.4 post-gate marker entry. The
// caller supplies bounded PE byte windows; this header builds an owned image
// and patch only. It does not install a patch, register unwind metadata, or
// call any game/native function.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>

namespace information::battle::gate_marker_entry {

using Address = std::uintptr_t;
static_assert(sizeof(Address) == sizeof(std::uint64_t),
              "this fixed plan is for Win64 only");

inline constexpr char kTargetExeSha256[] =
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77";
inline constexpr Address kStaticImageBase = UINT64_C(0x0000000140000000);
inline constexpr Address kMaxUserAddress = UINT64_C(0x0000800000000000);
inline constexpr std::uint32_t kEntryRva = 0x008befa0u;
inline constexpr std::uint32_t kEndRva = 0x008bf04fu;
inline constexpr std::uint32_t kUnwindRva = 0x01e6d894u;
inline constexpr std::uint32_t kGlobalCellRva = 0x0242bcd8u;
inline constexpr std::uint32_t kLandGateRva = 0x002353d0u;
inline constexpr std::uint32_t kNavalGateRva = 0x00230b4eu;

inline constexpr std::size_t kPrefixBytes = 17u;
inline constexpr std::size_t kOriginalPrologueBytes = 10u;
inline constexpr std::size_t kUnwindBytes = 16u;
inline constexpr std::size_t kProjectedUnwindBytes = 12u;
inline constexpr std::size_t kRelocatedLoadBytes = 13u;
inline constexpr std::size_t kAbsoluteJumpBytes = 14u;
inline constexpr std::size_t kPatchBytes = 17u;
inline constexpr std::size_t kHomeSlotJumpBytes = 29u;
inline constexpr std::uint32_t kStackDelta = 0x28u;
inline constexpr std::uint32_t kHomeSlotOffset = 0x18u;
inline constexpr std::uint32_t kHomeSlotJumpDisplacement =
    kStackDelta + kHomeSlotOffset;
inline constexpr std::size_t kUnwindOffset = 64u;
inline constexpr std::size_t kCodeBytes = kOriginalPrologueBytes
    + kRelocatedLoadBytes + kHomeSlotJumpBytes;
inline constexpr std::size_t kImageBytes = kUnwindOffset
    + kProjectedUnwindBytes;
inline constexpr std::size_t kMaxImageBytes = 128u;
inline constexpr std::size_t kGateWindowBytes = 11u;

struct Spec final {
    std::uint32_t entry_rva = 0u;
    std::uint32_t end_rva = 0u;
    std::uint32_t unwind_rva = 0u;
    std::array<unsigned char, kPrefixBytes> prefix{};
    std::array<unsigned char, kUnwindBytes> unwind_expected{};
};

struct RuntimeFunction final {
    // Image-relative values matching x64 PE RUNTIME_FUNCTION.
    std::uint32_t begin = 0u;
    std::uint32_t end = 0u;
    std::uint32_t unwind = 0u;
};
static_assert(sizeof(RuntimeFunction) == 12u,
              "runtime function row must match x64 PE layout");

struct Plan final {
    std::array<unsigned char, kMaxImageBytes> image{};
    std::array<unsigned char, kPatchBytes> patch{};
    RuntimeFunction runtime{};
    std::size_t image_bytes = 0u;
    std::size_t patch_bytes = 0u;
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
    prefix_mismatch,
    unwind_mismatch,
    image_overflow,
};

namespace detail {

constexpr std::array<unsigned char, kPrefixBytes> fixed_prefix() noexcept {
    // The first 10 bytes are the original unwind-described prologue. The
    // final seven bytes are the RIP-relative MOV relocated into the image.
    return {{
        0x48u,0x89u,0x5cu,0x24u,0x10u,0x57u,0x48u,0x83u,0xecu,
        0x20u,0x48u,0x8bu,0x05u,0x27u,0xcdu,0xb6u,0x01u,
    }};
}

constexpr std::array<unsigned char, kUnwindBytes> fixed_unwind() noexcept {
    // UNWIND_INFO v1 with EHANDLER, 10-byte prologue, four code slots. The
    // plan projects the first 12 bytes and clears EHANDLER because the game's
    // handler is not part of the trampoline.
    return {{
        0x11u,0x0au,0x04u,0x00u,
        0x0au,0x34u,0x07u,0x00u,
        0x0au,0x32u,0x06u,0x70u,
        0x9cu,0x4du,0xa3u,0x01u,
    }};
}

inline constexpr Spec kSpec{
    kEntryRva,
    kEndRva,
    kUnwindRva,
    fixed_prefix(),
    fixed_unwind(),
};

}  // namespace detail

inline constexpr const Spec& spec() noexcept { return detail::kSpec; }

// Exact 11-byte JZ+CALL windows read from the fixed 1.37.4 PE. The JZ target
// lies after the corresponding CALL; observing the CALL return PC therefore
// marks arrival through the gate-true path.
inline constexpr std::array<unsigned char, kGateWindowBytes> kLandGateBytes{{
    0x0fu,0x84u,0xf3u,0x00u,0x00u,0x00u,
    0xe8u,0xc5u,0x9bu,0x68u,0x00u,
}};
inline constexpr std::array<unsigned char, kGateWindowBytes> kNavalGateBytes{{
    0x0fu,0x84u,0xcbu,0x1eu,0x00u,0x00u,
    0xe8u,0x47u,0xe4u,0x68u,0x00u,
}};
inline constexpr char kLandGateBytesSha256[] =
    "7f4468515c224a95724e72eeb3e91e615613750d2755cff3647ad316b4cdb767";
inline constexpr char kNavalGateBytesSha256[] =
    "4bb0d3a257a3b79e7221f71fba80c53ce33a5d88cf15a31c2abc05948f803205";

inline bool validate_gate_windows(const unsigned char* land,
                                  std::size_t land_size,
                                  const unsigned char* naval,
                                  std::size_t naval_size) noexcept {
    return land != nullptr && naval != nullptr
        && land_size == kLandGateBytes.size()
        && naval_size == kNavalGateBytes.size()
        && std::memcmp(land, kLandGateBytes.data(), kLandGateBytes.size()) == 0
        && std::memcmp(naval, kNavalGateBytes.data(), kNavalGateBytes.size()) == 0;
}

namespace detail {

inline bool valid_user_range(Address begin, std::size_t size = 1u) noexcept {
    return begin >= UINT64_C(0x10000) && begin < kMaxUserAddress
        && size != 0u
        && static_cast<Address>(size) <= kMaxUserAddress - begin;
}

inline bool range_end(Address begin, std::size_t size,
                      Address& end) noexcept {
    if (size == 0u
            || static_cast<Address>(size)
                > (std::numeric_limits<Address>::max)() - begin) {
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

inline void write_u32(unsigned char* output, std::uint32_t value) noexcept {
    for (unsigned shift = 0u; shift < 32u; shift += 8u) {
        output[shift / 8u] = static_cast<unsigned char>(value >> shift);
    }
}

inline void write_u64(unsigned char* output, std::uint64_t value) noexcept {
    for (unsigned shift = 0u; shift < 64u; shift += 8u) {
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
    // Two MOV dword stores form the 64-bit continuation pointer in the third
    // caller home slot, then JMP through that slot. The sequence preserves
    // GPRs and flags.
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

}  // namespace detail

// Builds a 128-byte owned image: copied 10-byte prologue, a 13-byte
// absolute-cell load, the 29-byte home-slot continuation jump, and projected
// unwind data at offset 64. On every failure, output is unchanged.
inline Status prepare(const unsigned char* readprefix,
                      std::size_t readprefix_size,
                      const unsigned char* readunwind,
                      std::size_t readunwind_size,
                      Address original_entry,
                      Address hook,
                      Plan& output) noexcept {
    const Spec& selected = spec();
    if (original_entry < selected.entry_rva) return Status::invalid_address;
    const Address module_base = original_entry - selected.entry_rva;
    if (!detail::valid_user_range(module_base, kEntryRva)
            || (module_base & UINT64_C(0xffff)) != 0u
            || !detail::valid_user_range(module_base + kEntryRva, kPatchBytes)
            || !detail::valid_user_range(module_base + kEndRva)
            || !detail::valid_user_range(module_base + kUnwindRva,
                                         kUnwindBytes)
            || !detail::valid_user_range(module_base + kGlobalCellRva,
                                         sizeof(Address))) {
        return Status::invalid_address;
    }
    if (!detail::valid_user_range(hook)
            || original_entry == hook
            || original_entry > (std::numeric_limits<Address>::max)()
                - kPatchBytes) {
        return original_entry == hook ? Status::invalid_identity
                                      : Status::invalid_address;
    }
    if (readprefix == nullptr || readunwind == nullptr
            || readprefix_size != selected.prefix.size()
            || readunwind_size != selected.unwind_expected.size()) {
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
    if (std::memcmp(readprefix, selected.prefix.data(), readprefix_size) != 0) {
        return Status::prefix_mismatch;
    }
    if (std::memcmp(readunwind, selected.unwind_expected.data(),
                    readunwind_size) != 0) {
        return Status::unwind_mismatch;
    }

    Address continuation = 0u;
    if (!detail::range_end(original_entry, kPatchBytes, continuation)
            || !detail::valid_user_range(continuation)) {
        return Status::invalid_address;
    }

    Plan candidate{};
    candidate.image_bytes = kImageBytes;
    candidate.patch_bytes = kPatchBytes;
    candidate.original_entry = original_entry;
    candidate.continuation = continuation;
    candidate.hook = hook;
    candidate.runtime.begin = 0u;
    candidate.runtime.end = static_cast<std::uint32_t>(kCodeBytes);
    candidate.runtime.unwind = static_cast<std::uint32_t>(kUnwindOffset);

    std::memcpy(candidate.image.data(), readprefix,
                kOriginalPrologueBytes);
    unsigned char* const relocated_load =
        candidate.image.data() + kOriginalPrologueBytes;
    relocated_load[0] = 0x48u;
    relocated_load[1] = 0xb8u;
    detail::write_u64(relocated_load + 2u,
                      static_cast<std::uint64_t>(module_base + kGlobalCellRva));
    relocated_load[10] = 0x48u;
    relocated_load[11] = 0x8bu;
    relocated_load[12] = 0x00u;

    detail::home_slot_jump(
        candidate.image.data() + kOriginalPrologueBytes + kRelocatedLoadBytes,
        kHomeSlotJumpDisplacement, continuation);
    std::memcpy(candidate.image.data() + kUnwindOffset,
                readunwind, kProjectedUnwindBytes);
    candidate.image[kUnwindOffset] = static_cast<unsigned char>(
        candidate.image[kUnwindOffset] & 0x07u);

    candidate.patch.fill(0x90u);
    detail::absolute_jump(candidate.patch.data(), hook);
    output = candidate;
    return Status::prepared;
}

}  // namespace information::battle::gate_marker_entry

#endif  // INFORMATION_BATTLE_GATE_MARKER_ENTRY_PLAN_H
