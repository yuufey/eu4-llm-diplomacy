#ifndef INFORMATION_BATTLE_NAME_HANDOFF_ENTRY_PLAN_H
#define INFORMATION_BATTLE_NAME_HANDOFF_ENTRY_PLAN_H

// Fixed B23 leaf-entry preparation only. No patch, allocation, native call or
// runtime-function registration occurs in this component.
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>

namespace information::battle::name_handoff_entry {
using Address = std::uintptr_t;
inline constexpr char kTargetExeSha256[] =
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77";
inline constexpr Address kEntryRva = 0x1af6a0u;
inline constexpr Address kEndRva = 0x1af73bu;
inline constexpr std::size_t kFunctionBytes = 155u;
inline constexpr std::size_t kPrefixBytes = 17u;
inline constexpr std::size_t kJumpBytes = 14u;
inline constexpr std::size_t kUnwindOffset = 64u;
inline constexpr std::size_t kImageCapacity = 128u;
inline constexpr Address kMaxAddress = UINT64_C(0x800000000000);

// Generated ordinary PE bytes are separate from the REA move-semantics proof.
inline constexpr std::array<unsigned char, kFunctionBytes> kExpectedFunction{{
    0x45u, 0x33u, 0xc9u, 0x66u, 0xc7u, 0x44u, 0x24u, 0x08u, 0x2du, 0x2du, 0x4cu, 0x89u,
    0x09u, 0x4cu, 0x89u, 0x49u, 0x10u, 0x4cu, 0x89u, 0x49u, 0x18u, 0x0fu, 0x10u, 0x02u,
    0xc7u, 0x44u, 0x24u, 0x0au, 0x2du, 0x00u, 0x00u, 0x00u, 0x66u, 0x44u, 0x89u, 0x4cu,
    0x24u, 0x0eu, 0x48u, 0x8bu, 0x44u, 0x24u, 0x08u, 0x0fu, 0x11u, 0x01u, 0x66u, 0xc7u,
    0x44u, 0x24u, 0x10u, 0x2du, 0x2du, 0x0fu, 0x10u, 0x4au, 0x10u, 0xc7u, 0x44u, 0x24u,
    0x12u, 0x2du, 0x00u, 0x00u, 0x00u, 0x66u, 0x44u, 0x89u, 0x4cu, 0x24u, 0x16u, 0x0fu,
    0x11u, 0x49u, 0x10u, 0x4cu, 0x89u, 0x4au, 0x10u, 0x48u, 0xc7u, 0x42u, 0x18u, 0x0fu,
    0x00u, 0x00u, 0x00u, 0x44u, 0x88u, 0x0au, 0x4cu, 0x89u, 0x49u, 0x20u, 0x4cu, 0x89u,
    0x49u, 0x30u, 0x4cu, 0x89u, 0x49u, 0x38u, 0x41u, 0x0fu, 0x10u, 0x00u, 0x0fu, 0x11u,
    0x41u, 0x20u, 0x41u, 0x0fu, 0x10u, 0x48u, 0x10u, 0x0fu, 0x11u, 0x49u, 0x30u, 0x4du,
    0x89u, 0x48u, 0x10u, 0x49u, 0xc7u, 0x40u, 0x18u, 0x0fu, 0x00u, 0x00u, 0x00u, 0x45u,
    0x88u, 0x08u, 0x48u, 0x89u, 0x41u, 0x40u, 0x48u, 0x8bu, 0x44u, 0x24u, 0x10u, 0x48u,
    0x89u, 0x41u, 0x48u, 0x48u, 0x8bu, 0xc1u, 0x4cu, 0x89u, 0x49u, 0x50u, 0xc3u
}};

struct RuntimeFunction final { std::uint32_t begin{}, end{}, unwind{}; };
static_assert(sizeof(RuntimeFunction) == 12u, "Win64 RUNTIME_FUNCTION layout");
struct Plan final {
    std::array<unsigned char, kImageCapacity> image{};
    std::array<unsigned char, kPrefixBytes> patch{};
    RuntimeFunction runtime{};
    std::size_t image_bytes{};
    std::size_t patch_bytes{};
    Address original_entry{};
    Address continuation{};
    Address hook{};
};
enum class Status : std::uint8_t {
    prepared, invalid_input, input_output_alias, code_mismatch,
    unexpected_original_unwind, invalid_address,
};

inline bool range(Address address, std::size_t bytes) noexcept {
    return bytes && address >= 0x10000u && address < kMaxAddress
        && bytes <= kMaxAddress - address;
}
inline bool overlap(Address a, std::size_t as, Address b, std::size_t bs) noexcept {
    if (!as || !bs) return false;
    if (a > std::numeric_limits<Address>::max() - as
            || b > std::numeric_limits<Address>::max() - bs) return true;
    return a < b + bs && b < a + as;
}
inline void jump(unsigned char* output, Address target) noexcept {
    output[0] = 0xffu; output[1] = 0x25u;
    output[2] = output[3] = output[4] = output[5] = 0u;
    std::memcpy(output + 6u, &target, sizeof(target));
}

inline Status prepare(const unsigned char* function, std::size_t bytes,
                      Address module_base, std::size_t image_size,
                      Address hook, bool original_unwind_absent,
                      Plan& output) noexcept {
    // Never clear an alias before rejecting it: the input may be copied game
    // code. All ordinary failures clear only the separate owned plan.
    if (function && overlap(reinterpret_cast<Address>(function), bytes,
                            reinterpret_cast<Address>(&output), sizeof(output)))
        return Status::input_output_alias;
    output = Plan{};
    if (!function || bytes != kFunctionBytes) return Status::invalid_input;
    if (!original_unwind_absent) return Status::unexpected_original_unwind;
    if (!range(module_base, image_size) || (module_base & 0xfffu)
            || image_size < kEndRva || !range(hook, 1u)) return Status::invalid_address;
    const Address entry = module_base + kEntryRva;
    const Address continuation = entry + kPrefixBytes;
    if (hook >= entry && hook < module_base + kEndRva) return Status::invalid_address;
    if (std::memcmp(function, kExpectedFunction.data(), kFunctionBytes))
        return Status::code_mismatch;
    Plan plan{};
    std::memcpy(plan.image.data(), function, kPrefixBytes);
    jump(plan.image.data() + kPrefixBytes, continuation);
    // The original is a genuine no-stack-adjustment leaf with no .pdata row.
    // Its copied prefix only changes R9, caller home slots and destination
    // memory. A zero-code v1 UNWIND_INFO describes the complete trampoline.
    plan.image[kUnwindOffset] = 1u;
    plan.runtime = {0u, static_cast<std::uint32_t>(kPrefixBytes + kJumpBytes),
                    static_cast<std::uint32_t>(kUnwindOffset)};
    plan.patch.fill(0x90u);
    jump(plan.patch.data(), hook);
    plan.image_bytes = kUnwindOffset + 4u;
    plan.patch_bytes = kPrefixBytes;
    plan.original_entry = entry;
    plan.continuation = continuation;
    plan.hook = hook;
    output = plan;
    return Status::prepared;
}
} // namespace information::battle::name_handoff_entry
#endif
