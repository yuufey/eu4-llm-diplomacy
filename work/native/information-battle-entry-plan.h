#ifndef INFORMATION_BATTLE_ENTRY_PLAN_H
#define INFORMATION_BATTLE_ENTRY_PLAN_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>

// Fixed1374 RVA238620 candidate only.  This constructs an owned byte image;
// it neither allocates executable memory nor publishes a patch/function table.
// Caller must validate the complete executable/session and safely read the
// supplied source buffers.  Both source buffers must remain readable here.
// A published executable image, RUNTIME_FUNCTION and registration must remain
// alive for every possible in-flight/stale-INT3 reference, even after rollback.
namespace information::battle::entry {

inline constexpr std::size_t kPatchBytes = 21;
inline constexpr std::size_t kAbsoluteJumpBytes = 14;
inline constexpr std::size_t kTailJumpBytes = 20;
inline constexpr std::size_t kCodeBytes = kPatchBytes + kTailJumpBytes;
inline constexpr std::size_t kUnwindOffset = 64;
inline constexpr std::size_t kImageBytes = 96;
inline constexpr std::uintptr_t kMaxUserAddress = 0x0000800000000000ull;

inline constexpr std::array<unsigned char, 36> kOriginalPrologue{{
    0x48,0x89,0x5c,0x24,0x10, 0x48,0x89,0x4c,0x24,0x08,
    0x55,0x56,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,
    0x48,0x8d,0xac,0x24,0x60,0xfb,0xff,0xff,
    0x48,0x81,0xec,0xa0,0x05,0x00,0x00
}};

// Original32-byte UNWIND_INFO prefix including UHANDLER RVA1A34D9C.
// Validation does not authorize invoking or relocating that handler.
inline constexpr std::array<unsigned char, 32> kOriginalUnwind{{
    0x11,0x24,0x0b,0x00, 0x24,0x34,0xbd,0x00,
    0x24,0x01,0xb4,0x00, 0x15,0xf0,0x13,0xe0,
    0x11,0xd0,0x0f,0xc0, 0x0d,0x70,0x0c,0x60,
    0x0b,0x50,0x00,0x00, 0x9c,0x4d,0xa3,0x01
}};

// Project exactly the copied prefix: seven pushes, no allocation/frame/handler.
// RBX is stored at entry+10h but is never changed by this prefix; the original
// delayed SAVE_NONVOL at offset36 is unnecessary until the native continuation.
// RCX's home store is volatile and does not require an unwind operation.
// A bareFF25 after these pushes is misread as an epilog, even when SizeOfProlog
// covers the jump. Instead the tail uses the callee-owned third home slot and
// an explicit mod01 indirect jump, which is outside the x64 epilog grammar.
// No GPR/flags/stack arguments5+ are changed. The third home slot is clobbered.
inline constexpr std::array<unsigned char, 20> kProjectedUnwind{{
    0x01,0x15,0x07,0x00, 0x15,0xf0,0x13,0xe0,
    0x11,0xd0,0x0f,0xc0, 0x0d,0x70,0x0c,0x60,
    0x0b,0x50,0x00,0x00
}};

struct RuntimeFunction final {
    std::uint32_t begin = 0;
    std::uint32_t end = static_cast<std::uint32_t>(kCodeBytes);
    std::uint32_t unwind = static_cast<std::uint32_t>(kUnwindOffset);
};
static_assert(sizeof(RuntimeFunction) == 12, "Windows x64 runtime row is12 bytes");
static_assert(kPatchBytes <= 32, "keep existing transaction bound unchanged");
static_assert(kUnwindOffset % 4 == 0, "UNWIND_INFO must be DWORD aligned");
static_assert(kUnwindOffset + kProjectedUnwind.size() <= kImageBytes,
              "unwind must fit owned image");

struct Plan final {
    std::array<unsigned char, kImageBytes> image{};
    std::array<unsigned char, kPatchBytes> patch{};
    RuntimeFunction runtime{};  // relative to the executable image's allocation
    std::uintptr_t original_entry = 0;
    std::uintptr_t continuation = 0;
    std::uintptr_t observation_stub = 0;
};

enum class Status : unsigned char {
    prepared,
    invalid_address,
    invalid_buffer,
    output_alias,
    prologue_mismatch,
    unwind_mismatch
};

inline bool valid_code_address(std::uintptr_t value,
                               std::size_t extent = 1) noexcept {
    return value >= 0x10000 && value < kMaxUserAddress
        && extent > 0 && extent <= kMaxUserAddress - value;
}

inline bool range_end(std::uintptr_t start, std::size_t size,
                      std::uintptr_t& end) noexcept {
    if (size > std::numeric_limits<std::uintptr_t>::max() - start) return false;
    end = start + size;
    return true;
}

inline bool overlaps(std::uintptr_t a, std::uintptr_t a_end,
                     std::uintptr_t b, std::uintptr_t b_end) noexcept {
    return a < b_end && b < a_end;
}

inline void absolute_jump(unsigned char* output, std::uintptr_t target) noexcept {
    output[0] = 0xff; output[1] = 0x25;
    output[2] = output[3] = output[4] = output[5] = 0;
    const std::uint64_t value = static_cast<std::uint64_t>(target);
    for (unsigned i = 0; i != 8; ++i)
        output[6 + i] = static_cast<unsigned char>(value >> (8 * i));
}

// After seven pushes RSP=entryRSP-56. [RSP+50h] is entryRSP+18h, within
// the mandatory32-byte home area owned by this native callee. Write its low
// and high halves without a scratch register, then JMP [RSP+50h] (mod01).
// Do not use this sequence outside this exact stack/prefix contract.
inline void home_slot_jump(unsigned char* output, std::uintptr_t target) noexcept {
    output[0] = output[8] = 0xc7;
    output[1] = output[9] = 0x44;
    output[2] = output[10] = 0x24;
    output[3] = 0x50; output[11] = 0x54;
    const std::uint64_t value = static_cast<std::uint64_t>(target);
    for (unsigned i = 0; i != 4; ++i) {
        output[4 + i] = static_cast<unsigned char>(value >> (8 * i));
        output[12 + i] = static_cast<unsigned char>(value >> (32 + 8 * i));
    }
    output[16] = 0xff; output[17] = 0x64;
    output[18] = 0x24; output[19] = 0x50;
}

// On failure output is unchanged.  On success no borrowed source pointer is
// retained; code addresses are private installation metadata, never event IDs.
inline Status prepare(const unsigned char* prologue, std::size_t prologue_size,
                      const unsigned char* unwind, std::size_t unwind_size,
                      std::uintptr_t original_entry,
                      std::uintptr_t observation_stub, Plan& output) noexcept {
    if (!valid_code_address(original_entry, kOriginalPrologue.size())
        || !valid_code_address(observation_stub)) return Status::invalid_address;
    if (!prologue || !unwind || prologue_size != kOriginalPrologue.size()
        || unwind_size != kOriginalUnwind.size()) return Status::invalid_buffer;
    const auto p = reinterpret_cast<std::uintptr_t>(prologue);
    const auto u = reinterpret_cast<std::uintptr_t>(unwind);
    const auto o = reinterpret_cast<std::uintptr_t>(&output);
    std::uintptr_t pe = 0, ue = 0, oe = 0;
    if (!range_end(p, prologue_size, pe) || !range_end(u, unwind_size, ue)
        || !range_end(o, sizeof(output), oe)) return Status::invalid_buffer;
    if (overlaps(o, oe, p, pe) || overlaps(o, oe, u, ue)) return Status::output_alias;
    if (std::memcmp(prologue, kOriginalPrologue.data(), prologue_size) != 0)
        return Status::prologue_mismatch;
    if (std::memcmp(unwind, kOriginalUnwind.data(), unwind_size) != 0)
        return Status::unwind_mismatch;
    Plan candidate{};
    candidate.original_entry = original_entry;
    candidate.continuation = original_entry + kPatchBytes;
    candidate.observation_stub = observation_stub;
    std::memcpy(candidate.image.data(), prologue, kPatchBytes);
    home_slot_jump(candidate.image.data() + kPatchBytes, candidate.continuation);
    std::memcpy(candidate.image.data() + kUnwindOffset,
                kProjectedUnwind.data(), kProjectedUnwind.size());
    candidate.patch.fill(0x90);
    absolute_jump(candidate.patch.data(), observation_stub);
    output = candidate;
    return Status::prepared;
}

}  // namespace information::battle::entry
#endif
