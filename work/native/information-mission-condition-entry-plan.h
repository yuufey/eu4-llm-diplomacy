#pragma once

#include "information-battle-message-entry-plan.h"
#include <limits>

// B23 conjunction dispatch gateway, validated by the retained338 fixture.
namespace information::mission_condition::dispatch {

namespace jumps = information::battle::message_entry;
constexpr uint32_t kFunctionRva = 0xb98070;
constexpr uint32_t kFunctionEndRva = 0xb980d0;
constexpr uint32_t kSourceUnwindRva = 0x1dc97a4;
constexpr size_t kPatchOffset = 0x29;
constexpr size_t kPatchBytes = 6;
constexpr size_t kGatewayBytes = 90;
constexpr size_t kUnwindOffset = 96;
constexpr size_t kHookImmediateOffset = 70;
constexpr size_t kBarrierFunctionOffset = 112;
constexpr size_t kBarrierUnwindOffset = 208;
constexpr std::array<unsigned char, 96> kSource{{
    0x48,0x89,0x5c,0x24,0x08,0x48,0x89,0x74,0x24,0x10,0x57,0x48,0x83,0xec,0x20,
    0x48,0x8b,0x59,0x08,0x48,0x8b,0xf2,0x48,0x63,0x41,0x14,0x48,0x8d,0x3c,0xc3,
    0x48,0x3b,0xdf,0x74,0x19,0x48,0x8b,0x0b,0x48,0x8b,0xd6,0x48,0x8b,0x01,
    0xff,0x50,0x30,0x84,0xc0,0x74,0x1b,0x48,0x83,0xc3,0x08,0x48,0x3b,0xdf,
    0x75,0xe7,0xb0,0x01,0x48,0x8b,0x5c,0x24,0x30,0x48,0x8b,0x74,0x24,0x38,
    0x48,0x83,0xc4,0x20,0x5f,0xc3,0x48,0x8b,0x5c,0x24,0x30,0x32,0xc0,
    0x48,0x8b,0x74,0x24,0x38,0x48,0x83,0xc4,0x20,0x5f,0xc3,
}};
constexpr std::array<unsigned char, 16> kSourceUnwind{{
    0x01,0x0f,0x06,0x00,0x0f,0x64,0x07,0x00,0x0f,0x34,0x06,0x00,0x0f,0x32,0x0b,0x70,
}};
constexpr std::array<unsigned char, 8> kGatewayUnwind{{
    0x01,0x04,0x01,0x00,0x04,0xa2,0x00,0x00,
}};
struct RuntimeFunction final {
    uint32_t begin = 0, end = kGatewayBytes, unwind = kUnwindOffset;
};
struct Plan final {
    std::array<unsigned char, 224> image{};
    std::array<unsigned char, kPatchBytes> patch{};
    RuntimeFunction runtime{};
    RuntimeFunction barrier_runtime{kBarrierFunctionOffset, kBarrierUnwindOffset, kBarrierUnwindOffset};
};

// The gateway calls the original callee itself, preserving its integer and
// vector inputs. A post-observer receives (child, context, full RAX, vector
// slot, actual callee). Its return value is ignored. It preserves LastError.
inline bool prepare(const std::array<unsigned char, 96>& source,
                    const std::array<unsigned char, 16>& unwind,
                    uintptr_t function, uintptr_t gateway, uintptr_t observer,
                    Plan& output) noexcept {
    if (source != kSource || unwind != kSourceUnwind
        || !jumps::detail::valid_code_address(function, source.size())
        || !jumps::detail::valid_code_address(gateway, output.image.size())
        || !jumps::detail::valid_code_address(observer)
        || (gateway < function+source.size() && gateway+output.image.size() > function)
        || (observer >= function && observer < function+source.size())
        || (observer >= gateway && observer < gateway+output.image.size())) return false;
    const int64_t displacement = static_cast<int64_t>(gateway)
        - static_cast<int64_t>(function+kPatchOffset+kPatchBytes);
    if (displacement < std::numeric_limits<int32_t>::min()
        || displacement > std::numeric_limits<int32_t>::max()) return false;
    Plan candidate{};
    // Both the old indirect CALL and the new CALL return to the untouched TEST
    // at patch+6. An in-flight call has no return address inside these six bytes.
    candidate.patch[0] = 0x90;
    candidate.patch[1] = 0xe8;
    const int32_t relative = static_cast<int32_t>(displacement);
    std::memcpy(candidate.patch.data()+2, &relative, sizeof(relative));
    constexpr std::array<unsigned char, kGatewayBytes> code{{
        0x48,0x83,0xec,0x58,              // home area, fifth argument and locals
        0x48,0x89,0x4c,0x24,0x28,         // original child
        0x48,0x89,0x54,0x24,0x30,         // original context
        0x48,0x89,0x5c,0x24,0x38,         // original RBX vector slot
        0x48,0x8b,0x01,
        0x48,0x8b,0x40,0x30,
        0x48,0x89,0x44,0x24,0x48,         // exact original virtual callee
        0xff,0xd0,                        // native call, original input registers
        0x48,0x89,0x44,0x24,0x40,         // full native RAX
        0x48,0x8b,0x4c,0x24,0x28,
        0x48,0x8b,0x54,0x24,0x30,
        0x4c,0x8b,0x44,0x24,0x40,
        0x4c,0x8b,0x4c,0x24,0x38,
        0x48,0x8b,0x44,0x24,0x48,
        0x48,0x89,0x44,0x24,0x20,         // fifth post-observer argument
        0x48,0xb8,0,0,0,0,0,0,0,0,
        0xff,0xd0,
        0x48,0x8b,0x44,0x24,0x40,         // discard post-observer return value
        0x48,0x83,0xc4,0x58,
        0xc3,                            // unchanged TEST AL,AL runs next
    }};
    std::memcpy(candidate.image.data(), code.data(), code.size());
    std::memcpy(candidate.image.data()+kHookImmediateOffset, &observer, sizeof(observer));
    std::memcpy(candidate.image.data()+kUnwindOffset, kGatewayUnwind.data(), kGatewayUnwind.size());
    // The transaction's breakpoint handler redirects RIP without a CALL.
    // Continue at the same offset in a position-independent copy of the full
    // original function, using its existing parent frame and unwind metadata.
    // A CALL gateway cannot serve this role because it expects a return address.
    std::memcpy(candidate.image.data()+kBarrierFunctionOffset, kSource.data(), kSource.size());
    std::memcpy(candidate.image.data()+kBarrierUnwindOffset, kSourceUnwind.data(), kSourceUnwind.size());
    output = candidate;
    return true;
}

} // namespace information::mission_condition::dispatch
