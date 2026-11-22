#pragma once

#include "information-country-modifier-add.h"
#include "information-claim-expiry-native-guards.h"

namespace information::claim_expiry {

using Address = std::uintptr_t;
inline constexpr Address kRemovalRva = 0xa06cc0;
inline constexpr Address kExpiryReturnRva = 0x304161;
inline constexpr std::size_t kMaxClaims = 256;

struct Context final {
    Address module = 0;
    std::int32_t date = 0;
    bool bound_frame_thread = false;
    bool (*observable)(std::uint64_t) noexcept = nullptr;

    bool observes(std::uint64_t reference) const noexcept {
        return observable ? observable(reference) : (reference & 0xffffff) == 0x415246;
    }
};

struct Value final {
    std::uint64_t claimant = 0, owner = 0, observer = 0;
    std::int32_t province = 0, date = 0;
};

struct Pending final {
    Context context{};
    Address instance = 0, game = 0;
    std::array<std::uint64_t, kMaxClaims> other_claims{};
    Value value{};
    bool ready = false;
};

enum class Decision : unsigned char { ignored, ready, unreadable };

namespace detail {
namespace shared = information::country_modifier::detail;

inline bool tag(std::uint64_t reference, bool allow_empty = false) noexcept {
    if (allow_empty && (reference & 0xffffff) == 0x2d2d2d) return true;
    for (unsigned index = 0; index < 3; ++index) {
        const auto character = static_cast<unsigned char>(reference >> (index * 8));
        if (!((character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9'))) return false;
    }
    return true;
}

template<class Reader>
bool canonical(shared::Copy<Reader>& copy, Address module, std::uint64_t reference) noexcept {
    const auto slot = static_cast<std::uint32_t>((reference >> 32) & 0xffff);
    Address database = 0, table = 0, country = 0;
    std::uint32_t count = 0;
    std::uint64_t actual = 0;
    return slot < 4096 && copy.value(module + 0x233d8b0, database)
        && copy.value(database + 0x124, count) && count > 0 && count <= 4096 && slot < count
        && copy.value(database + 0x118, table) && copy.value(table + slot * 8, country)
        && copy.value(country + 0x20, actual) && actual == reference;
}

template<class Reader>
bool identity(shared::Copy<Reader>& copy, const Pending& pending) noexcept {
    Address game = 0, begin = 0, end = 0, records = 0, discovery = 0;
    std::int32_t date = 0, province = 0;
    std::uint64_t owner = 0;
    std::uint32_t word = 0;
    if (!copy.value(pending.context.module + 0x233fe58, game) || game != pending.game
        || !copy.value(game + 0x1dd0, date) || date != pending.context.date
        || !copy.value(game + 0x1c90, begin) || !copy.value(game + 0x1c98, end)
        || !shared::range(begin, 8) || end < begin || (end - begin) % 8
        || !copy.value(game + 0x1ca8, records)) return false;
    const Address count = (end - begin) / 8;
    if (count <= 1 || count > 65536 || pending.value.province <= 0
        || static_cast<Address>(pending.value.province) >= count
        || !shared::range(records, count * 0x2e10)
        || records + static_cast<Address>(pending.value.province) * 0x2e10 != pending.instance
        || !copy.value(pending.instance + 0x20, province) || province != pending.value.province
        || !copy.value(pending.instance + 0x468, owner) || owner != pending.value.owner
        || !canonical(copy, pending.context.module, pending.value.claimant)
        || !canonical(copy, pending.context.module, pending.value.owner)
        || !copy.value(pending.instance + 0x5e0, discovery)) return false;
    const auto slot = static_cast<std::uint32_t>((pending.value.observer >> 32) & 0xffff);
    return copy.value(discovery + (slot >> 5) * 4, word) && (word & (1u << (slot & 31))) != 0;
}

template<class Reader>
bool members(shared::Copy<Reader>& copy, const Pending& pending,
             std::array<std::uint64_t, kMaxClaims>& others, unsigned& matches) noexcept {
    others = {};
    matches = 0;
    std::array<Address, kMaxClaims> visited{};
    unsigned count = 0, other_count = 0;
    Address node = 0;
    if (!copy.value(pending.instance + 0x4c0, node)) return false;
    while (node) {
        if (count == kMaxClaims || !shared::range(node, 0x18) || (node & 7)) return false;
        for (unsigned index = 0; index < count; ++index) {
            if (node < visited[index] + 0x18 && visited[index] < node + 0x18) return false;
        }
        visited[count++] = node;
        std::uint64_t reference = 0;
        Address next = 0;
        // The opaque node+8 payload is outside the capture reads.
        if (!copy.value(node, reference) || !copy.value(node + 0x10, next)) return false;
        if (reference == pending.value.claimant) {
            if (++matches > 1) return false;
        } else {
            if (((reference >> 32) & 0xffff) == ((pending.value.claimant >> 32) & 0xffff)) return false;
            others[other_count++] = reference;
        }
        node = next;
    }
    return true;
}

template<class Reader, std::size_t Size>
bool guard(shared::Copy<Reader>& copy, Address address,
           const std::array<unsigned char, Size>& expected) noexcept {
    std::array<unsigned char, 128> bytes{};
    for (std::size_t offset = 0; offset < Size; offset += bytes.size()) {
        const std::size_t size = (Size - offset < bytes.size()) ? Size - offset : bytes.size();
        if (!copy.bytes(address + offset, bytes.data(), size)
            || std::memcmp(bytes.data(), expected.data() + offset, size)) return false;
    }
    return true;
}
} // namespace detail

template<class Reader>
bool guards(Reader& reader, Address module) noexcept {
    detail::shared::Copy<Reader> copy(reader);
    return detail::guard(copy, module + kRemovalRva, kRemovalBytes)
        && detail::guard(copy, module + kNaturalCallerRva, kNaturalCallerBytes);
}

template<class Reader>
Decision begin(Reader& reader, const Context& context, Address instance,
               std::uint64_t claimant, Address caller_return, Pending& pending) noexcept {
    pending = {};
    if (!context.bound_frame_thread || context.date < 0
        || !detail::shared::range(context.module, 0x233fe60)
        || caller_return != context.module + kExpiryReturnRva) return Decision::ignored;
    detail::shared::Copy<Reader> copy(reader);
    Pending candidate{};
    candidate.context = context;
    candidate.instance = instance;
    candidate.value.claimant = claimant;
    candidate.value.date = context.date;
    if (!copy.value(instance + 0x468, candidate.value.owner)) return Decision::unreadable;
    candidate.value.observer = context.observes(claimant) ? claimant
        : context.observes(candidate.value.owner) ? candidate.value.owner : 0;
    if (!candidate.value.observer) return Decision::ignored;
    if (!detail::tag(claimant) || !detail::tag(candidate.value.owner, true)
        || !copy.value(instance + 0x20, candidate.value.province)
        || !copy.value(context.module + 0x233fe58, candidate.game)
        || !detail::identity(copy, candidate)) return Decision::unreadable;
    unsigned matches = 0;
    if (!detail::members(copy, candidate, candidate.other_claims, matches)) return Decision::unreadable;
    if (matches == 0) return Decision::ignored;
    candidate.ready = true;
    pending = candidate;
    return Decision::ready;
}

template<class Reader>
bool finish(Reader& reader, Pending& pending, Value& output) noexcept {
    const bool ready = pending.ready;
    pending.ready = false;
    if (!ready) return false;
    detail::shared::Copy<Reader> copy(reader);
    std::array<std::uint64_t, kMaxClaims> others{};
    unsigned matches = 0;
    if (!detail::identity(copy, pending) || !detail::members(copy, pending, others, matches)
        || matches != 0 || others != pending.other_claims) return false;
    output = pending.value;
    return true;
}
} // namespace information::claim_expiry
