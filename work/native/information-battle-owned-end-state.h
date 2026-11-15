#ifndef INFORMATION_BATTLE_OWNED_END_STATE_H
#define INFORMATION_BATTLE_OWNED_END_STATE_H

// Research-only bounded copy of the raw per-side +0x169 byte used by the
// land/naval overrun path.  The byte remains uninterpreted here.  This helper
// never calls game code, allocates, performs I/O, or retains source pointers.

#include "information-battle-owned-context.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <type_traits>

namespace information::battle::owned_end_state {

using Address = owned_context::Address;

constexpr Address kMinCanonicalAddress = UINT64_C(0x10000);
constexpr Address kMaxCanonicalExclusive = UINT64_C(0x800000000000);
constexpr std::size_t kCombatSidePointerOffset = 0x20u;
constexpr std::size_t kCombatSidePointerBytes = 2u * sizeof(Address);
constexpr std::size_t kSideRawGateOffset = 0x169u;
constexpr std::size_t kMaxSingleReadBytes = 16u;
constexpr std::size_t kMaxReadBudgetBytes = 128u;
constexpr std::size_t kMaxReadCalls = 6u;

static_assert(kCombatSidePointerBytes <= kMaxSingleReadBytes,
              "the side pointer pair must fit in one bounded read");

// Only the two native bytes are retained; no source address escapes capture.
struct Snapshot {
    std::array<std::uint8_t, 2> raw_gate{};
};

static_assert(sizeof(Snapshot) == 2u,
              "end-state snapshot must contain exactly two bytes");
static_assert(std::is_trivially_copyable<Snapshot>::value,
              "end-state snapshot must be a plain value object");

namespace detail {

inline bool checked_range(Address begin, std::size_t size,
                          Address& end) noexcept {
    if (size == 0u || size > kMaxSingleReadBytes) {
        return false;
    }
    const Address max_value = std::numeric_limits<Address>::max();
    if (begin > max_value - static_cast<Address>(size)) {
        return false;
    }
    end = begin + static_cast<Address>(size);
    return begin >= kMinCanonicalAddress
        && end <= kMaxCanonicalExclusive
        && end > begin;
}

inline bool checked_add(Address left, Address right,
                        Address& result) noexcept {
    const Address max_value = std::numeric_limits<Address>::max();
    if (left > max_value - right) {
        return false;
    }
    result = left + right;
    return true;
}

inline bool valid_pointer(Address pointer) noexcept {
    Address end = 0;
    return pointer % alignof(Address) == 0u
        && checked_range(pointer, 1u, end);
}

inline bool ranges_overlap(Address left_begin, Address left_end,
                           Address right_begin, Address right_end) noexcept {
    return left_begin < right_end && right_begin < left_end;
}

inline bool output_range(const Snapshot& output, Address& begin,
                         Address& end) noexcept {
    begin = reinterpret_cast<Address>(&output);
    const Address max_value = std::numeric_limits<Address>::max();
    if (begin > max_value - static_cast<Address>(sizeof(output))) {
        return false;
    }
    end = begin + static_cast<Address>(sizeof(output));
    return end > begin;
}

inline Address load_address(const unsigned char* bytes) noexcept {
    Address value = 0;
    std::memcpy(&value, bytes, sizeof(value));
    return value;
}

template <typename Reader>
class BoundedReader {
public:
    BoundedReader(Reader& reader, Address output_begin,
                  Address output_end) noexcept
        : reader_(reader), output_begin_(output_begin),
          output_end_(output_end) {}

    bool read(Address address, unsigned char* destination,
              std::size_t size) noexcept {
        Address end = 0;
        if (destination == nullptr || !checked_range(address, size, end)
                || ranges_overlap(address, end, output_begin_, output_end_)
                || calls_ >= kMaxReadCalls
                || size > kMaxReadBudgetBytes - bytes_) {
            return false;
        }
        ++calls_;
        if (!reader_.read(address, destination, size)) {
            return false;
        }
        bytes_ += size;
        return true;
    }

    std::size_t bytes_read() const noexcept { return bytes_; }
    std::size_t calls() const noexcept { return calls_; }

private:
    Reader& reader_;
    Address output_begin_;
    Address output_end_;
    std::size_t bytes_ = 0u;
    std::size_t calls_ = 0u;
};

template <typename Reader, typename = void>
struct reader_contract : std::false_type {};

template <typename Reader>
struct reader_contract<Reader, std::void_t<decltype(&Reader::read)>>
    : std::is_same<decltype(&Reader::read),
                   bool (Reader::*)(Address, unsigned char*,
                                    std::size_t) noexcept> {};

struct Pass {
    std::array<Address, 2> side_ptrs{};
    std::array<std::uint8_t, 2> raw_gate{};
};

template <typename Reader>
bool read_pass(BoundedReader<Reader>& reader, Address combat_ptr,
               const std::array<Address, 2>& verified_side_ptrs,
               Pass& output) noexcept {
    Address side_pair_address = 0;
    if (!checked_add(combat_ptr,
                     static_cast<Address>(kCombatSidePointerOffset),
                     side_pair_address)) {
        return false;
    }

    std::array<unsigned char, kCombatSidePointerBytes> side_pointer_bytes{};
    if (!reader.read(side_pair_address, side_pointer_bytes.data(),
                     side_pointer_bytes.size())) {
        return false;
    }

    Pass candidate{};
    for (std::size_t index = 0u; index < candidate.side_ptrs.size(); ++index) {
        candidate.side_ptrs[index] = load_address(
            side_pointer_bytes.data() + index * sizeof(Address));
        if (!valid_pointer(candidate.side_ptrs[index])
                || candidate.side_ptrs[index] != verified_side_ptrs[index]) {
            return false;
        }
    }
    if (candidate.side_ptrs[0] == candidate.side_ptrs[1]) {
        return false;
    }

    for (std::size_t index = 0u; index < candidate.side_ptrs.size(); ++index) {
        Address gate_address = 0;
        if (!checked_add(candidate.side_ptrs[index],
                         static_cast<Address>(kSideRawGateOffset),
                         gate_address)
                || !reader.read(gate_address,
                                reinterpret_cast<unsigned char*>(
                                    &candidate.raw_gate[index]),
                                sizeof(candidate.raw_gate[index]))) {
            return false;
        }
    }
    output = candidate;
    return true;
}

inline bool valid_context(const owned_context::Snapshot& context) noexcept {
    if (!context.known_router || !context.selector_code_verified) {
        return false;
    }
    const bool valid_kind = context.kind == owned_context::Kind::land
        || context.kind == owned_context::Kind::naval;
    if (!valid_kind
            || context.raw_selector != static_cast<std::uint32_t>(context.kind)) {
        return false;
    }
    for (const owned_context::CombatSide& side : context.sides) {
        if (!side.present || !side.participants.complete
                || side.participants.count == 0u
                || side.participants.count > side.participants.full_refs.size()) {
            return false;
        }
    }
    return true;
}

}  // namespace detail

using detail::reader_contract;

// verified_side_ptrs must be the pointer pair already bound to the validated
// owned_context snapshot by the caller.  The pair is reread during both passes
// so this leaf cannot silently switch to another combat-side object.
template <typename Reader>
bool capture(Reader& reader, Address combat_ptr,
             const owned_context::Snapshot& verified_context,
             const std::array<Address, 2>& verified_side_ptrs,
             Snapshot& output) noexcept {
    static_assert(reader_contract<Reader>::value,
                  "Reader::read must be bool(Address,unsigned char*,size_t) noexcept");

    Address output_begin = 0;
    Address output_end = 0;
    Address combat_pair_address = 0;
    Address combat_pair_end = 0;
    if (!detail::output_range(output, output_begin, output_end)
            || !detail::valid_context(verified_context)
            || !detail::valid_pointer(combat_ptr)
            || !detail::checked_add(
                combat_ptr,
                static_cast<Address>(kCombatSidePointerOffset),
                combat_pair_address)
            || !detail::checked_range(combat_pair_address,
                                      kCombatSidePointerBytes,
                                      combat_pair_end)
            || detail::ranges_overlap(combat_pair_address, combat_pair_end,
                                      output_begin, output_end)) {
        return false;
    }
    for (std::size_t index = 0u; index < verified_side_ptrs.size(); ++index) {
        if (!detail::valid_pointer(verified_side_ptrs[index])) {
            return false;
        }
    }
    if (verified_side_ptrs[0] == verified_side_ptrs[1]) {
        return false;
    }

    detail::BoundedReader<Reader> bounded(reader, output_begin, output_end);
    detail::Pass first{};
    detail::Pass second{};
    if (!detail::read_pass(bounded, combat_ptr, verified_side_ptrs, first)
            || !detail::read_pass(bounded, combat_ptr,
                                  verified_side_ptrs, second)
            || first.side_ptrs != second.side_ptrs
            || first.raw_gate != second.raw_gate
            || bounded.bytes_read() > kMaxReadBudgetBytes
            || bounded.calls() > kMaxReadCalls) {
        return false;
    }

    Snapshot candidate{};
    candidate.raw_gate = second.raw_gate;
    output = candidate;
    return true;
}

}  // namespace information::battle::owned_end_state

#endif  // INFORMATION_BATTLE_OWNED_END_STATE_H
