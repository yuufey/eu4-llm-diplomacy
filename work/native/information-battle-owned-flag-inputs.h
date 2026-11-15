#ifndef INFORMATION_BATTLE_OWNED_FLAG_INPUTS_H
#define INFORMATION_BATTLE_OWNED_FLAG_INPUTS_H
#include "information-battle-flag-input-wire.h"
#include "information-battle-owned-template.h"
#include <utility>

namespace information::battle::owned_flag_inputs {
namespace wire = flag_input_wire;
namespace text = owned_template;
using Address = text::Address;
enum class Failure : std::uint8_t {
    none = 0, not_captured = 1, base_unknown = 2, copy_failed = 3,
    input_changed = 4, rebel_read_failed = 5, budget = 6, guard = 7, invalid = 8,
};
struct Workspace final { text::Snapshot replayed{}; };
inline bool same_pairs(const text::Snapshot& left, const text::Snapshot& right) noexcept {
    if (left.pair_count != right.pair_count || left.pair_count > text::kMaxPairs) return false;
    const auto same = [&](text::TextRange a, text::TextRange b) noexcept {
        return a.length == b.length && a.offset <= left.arena.size() && b.offset <= right.arena.size()
            && a.length <= left.arena.size() - a.offset && b.length <= right.arena.size() - b.offset
            && !std::memcmp(left.arena.data() + a.offset, right.arena.data() + b.offset, a.length);
    };
    for (std::size_t index = 0; index < left.pair_count; ++index)
        if (!same(left.pairs[index].key, right.pairs[index].key)
                || !same(left.pairs[index].value, right.pairs[index].value)) return false;
    return true;
}
inline void clear(wire::Snapshot& output, std::uint64_t sequence, std::int32_t date,
                  std::uint8_t kind, Failure failure) noexcept {
    output = wire::Snapshot{};
    output.sequence = sequence; output.raw_date = date; output.kind = kind;
    output.failure = static_cast<std::uint8_t>(failure);
}
namespace detail {
class Replay final {
public:
    const text::detail::ReadLog& log;
    std::size_t index = 0;
    bool read(Address address, unsigned char* output, std::size_t size) noexcept {
        if (!output || index >= log.record_count) return false;
        const auto& row = log.records[index];
        if (row.address != address || row.size != size || row.offset > log.bytes_used
                || size > log.bytes_used - row.offset) return false;
        std::memcpy(output, log.bytes.data() + row.offset, size);
        ++index;
        return true;
    }
};
inline bool objects_disjoint(const text::detail::ReadLog& log, const text::Snapshot& source,
                             const Workspace& workspace, const wire::Snapshot& output) noexcept {
    using Bounds = std::array<wire::previous::previous::Address, 2>;
    std::array<Bounds, 4> bounds{};
    if (!wire::ranges::pointer_range(&log, sizeof(log), bounds[0][0], bounds[0][1])
            || !wire::ranges::pointer_range(&source, sizeof(source), bounds[1][0], bounds[1][1])
            || !wire::ranges::pointer_range(&workspace, sizeof(workspace), bounds[2][0], bounds[2][1])
            || !wire::ranges::pointer_range(&output, sizeof(output), bounds[3][0], bounds[3][1])) return false;
    for (std::size_t left = 0; left < bounds.size(); ++left)
        for (std::size_t right = left + 1; right < bounds.size(); ++right)
            if (wire::ranges::overlaps(bounds[left][0], bounds[left][1], bounds[right][0], bounds[right][1])) return false;
    return true;
}
inline bool key(const text::Snapshot& source, const text::TextRange& range, const char* expected) noexcept {
    return range.length == std::strlen(expected) && range.offset <= source.arena.size()
        && range.length <= source.arena.size() - range.offset
        && !std::memcmp(source.arena.data() + range.offset, expected, range.length);
}
template <typename Reader>
bool rebel_value(Reader& reader, Address pointer, const text::detail::ReadLog& log,
                 const text::Snapshot& source, const Workspace& workspace,
                 const wire::Snapshot& output, std::uint32_t& value) noexcept {
    Address address = 0, end = 0;
    if (!text::detail::valid_pointer(pointer) || !text::detail::checked_add(pointer, 0x38, address)
            || !text::detail::checked_range(address, 4, end)) return false;
    const std::array<std::pair<Address, std::size_t>, 4> owned{{
        {reinterpret_cast<Address>(&log), sizeof(log)}, {reinterpret_cast<Address>(&source), sizeof(source)},
        {reinterpret_cast<Address>(&workspace), sizeof(workspace)}, {reinterpret_cast<Address>(&output), sizeof(output)}}};
    for (const auto& region : owned)
        if (text::detail::ranges_overlap(address, end, region.first, region.first + region.second)) return false;
    std::array<unsigned char, 4> first{}, second{};
    if (!reader.read(address, first.data(), first.size()) || !reader.read(address, second.data(), second.size())
            || first != second) return false;
    value = text::detail::load_u32(first.data());
    return true;
}
} // namespace detail

// The node headers come from the successful two-pass template copy. Only
// rebel flag IDs require fresh reads, bounded to eight bytes per occurrence.
template <typename Reader>
bool capture(Reader& reader, const text::detail::ReadLog& log, const text::Snapshot& source,
             std::uint64_t sequence, std::int32_t date, std::uint8_t kind,
             Workspace& workspace, wire::Snapshot& output) noexcept {
    if (!detail::objects_disjoint(log, source, workspace, output)) return false;
    clear(output, sequence, date, kind, Failure::not_captured);
    if (kind == 2) {
        output.state = wire::State::not_applicable; output.failure = 0;
        return true;
    }
    if (!sequence || date < 0 || kind != 1 || source.pair_count > text::kMaxPairs
            || !log.record_count || log.record_count > text::detail::kMaxReadRecords
            || log.bytes_used > text::kMaxPerPassReadBytes
            || !text::detail::valid_pointer(log.records[0].address)) {
        output.failure = static_cast<std::uint8_t>(Failure::invalid); return false;
    }
    detail::Replay replay{log};
    if (!text::detail::capture_container_one(replay, log.records[0].address, workspace.replayed)
            || replay.index != log.record_count || !text::detail::same_snapshot(source, workspace.replayed)) {
        output.failure = static_cast<std::uint8_t>(Failure::input_changed); return false;
    }
    wire::Snapshot candidate{};
    candidate.sequence = sequence; candidate.raw_date = date; candidate.kind = kind;
    candidate.state = wire::State::known; candidate.failure = 0;
    std::size_t record_index = 1;
    for (std::size_t index = 0; index < source.pair_count; ++index) {
        if (record_index >= log.record_count) {
            output.failure = static_cast<std::uint8_t>(Failure::invalid); return false;
        }
        const auto& record = log.records[record_index];
        if (record.size != text::kNodeBytes || record.offset > log.bytes_used
                || record.size > log.bytes_used - record.offset) {
            output.failure = static_cast<std::uint8_t>(Failure::invalid); return false;
        }
        const auto* node = log.bytes.data() + record.offset;
        const auto& pair = source.pairs[index];
        const bool ours = detail::key(source, pair.key, "OURFLAG");
        if (ours || detail::key(source, pair.key, "ENEMYFLAG")) {
            auto& entry = candidate.entries[candidate.entry_count++];
            entry.pair_index = static_cast<std::uint16_t>(index); entry.side = ours ? 0 : 1;
            const Address rebel = text::detail::load_u64(node + 0x50);
            if (rebel) {
                entry.mode = wire::Mode::rebel;
                if (!detail::rebel_value(reader, rebel, log, source, workspace, output, entry.rebel_raw)) {
                    output.failure = static_cast<std::uint8_t>(Failure::rebel_read_failed); return false;
                }
            } else if (node[0x47]) {
                entry.mode = wire::Mode::country;
                entry.country_ref = text::detail::load_u64(node + 0x40);
            }
        }
        // Each heap String32 adds exactly one read after its node header.
        record_index += 1 + (text::detail::load_u64(node + 0x18) >= 16 ? 1 : 0)
                          + (text::detail::load_u64(node + 0x38) >= 16 ? 1 : 0);
    }
    if (record_index != log.record_count || !wire::detail::valid_fields(candidate)) {
        output.failure = static_cast<std::uint8_t>(Failure::invalid); return false;
    }
    output = candidate;
    return true;
}
} // namespace information::battle::owned_flag_inputs
#endif
