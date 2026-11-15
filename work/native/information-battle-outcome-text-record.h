#ifndef INFORMATION_BATTLE_OUTCOME_TEXT_RECORD_H
#define INFORMATION_BATTLE_OUTCOME_TEXT_RECORD_H

// Convert an owned capture into one canonical OCTX group. Failure affects
// this group only; the caller's base11 and sibling groups are not parameters.
#include "information-battle-owned-outcome-text.h"
#include "information-battle-outcome-text-wire.h"

namespace information::battle::outcome_text_record {
namespace owned = owned_outcome_text;
namespace wire = outcome_text_wire;
namespace model = display_context;
static_assert(owned::kOutcomeKeyCount + 1u == wire::kFieldCount);

inline void clear(wire::Snapshot& output, std::uint64_t sequence,
                  std::int32_t date, std::uint8_t kind,
                  model::Failure failure = model::Failure::not_captured) noexcept {
    output = wire::Snapshot{};
    output.sequence = sequence;
    output.raw_date = date;
    output.kind = kind;
    const auto code = static_cast<std::uint16_t>(failure);
    output.failure = code >= 1u && code <= 9u ? code : 1u;
}

namespace detail {
template <std::size_t Limit>
inline bool valid(const owned::TextValue<Limit>& value, bool language) noexcept {
    if (value.state == model::State::absent)
        return !language && value.length == 0u;
    if (value.state != model::State::observed || value.length > Limit
            || value.bytes[value.length] != 0u) return false;
    for (std::size_t i = 0; i < value.length; ++i)
        if (value.bytes[i] == 0u) return false;
    return !language || wire::detail::language_valid(value.bytes.data(), value.length);
}

template <std::size_t Limit>
inline void copy(wire::Text& target, const owned::TextValue<Limit>& source) noexcept {
    target.state = source.state == model::State::absent ? wire::State::absent : wire::State::known;
    target.length = source.length;
    // Wire storage has exactly8192 bytes; the owned terminator is not copied.
    if (source.length) std::memcpy(target.bytes.data(), source.bytes.data(), source.length);
}

inline bool disjoint(const owned::Snapshot& source, const owned::Result& result,
                     wire::Snapshot& output) noexcept {
    wire::Address s=0,se=0,r=0,re=0,o=0,oe=0;
    return wire::detail::pointer_range(&source,sizeof(source),s,se)
        && wire::detail::pointer_range(&result,sizeof(result),r,re)
        && wire::detail::pointer_range(&output,sizeof(output),o,oe)
        && !wire::detail::overlaps(s,se,o,oe)
        && !wire::detail::overlaps(r,re,o,oe);
}
} // namespace detail

// Returns true for a canonical known or failed group. A malformed "success"
// is downgraded to unknown/invalid_input, never treated as a successful copy.
// Overlapping output parameters are refused without modifying their storage.
inline bool assign(std::uint64_t sequence, std::int32_t date, std::uint8_t kind,
                   bool captured, const owned::Snapshot& source,
                   const owned::Result& result, wire::Snapshot& output) noexcept {
    if (!detail::disjoint(source,result,output)) return false;
    clear(output,sequence,date,kind);
    if (!sequence || date < 0 || (kind != 1u && kind != 2u)) return false;
    if (!captured) {
        clear(output,sequence,date,kind,result.failure);
        return true;
    }
    bool valid = result.attempted && result.observed && result.two_pass_consistent
        && result.failure == model::Failure::none
        && source.sequence == sequence && source.raw_date == date && source.kind == kind
        && detail::valid(source.language,true);
    for (const auto& field : source.fields) valid = detail::valid(field,false) && valid;
    if (!valid) {
        clear(output,sequence,date,kind,model::Failure::invalid_input);
        return true;
    }
    output.failure = 0u;
    detail::copy(output.fields[wire::language],source.language);
    for (std::size_t i=0;i<source.fields.size();++i) detail::copy(output.fields[i+1u],source.fields[i]);
    return true;
}
} // namespace information::battle::outcome_text_record
#endif
