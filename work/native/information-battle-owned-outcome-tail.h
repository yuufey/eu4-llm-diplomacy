#ifndef INFORMATION_BATTLE_OWNED_OUTCOME_TAIL_H
#define INFORMATION_BATTLE_OWNED_OUTCOME_TAIL_H

// Copies three same-event special-country i32 slots and four naval cache entries.
// This reader does not select a WINORLOSE branch, format text, or call any
// native lookup, formatter, fallback, or message function.
#include "information-battle-owned-name-sources.h"
#include "information-battle-owned-display-context.h"

namespace information::battle::owned_outcome_tail {

namespace cache = owned_display_context;
namespace model = display_context;
using Address = cache::Address;
using Result = cache::Result;

inline constexpr std::size_t kOutcomeKeyCount = 4u;

enum class Key : std::uint8_t {
    combat_flee = 0u, combat_triumph = 1u,
    combat_winnertype_our = 2u, combat_winnertype_their = 3u,
};
inline constexpr std::array<const char*, kOutcomeKeyCount> kLocalizationKeys{{
    "COMBAT_FLEE", "COMBAT_TRIUMPH", "COMBAT_WINNERTYPE_OUR", "COMBAT_WINNERTYPE_THEIR",
}};
inline constexpr std::array<Address, 3u> kSpecialSlotRvas{{
    Address(0x233d884u), Address(0x233d8b8u), Address(0x233d8bcu),
}};

template <std::size_t MaxBytes>
struct TextValue final {
    model::State state = model::State::unknown;
    std::uint32_t length = 0u;
    std::array<unsigned char, MaxBytes + 1u> bytes{};
};

using OutcomeValue = TextValue<model::kMaxTextBytes>;
using LanguageValue = TextValue<model::kMaxLanguageBytes>;

// Pointer-free, byte-preserving copies. observed with length zero is distinct
// from absent; unknown is reserved for a failed or not-yet-captured bundle.
struct Snapshot final {
    std::uint64_t sequence = 0u;
    std::int32_t raw_date = 0;
    std::uint8_t kind = 0u;
    std::array<std::int32_t, 3u> reserved_slots{};
    LanguageValue language{};
    std::array<OutcomeValue, kOutcomeKeyCount> fields{};
};

static_assert(std::is_trivially_copyable<OutcomeValue>::value);
static_assert(std::is_trivially_copyable<LanguageValue>::value);
static_assert(std::is_trivially_copyable<Snapshot>::value);

struct Workspace final {
    Snapshot first_snapshot{};
    Snapshot second_snapshot{};
    model::Snapshot temporary_snapshot{};
    cache::detail::ReadLog first_pass{};
    std::array<unsigned char, cache::kMaxSingleReadBytes> scratch{};

    void clear() noexcept {
        first_snapshot = Snapshot{};
        second_snapshot = Snapshot{};
        temporary_snapshot = model::Snapshot{};
        first_pass = cache::detail::ReadLog{};
        scratch.fill(0u);
    }
};

static_assert(std::is_trivially_copyable<Workspace>::value,
              "workspace must remain fixed value storage");
static_assert(sizeof(Workspace) < 512u * 1024u,
              "workspace must remain inside the existing 512 KiB read budget");

namespace detail {

inline bool copy_text(const model::Snapshot& source, std::size_t field_index,
               std::size_t max_bytes, model::State expected_state,
               model::State& state, std::uint32_t& length,
               unsigned char* destination, std::size_t destination_capacity) noexcept {
    if (field_index >= model::kFieldCount || destination == nullptr
            || destination_capacity == 0u) {
        return false;
    }
    const model::Text& text = source.fields[field_index];
    if (text.state != expected_state || text.length > max_bytes
            || text.length >= destination_capacity
            || text.offset > source.arena_used
            || text.length > source.arena_used - text.offset) {
        return false;
    }
    state = text.state;
    length = text.length;
    if (text.length != 0u) {
        std::memcpy(destination, source.arena.data() + text.offset, text.length);
    }
    destination[text.length] = 0u;
    return true;
}

inline bool copy_lookup(const model::Snapshot& source,
                        OutcomeValue& destination) noexcept {
    const model::State state = source.fields[2u].state;
    if (state != model::State::observed && state != model::State::absent) {
        return false;
    }
    if (state == model::State::absent) {
        destination = OutcomeValue{};
        destination.state = model::State::absent;
        return true;
    }
    return copy_text(source, 2u, model::kMaxTextBytes,
                     model::State::observed, destination.state,
                     destination.length, destination.bytes.data(),
                     destination.bytes.size());
}

template <typename Pass>
bool capture_one(Pass& pass, Address base, std::size_t image_size,
                 Address game, std::uint64_t sequence, std::int32_t date,
                 std::uint8_t kind, Workspace& workspace,
                 Snapshot& output) noexcept {
    Address date_address = 0u;
    if (!cache::detail::checked_add(game, cache::kGameDateOffset, date_address)
            || !pass.read(date_address, sizeof(std::int32_t))) {
        pass.fail(model::Failure::invalid_input);
        return false;
    }
    std::int32_t observed_date = 0;
    if (!cache::detail::load_i32(pass.scratch(), sizeof(observed_date), 0u,
                                 observed_date)
            || observed_date != date) {
        pass.fail(model::Failure::guard);
        return false;
    }

    // Read each actual i32 cell, not padding between the three globals.
    for (std::size_t index = 0u; index < kSpecialSlotRvas.size(); ++index) {
        const auto offset = kSpecialSlotRvas[index];
        Address address = 0u;
        if (offset > image_size || sizeof(std::int32_t) > image_size - offset
                || !cache::detail::checked_add(base, offset, address)) {
            pass.fail(model::Failure::invalid_input);
            return false;
        }
        if (!pass.read(address, sizeof(std::int32_t))
                || !cache::detail::load_i32(pass.scratch(), sizeof(std::int32_t), 0u,
                                          output.reserved_slots[index])) {
            if (pass.failure() == model::Failure::none) pass.fail(model::Failure::read_failed);
            return false;
        }
    }

    cache::detail::LocalizationSource source{};
    workspace.temporary_snapshot = model::Snapshot{};
    if (!cache::detail::capture_localization_headers(
            pass, base, image_size, source, workspace.temporary_snapshot)) {
        return false;
    }
    const model::Text& language = workspace.temporary_snapshot.fields[1u];
    if (language.state != model::State::observed
            || language.length > model::kMaxLanguageBytes
            || !cache::detail::valid_language(
                workspace.temporary_snapshot.arena.data() + language.offset,
                language.length)
            || !copy_text(workspace.temporary_snapshot, 1u,
                          model::kMaxLanguageBytes,
                          model::State::observed, output.language.state,
                          output.language.length,
                          output.language.bytes.data(),
                          output.language.bytes.size())) {
        pass.fail(model::Failure::cache_invalid);
        return false;
    }

    for (std::size_t index = 0u; index < kOutcomeKeyCount; ++index) {
        workspace.temporary_snapshot = model::Snapshot{};
        if (!cache::detail::lookup_localization(
                pass, source, kLocalizationKeys[index],
                workspace.temporary_snapshot, 2u)
                || !copy_lookup(workspace.temporary_snapshot,
                                output.fields[index])) {
            if (pass.failure() == model::Failure::none) {
                pass.fail(model::Failure::cache_invalid);
            }
            return false;
        }
    }

    output.sequence = sequence;
    output.raw_date = date;
    output.kind = kind;
    return true;
}

inline bool same_text(const LanguageValue& left,
                      const LanguageValue& right) noexcept {
    return left.state == right.state && left.length == right.length
        && left.length <= model::kMaxLanguageBytes
        && std::memcmp(left.bytes.data(), right.bytes.data(),
                       static_cast<std::size_t>(left.length) + 1u) == 0;
}

inline bool same_text(const OutcomeValue& left,
                      const OutcomeValue& right) noexcept {
    return left.state == right.state && left.length == right.length
        && left.length <= model::kMaxTextBytes
        && std::memcmp(left.bytes.data(), right.bytes.data(),
                       static_cast<std::size_t>(left.length) + 1u) == 0;
}

inline bool same_snapshot(const Snapshot& left,
                          const Snapshot& right) noexcept {
    if (left.sequence != right.sequence || left.raw_date != right.raw_date
            || left.kind != right.kind || left.reserved_slots != right.reserved_slots
            || !same_text(left.language, right.language)) {
        return false;
    }
    for (std::size_t index = 0u; index < kOutcomeKeyCount; ++index) {
        if (!same_text(left.fields[index], right.fields[index])) return false;
    }
    return true;
}

inline bool source_overlaps(const cache::detail::AddressRange& source,
                            const cache::detail::AddressRange& workspace,
                            const cache::detail::AddressRange& output,
                            const cache::detail::AddressRange& result) noexcept {
    return cache::detail::ranges_overlap(source, workspace)
        || cache::detail::ranges_overlap(source, output)
        || cache::detail::ranges_overlap(source, result);
}

} // namespace detail

// Guard must bind the EXE/code, frame thread, date and live combat scope.
// Each pass reads only the cached localization structures and validates every
// byte/address against the first-pass log before returning a pointer-free copy.
template <typename Reader, typename Guard>
bool capture(Reader& reader, Guard& guard, Address base, std::size_t image_size,
             Address game, std::uint64_t sequence, std::int32_t date,
             std::uint8_t kind, Workspace& workspace, Snapshot& output,
             Result& result) noexcept {
    static_assert(owned_name_sources::reader_contract<Reader>::value,
                  "Reader::read must match the existing noexcept contract");
    static_assert(owned_name_sources::guard_contract<Guard>::value,
                  "Guard::guard must match the existing noexcept contract");

    cache::detail::AddressRange workspace_range{}, output_range{}, result_range{};
    if (!cache::detail::object_range(&workspace, sizeof(workspace), workspace_range)
            || !cache::detail::object_range(&output, sizeof(output), output_range)
            || !cache::detail::object_range(&result, sizeof(result), result_range)
            || cache::detail::ranges_overlap(workspace_range, output_range)
            || cache::detail::ranges_overlap(workspace_range, result_range)
            || cache::detail::ranges_overlap(output_range, result_range)) {
        return false;
    }

    Address image_end = 0u;
    const bool image_valid = cache::detail::checked_range(base, image_size, image_end);
    Address game_date_address = 0u;
    Address game_date_end = 0u;
    const bool game_date_valid = cache::detail::valid_pointer(game)
        && cache::detail::checked_add(game, cache::kGameDateOffset,
                                      game_date_address)
        && cache::detail::checked_range(game_date_address,
                                        sizeof(std::int32_t), game_date_end);
    if ((image_valid && detail::source_overlaps(
             {base, image_end}, workspace_range, output_range, result_range))
            || (game_date_valid && detail::source_overlaps(
                {game_date_address, game_date_end}, workspace_range,
                output_range, result_range))) {
        return false;
    }

    workspace.clear();
    output = Snapshot{};
    result = Result{};
    result.attempted = true;
    result.failure = model::Failure::none;
    auto fail = [&](model::Failure fallback) noexcept {
        if (result.failure == model::Failure::none) result.failure = fallback;
        output = Snapshot{};
        workspace.clear();
        return false;
    };

    if (sequence == 0u || date < 0 || (kind != 1u && kind != 2u)
            || !image_valid || !game_date_valid) {
        return fail(model::Failure::invalid_input);
    }
    if (!guard.guard()) return fail(model::Failure::guard);

    cache::detail::PassReader<Reader, Workspace> first(
        reader, workspace, result, 0u, workspace_range, output_range,
        result_range, &workspace.first_pass, nullptr);
    if (!detail::capture_one(first, base, image_size, game, sequence, date,
                             kind, workspace, workspace.first_snapshot)
            || !first.complete()) {
        return fail(model::Failure::cache_invalid);
    }

    if (!guard.guard()) return fail(model::Failure::guard);
    cache::detail::PassReader<Reader, Workspace> second(
        reader, workspace, result, 1u, workspace_range, output_range,
        result_range, nullptr, &workspace.first_pass);
    if (!detail::capture_one(second, base, image_size, game, sequence, date,
                             kind, workspace, workspace.second_snapshot)
            || !second.complete()
            || !detail::same_snapshot(workspace.first_snapshot,
                                      workspace.second_snapshot)) {
        return fail(model::Failure::source_changed);
    }

    if (!guard.guard()) return fail(model::Failure::guard);
    output = workspace.first_snapshot;
    result.observed = true;
    result.two_pass_consistent = true;
    workspace.clear();
    return true;
}

} // namespace information::battle::owned_outcome_tail
#endif
