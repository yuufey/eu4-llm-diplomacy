#ifndef INFORMATION_BATTLE_OWNED_NAME_PREFIX_H
#define INFORMATION_BATTLE_OWNED_NAME_PREFIX_H

// Cached, same-event BATTLE_OF input only. No formatter, lazy lookup fallback,
// message dispatch, plugin or other engine function is invoked.
#include "information-battle-owned-name-sources.h"
#include "information-battle-owned-display-context.h"

namespace information::battle::owned_name_prefix {
namespace cache = owned_display_context;
namespace model = display_context;
using Address = owned_name_sources::Address;
using OwnedText = owned_name_sources::OwnedText;
using Result = cache::Result;

struct Snapshot final {
    std::uint64_t sequence = 0;
    std::int32_t raw_date = 0;
    std::uint8_t kind = 0;
    model::State state = model::State::unknown;
    model::State template_state = model::State::unknown;
    OwnedText language{};
    OwnedText template_text{};
};

struct Workspace final {
    // These model snapshots are private string containers. They are never
    // published as observed message definitions: no definition is read here.
    model::Snapshot first_snapshot{};
    model::Snapshot second_snapshot{};
    cache::detail::ReadLog first_pass{};
    std::array<unsigned char, cache::kMaxSingleReadBytes> scratch{};
    void clear() noexcept {
        first_snapshot = model::Snapshot{};
        second_snapshot = model::Snapshot{};
        first_pass = cache::detail::ReadLog{};
        scratch.fill(0);
    }
};
static_assert(sizeof(Workspace) < 512u * 1024u);

namespace detail {
template <typename Pass>
bool capture_one(Pass& pass, Address base, std::size_t image_size,
                 Address game, const model::Identity& identity,
                 model::Snapshot& output) noexcept {
    Address date_address = 0;
    if (!cache::detail::checked_add(game, cache::kGameDateOffset, date_address)
            || !pass.read(date_address, sizeof(std::int32_t))) return false;
    std::int32_t date = 0;
    if (!cache::detail::load_i32(pass.scratch(), sizeof(date), 0, date)
            || date != identity.date) {
        pass.fail(model::Failure::guard);
        return false;
    }
    cache::detail::LocalizationSource source{};
    if (!cache::detail::capture_localization_headers(pass, base, image_size, source, output)
            || !cache::detail::lookup_localization(pass, source, "BATTLE_OF", output, 2u))
        return false;
    const auto& language = output.fields[1];
    if (language.state != model::State::observed
            || !cache::detail::valid_language(output.arena.data() + language.offset,
                                               language.length)) {
        pass.fail(model::Failure::cache_invalid);
        return false;
    }
    output.identity = identity;
    return true;
}

inline void copy(const model::Snapshot& source, std::size_t field, OwnedText& output) noexcept {
    const auto& text = source.fields[field];
    output.length = text.length;
    if (text.length)
        std::memcpy(output.bytes.data(), source.arena.data() + text.offset, text.length);
}
} // namespace detail

// Guard must bind the EXE/code, frame thread, date and live combat scope.
// Separate parameters are metadata, not proof of that binding. Every byte
// used in the first pass must be read from the same address with the same
// value in the second pass, including cache headers and binary-search nodes.
template <typename Reader, typename Guard>
bool capture(Reader& reader, Guard& guard, Address base, std::size_t image_size,
             Address game, std::uint64_t sequence, std::int32_t date,
             std::uint8_t kind, Workspace& workspace, Snapshot& output,
             Result& result) noexcept {
    static_assert(owned_name_sources::reader_contract<Reader>::value);
    static_assert(owned_name_sources::guard_contract<Guard>::value);
    cache::detail::AddressRange wr{}, out{}, rr{};
    if (!cache::detail::object_range(&workspace, sizeof(workspace), wr)
            || !cache::detail::object_range(&output, sizeof(output), out)
            || !cache::detail::object_range(&result, sizeof(result), rr)
            || cache::detail::ranges_overlap(wr, out)
            || cache::detail::ranges_overlap(wr, rr)
            || cache::detail::ranges_overlap(out, rr)) return false;
    workspace.clear();
    output = Snapshot{};
    result = Result{};
    result.attempted = true;
    result.failure = model::Failure::none;
    auto fail = [&](model::Failure failure) noexcept {
        if (result.failure == model::Failure::none) result.failure = failure;
        output = Snapshot{};
        workspace.clear();
        return false;
    };
    Address image_end = 0;
    if (!sequence || date < 0 || (kind != 1 && kind != 2)
            || !cache::detail::checked_range(base, image_size, image_end)
            || !cache::detail::valid_pointer(game)) return fail(model::Failure::invalid_input);
    if (!guard.guard()) return fail(model::Failure::guard);
    model::Identity identity{sequence, date, kind, 1u};
    cache::detail::PassReader<Reader, Workspace> first(
        reader, workspace, result, 0, wr, out, rr, &workspace.first_pass, nullptr);
    if (!detail::capture_one(first, base, image_size, game, identity, workspace.first_snapshot)
            || !first.complete()) return fail(model::Failure::cache_invalid);
    if (!guard.guard()) return fail(model::Failure::guard);
    cache::detail::PassReader<Reader, Workspace> second(
        reader, workspace, result, 1, wr, out, rr, nullptr, &workspace.first_pass);
    if (!detail::capture_one(second, base, image_size, game, identity, workspace.second_snapshot)
            || !second.complete()
            || !cache::detail::same_snapshot(workspace.first_snapshot, workspace.second_snapshot))
        return fail(model::Failure::source_changed);
    if (!guard.guard()) return fail(model::Failure::guard);
    output.sequence = sequence;
    output.raw_date = date;
    output.kind = kind;
    output.state = model::State::observed;
    output.template_state = workspace.first_snapshot.fields[2].state;
    detail::copy(workspace.first_snapshot, 1, output.language);
    if (output.template_state == model::State::observed)
        detail::copy(workspace.first_snapshot, 2, output.template_text);
    result.observed = true;
    result.two_pass_consistent = true;
    workspace.clear();
    return true;
}
} // namespace information::battle::owned_name_prefix
#endif
