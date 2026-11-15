#ifndef INFORMATION_BATTLE_OWNED_INDEPENDENT_LINE_H
#define INFORMATION_BATTLE_OWNED_INDEPENDENT_LINE_H

// Request one independent name-line render from same-event owned inputs.
// The caller supplies the guarded native invocation and its owned destructor.
#include "information-battle-independent-line-wire.h"
#include "information-battle-name-sources-wire.h"
#include "information-battle-display-context-layout.h"
#include "information-battle-owned-title-query.h"
#include "format_input_builder.h"

namespace information::battle::owned_independent_line {
namespace wire = independent_line_wire;
namespace names = name_sources_wire;
namespace model = display_context;
namespace text = owned_native_text;
using String32 = owned_title_query::String32;
enum class Failure : std::uint8_t {
    none = 0, not_captured = 1, inputs = 2, template_unsupported = 3,
    name_source = 4, input_bound = 5, guard_before = 6,
    returned_pointer = 7, guard_after = 8, output_copy = 9,
    guard_after_destroy = 10, arguments_changed = 11, invalid_output = 12,
};
struct Workspace final {
    battle_format_input::Workspace arguments{};
    battle_format_input::NativeArg104 expected_argument{};
    std::array<battle_format_input::InputRow, 1> rows{};
    wire::Snapshot prepared{};
    text::Snapshot native_output{};
    String32 output{};
};

inline void clear(wire::Snapshot& value, const model::Identity& identity,
                  Failure failure, std::uint8_t flags = 0) noexcept {
    value = wire::Snapshot{};
    value.sequence = identity.sequence;
    value.raw_date = identity.date;
    value.kind = identity.kind;
    value.failure = static_cast<std::uint8_t>(failure);
    value.flags = flags;
}

namespace detail {
inline std::string_view field(const model::Snapshot& context, std::size_t index) noexcept {
    const auto& value = context.fields[index];
    return {reinterpret_cast<const char*>(context.arena.data() + value.offset), value.length};
}
inline std::string_view field(const names::Text& value) noexcept {
    return {reinterpret_cast<const char*>(value.bytes.data()), value.length};
}
inline void copy(wire::Text& target, std::string_view value) noexcept {
    target.state = wire::State::known;
    target.length = static_cast<std::uint32_t>(value.size());
    std::memcpy(target.bytes.data(), value.data(), value.size());
}
inline Failure prepare(const model::Snapshot& context, const names::Snapshot& source,
                       Workspace& workspace) noexcept {
    workspace.prepared = wire::Snapshot{};
    if (!model::valid(context) || context.state != model::State::observed
            || source.sequence != context.identity.sequence || source.raw_date != context.identity.date
            || source.kind != context.identity.kind || source.raw_failure || source.prefix_failure)
        return Failure::inputs;
    if (context.fields[2].state != model::State::observed || field(context, 2) != "$NAME$")
        return Failure::template_unsupported;
    if (source.transform_mode != 1 && source.transform_mode != 2) return Failure::name_source;
    for (std::size_t index = 0; index < source.fields.size(); ++index) {
        const auto& value = source.fields[index];
        const auto maximum = index == names::language ? 256u : 8192u;
        if (value.state != names::State::known || value.length > maximum
                || std::memchr(value.bytes.data(), 0, value.length)) return Failure::name_source;
    }
    const auto prefix = field(source.fields[names::battle_of_template]);
    if (field(source.fields[names::language]) != field(context, 1)
            || prefix.find('$') != std::string_view::npos) return Failure::name_source;
    const auto global = field(source.fields[names::global_name]);
    const auto owner = field(source.fields[names::owner_name]);
    const bool plugin = source.transform_mode == 2;
    const auto tail_size = global.size() + owner.size();
    if (plugin && !tail_size) return Failure::name_source;
    const auto size = prefix.size() + tail_size - (plugin ? 1u : 0u);
    // Leave four bytes for the formatter's possible color wrappers within
    // the existing bounded native String32 reader's 8192-byte output limit.
    if (size > text::kMaxTextBytes - 4) return Failure::input_bound;
    auto& row = workspace.rows[0];
    row.key = "NAME";
    row.value.clear();
    row.value.reserve(size);
    if (!plugin) row.value.append(prefix);
    row.value.append(global);
    row.value.append(owner);
    if (plugin) {
        row.value.erase(0, 1);
        row.value.append(prefix);
    }
    if (workspace.arguments.build_for_bound_template(field(context, 0), workspace.rows, field(context, 2))
            != battle_format_input::BuildStatus::ok) return Failure::input_bound;
    workspace.expected_argument = *workspace.arguments.argument(0);
    auto& prepared = workspace.prepared;
    prepared.sequence = source.sequence;
    prepared.raw_date = source.raw_date;
    prepared.kind = source.kind;
    prepared.transform_mode = source.transform_mode;
    copy(prepared.fields[wire::language], field(context, 1));
    copy(prepared.fields[wire::definition_key], field(context, 0));
    copy(prepared.fields[wire::body_template], field(context, 2));
    copy(prepared.fields[wire::name_input], row.value);
    return Failure::none;
}
inline bool arguments_unchanged(const Workspace& workspace) noexcept {
    const auto& arguments = workspace.arguments;
    const auto* entries = arguments.argument(0);
    if (!entries || arguments.argument_count() != 1) return false;
    const auto* key = battle_format_input::cstr_pointer(entries[0], 0);
    const auto* value = battle_format_input::cstr_pointer(entries[0], 0x60);
    const auto& definition = workspace.prepared.fields[wire::definition_key];
    return !std::memcmp(entries, &workspace.expected_argument, sizeof(*entries))
        && arguments.owns_c_string(arguments.body_key(), 64)
        && std::strlen(arguments.body_key()) == definition.length + 2
        && !std::memcmp(arguments.body_key(), definition.bytes.data(), definition.length)
        && std::strcmp(arguments.body_key() + definition.length, "_1") == 0
        && arguments.owns_c_string(key, 4)
        && arguments.owns_c_string(value, workspace.rows[0].value.size())
        && std::strcmp(key, "NAME") == 0
        && std::strcmp(value, workspace.rows[0].value.c_str()) == 0
        && battle_format_input::dword_at(entries[0], 0x28) == 2;
}
} // namespace detail

template <typename Reader, typename Invoker>
bool capture(Reader& reader, Invoker& invoker, const model::Snapshot& context,
             const names::Snapshot& source, Workspace& workspace, wire::Snapshot& result) noexcept {
    clear(result, context.identity, Failure::not_captured);
    const auto prepared = detail::prepare(context, source, workspace);
    if (prepared != Failure::none) {
        clear(result, context.identity, prepared);
        return false;
    }
    if (!invoker.guard(context)) {
        clear(result, context.identity, Failure::guard_before);
        return false;
    }
    workspace.output = String32{};
    text::clear(workspace.native_output);
    const auto* returned = invoker.invoke(&workspace.output, workspace.arguments.body_key(),
        workspace.arguments.argument(0), static_cast<std::int32_t>(workspace.arguments.argument_count()));
    std::uint8_t flags = 1;
    Failure failure = Failure::none;
    const bool same_pointer = returned == &workspace.output;
    if (same_pointer) flags |= 2;
    else failure = Failure::returned_pointer;
    const bool after = invoker.guard(context);
    if (!after && failure == Failure::none) failure = Failure::guard_after;
    if (!detail::arguments_unchanged(workspace) && failure == Failure::none)
        failure = Failure::arguments_changed;
    // Reuse only the bounded String32 copy mechanics. This scratch field is
    // never published as a title helper or an actual popup Line1 observation.
    if (failure == Failure::none
            && !text::capture_string(reader, reinterpret_cast<text::Address>(&workspace.output),
                text::SourceKind::title_helper_candidate, workspace.native_output)) failure = Failure::output_copy;
    invoker.destroy(&workspace.output);
    flags |= 4;
    const bool destroyed_guard = invoker.guard(context);
    if (after && destroyed_guard) flags |= 8;
    if (!destroyed_guard && failure == Failure::none) failure = Failure::guard_after_destroy;
    if (failure != Failure::none) {
        clear(result, context.identity, failure, flags);
        text::clear(workspace.native_output);
        return false;
    }
    const auto& field = workspace.native_output.title_helper_candidate.bytes;
    detail::copy(workspace.prepared.fields[wire::output], {
        reinterpret_cast<const char*>(workspace.native_output.arena.data() + field.offset), field.length});
    workspace.prepared.state = wire::State::known;
    workspace.prepared.failure = 0;
    workspace.prepared.flags = flags;
    if (!wire::detail::valid_fields(workspace.prepared)) {
        clear(result, context.identity, Failure::invalid_output, flags);
        return false;
    }
    result = workspace.prepared;
    text::clear(workspace.native_output);
    return true;
}
} // namespace information::battle::owned_independent_line
#endif
