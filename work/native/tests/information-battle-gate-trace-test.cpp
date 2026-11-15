#include "../information-battle-gate-trace.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <limits>
#include <type_traits>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

namespace gate = information::battle::gate_trace;
namespace inputs = information::battle::owned_gate_inputs;

namespace {

static_assert(std::is_same<std::size_t, std::uint64_t>::value,
              "the Win64 fixture requires size_t and uint64_t to share a type");

unsigned g_checks = 0u;
unsigned g_failures = 0u;

void check(bool condition, const char* label) noexcept {
    ++g_checks;
    if (!condition) {
        ++g_failures;
        std::fprintf(stderr, "FAIL:%s\n", label);
    }
}

bool same_identity(const gate::Identity& left,
                   const gate::Identity& right) noexcept {
    return left.pid == right.pid
        && left.creation == right.creation
        && left.installation == right.installation
        && left.generation == right.generation
        && left.sequence == right.sequence
        && left.native_date == right.native_date
        && left.kind == right.kind
        && left.dll_sha256 == right.dll_sha256;
}

bool same_input_sample(const inputs::Snapshot& left,
                       const inputs::Snapshot& right) noexcept {
    return left.status == right.status
        && left.failure == right.failure
        && left.kind == right.kind
        && left.current_country_state == right.current_country_state
        && left.current_country_raw == right.current_country_raw
        && left.mode == right.mode
        && left.alternate_flag == right.alternate_flag
        && left.default_ref_state == right.default_ref_state
        && left.default_ref == right.default_ref
        && left.alternate_ref_state == right.alternate_ref_state
        && left.alternate_ref == right.alternate_ref
        && left.selected_ref_state == right.selected_ref_state
        && left.selected_ref == right.selected_ref
        && left.land_enable_state == right.land_enable_state
        && left.land_enable_raw == right.land_enable_raw
        && left.registry_state == right.registry_state
        && left.slot_state == right.slot_state
        && left.combat_state == right.combat_state
        && left.equals_current_combat_known == right.equals_current_combat_known
        && left.equals_current_combat == right.equals_current_combat
        && left.ui_override_known == right.ui_override_known
        && left.ui_override_value == right.ui_override_value
        && left.read_calls == right.read_calls
        && left.read_bytes == right.read_bytes;
}

bool same_snapshot(const gate::Snapshot& left,
                   const gate::Snapshot& right) noexcept {
    if (left.sample_mask != right.sample_mask
            || left.passed_marker_candidates != right.passed_marker_candidates
            || left.passed_marker_accepted != right.passed_marker_accepted
            || left.message_entries != right.message_entries
            || left.message_copy_attempts != right.message_copy_attempts
            || left.cleanup_entries != right.cleanup_entries
            || left.line1_entries != right.line1_entries
            || left.marker_reject_mask != right.marker_reject_mask
            || left.message_reject_mask != right.message_reject_mask
            || left.line1_reject_mask != right.line1_reject_mask
            || left.cleanup_reject_mask != right.cleanup_reject_mask
            || left.last_marker_return_rva != right.last_marker_return_rva
            || left.last_message_return_rva != right.last_message_return_rva
            || left.router_return_rva != right.router_return_rva
            || left.observation_drops != right.observation_drops
            || left.scope_completed != right.scope_completed
            || left.scope_ambiguous != right.scope_ambiguous
            || left.counter_overflow != right.counter_overflow) {
        return false;
    }
    for (unsigned index = 0u; index < static_cast<unsigned>(gate::Stage::count);
            ++index) {
        if (!same_input_sample(left.samples[index], right.samples[index])) {
            return false;
        }
    }
    return true;
}

template <typename Call>
bool rejected_without_input_mutation(const gate::Identity& identity,
                                     const gate::Snapshot& trace,
                                     Call&& call) noexcept {
    const gate::Identity identity_before = identity;
    const gate::Snapshot trace_before = trace;
    return !call() && same_identity(identity, identity_before)
        && same_snapshot(trace, trace_before);
}

gate::Identity valid_identity() noexcept {
    gate::Identity identity{};
    identity.pid = 64201u;
    identity.creation = (std::numeric_limits<std::uint64_t>::max)();
    identity.installation = (std::numeric_limits<std::uint64_t>::max)();
    identity.generation = (std::numeric_limits<std::uint64_t>::max)();
    identity.sequence = (std::numeric_limits<std::uint64_t>::max)();
    identity.native_date = 56562768;
    identity.kind = inputs::Kind::land;
    constexpr char digest[] =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    static_assert(sizeof(digest) == 65u, "the test digest must be SHA-256 text");
    std::memcpy(identity.dll_sha256.data(), digest, sizeof(digest));
    return identity;
}

void make_known_sample(inputs::Snapshot& sample, inputs::Kind kind) noexcept {
    sample.status = inputs::Status::complete;
    sample.failure = inputs::Failure::none;
    sample.kind = kind;
    sample.current_country_state = inputs::FieldState::observed;
    constexpr unsigned char current_country[16] = {
        0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 7u, 0u,
        0xfeu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 1u,
    };
    for (unsigned index = 0u; index < 16u; ++index) {
        sample.current_country_raw[index] = current_country[index];
    }
    sample.mode = 7u;
    sample.alternate_flag = 1u;
    sample.default_ref_state = inputs::FieldState::observed;
    sample.default_ref = (std::numeric_limits<std::uint64_t>::max)();
    sample.alternate_ref_state = inputs::FieldState::observed;
    sample.alternate_ref = (std::numeric_limits<std::uint64_t>::max)() - 1u;
    sample.selected_ref_state = inputs::FieldState::observed;
    sample.selected_ref = sample.alternate_ref;
    sample.land_enable_state = inputs::FieldState::observed;
    sample.land_enable_raw = 1u;
    sample.registry_state = inputs::ObjectState::present;
    sample.slot_state = inputs::ObjectState::present;
    sample.combat_state = inputs::ObjectState::present;
    sample.equals_current_combat_known = true;
    sample.equals_current_combat = true;
    sample.ui_override_known = true;
    sample.ui_override_value = true;
    sample.read_calls = 9u;
    sample.read_bytes = 81u;
}

gate::Snapshot valid_trace() noexcept {
    gate::Snapshot trace{};
    trace.sample_mask = 0x0fu;
    trace.passed_marker_candidates = 7u;
    trace.passed_marker_accepted = 6u;
    trace.message_entries = 5u;
    trace.message_copy_attempts = 4u;
    trace.cleanup_entries = 3u;
    trace.line1_entries = 2u;
    trace.marker_reject_mask = gate::wrong_return | gate::wrong_callback;
    trace.message_reject_mask = gate::wrong_sequence;
    trace.line1_reject_mask = gate::line1_filter_rejected;
    trace.cleanup_reject_mask = gate::invalid_owner;
    trace.last_marker_return_rva = 0x002353d0u;
    trace.last_message_return_rva = 0x00244630u;
    trace.scope_completed = true;

    make_known_sample(trace.samples[0], inputs::Kind::land);

    inputs::Snapshot& unknown = trace.samples[1];
    unknown.status = inputs::Status::partial;
    unknown.failure = inputs::Failure::reader_failed;
    unknown.kind = inputs::Kind::naval;
    unknown.current_country_state = inputs::FieldState::unknown;
    unknown.default_ref_state = inputs::FieldState::unknown;
    unknown.alternate_ref_state = inputs::FieldState::unknown;
    unknown.selected_ref_state = inputs::FieldState::unknown;
    unknown.land_enable_state = inputs::FieldState::unknown;
    unknown.registry_state = inputs::ObjectState::unknown;
    unknown.slot_state = inputs::ObjectState::unknown;
    unknown.combat_state = inputs::ObjectState::unknown;
    unknown.equals_current_combat_known = false;
    unknown.ui_override_known = false;

    inputs::Snapshot& absent = trace.samples[2];
    absent.status = inputs::Status::complete;
    absent.failure = inputs::Failure::none;
    absent.kind = inputs::Kind::land;
    absent.current_country_state = inputs::FieldState::observed;
    absent.default_ref_state = inputs::FieldState::observed;
    absent.alternate_ref_state = inputs::FieldState::observed;
    absent.selected_ref_state = inputs::FieldState::observed;
    absent.land_enable_state = inputs::FieldState::observed;
    absent.registry_state = inputs::ObjectState::absent;
    absent.slot_state = inputs::ObjectState::absent;
    absent.combat_state = inputs::ObjectState::absent;
    absent.equals_current_combat_known = true;
    absent.equals_current_combat = false;
    absent.ui_override_known = true;
    absent.ui_override_value = false;

    inputs::Snapshot& mixed = trace.samples[3];
    mixed.status = inputs::Status::partial;
    mixed.failure = inputs::Failure::reader_failed;
    mixed.kind = inputs::Kind::naval;
    mixed.current_country_state = inputs::FieldState::observed;
    mixed.default_ref_state = inputs::FieldState::unknown;
    mixed.alternate_ref_state = inputs::FieldState::observed;
    mixed.selected_ref_state = inputs::FieldState::unknown;
    mixed.land_enable_state = inputs::FieldState::unknown;
    mixed.registry_state = inputs::ObjectState::present;
    mixed.slot_state = inputs::ObjectState::absent;
    mixed.combat_state = inputs::ObjectState::unknown;
    mixed.equals_current_combat_known = false;
    mixed.ui_override_known = true;
    mixed.ui_override_value = false;
    mixed.read_calls = 2u;
    mixed.read_bytes = 24u;
    return trace;
}

struct EncodedLine final {
    std::array<char, gate::kMaxJsonBytes> bytes{};
    std::size_t size = 0u;
};

bool encode_line(const gate::Identity& identity, const gate::Snapshot& trace,
                 EncodedLine& line) noexcept {
    line.size = 0u;
    return gate::encode_jsonl(identity, trace, line.bytes.data(),
                              line.bytes.size(), line.size);
}

template <typename U64 = std::uint64_t>
bool written_aliases_identity_is_rejected(gate::Identity& identity,
                                           const gate::Snapshot& trace) noexcept {
    if constexpr (std::is_same<U64, std::size_t>::value) {
        const std::uint64_t before = identity.sequence;
        const gate::Snapshot trace_before = trace;
        std::array<char, gate::kMaxJsonBytes> output{};
        std::size_t& written = identity.sequence;
        const bool accepted = gate::encode_jsonl(
            identity, trace, output.data(), output.size(), written);
        return !accepted && identity.sequence == before
            && same_snapshot(trace, trace_before);
    }
    return false;
}

bool emit(const EncodedLine& line) noexcept {
    if (line.size == 0u || line.size > line.bytes.size()
            || line.bytes[line.size - 1u] != '\n') {
        return false;
    }
    return std::fwrite(line.bytes.data(), 1u, line.size, stdout) == line.size;
}

}  // namespace

int main() {
#ifdef _WIN32
    check(_setmode(_fileno(stdout), _O_BINARY) != -1,
          "stdout_binary_mode_preserves_jsonl_lf");
#endif
    gate::Identity identity = valid_identity();
    gate::Snapshot trace = valid_trace();
    std::array<EncodedLine, 7u> lines{};

    check(gate::observation_complete(trace), "complete_scope_is_complete");
    check(encode_line(identity, trace, lines[0]), "encode_full_four_stage_record");
    check(lines[0].size <= gate::kMaxJsonBytes, "full_record_within_8192");
    check(trace.router_return_rva == 0u, "router_return_rva_defaults_to_zero");
    check(std::strstr(lines[0].bytes.data(),
                      "\"router_return_rva\":0,\"sample_mask\":") != nullptr,
          "router_return_rva_zero_is_encoded");

    gate::Snapshot routed_trace = trace;
    routed_trace.router_return_rva = 0x89abcdefu;
    EncodedLine routed_line{};
    check(encode_line(identity, routed_trace, routed_line),
          "encode_nonzero_router_return_rva_record");
    check(std::strstr(routed_line.bytes.data(),
                      "\"router_return_rva\":2309737967,\"sample_mask\":") != nullptr,
          "router_return_rva_nonzero_is_retained_as_decimal");

    std::array<char, gate::kMaxJsonBytes + 1u> boundary{};
    std::size_t boundary_written = 99u;
    check(gate::encode_jsonl(identity, trace, boundary.data(),
                            gate::kMaxJsonBytes, boundary_written),
          "capacity_8192_is_accepted");
    check(boundary_written > 0u && boundary_written <= gate::kMaxJsonBytes,
          "capacity_8192_written_range");
    check(boundary[boundary_written - 1u] == '\n', "record_ends_with_lf");
    check(boundary[boundary_written] == '\0', "record_nul_terminator_after_lf");

    const gate::Identity sparse_identity = []() noexcept {
        gate::Identity value = valid_identity();
        value.sequence = 5u;
        return value;
    }();
    gate::Snapshot sparse_trace = trace;
    sparse_trace.sample_mask = 0x05u;
    check(encode_line(sparse_identity, sparse_trace, lines[1]),
          "encode_sparse_sample_mask");

    gate::Identity unknown_kind_identity = valid_identity();
    unknown_kind_identity.sequence = 6u;
    unknown_kind_identity.kind = static_cast<inputs::Kind>(0u);
    check(encode_line(unknown_kind_identity, trace, lines[2]),
          "explicit_unknown_identity_kind_is_serialized");

    gate::Snapshot overflow_trace = trace;
    overflow_trace.passed_marker_candidates =
        (std::numeric_limits<std::uint32_t>::max)();
    gate::increment(overflow_trace.passed_marker_candidates, overflow_trace);
    check(overflow_trace.counter_overflow, "counter_saturation_is_recorded");
    check(overflow_trace.passed_marker_candidates
              == (std::numeric_limits<std::uint32_t>::max)(),
          "saturated_counter_does_not_wrap");
    check(!gate::observation_complete(overflow_trace),
          "counter_overflow_is_not_complete");
    gate::Identity overflow_identity = valid_identity();
    overflow_identity.sequence = 1u;
    check(encode_line(overflow_identity, overflow_trace, lines[3]),
          "encode_counter_overflow_record");

    gate::Snapshot drops_trace = trace;
    drops_trace.observation_drops = 1u;
    check(!gate::observation_complete(drops_trace), "observation_drops_is_not_complete");
    gate::Identity drops_identity = valid_identity();
    drops_identity.sequence = 2u;
    check(encode_line(drops_identity, drops_trace, lines[4]),
          "encode_observation_drops_record");

    gate::Snapshot ambiguous_trace = trace;
    ambiguous_trace.scope_ambiguous = true;
    check(!gate::observation_complete(ambiguous_trace), "ambiguous_scope_is_not_complete");
    gate::Identity ambiguous_identity = valid_identity();
    ambiguous_identity.sequence = 3u;
    check(encode_line(ambiguous_identity, ambiguous_trace, lines[5]),
          "encode_ambiguous_scope_record");

    gate::Snapshot incomplete_trace = trace;
    incomplete_trace.scope_completed = false;
    check(!gate::observation_complete(incomplete_trace), "incomplete_scope_is_not_complete");
    gate::Identity incomplete_identity = valid_identity();
    incomplete_identity.sequence = 4u;
    check(encode_line(incomplete_identity, incomplete_trace, lines[6]),
          "encode_incomplete_scope_record");

    auto check_rejection = [&](const char* label, const gate::Identity& bad_identity,
                               const gate::Snapshot& bad_trace, auto&& call) noexcept {
        check(rejected_without_input_mutation(bad_identity, bad_trace,
                                              static_cast<decltype(call)&&>(call)),
              label);
    };
    std::array<char, gate::kMaxJsonBytes> scratch{};

    gate::Identity bad_sha = identity;
    bad_sha.dll_sha256[17] = 'G';
    std::size_t written = 77u;
    check_rejection("invalid_sha_rejected_without_mutation", bad_sha, trace, [&]() noexcept {
        return gate::encode_jsonl(bad_sha, trace, scratch.data(), scratch.size(), written);
    });

    for (unsigned invalid_kind : {3u, 255u}) {
        gate::Identity bad_kind = identity;
        bad_kind.kind = static_cast<inputs::Kind>(invalid_kind);
        written = 77u;
        check_rejection(invalid_kind == 3u
                            ? "first_invalid_kind_rejected_without_mutation"
                            : "high_invalid_kind_rejected_without_mutation",
                        bad_kind, trace, [&]() noexcept {
            return gate::encode_jsonl(bad_kind, trace, scratch.data(),
                                      scratch.size(), written);
        });
    }

    gate::Identity bad_identity = identity;
    bad_identity.sequence = 0u;
    written = 77u;
    check_rejection("zero_sequence_rejected_without_mutation", bad_identity, trace, [&]() noexcept {
        return gate::encode_jsonl(bad_identity, trace, scratch.data(), scratch.size(), written);
    });

    gate::Snapshot bad_mask = trace;
    bad_mask.sample_mask = 0x10u;
    written = 77u;
    check_rejection("invalid_sample_mask_rejected_without_mutation", identity, bad_mask, [&]() noexcept {
        return gate::encode_jsonl(identity, bad_mask, scratch.data(), scratch.size(), written);
    });

    written = 77u;
    check_rejection("null_output_rejected_without_mutation", identity, trace, [&]() noexcept {
        return gate::encode_jsonl(identity, trace, nullptr, gate::kMaxJsonBytes, written);
    });
    check(written == 0u, "null_output_zeroes_external_written");

    std::array<char, gate::kMaxJsonBytes + 1u> too_large{};
    too_large.fill('#');
    written = 77u;
    check_rejection("8193_capacity_rejected_without_input_mutation", identity, trace, [&]() noexcept {
        return gate::encode_jsonl(identity, trace, too_large.data(), too_large.size(), written);
    });
    check(written == 0u, "8193_capacity_zeroes_written");
    bool too_large_unchanged = true;
    for (char character : too_large) too_large_unchanged = too_large_unchanged && character == '#';
    check(too_large_unchanged, "8193_capacity_does_not_write_output");

    std::array<char, 64u> small{};
    small.fill('#');
    written = 77u;
    check_rejection("small_buffer_rejected_without_input_mutation", identity, trace, [&]() noexcept {
        return gate::encode_jsonl(identity, trace, small.data(), small.size(), written);
    });
    check(written == 0u, "small_buffer_zeroes_written");

    written = 77u;
    char* identity_alias = reinterpret_cast<char*>(
        const_cast<gate::Identity*>(&identity));
    check_rejection("output_identity_alias_rejected_without_mutation", identity, trace, [&]() noexcept {
        return gate::encode_jsonl(identity, trace, identity_alias, sizeof(identity), written);
    });
    check(written == 0u, "output_identity_alias_zeroes_external_written");

    written = 77u;
    char* trace_alias = reinterpret_cast<char*>(
        const_cast<gate::Snapshot*>(&trace));
    check_rejection("output_trace_alias_rejected_without_mutation", identity, trace, [&]() noexcept {
        return gate::encode_jsonl(identity, trace, trace_alias, sizeof(trace), written);
    });
    check(written == 0u, "output_trace_alias_zeroes_external_written");

    std::size_t written_alias = 123u;
    const std::size_t written_before = written_alias;
    const bool written_output_alias_accepted = gate::encode_jsonl(
        identity, trace, reinterpret_cast<char*>(&written_alias),
        sizeof(written_alias), written_alias);
    check(!written_output_alias_accepted, "written_output_alias_rejected");
    check(written_alias == written_before, "written_output_alias_is_untouched");

    gate::Identity mutable_identity = identity;
    check(written_aliases_identity_is_rejected(mutable_identity, trace),
          "written_identity_alias_rejected_without_mutation");
    check(same_identity(mutable_identity, identity), "written_identity_alias_preserves_identity");

    check(g_failures == 0u, "all_cpp_checks_passed");
    if (g_failures != 0u) {
        std::fprintf(stderr, "CHECKS=%u FAILURES=%u\n", g_checks, g_failures);
        return 1;
    }
    for (const EncodedLine& line : lines) {
        if (!emit(line)) {
            std::fprintf(stderr, "FAIL:write_jsonl_stdout\n");
            return 2;
        }
    }
    std::fprintf(stderr, "CHECKS=%u FAILURES=0\n", g_checks);
    return 0;
}
