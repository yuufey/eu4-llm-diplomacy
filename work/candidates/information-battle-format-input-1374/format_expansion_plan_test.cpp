#include "format_expansion_plan.h"
#include "format_input_builder.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <limits>
#include <span>
#include <string>
#include <string_view>

namespace plan = information::battle::format_expansion_plan;
namespace builder = battle_format_input;

namespace {

int failures = 0;

void expect(bool condition, const char* name) {
    if (condition) {
        std::cout << "PASS " << name << '\n';
    } else {
        std::cout << "FAIL " << name << '\n';
        ++failures;
    }
}

void test_many_small_replacements() {
    std::string text;
    for (int i = 0; i < 12; ++i) {
        text += "$x$";
    }
    const std::array<plan::Type2Row, 1> rows{{{"x", "short"}}};
    plan::Plan result{};
    const bool valid = plan::make_plan(text, rows, result);
    const std::size_t legacy_dollar_bound =
        text.size() + 24 * plan::kMaximumValueBytes;
    expect(valid && result.replacement_count == 12 &&
               result.literal_bytes == 0 && result.all_placeholders_bound &&
               result.upper_bound == 12 * (5 + 4) + 1 &&
               result.below_60_kib &&
               legacy_dollar_bound >= plan::kExpansionLimitBytes,
           "many_short_values_fit_where_per_dollar_bound_rejects");
}

void test_dangling_dollar_is_literal() {
    constexpr std::string_view text = "A$k$B$unfinished";
    const std::array<plan::Type2Row, 1> rows{{{"k", "v"}}};
    plan::Plan result{};
    const bool valid = plan::make_plan(text, rows, result);
    expect(valid && result.replacement_count == 1 &&
               result.literal_bytes == text.size() - 3 &&
               result.upper_bound == result.literal_bytes + 1 + 4 + 1 &&
               result.missing_key_count == 0,
           "unclosed_dollar_tail_is_literal");
}

void test_empty_key_and_pipe() {
    constexpr std::string_view text = "$$/$|$";
    const std::array<plan::Type2Row, 1> rows{{{"", "v"}}};
    plan::Plan result{};
    const bool valid = plan::make_plan(text, rows, result);
    expect(valid && result.replacement_count == 2 &&
               result.literal_bytes == 1 && result.upper_bound == 12 &&
               result.all_placeholders_bound,
           "empty_key_matches_both_empty_and_pipe_forms");
}

void test_pipe_modifiers_and_nonrecursive_value() {
    constexpr std::string_view text = "$k|U|#x$";
    constexpr std::string_view value = "$nested$";
    const std::array<plan::Type2Row, 1> rows{{{"k", value}}};
    plan::Plan result{};
    const bool valid = plan::make_plan(text, rows, result);
    expect(valid && result.replacement_count == 1 &&
               result.literal_bytes == 0 && result.upper_bound == value.size() + 5 &&
               result.all_placeholders_bound,
           "first_pipe_ends_key_and_value_is_not_recursively_scanned");
}

void test_missing_keys_keep_order_and_duplicates() {
    constexpr std::string_view text = "$z$/$y|U$/$z$";
    plan::Plan result{};
    const bool valid = plan::make_plan(text, {}, result);
    const bool names_match =
        result.missing_key_count == 3 &&
        text.substr(result.missing_keys[0].offset,
                    result.missing_keys[0].length) == "z" &&
        text.substr(result.missing_keys[1].offset,
                    result.missing_keys[1].length) == "y" &&
        text.substr(result.missing_keys[2].offset,
                    result.missing_keys[2].length) == "z";
    expect(valid && names_match && !result.all_placeholders_bound &&
               result.upper_bound == 0 && !result.below_60_kib,
           "missing_keys_preserve_occurrence_order_and_disable_bound");
}

void test_embedded_nul_and_duplicate_rows_rejected() {
    const std::string nul_text{"a\0b", 3};
    const std::array<plan::Type2Row, 1> good_rows{{{"x", "v"}}};
    plan::Plan result{};
    const bool nul_template_rejected = !plan::make_plan(nul_text, good_rows, result);

    const std::string nul_key{"x\0y", 3};
    const std::array<plan::Type2Row, 1> nul_key_rows{{{nul_key, "v"}}};
    const bool nul_key_rejected = !plan::make_plan("$x$", nul_key_rows, result);

    const std::string nul_value{"v\0w", 3};
    const std::array<plan::Type2Row, 1> nul_value_rows{{{"x", nul_value}}};
    const bool nul_value_rejected = !plan::make_plan("$x$", nul_value_rows, result);

    const std::array<plan::Type2Row, 2> duplicate_rows{{{"x", "a"},
                                                        {"x", "b"}}};
    const bool duplicate_rejected = !plan::make_plan("unused", duplicate_rows, result);

    expect(nul_template_rejected && nul_key_rejected && nul_value_rejected &&
               duplicate_rejected,
           "embedded_nul_and_duplicate_row_keys_rejected");
}

void test_template_row_key_and_value_limits() {
    std::string max_template(plan::kMaximumTemplateBytes, 'a');
    plan::Plan result{};
    const bool max_template_accepted = plan::make_plan(max_template, {}, result) &&
        result.upper_bound == plan::kMaximumTemplateBytes + 1;
    max_template.push_back('a');
    const bool oversized_template_rejected = !plan::make_plan(max_template, {}, result);

    std::string key256(plan::kMaximumKeyBytes, 'q');
    const std::string text256 = "$" + key256 + "$";
    const std::array<plan::Type2Row, 1> key256_rows{{{key256, ""}}};
    const bool key256_accepted = plan::make_plan(text256, key256_rows, result) &&
        result.replacement_count == 1;

    std::string key257(plan::kMaximumKeyBytes + 1, 'q');
    const std::string text257 = "$" + key257 + "$";
    const std::array<plan::Type2Row, 1> key257_rows{{{key257, ""}}};
    const bool key257_rejected = !plan::make_plan(text257, key257_rows, result);

    const std::string value8192(plan::kMaximumValueBytes, 'v');
    const std::array<plan::Type2Row, 1> value8192_rows{{{"k", value8192}}};
    const bool value8192_accepted = plan::make_plan("$k$", value8192_rows, result) &&
        result.upper_bound == plan::kMaximumValueBytes + 5;

    const std::string value8193(plan::kMaximumValueBytes + 1, 'v');
    const std::array<plan::Type2Row, 1> value8193_rows{{{"k", value8193}}};
    const bool value8193_rejected = !plan::make_plan("$k$", value8193_rows, result);

    expect(max_template_accepted && oversized_template_rejected &&
               key256_accepted && key257_rejected && value8192_accepted &&
               value8193_rejected,
           "template_key_and_value_size_boundaries");
}

void test_row_count_boundary() {
    std::array<std::array<char, 2>, plan::kMaximumRows + 1> key_bytes{};
    std::array<plan::Type2Row, plan::kMaximumRows + 1> rows{};
    for (std::size_t i = 0; i < rows.size(); ++i) {
        key_bytes[i] = {
            static_cast<char>('A' + i / 8),
            static_cast<char>('a' + i % 8),
        };
        rows[i] = {std::string_view(key_bytes[i].data(), key_bytes[i].size()), ""};
    }
    plan::Plan result{};
    const bool max_accepted = plan::make_plan("literal", std::span(rows).first(64), result);
    const bool too_many_rejected = !plan::make_plan("literal", rows, result);
    expect(max_accepted && too_many_rejected, "row_count_64_boundary");
}

void test_strict_60_kib_threshold() {
    const std::string max_value(plan::kMaximumValueBytes, 'v');
    const std::array<plan::Type2Row, 1> rows{{{"k", max_value}}};
    std::string exact(4067, 'L');
    for (int i = 0; i < 7; ++i) {
        exact += "$k$";
    }
    plan::Plan result{};
    const bool exact_valid = plan::make_plan(exact, rows, result);
    const bool exact_at_limit = exact_valid &&
        result.upper_bound == plan::kExpansionLimitBytes && !result.below_60_kib;

    exact.insert(exact.begin(), 'L');
    const bool above_valid = plan::make_plan(exact, rows, result);
    const bool above_limit = above_valid &&
        result.upper_bound == plan::kExpansionLimitBytes + 1 && !result.below_60_kib;
    expect(exact_at_limit && above_limit, "sixty_kib_threshold_is_strict_and_includes_nul");
}

void test_checked_add_overflow() {
    std::size_t result = 17;
    const bool overflow_rejected = !plan::detail::checked_add(
        std::numeric_limits<std::size_t>::max(), 1, result);
    const bool output_cleared = result == 0;
    expect(overflow_rejected && output_cleared, "checked_add_rejects_size_t_overflow");
}

void test_bound_template_build_owns_104_byte_views() {
    builder::Workspace workspace;
    const std::array<builder::InputRow, 1> rows{{{"NAME", "Portugal"}}};
    std::string text;
    for (int i = 0; i < 12; ++i) {
        if (i != 0) {
            text += ',';
        }
        text += "$NAME$";
    }

    const auto legacy = builder::estimate_expansion(
        text.size(), static_cast<std::size_t>(std::count(text.begin(), text.end(), '$')));
    const auto status = workspace.build_for_bound_template("BATTLE", rows, text);
    const auto* first_argument = workspace.argument(0);
    const char* body_key = workspace.body_key();
    const char* row_key = first_argument == nullptr
        ? nullptr
        : builder::cstr_pointer(*first_argument, 0x00);
    const char* row_value = first_argument == nullptr
        ? nullptr
        : builder::cstr_pointer(*first_argument, 0x60);

    expect(status == builder::BuildStatus::ok &&
               legacy.status == builder::ExpansionStatus::limit_reached &&
               workspace.expansion_status() == builder::ExpansionStatus::below_limit &&
               workspace.expansion_worst_case_bytes() == 156 &&
               workspace.argument_count() == 1 && first_argument != nullptr &&
               sizeof(*first_argument) == builder::kNativeArgBytes &&
               body_key != nullptr && std::string_view(body_key) == "BATTLE_1" &&
               row_key != nullptr && std::string_view(row_key) == "NAME" &&
               row_value != nullptr && std::string_view(row_value) == "Portugal" &&
               builder::dword_at(*first_argument, 0x28) == 2 &&
               workspace.owns_c_string(body_key, builder::kMaxKeyBytes) &&
               workspace.owns_c_string(row_key, builder::kMaxKeyBytes) &&
               workspace.owns_c_string(row_value, builder::kMaxValueBytes) &&
               workspace.argument(0) == first_argument &&
               workspace.body_key() == body_key &&
               workspace.expansion_below_limit(),
           "bound_template_build_accepts_small_values_and_owns_stable_104_byte_views");
}

void test_bound_template_failures_clear_ready_state() {
    builder::Workspace workspace;
    const std::array<builder::InputRow, 1> good_rows{{{"NAME", "value"}}};
    const auto seed_ready = [&]() {
        return workspace.build_for_bound_template("BATTLE", good_rows, "$NAME$") ==
               builder::BuildStatus::ok;
    };
    const auto is_cleared = [&]() {
        return workspace.body_key() == nullptr && workspace.argument_count() == 0 &&
               workspace.arena_used_bytes() == 0 &&
               workspace.expansion_status() == builder::ExpansionStatus::unknown &&
               workspace.expansion_worst_case_bytes() == 0 &&
               !workspace.expansion_below_limit();
    };

    const bool seeded_missing = seed_ready();
    const auto missing_status = workspace.build_for_bound_template(
        "BATTLE", good_rows, "$UNBOUND$");
    const bool missing_cleared = is_cleared();

    const bool seeded_boundary = seed_ready();
    const std::string oversized_template(plan::kMaximumTemplateBytes + 1, 'x');
    const auto boundary_status = workspace.build_for_bound_template(
        "BATTLE", good_rows, oversized_template);
    const bool boundary_cleared = is_cleared();

    const bool seeded_duplicate = seed_ready();
    const std::array<builder::InputRow, 2> duplicate_rows{{{"NAME", "one"},
                                                            {"NAME", "two"}}};
    const auto duplicate_status = workspace.build_for_bound_template(
        "BATTLE", duplicate_rows, "$NAME$");
    const bool duplicate_cleared = is_cleared();

    expect(seeded_missing && missing_status == builder::BuildStatus::missing_template_argument &&
               missing_cleared && seeded_boundary &&
               boundary_status == builder::BuildStatus::invalid_resolved_template &&
               boundary_cleared && seeded_duplicate &&
               duplicate_status == builder::BuildStatus::duplicate_key &&
               duplicate_cleared,
           "missing_boundary_and_duplicate_failures_clear_workspace");
}

void test_bound_template_alias_clears_ready_state() {
    builder::Workspace workspace;
    const std::array<builder::InputRow, 1> rows{{{"NAME", "value"}}};
    const bool seeded = workspace.build_for_bound_template("BATTLE", rows, "$NAME$") ==
                        builder::BuildStatus::ok;
    const char* old_body_key = workspace.body_key();
    const std::string_view aliased_template = old_body_key == nullptr
        ? std::string_view{}
        : std::string_view(old_body_key, 8);
    const auto status = workspace.build_for_bound_template("OTHER", {}, aliased_template);
    const bool cleared = workspace.body_key() == nullptr &&
        workspace.argument_count() == 0 && workspace.arena_used_bytes() == 0 &&
        workspace.expansion_status() == builder::ExpansionStatus::unknown;
    expect(seeded && status == builder::BuildStatus::alias && cleared,
           "workspace_template_alias_is_rejected_and_cleared");
}

} // namespace

int main() {
    test_many_small_replacements();
    test_dangling_dollar_is_literal();
    test_empty_key_and_pipe();
    test_pipe_modifiers_and_nonrecursive_value();
    test_missing_keys_keep_order_and_duplicates();
    test_embedded_nul_and_duplicate_rows_rejected();
    test_template_row_key_and_value_limits();
    test_row_count_boundary();
    test_strict_60_kib_threshold();
    test_checked_add_overflow();
    test_bound_template_build_owns_104_byte_views();
    test_bound_template_failures_clear_ready_state();
    test_bound_template_alias_clears_ready_state();
    return failures == 0 ? 0 : 1;
}
