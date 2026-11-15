#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string_view>
#include <type_traits>

namespace information::battle::format_expansion_plan {

inline constexpr std::size_t kMaximumTemplateBytes = 8192;
inline constexpr std::size_t kMaximumRows = 64;
inline constexpr std::size_t kMaximumKeyBytes = 256;
inline constexpr std::size_t kMaximumValueBytes = 8192;
inline constexpr std::size_t kExpansionLimitBytes = 60 * 1024;
inline constexpr std::size_t kMaximumColorPrefixBytes = 2;
inline constexpr std::size_t kMaximumColorSuffixBytes = 2;
inline constexpr std::size_t kMatchedPlaceholderOverheadBytes =
    kMaximumColorPrefixBytes + kMaximumColorSuffixBytes;
inline constexpr std::size_t kMaximumPlaceholderCount =
    kMaximumTemplateBytes / 2;

// Rows passed to make_plan must already have been selected as type-2 rows.
// Values are copied literally by type 2; dollar characters inside a value are
// not scanned recursively.
struct Type2Row final {
    std::string_view key{};
    std::string_view value{};
};

struct MissingKeySpan final {
    std::uint16_t offset{};
    std::uint16_t length{};
};

struct Plan final {
    std::size_t literal_bytes{};
    std::size_t replacement_count{};
    std::size_t missing_key_count{};
    std::array<MissingKeySpan, kMaximumPlaceholderCount> missing_keys{};
    // Zero means no certified upper bound is available because a key is
    // missing. Otherwise this includes the terminating NUL byte.
    std::size_t upper_bound{};
    bool below_60_kib{};
    bool all_placeholders_bound{};
};

static_assert(std::is_trivially_copyable_v<Plan>);

namespace detail {

inline bool checked_add(std::size_t left, std::size_t right,
                        std::size_t& result) noexcept {
    if (right > std::numeric_limits<std::size_t>::max() - left) {
        result = 0;
        return false;
    }
    result = left + right;
    return true;
}

inline bool contains_nul(std::string_view bytes) noexcept {
    return bytes.find('\0') != std::string_view::npos;
}

} // namespace detail

// Produces a bounded, value-only expansion estimate. A false return means an
// invalid/over-limit input or arithmetic failure; output is left unchanged.
// A true return may still report missing keys. Callers must require both
// all_placeholders_bound and below_60_kib before treating the estimate as
// usable. This planner alone never authorizes a native call: the actual local
// template and its type-2 rows must be independently verified by the caller.
inline bool make_plan(std::string_view text, std::span<const Type2Row> rows,
                     Plan& output) noexcept {
    if (text.size() > kMaximumTemplateBytes || rows.size() > kMaximumRows ||
        (text.data() == nullptr && !text.empty()) || detail::contains_nul(text)) {
        return false;
    }

    for (std::size_t row_index = 0; row_index < rows.size(); ++row_index) {
        const auto& row = rows[row_index];
        if (row.key.size() > kMaximumKeyBytes ||
            row.value.size() > kMaximumValueBytes ||
            (row.key.data() == nullptr && !row.key.empty()) ||
            (row.value.data() == nullptr && !row.value.empty()) ||
            detail::contains_nul(row.key) || detail::contains_nul(row.value)) {
            return false;
        }
        for (std::size_t prior = 0; prior < row_index; ++prior) {
            if (rows[prior].key == row.key) {
                return false;
            }
        }
    }

    Plan candidate{};
    candidate.all_placeholders_bound = true;
    std::size_t content_upper_bound = 0;
    std::size_t cursor = 0;

    const auto add_literal = [&](std::size_t count) noexcept -> bool {
        std::size_t next_literal{};
        std::size_t next_content{};
        if (!detail::checked_add(candidate.literal_bytes, count, next_literal) ||
            !detail::checked_add(content_upper_bound, count, next_content)) {
            return false;
        }
        candidate.literal_bytes = next_literal;
        content_upper_bound = next_content;
        return true;
    };

    while (cursor < text.size()) {
        const std::size_t opening = text.find('$', cursor);
        if (opening == std::string_view::npos) {
            if (!add_literal(text.size() - cursor)) {
                return false;
            }
            cursor = text.size();
            break;
        }

        if (!add_literal(opening - cursor)) {
            return false;
        }

        const std::size_t closing = text.find('$', opening + 1);
        if (closing == std::string_view::npos) {
            // The unmatched dollar and remainder are emitted literally.
            if (!add_literal(text.size() - opening)) {
                return false;
            }
            cursor = text.size();
            break;
        }

        const std::size_t key_begin = opening + 1;
        const std::size_t pipe = text.find('|', key_begin);
        const std::size_t key_end =
            (pipe != std::string_view::npos && pipe < closing) ? pipe : closing;
        const std::size_t key_length = key_end - key_begin;
        if (key_length > kMaximumKeyBytes) {
            return false;
        }

        const std::string_view key = text.substr(key_begin, key_length);
        const Type2Row* match = nullptr;
        for (const auto& row : rows) {
            if (row.key == key) {
                match = &row;
                break;
            }
        }

        if (match == nullptr) {
            if (candidate.missing_key_count >= candidate.missing_keys.size()) {
                return false;
            }
            candidate.missing_keys[candidate.missing_key_count++] = {
                static_cast<std::uint16_t>(key_begin),
                static_cast<std::uint16_t>(key_length),
            };
            candidate.all_placeholders_bound = false;
        } else {
            std::size_t replacement_bound{};
            std::size_t next_content{};
            if (!detail::checked_add(match->value.size(),
                                     kMatchedPlaceholderOverheadBytes,
                                     replacement_bound) ||
                !detail::checked_add(content_upper_bound, replacement_bound,
                                     next_content)) {
                return false;
            }
            content_upper_bound = next_content;
            ++candidate.replacement_count;
        }
        cursor = closing + 1;
    }

    if (candidate.all_placeholders_bound) {
        if (!detail::checked_add(content_upper_bound, 1, candidate.upper_bound)) {
            return false;
        }
        candidate.below_60_kib = candidate.upper_bound < kExpansionLimitBytes;
    } else {
        // Unknown replacements have no finite certified upper bound.
        candidate.upper_bound = 0;
        candidate.below_60_kib = false;
    }

    output = candidate;
    return true;
}

} // namespace information::battle::format_expansion_plan
