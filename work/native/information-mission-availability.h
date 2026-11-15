#pragma once

#include "information-mission-completion.h"

namespace information::mission_availability {

using mission_completion::Name;
constexpr unsigned kMaxTasks = 4096;
struct Value final {
    uint64_t country = 0;
    uintptr_t definition = 0;
    Name mission{};
    int32_t date = 0;
    bool eligible = false;
};
struct Change final { Value after{}; int32_t previous_date = 0; bool before = false; };
enum class Result { baseline, unchanged, changed, reset, invalid, full };

// Serialized by the observer queue lock. Each task stores its last actual
// native predicate result, including the date of an unchanged observation.
struct Baselines final {
    Value values[kMaxTasks]{};
    unsigned count = 0;

    Result observe(const Value& value, Change& change) noexcept {
        change = {};
        if (!value.country || value.date <= 0 || !value.definition
            || !mission_completion::valid(value.mission)) return Result::invalid;
        for (unsigned index = 0; index < count; ++index) {
            auto& previous = values[index];
            if (previous.country != value.country
                || !mission_completion::equal(previous.mission, value.mission)) continue;
            const auto old = previous;
            previous = value;
            if (old.definition != value.definition || old.date > value.date) return Result::reset;
            if (old.eligible == value.eligible) return Result::unchanged;
            change = {value, old.date, old.eligible};
            return Result::changed;
        }
        if (count == kMaxTasks) return Result::full;
        values[count++] = value;
        return Result::baseline;
    }
};

} // namespace information::mission_availability
