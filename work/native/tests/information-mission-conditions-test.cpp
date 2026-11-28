#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>

#include "information-mission-conditions.h"
#include "information-mission-province-conditions.h"

namespace mc = information::mission_conditions;
namespace pc = information::mission_province_condition;

namespace {

constexpr std::uintptr_t kBase = 0x140000000ULL;
constexpr std::uintptr_t kDefinition = kBase + 0x300000u;
constexpr std::uintptr_t kSlots = kBase + 0x400000u;
constexpr std::uintptr_t kContext = kBase + 0x500000u;
constexpr std::uint64_t kFra = 0x465241u;

unsigned g_checks = 0;
unsigned g_failures = 0;

void check(bool condition, const char* label) {
    ++g_checks;
    std::printf("%s %s\n", condition ? "PASS" : "FAIL", label);
    if (!condition) ++g_failures;
}

struct FakeReader final {
    struct Region final {
        std::uintptr_t start = 0;
        std::size_t size = 0;
        const unsigned char* bytes = nullptr;
    };
    std::array<Region, 24> regions{};
    unsigned count = 0;

    void add(std::uintptr_t start, const void* data, std::size_t size) {
        const auto* bytes = static_cast<const unsigned char*>(data);
        for (unsigned i = 0; i < count; ++i) {
            if (regions[i].start == start) {
                regions[i] = {start, size, bytes};
                return;
            }
        }
        regions[count++] = {start, size, bytes};
    }

    void erase(std::uintptr_t start) {
        for (unsigned i = 0; i < count; ++i) {
            if (regions[i].start != start) continue;
            for (unsigned j = i + 1; j < count; ++j) regions[j - 1] = regions[j];
            --count;
            return;
        }
    }

    bool read(std::uintptr_t address, void* output, std::size_t size) noexcept {
        for (unsigned i = 0; i < count; ++i) {
            const auto& region = regions[i];
            if (address < region.start) continue;
            const std::uintptr_t offset = address - region.start;
            if (offset <= region.size && size <= region.size - offset) {
                std::memcpy(output, region.bytes + offset, size);
                return true;
            }
        }
        return false;
    }
};

struct RootMemory final {
    FakeReader reader{};
    unsigned char root_bytes[24]{};
    std::uintptr_t root_method = kBase + mc::kEvaluateRva;
    std::uintptr_t child_methods[2] = {kBase + 0x510000u, kBase + 0x520000u};
    std::uintptr_t child_vtables[2] = {kBase + 0x610000u, kBase + 0x620000u};
    std::uintptr_t child_vtable_words[2]{};
    std::uintptr_t slot_words[2] = {kBase + 0x710000u, kBase + 0x720000u};

    explicit RootMemory(std::int32_t nodes = 2) {
        const std::uintptr_t root_vtable = kBase + mc::kRootVtableRva;
        std::memcpy(root_bytes, &root_vtable, sizeof(root_vtable));
        std::memcpy(root_bytes + 8, &kSlots, sizeof(kSlots));
        std::memcpy(root_bytes + 20, &nodes, sizeof(nodes));
        for (unsigned i = 0; i < 2; ++i) child_vtable_words[i] = child_vtables[i];
        reader.add(kDefinition + mc::kRootOffset, root_bytes, sizeof(root_bytes));
        reader.add(root_vtable + 0x30, &root_method, sizeof(root_method));
        reader.add(kSlots, slot_words, sizeof(slot_words));
        for (unsigned i = 0; i < 2; ++i) {
            reader.add(slot_words[i], &child_vtable_words[i], sizeof(std::uintptr_t));
            reader.add(child_vtables[i] + 0x30, &child_methods[i], sizeof(std::uintptr_t));
        }
    }
};

bool root_equal(const mc::Root& left, const mc::Root& right) {
    if (left.definition != right.definition || left.slots != right.slots
        || left.count != right.count) return false;
    for (unsigned i = 0; i < mc::kMaxConditions; ++i) {
        if (left.nodes[i].child != right.nodes[i].child
            || left.nodes[i].callee != right.nodes[i].callee) return false;
    }
    return true;
}

mc::Root sentinel_root() {
    mc::Root root{};
    root.definition = 0x13579000u;
    root.slots = 0x2468a000u;
    root.count = 2;
    root.nodes[0] = {0x11111000u, 0x22222000u};
    root.nodes[1] = {0x33333000u, 0x44444000u};
    root.nodes[127] = {0x55555000u, 0x66666000u};
    return root;
}

void test_read_root() {
    RootMemory memory;
    mc::Root output{};
    const bool read = mc::read_root(memory.reader, kBase, kDefinition, output);
    check(read && output.definition == kDefinition && output.slots == kSlots
          && output.count == 2 && output.nodes[0].child == memory.slot_words[0]
          && output.nodes[0].callee == memory.child_methods[0]
          && output.nodes[1].child == memory.slot_words[1]
          && output.nodes[1].callee == memory.child_methods[1],
          "read_root_exact_vtable_child_methods_and_slots");

    const auto unchanged = [&](const char* label) {
        mc::Root target = sentinel_root();
        const mc::Root before = target;
        const bool accepted = mc::read_root(memory.reader, kBase, kDefinition, target);
        check(!accepted && root_equal(target, before), label);
    };
    const std::uintptr_t valid_root_vtable = kBase + mc::kRootVtableRva;
    const std::uintptr_t wrong_root_vtable = valid_root_vtable + 8;
    std::memcpy(memory.root_bytes, &wrong_root_vtable, sizeof(wrong_root_vtable));
    unchanged("read_root_wrong_root_vtable_output_unchanged");
    std::memcpy(memory.root_bytes, &valid_root_vtable, sizeof(valid_root_vtable));

    memory.root_method++;
    unchanged("read_root_wrong_evaluate_method_output_unchanged");
    memory.root_method--;
    const auto saved_child_method = memory.child_methods[0];
    memory.child_methods[0] = kBase + 0x2000000u;
    unchanged("read_root_invalid_child_callee_output_unchanged");
    memory.child_methods[0] = saved_child_method;

    const auto child_method_address = memory.child_vtables[0] + 0x30;
    memory.reader.erase(child_method_address);
    unchanged("read_root_unreadable_child_method_output_unchanged");
    memory.reader.add(child_method_address, &memory.child_methods[0], sizeof(std::uintptr_t));

    const std::int32_t too_many = static_cast<std::int32_t>(mc::kMaxConditions + 1u);
    std::memcpy(memory.root_bytes + 20, &too_many, sizeof(too_many));
    unchanged("read_root_over_capacity_output_unchanged");
}

struct ContextMemory final {
    FakeReader reader{};
    unsigned char bytes[56]{};

    explicit ContextMemory(std::uint64_t country = kFra) {
        const std::uintptr_t vtable = kBase + mc::kContextVtableRva;
        const std::uint32_t discriminator = 0x165u;
        const std::uint32_t province = 0;
        const std::uint32_t mode = 1;
        std::memcpy(bytes, &vtable, 8);
        std::memcpy(bytes + 8, &discriminator, 4);
        std::memcpy(bytes + 0x10, &kContext, 8);
        std::memcpy(bytes + 0x18, &kContext, 8);
        std::memcpy(bytes + 0x20, &kContext, 8);
        std::memcpy(bytes + 0x28, &province, 4);
        std::memcpy(bytes + 0x2c, &country, 8);
        std::memcpy(bytes + 0x34, &mode, 4);
        reader.add(kContext, bytes, sizeof(bytes));
    }
};

void test_root_context() {
    ContextMemory memory;
    check(mc::root_context(memory.reader, kBase, kContext, kFra),
          "root_context_accepts_full_fra_self_anchors");
    const auto rejected = [&](const char* label) {
        check(!mc::root_context(memory.reader, kBase, kContext, kFra), label);
    };
    const std::uintptr_t wrong_vtable = kBase + mc::kContextVtableRva + 8;
    std::memcpy(memory.bytes, &wrong_vtable, 8);
    rejected("root_context_rejects_wrong_vtable");
    const std::uintptr_t valid_vtable = kBase + mc::kContextVtableRva;
    std::memcpy(memory.bytes, &valid_vtable, 8);
    const std::uintptr_t wrong_anchor = kContext + 8;
    std::memcpy(memory.bytes + 0x18, &wrong_anchor, 8);
    rejected("root_context_rejects_nonself_anchor");
    std::memcpy(memory.bytes + 0x18, &kContext, 8);
    const std::uint32_t province = 1;
    std::memcpy(memory.bytes + 0x28, &province, 4);
    rejected("root_context_rejects_province_context");
    const std::uint32_t no_province = 0;
    std::memcpy(memory.bytes + 0x28, &no_province, 4);
    const std::uint64_t foreign_country = 0x454e47u;
    std::memcpy(memory.bytes + 0x2c, &foreign_country, 8);
    rejected("root_context_rejects_foreign_country");
    std::memcpy(memory.bytes + 0x2c, &kFra, 8);
    const std::uint32_t wrong_discriminator = 0x164u;
    std::memcpy(memory.bytes + 8, &wrong_discriminator, 4);
    rejected("root_context_rejects_discriminator_mismatch");
    const std::uint32_t discriminator = 0x165u;
    std::memcpy(memory.bytes + 8, &discriminator, 4);
    memory.reader.erase(kContext);
    check(!mc::root_context(memory.reader, kBase, kContext, kFra),
          "root_context_rejects_unreadable_context");
}

mc::names::Name make_name(const char* text) {
    mc::names::Name value{};
    value.length = static_cast<unsigned>(std::strlen(text));
    std::memcpy(value.text, text, value.length);
    return value;
}

mc::Evaluation make_evaluation(unsigned count, unsigned seen,
                               const std::uint64_t* values,
                               std::int32_t date, const char* name = "mission_a") {
    mc::Evaluation value{};
    value.root.definition = kDefinition;
    value.root.slots = kSlots;
    value.root.count = count;
    for (unsigned i = 0; i < count && i < mc::kMaxConditions; ++i) {
        value.root.nodes[i] = {kBase + 0x710000u + i * 0x1000u,
                               kBase + 0x510000u + i * 0x1000u};
    }
    value.country = kFra;
    value.mission = make_name(name);
    value.date = date;
    value.seen = seen;
    value.valid = true;
    for (unsigned i = 0; i < seen && i < mc::kMaxConditions; ++i)
        value.returns[i] = values[i];
    return value;
}

void test_evaluation_capture() {
    ContextMemory memory;
    const std::uint64_t three[] = {0x101u, 0x202u, 0x303u};
    auto good = make_evaluation(3, 0, three, 100);
    const std::uintptr_t outside_slot = kSlots + 3u * 8u;
    check(good.observe(memory.reader, kBase, 0, kContext, 0, outside_slot, 0)
              == mc::CaptureResult::ignored && good.valid && good.seen == 0,
          "evaluation_ignores_unrelated_slot");
    for (unsigned i = 0; i < 3; ++i) {
        const auto result = good.observe(memory.reader, kBase,
            good.root.nodes[i].child, kContext, three[i], kSlots + i * 8u,
            good.root.nodes[i].callee);
        check(result == mc::CaptureResult::observed, "evaluation_records_ordered_root_slot");
    }
    check(good.complete(), "evaluation_complete_after_all_root_slots");

    auto out_of_order = make_evaluation(3, 0, three, 100);
    check(out_of_order.observe(memory.reader, kBase,
              out_of_order.root.nodes[1].child, kContext, three[1], kSlots + 8u,
              out_of_order.root.nodes[1].callee) == mc::CaptureResult::invalid
          && !out_of_order.valid, "evaluation_rejects_out_of_order_slot");

    const std::uint64_t first_false[] = {0x100u, 0x200u};
    auto short_circuit = make_evaluation(3, 0, first_false, 100);
    short_circuit.observe(memory.reader, kBase, short_circuit.root.nodes[0].child,
        kContext, first_false[0], kSlots, short_circuit.root.nodes[0].callee);
    check(short_circuit.observe(memory.reader, kBase,
              short_circuit.root.nodes[1].child, kContext, first_false[1], kSlots + 8u,
              short_circuit.root.nodes[1].callee) == mc::CaptureResult::invalid
          && !short_circuit.valid, "evaluation_rejects_call_after_false_short_circuit");

    auto wrong_child = make_evaluation(3, 0, three, 100);
    check(wrong_child.observe(memory.reader, kBase, 0x12345000u, kContext,
              three[0], kSlots, wrong_child.root.nodes[0].callee)
              == mc::CaptureResult::invalid, "evaluation_rejects_child_mismatch");
    auto wrong_callee = make_evaluation(3, 0, three, 100);
    check(wrong_callee.observe(memory.reader, kBase, wrong_callee.root.nodes[0].child,
              kContext, three[0], kSlots, wrong_callee.root.nodes[0].callee + 1u)
              == mc::CaptureResult::invalid, "evaluation_rejects_callee_mismatch");
    auto wrong_context = make_evaluation(3, 0, three, 100);
    check(wrong_context.observe(memory.reader, kBase, wrong_context.root.nodes[0].child,
              kContext + 0x100u, three[0], kSlots, wrong_context.root.nodes[0].callee)
              == mc::CaptureResult::invalid, "evaluation_rejects_context_mismatch");
}

mc::Result observe(mc::Baselines& baselines, const mc::Evaluation& value,
                   mc::Changes& changes) {
    return baselines.observe(value, changes);
}

void test_baselines() {
    {
        auto store = std::make_unique<mc::Baselines>();
        mc::Changes changes{};
        const std::uint64_t initial[] = {0x101u, 0x201u, 0x301u};
        auto first = make_evaluation(3, 3, initial, 100);
        check(observe(*store, first, changes) == mc::Result::baseline
              && changes.count == 0, "baseline_first_observation_has_no_change_event");

        const std::uint64_t false_at_zero[] = {0x100u};
        auto second = make_evaluation(3, 1, false_at_zero, 101);
        check(observe(*store, second, changes) == mc::Result::changed
              && changes.count == 1 && changes.nodes[0].index == 0
              && changes.nodes[0].previous_date == 100,
              "baseline_observed_false_change_only");
        const auto& after_short = store->tasks[0];
        check(after_short.returns[1] == initial[1] && after_short.dates[1] == 100
              && after_short.returns[2] == initial[2] && after_short.dates[2] == 100,
              "baseline_short_circuit_tail_values_and_dates_retained");

        const std::uint64_t recovered_but_still_false[] = {0x102u, 0x200u};
        auto third = make_evaluation(3, 2, recovered_but_still_false, 102);
        check(observe(*store, third, changes) == mc::Result::changed
              && changes.count == 2 && changes.nodes[0].index == 0
              && changes.nodes[1].index == 1,
              "baseline_false_to_true_emits_only_observed_changes");
        check(store->tasks[0].dates[2] == 100 && store->tasks[0].returns[2] == initial[2],
              "baseline_unobserved_tail_remains_at_old_date_and_value");
    }

    {
        auto store = std::make_unique<mc::Baselines>();
        mc::Changes changes{};
        const std::uint64_t one[] = {0x1111111111111101ULL};
        auto first = make_evaluation(1, 1, one, 200, "al_mode");
        observe(*store, first, changes);
        const std::uint64_t two[] = {0xeeeeeeeeeeeeee02ULL};
        auto second = make_evaluation(1, 1, two, 201, "al_mode");
        check(observe(*store, second, changes) == mc::Result::unchanged
              && changes.count == 0, "baseline_al_nonzero_1_to_2_and_high_bits_no_event");
        const std::uint64_t high_only[] = {0x123456789abcde7fULL};
        auto third = make_evaluation(1, 1, high_only, 202, "al_mode");
        check(observe(*store, third, changes) == mc::Result::unchanged
              && changes.count == 0, "baseline_high_bit_only_change_no_event");
    }

    {
        auto store = std::make_unique<mc::Baselines>();
        mc::Changes changes{};
        const std::uint64_t value[] = {0x101u};
        auto first = make_evaluation(1, 1, value, 300, "reset_case");
        observe(*store, first, changes);
        auto back_date = make_evaluation(1, 1, value, 299, "reset_case");
        check(observe(*store, back_date, changes) == mc::Result::reset
              && changes.count == 0, "baseline_date_backwards_resets");
        auto definition_change = make_evaluation(1, 1, value, 301, "reset_case");
        definition_change.root.definition++;
        check(observe(*store, definition_change, changes) == mc::Result::reset
              && changes.count == 0, "baseline_definition_change_resets");
        auto child_change = make_evaluation(1, 1, value, 302, "reset_case");
        child_change.root.nodes[0].child++;
        check(observe(*store, child_change, changes) == mc::Result::reset
              && changes.count == 0, "baseline_child_change_resets");
    }

    {
        auto store = std::make_unique<mc::Baselines>();
        mc::Changes changes{};
        const std::uint64_t before[] = {0x101u, 0x201u};
        auto first = make_evaluation(2, 2, before, 400, "new_node");
        observe(*store, first, changes);
        const std::uint64_t after[] = {0x101u, 0x201u, 0x300u};
        auto next = make_evaluation(3, 3, after, 401, "new_node");
        check(observe(*store, next, changes) == mc::Result::reset
              && changes.count == 0 && store->tasks[0].root.count == 3
              && store->tasks[0].dates[2] == 401,
              "baseline_new_node_only_builds_reset_baseline");
    }
}

void test_invalid_and_capacity() {
    auto store = std::make_unique<mc::Baselines>();
    mc::Changes changes{};
    const std::uint64_t false_value[] = {0x100u};
    auto valid = make_evaluation(1, 1, false_value, 500, "invalid_case");
    auto bad = valid;
    bad.valid = false;
    check(observe(*store, bad, changes) == mc::Result::invalid,
          "baseline_rejects_invalid_evaluation");
    bad = valid;
    bad.country = 0;
    check(observe(*store, bad, changes) == mc::Result::invalid,
          "baseline_rejects_zero_country");
    bad = valid;
    bad.date = 0;
    check(observe(*store, bad, changes) == mc::Result::invalid,
          "baseline_rejects_nonpositive_date");
    bad = valid;
    bad.mission = {};
    check(observe(*store, bad, changes) == mc::Result::invalid,
          "baseline_rejects_invalid_name");
    bad = valid;
    bad.root.count = mc::kMaxConditions + 1u;
    check(observe(*store, bad, changes) == mc::Result::invalid,
          "baseline_rejects_condition_capacity_overflow");
    check(store->count == 0, "invalid_baselines_do_not_mutate_store");

    auto full = std::make_unique<mc::Baselines>();
    full->count = mc::kMaxTasks;
    check(observe(*full, valid, changes) == mc::Result::full
          && changes.count == 0 && full->count == mc::kMaxTasks,
          "baseline_task_capacity_boundary_returns_full");
    std::printf("BASELINES_BYTES=%zu (heap allocated)\n", sizeof(mc::Baselines));
}

#ifdef BRIDGE_NATIVE_COUNTRY_CONTROL
void test_scoped_province_baselines() {
    auto store = std::make_unique<pc::Baselines>();
    pc::Value first{};
    first.binding.country = UINT64_C(0x0100004200455753); // SWE, slot 66
    first.binding.province = 10;
    first.binding.root_index = 1;
    first.binding.child_index = 0;
    first.binding.child_count = 1;
    first.mission = make_name("mission_swe");
    first.date = 100;
    first.returned = 1;
    pc::Change change{};
    check(store->observe(first, change) == pc::Result::baseline,
          "province_baseline_accepts_configured_non_fra_country");
    pc::Value second = first;
    second.date++;
    second.returned = 0;
    check(store->observe(second, change) == pc::Result::changed
          && change.before.binding.country == first.binding.country
          && change.after.binding.country == first.binding.country,
          "province_change_preserves_country_reference");
    pc::Value invalid = first;
    invalid.binding.country = 0;
    check(store->observe(invalid, change) == pc::Result::invalid,
          "province_baseline_rejects_missing_country");
}
#endif

} // namespace

int main() {
    std::printf("TEST information-mission-conditions\n");
    test_read_root();
    test_root_context();
    test_evaluation_capture();
    test_baselines();
    test_invalid_and_capacity();
#ifdef BRIDGE_NATIVE_COUNTRY_CONTROL
    test_scoped_province_baselines();
#endif
    std::printf("CHECKS=%u FAILURES=%u\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
