#include "information-battle-owned-title-query.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

namespace {

using information::battle::owned_native_text::Address;
using information::battle::owned_native_text::FieldState;
using information::battle::owned_title_query::FailureStage;
using information::battle::owned_title_query::String32;
using information::battle::owned_title_query::Workspace;
using information::battle::owned_title_query::kGlobalStringRva;
using information::battle::owned_title_query::kMaxTextBytes;
using information::battle::owned_title_query::kSelectorOffset;
using information::battle::owned_title_query::Result;
namespace owned_native_text = information::battle::owned_native_text;

constexpr Address kBase = UINT64_C(0x140000000);
constexpr std::size_t kImageSize = kGlobalStringRva + 0x100u;
constexpr Address kCombat = UINT64_C(0x200000);
constexpr Address kVtable = kBase + UINT64_C(0x1000);
constexpr Address kSelectorFunction = kBase + UINT64_C(0x1100);
constexpr Address kSelectorFunctionAlt = kBase + UINT64_C(0x1200);
constexpr Address kSelectorFunctionOutOfImage = UINT64_C(0x260000);
constexpr Address kProvince = UINT64_C(0x220000);
constexpr Address kNameOwner = UINT64_C(0x230000);
constexpr Address kOwnerHeap = UINT64_C(0x240000);
constexpr Address kGlobalHeap = UINT64_C(0x250000);

struct Region final {
    Address address = 0u;
    std::vector<unsigned char> bytes{};
};

struct MemoryReader final {
    std::vector<Region> regions{};
    Address output_object = 0u;
    unsigned char* output_object_bytes = nullptr;
    Address output_heap = 0u;
    unsigned char* output_heap_bytes = nullptr;
    std::size_t output_heap_size = 0u;
    Address owner_string = 0u;

    void mutate_selector_slot() noexcept {
        put(kVtable + kSelectorOffset, kSelectorFunctionAlt);
    }

    void add(Address address, std::size_t size) {
        Region region{};
        region.address = address;
        region.bytes.assign(size, 0u);
        regions.push_back(std::move(region));
    }

    Region* find(Address address, std::size_t size) noexcept {
        for (Region& region : regions) {
            if (address >= region.address
                    && address - region.address <= region.bytes.size()
                    && size <= region.bytes.size() -
                                   static_cast<std::size_t>(
                                       address - region.address)) {
                return &region;
            }
        }
        return nullptr;
    }

    bool read(Address address, unsigned char* destination,
              std::size_t size) noexcept {
        if (destination == nullptr || size == 0u) return false;
        if (output_object != 0u && address >= output_object
                && address - output_object <= sizeof(String32)
                && size <= sizeof(String32) -
                               static_cast<std::size_t>(address -
                                                        output_object)) {
            std::memcpy(destination,
                        output_object_bytes +
                            static_cast<std::size_t>(address - output_object),
                        size);
            return true;
        }
        if (output_heap != 0u && address >= output_heap
                && address - output_heap <= output_heap_size
                && size <= output_heap_size -
                               static_cast<std::size_t>(address -
                                                        output_heap)) {
            std::memcpy(destination,
                        output_heap_bytes +
                            static_cast<std::size_t>(address - output_heap),
                        size);
            return true;
        }
        Region* region = find(address, size);
        if (region == nullptr) return false;
        std::memcpy(destination, region->bytes.data() +
                                      static_cast<std::size_t>(address -
                                                               region->address),
                    size);
        return true;
    }

    bool write(Address address, const unsigned char* source,
               std::size_t size) noexcept {
        Region* region = find(address, size);
        if (region == nullptr || source == nullptr || size == 0u) return false;
        std::memcpy(region->bytes.data() +
                        static_cast<std::size_t>(address - region->address),
                    source, size);
        return true;
    }

    template <typename T>
    void put(Address address, T value) {
        (void)write(address, reinterpret_cast<const unsigned char*>(&value),
                    sizeof(value));
    }

    void put_bytes(Address address, const unsigned char* source,
                   std::size_t size) {
        (void)write(address, source, size);
    }

    void bind_output(String32& output) noexcept {
        output_object = reinterpret_cast<Address>(&output);
        output_object_bytes = reinterpret_cast<unsigned char*>(&output);
    }

    void bind_output_heap(Address address, unsigned char* bytes,
                          std::size_t size) noexcept {
        output_heap = address;
        output_heap_bytes = bytes;
        output_heap_size = size;
    }

    void mutate_owner() noexcept {
        static constexpr char changed[] = "Alter";
        std::array<unsigned char, 16u> bytes{};
        std::memcpy(bytes.data(), changed, sizeof(changed));
        (void)write(owner_string, bytes.data(), bytes.size());
    }
};

void set_inline(MemoryReader& reader, Address object, const char* text) {
    std::array<unsigned char, 32u> raw{};
    const std::size_t length = std::strlen(text);
    std::memcpy(raw.data(), text, length);
    raw[length] = 0u;
    const std::uint64_t size = static_cast<std::uint64_t>(length);
    const std::uint64_t capacity =
        information::battle::owned_title_query::kInlineCapacity;
    std::memcpy(raw.data() + 0x10u, &size, sizeof(size));
    std::memcpy(raw.data() + 0x18u, &capacity, sizeof(capacity));
    reader.add(object, raw.size());
    reader.put_bytes(object, raw.data(), raw.size());
}

void set_heap(MemoryReader& reader, Address object, Address payload,
              const char* text) {
    std::array<unsigned char, 32u> raw{};
    const std::size_t length = std::strlen(text);
    const std::uint64_t size = static_cast<std::uint64_t>(length);
    const std::uint64_t capacity = 32u;
    std::memcpy(raw.data(), &payload, sizeof(payload));
    std::memcpy(raw.data() + 0x10u, &size, sizeof(size));
    std::memcpy(raw.data() + 0x18u, &capacity, sizeof(capacity));
    reader.add(object, raw.size());
    reader.add(payload, length + 1u);
    reader.put_bytes(object, raw.data(), raw.size());
    reader.put_bytes(payload, reinterpret_cast<const unsigned char*>(text),
                     length);
    const unsigned char nul = 0u;
    reader.put_bytes(payload + static_cast<Address>(length), &nul, 1u);
}

struct Fixture final {
    MemoryReader reader{};
    bool source_heap = false;
    std::uint32_t kind = 1u;

    void make(std::uint32_t selector_kind = 1u, bool use_heap = false) {
        source_heap = use_heap;
        kind = selector_kind;
        reader = MemoryReader{};
        reader.add(kCombat, 0x40u);
        reader.add(kVtable + kSelectorOffset, sizeof(Address));
        reader.add(kSelectorFunction, 6u);
        reader.add(kSelectorFunctionAlt, 6u);
        reader.add(kSelectorFunctionOutOfImage, 6u);
        reader.add(kProvince, 0x30u);
        reader.add(kNameOwner, 0x10u);
        reader.put(kCombat, kVtable);
        reader.put(kCombat + 0x30u, kProvince);
        reader.put(kProvince + 0x28u, kNameOwner);

        std::array<unsigned char, 6u> selector{0xb8u, 0u, 0u, 0u, 0u,
                                                0xc3u};
        std::memcpy(selector.data() + 1u, &selector_kind, sizeof(selector_kind));
        reader.put_bytes(kSelectorFunction, selector.data(),
                         selector.size());
        reader.put_bytes(kSelectorFunctionAlt, selector.data(),
                         selector.size());
        reader.put(kVtable + kSelectorOffset, kSelectorFunction);

        reader.owner_string = kNameOwner + 0x10u;
        if (use_heap) {
            set_heap(reader, reader.owner_string, kOwnerHeap, "OwnerHeap");
            set_heap(reader, kBase + kGlobalStringRva, kGlobalHeap,
                     "GlobalHeap");
        } else {
            set_inline(reader, reader.owner_string, "Owner");
            set_inline(reader, kBase + kGlobalStringRva, "Global");
        }
    }
};

struct FakeInvoker final {
    enum class Mode : std::uint8_t { inline_text, heap_text, empty, mismatch };

    Fixture* fixture = nullptr;
    MemoryReader* reader = nullptr;
    Mode mode = Mode::inline_text;
    int guard_fail_call = 0;
    bool mutate_source = false;
    bool mutate_selector_slot = false;
    int guard_calls = 0;
    int invoke_calls = 0;
    int destroy_calls = 0;
    bool destroyed_local = false;
    bool destroyed_foreign = false;
    alignas(8) std::array<unsigned char, kMaxTextBytes + 1u> heap{};
    String32 foreign{};

    bool guard() noexcept {
        ++guard_calls;
        return guard_fail_call == 0 || guard_calls != guard_fail_call;
    }

    String32* invoke(Address, String32* output) noexcept {
        ++invoke_calls;
        if (mode == Mode::empty) {
            *output = String32{};
            output->capacity = 15u;
        } else if (mode == Mode::heap_text) {
            static constexpr char text[] = "ReturnedHeap";
            const std::size_t length = sizeof(text) - 1u;
            std::memcpy(heap.data(), text, sizeof(text));
            const Address payload = reinterpret_cast<Address>(heap.data());
            *output = String32{};
            std::memcpy(output->storage.data(), &payload, sizeof(payload));
            output->size = static_cast<std::uint64_t>(length);
            output->capacity = 32u;
        } else {
            static constexpr char text[] = "ReturnedInline";
            const std::size_t length =
                mode == Mode::mismatch ? sizeof(text) - 1u : sizeof(text) - 1u;
            *output = String32{};
            std::memcpy(output->storage.data(), text, length + 1u);
            output->size = static_cast<std::uint64_t>(length);
            output->capacity = 15u;
        }
        if (mutate_source && reader != nullptr) reader->mutate_owner();
        if (mutate_selector_slot && reader != nullptr) {
            reader->mutate_selector_slot();
        }
        return mode == Mode::mismatch ? &foreign : output;
    }

    void destroy(String32* value) noexcept {
        ++destroy_calls;
        if (value == &foreign) {
            destroyed_foreign = true;
        } else {
            destroyed_local = value != nullptr;
            if (value != nullptr) {
                *value = String32{};
                value->capacity = 15u;
            }
        }
    }
};

struct TestState final {
    int passed = 0;
    int failed = 0;

    void check(const char* name, bool condition) {
        if (condition) {
            ++passed;
            std::cout << "CHECK " << name << " PASS\n";
        } else {
            ++failed;
            std::cout << "CHECK " << name << " FAIL\n";
        }
    }
};

bool has_title(const owned_native_text::Snapshot& output,
               const char* expected) {
    const auto& field = output.title_helper_candidate;
    if (field.state != FieldState::observed) return false;
    const std::size_t length = std::strlen(expected);
    if (field.bytes.length != length) return false;
    return std::memcmp(output.arena.data() + field.bytes.offset, expected,
                       length) == 0;
}

bool run_capture(Fixture& fixture, FakeInvoker& invoker,
                 Workspace& workspace,
                 owned_native_text::Snapshot& output, Result& result) {
    fixture.reader.bind_output(workspace.output);
    fixture.reader.bind_output_heap(
        reinterpret_cast<Address>(invoker.heap.data()), invoker.heap.data(),
        invoker.heap.size());
    invoker.fixture = &fixture;
    invoker.reader = &fixture.reader;
    return information::battle::owned_title_query::capture(
        fixture.reader, invoker, kBase, kImageSize, kCombat, fixture.kind,
        workspace, output, result);
}

void test_success_inline(TestState& tests) {
    Fixture fixture;
    fixture.make(1u, false);
    FakeInvoker invoker;
    Workspace workspace{};
    owned_native_text::Snapshot output{};
    Result result{};
    const bool success = run_capture(fixture, invoker, workspace, output,
                                     result);
    tests.check("inline success", success && result.observed
                && result.destroyed && result.source_unchanged
                && has_title(output, "ReturnedInline")
                && invoker.destroy_calls == 1 && invoker.destroyed_local
                && !invoker.destroyed_foreign);
}

void test_success_heap_and_empty(TestState& tests) {
    Fixture fixture;
    fixture.make(2u, true);
    FakeInvoker invoker;
    invoker.mode = FakeInvoker::Mode::heap_text;
    Workspace workspace{};
    owned_native_text::Snapshot output{};
    Result result{};
    const bool heap_success = run_capture(fixture, invoker, workspace, output,
                                          result);
    tests.check("heap source/output success", heap_success
                && has_title(output, "ReturnedHeap"));

    fixture.make(2u, true);
    invoker = FakeInvoker{};
    invoker.mode = FakeInvoker::Mode::empty;
    Workspace empty_workspace{};
    owned_native_text::Snapshot empty_output{};
    Result empty_result{};
    const bool empty_success = run_capture(fixture, invoker, empty_workspace,
                                            empty_output, empty_result);
    tests.check("empty output observed", empty_success
                && empty_output.title_helper_candidate.state ==
                       FieldState::observed
                && empty_output.title_helper_candidate.bytes.length == 0u);
}

void test_source_and_guard_failures(TestState& tests) {
    Fixture fixture;
    fixture.make();
    FakeInvoker invoker;
    invoker.mutate_source = true;
    Workspace workspace{};
    owned_native_text::Snapshot output{};
    Result result{};
    const bool mutated = run_capture(fixture, invoker, workspace, output,
                                     result);
    tests.check("source mutation retracts", !mutated
                && result.failed_stage == FailureStage::source_changed
                && !result.source_unchanged && result.destroyed
                && invoker.destroy_calls == 1
                && output.title_helper_candidate.state == FieldState::unknown);

    fixture.make();
    invoker = FakeInvoker{};
    invoker.guard_fail_call = 3;
    Workspace guard_workspace{};
    owned_native_text::Snapshot guard_output{};
    Result guard_result{};
    const bool guard_ok = run_capture(fixture, invoker, guard_workspace,
                                      guard_output, guard_result);
    tests.check("post-invoke guard retracts", !guard_ok
                && guard_result.failed_stage == FailureStage::guard_after_invoke
                && guard_result.destroyed && invoker.destroy_calls == 1);

    fixture.make();
    invoker = FakeInvoker{};
    invoker.mutate_selector_slot = true;
    Workspace slot_workspace{};
    owned_native_text::Snapshot slot_output{};
    Result slot_result{};
    const bool slot_ok = run_capture(fixture, invoker, slot_workspace,
                                     slot_output, slot_result);
    tests.check("selector slot mutation retracts", !slot_ok
                && slot_result.failed_stage == FailureStage::source_changed
                && slot_result.destroyed && invoker.destroy_calls == 1);
}

void test_rejection_and_mismatch(TestState& tests) {
    Fixture fixture;
    fixture.make(3u, false);
    FakeInvoker invoker;
    Workspace workspace{};
    owned_native_text::Snapshot output{};
    Result result{};
    const bool bad_kind = run_capture(fixture, invoker, workspace, output,
                                      result);
    tests.check("malformed selector kind", !bad_kind
                && result.failed_stage == FailureStage::invalid_kind
                && invoker.invoke_calls == 0 && invoker.destroy_calls == 0);

    fixture.make();
    invoker = FakeInvoker{};
    invoker.mode = FakeInvoker::Mode::mismatch;
    Workspace mismatch_workspace{};
    owned_native_text::Snapshot mismatch_output{};
    Result mismatch_result{};
    const bool mismatch = run_capture(fixture, invoker, mismatch_workspace,
                                      mismatch_output, mismatch_result);
    tests.check("foreign return pointer", !mismatch
                && mismatch_result.failed_stage ==
                       FailureStage::returned_pointer
                && mismatch_result.destroyed && invoker.destroy_calls == 1
                && !invoker.destroyed_foreign
                && mismatch_output.title_helper_candidate.state ==
                       FieldState::unknown);

    fixture.make();
    std::array<unsigned char, 6u> bad_selector{0xb8u, 9u, 0u, 0u, 0u, 0xc3u};
    fixture.reader.put_bytes(kVtable + kSelectorOffset, bad_selector.data(),
                             bad_selector.size());
    invoker = FakeInvoker{};
    Workspace selector_workspace{};
    owned_native_text::Snapshot selector_output{};
    Result selector_result{};
    const bool selector_ok = run_capture(fixture, invoker, selector_workspace,
                                         selector_output, selector_result);
    tests.check("selector bytes rejected", !selector_ok
                && selector_result.failed_stage == FailureStage::source_before
                && invoker.invoke_calls == 0);

    fixture.make();
    fixture.reader.put(kVtable + kSelectorOffset,
                       kSelectorFunctionOutOfImage);
    invoker = FakeInvoker{};
    Workspace out_of_image_workspace{};
    owned_native_text::Snapshot out_of_image_output{};
    Result out_of_image_result{};
    const bool out_of_image_ok = run_capture(
        fixture, invoker, out_of_image_workspace, out_of_image_output,
        out_of_image_result);
    tests.check("selector function outside image rejected", !out_of_image_ok
                && out_of_image_result.failed_stage ==
                       FailureStage::source_before
                && invoker.invoke_calls == 0 && invoker.destroy_calls == 0);

    fixture.make();
    const std::uint64_t bad_capacity = 4u;
    fixture.reader.put(kNameOwner + 0x10u + 0x18u, bad_capacity);
    invoker = FakeInvoker{};
    Workspace source_workspace{};
    owned_native_text::Snapshot source_output{};
    Result source_result{};
    const bool source_ok = run_capture(fixture, invoker, source_workspace,
                                       source_output, source_result);
    tests.check("invalid source header rejected", !source_ok
                && source_result.failed_stage == FailureStage::source_before
                && invoker.invoke_calls == 0);
}

void test_plugin_short_input(TestState& tests) {
    Fixture fixture;
    fixture.make();
    String32 empty{};
    String32 one{};
    one.storage[0] = ' ';
    one.size = 1u;
    fixture.reader.put(kNameOwner + 0x10u, empty);
    fixture.reader.put(kBase + kGlobalStringRva, one);
    FakeInvoker invoker;
    Workspace workspace{};
    fixture.reader.bind_output(workspace.output);
    owned_native_text::Snapshot output{};
    Result result{};
    const bool copied = information::battle::owned_title_query::capture(
        fixture.reader, invoker, kBase, kImageSize, kCombat, 1u, workspace,
        output, result, 2u);
    tests.check("plugin short input rejected before invoke", !copied
                && result.failed_stage == FailureStage::source_too_short
                && invoker.invoke_calls == 0 && invoker.destroy_calls == 0);
}

}  // namespace

int main() {
    TestState tests{};
    test_success_inline(tests);
    test_success_heap_and_empty(tests);
    test_source_and_guard_failures(tests);
    test_rejection_and_mismatch(tests);
    test_plugin_short_input(tests);
    std::cout << "RESULT " << (tests.failed == 0 ? "PASS" : "FAIL") << "\n";
    std::cout << "SUMMARY passed=" << tests.passed
              << " failed=" << tests.failed << "\n";
    return tests.failed == 0 ? 0 : 1;
}
