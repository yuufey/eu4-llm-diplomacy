#include "../information-battle-owned-name-sources.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <new>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace {

namespace names = information::battle::owned_name_sources;
namespace title = information::battle::owned_title_query;
using information::battle::owned_native_text::Address;
using names::FailureStage;
using names::OwnedText;
using names::Result;
using names::Snapshot;
using names::Workspace;

constexpr Address kBase = UINT64_C(0x140000000);
constexpr std::size_t kImageSize = title::kGlobalStringRva + 0x100u;
constexpr Address kCombat = UINT64_C(0x200000);
constexpr Address kVtable = kBase + 0x1000u;
constexpr Address kAltVtable = kBase + 0x1800u;
constexpr Address kSelector = kBase + 0x1100u;
constexpr Address kAltSelector = kBase + 0x1900u;
constexpr Address kProvince = UINT64_C(0x220000);
constexpr Address kNameOwner = UINT64_C(0x230000);
constexpr Address kAltNameOwner = UINT64_C(0x231000);
constexpr Address kOwnerHeap = UINT64_C(0x240000);
constexpr Address kGlobalHeap = UINT64_C(0x250000);
constexpr Address kBudgetRegion = UINT64_C(0x300000);

struct Check final {
    std::size_t cases = 0u;
    std::size_t checks = 0u;
    std::size_t failures = 0u;

    void begin_case() noexcept { ++cases; }

    void expect(bool condition, const char* label) noexcept {
        ++checks;
        if (!condition) {
            ++failures;
            std::cerr << "FAIL: " << label << '\n';
        }
    }
};

struct Region final {
    Address address = 0u;
    std::vector<unsigned char> bytes{};
};

struct FakeReader final {
    static constexpr std::size_t kMaxLoggedReads = 128u;

    std::vector<Region> regions{};
    std::array<Address, kMaxLoggedReads> read_addresses{};
    std::size_t read_calls = 0u;
    std::size_t fail_on_call = 0u;

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
        ++read_calls;
        if (read_calls <= read_addresses.size()) {
            read_addresses[read_calls - 1u] = address;
        }
        if (destination == nullptr || size == 0u
                || (fail_on_call != 0u && read_calls == fail_on_call)) {
            return false;
        }
        Region* region = find(address, size);
        if (region == nullptr) return false;
        std::memcpy(destination,
                    region->bytes.data() +
                        static_cast<std::size_t>(address - region->address),
                    size);
        return true;
    }

    bool write(Address address, const unsigned char* source,
               std::size_t size) noexcept {
        if (source == nullptr || size == 0u) return false;
        Region* region = find(address, size);
        if (region == nullptr) return false;
        std::memcpy(region->bytes.data() +
                        static_cast<std::size_t>(address - region->address),
                    source, size);
        return true;
    }

    template <typename T>
    void put(Address address, T value) noexcept {
        static_assert(std::is_trivially_copyable<T>::value,
                      "fake memory values must be trivially copyable");
        (void)write(address,
                    reinterpret_cast<const unsigned char*>(&value),
                    sizeof(value));
    }

    bool read_address_seen(Address address) const noexcept {
        const std::size_t logged =
            read_calls < read_addresses.size() ? read_calls
                                               : read_addresses.size();
        for (std::size_t index = 0u; index < logged; ++index) {
            if (read_addresses[index] == address) return true;
        }
        return false;
    }
};

void set_selector(FakeReader& reader, Address selector,
                  std::uint32_t kind) noexcept {
    const std::array<unsigned char, title::kSelectorBytes> bytes{
        0xb8u,
        static_cast<unsigned char>(kind & 0xffu),
        static_cast<unsigned char>((kind >> 8u) & 0xffu),
        static_cast<unsigned char>((kind >> 16u) & 0xffu),
        static_cast<unsigned char>((kind >> 24u) & 0xffu),
        0xc3u,
    };
    (void)reader.write(selector, bytes.data(), bytes.size());
}

void set_inline(FakeReader& reader, Address object,
                const std::string& text) noexcept {
    std::array<unsigned char, title::kStringObjectBytes> raw{};
    const std::size_t length = text.size();
    if (length > title::kInlineCapacity) return;
    if (length != 0u) {
        std::memcpy(raw.data(), text.data(), length);
    }
    raw[length] = 0u;
    const std::uint64_t native_length = length;
    const std::uint64_t capacity = title::kInlineCapacity;
    std::memcpy(raw.data() + 0x10u, &native_length, sizeof(native_length));
    std::memcpy(raw.data() + 0x18u, &capacity, sizeof(capacity));
    (void)reader.write(object, raw.data(), raw.size());
}

void set_heap(FakeReader& reader, Address object, Address payload,
              const std::string& text, bool add_payload = true) {
    std::array<unsigned char, title::kStringObjectBytes> raw{};
    const std::size_t length = text.size();
    const std::uint64_t native_length = length;
    const std::uint64_t capacity = length < title::kHeapThreshold
        ? title::kHeapThreshold
        : length + 1u;
    std::memcpy(raw.data(), &payload, sizeof(payload));
    std::memcpy(raw.data() + 0x10u, &native_length, sizeof(native_length));
    std::memcpy(raw.data() + 0x18u, &capacity, sizeof(capacity));
    (void)reader.write(object, raw.data(), raw.size());
    if (!add_payload) return;
    reader.add(payload, length + 1u);
    if (length != 0u) {
        (void)reader.write(payload,
                           reinterpret_cast<const unsigned char*>(text.data()),
                           length);
    }
    const unsigned char nul = 0u;
    (void)reader.write(payload + static_cast<Address>(length), &nul, 1u);
}

struct Fixture final {
    FakeReader reader{};
    Address owner_string = kNameOwner + title::kNameOffset;
    Address global_string = kBase + title::kGlobalStringRva;
    std::uint32_t selector_kind = 1u;

    void make(std::uint32_t kind = 1u,
              bool owner_heap = false, bool global_heap = false,
              const std::string& owner_text = "Owner",
              const std::string& global_text = "Global") {
        reader = FakeReader{};
        selector_kind = kind;
        reader.add(kCombat, 0x40u);
        reader.add(kVtable + title::kSelectorOffset, sizeof(Address));
        reader.add(kAltVtable + title::kSelectorOffset, sizeof(Address));
        reader.add(kSelector, title::kSelectorBytes);
        reader.add(kAltSelector, title::kSelectorBytes);
        reader.add(kProvince, 0x30u);
        reader.add(kNameOwner, 0x40u);
        reader.add(kAltNameOwner, 0x40u);
        reader.add(global_string, title::kStringObjectBytes);
        reader.put(kCombat, kVtable);
        reader.put(kCombat + title::kProvinceOffset, kProvince);
        reader.put(kProvince + title::kNameOwnerOffset, kNameOwner);
        reader.put(kVtable + title::kSelectorOffset, kSelector);
        reader.put(kAltVtable + title::kSelectorOffset, kAltSelector);
        set_selector(reader, kSelector, kind);
        set_selector(reader, kAltSelector, kind);
        owner_string = kNameOwner + title::kNameOffset;
        if (owner_heap) {
            set_heap(reader, owner_string, kOwnerHeap, owner_text);
        } else {
            set_inline(reader, owner_string, owner_text);
        }
        if (global_heap) {
            set_heap(reader, global_string, kGlobalHeap, global_text);
        } else {
            set_inline(reader, global_string, global_text);
        }
    }

    void set_owner_heap_alias(Address payload, const std::string& text = "",
                              bool add_payload = false) {
        set_heap(reader, owner_string, payload, text, add_payload);
    }
};

struct FakeGuard final {
    enum class Mutation : std::uint8_t { none, owner_text, owner_pointer };

    FakeReader* reader = nullptr;
    int calls = 0;
    int fail_on_call = 0;
    int mutate_on_call = 0;
    Mutation mutation = Mutation::none;

    bool guard() noexcept {
        ++calls;
        if (calls == mutate_on_call && reader != nullptr) {
            if (mutation == Mutation::owner_text) {
                const unsigned char changed = static_cast<unsigned char>('X');
                (void)reader->write(kNameOwner + title::kNameOffset,
                                    &changed, 1u);
            } else if (mutation == Mutation::owner_pointer) {
                set_inline(*reader, kAltNameOwner + title::kNameOffset,
                           "Other");
                reader->put(kProvince + title::kNameOwnerOffset,
                            kAltNameOwner);
            }
        }
        return fail_on_call == 0 || calls != fail_on_call;
    }
};

void prime_outputs(Workspace& workspace, Snapshot& output,
                   Result& result) noexcept {
    workspace.before.combat_vtable = UINT64_C(0x111111);
    workspace.after.owner_name.payload_address = UINT64_C(0x222222);
    output.sequence = 99u;
    output.owner_name.length = 4u;
    output.owner_name.bytes[0] = static_cast<unsigned char>('x');
    result.failed_stage = FailureStage::source_changed;
    result.read_calls = 77u;
    result.bytes_read = 88u;
}

bool bytes_zero(const unsigned char* bytes, std::size_t size) noexcept {
    for (std::size_t index = 0u; index < size; ++index) {
        if (bytes[index] != 0u) return false;
    }
    return true;
}

bool snapshot_zero(const Snapshot& value) noexcept {
    return value.sequence == 0u && value.raw_date == 0
        && value.kind == 0u && value.owner_name.length == 0u
        && value.global_name.length == 0u
        && bytes_zero(value.owner_name.bytes.data(),
                      value.owner_name.bytes.size())
        && bytes_zero(value.global_name.bytes.data(),
                      value.global_name.bytes.size());
}

bool fingerprint_cleared(
    const title::GraphFingerprint& value) noexcept {
    const auto& strings = {value.owner_name, value.global_name};
    if (value.combat_vtable != 0u || value.selector_slot != 0u
            || value.selector_address != 0u || value.province != 0u
            || value.name_owner != 0u || value.global_string != 0u
            || value.kind != 0u
            || !bytes_zero(value.selector.data(), value.selector.size())) {
        return false;
    }
    for (const title::StringFingerprint& string : strings) {
        if (string.object_address != 0u || string.header.size != 0u
                || string.header.capacity != title::kInlineCapacity
                || string.payload_address != 0u || string.length != 0u
                || !bytes_zero(string.header.storage.data(),
                               string.header.storage.size())
                || !bytes_zero(string.bytes.data(), string.bytes.size())) {
            return false;
        }
    }
    return true;
}

bool workspace_cleared(const Workspace& workspace) noexcept {
    return fingerprint_cleared(workspace.before)
        && fingerprint_cleared(workspace.after);
}

bool text_equals(const OwnedText& text,
                 const std::string& expected) noexcept {
    if (text.length != expected.size()
            || text.bytes[expected.size()] != 0u) {
        return false;
    }
    if (!expected.empty()
            && std::memcmp(text.bytes.data(), expected.data(),
                           expected.size()) != 0) {
        return false;
    }
    for (std::size_t index = expected.size() + 1u;
         index < text.bytes.size(); ++index) {
        if (text.bytes[index] != 0u) return false;
    }
    return true;
}

void test_success(Check& check, std::uint8_t kind,
                  bool owner_heap, bool global_heap,
                  const std::string& owner_text,
                  const std::string& global_text) {
    check.begin_case();
    Fixture fixture{};
    fixture.make(kind, owner_heap, global_heap, owner_text, global_text);
    FakeGuard guard{};
    guard.reader = &fixture.reader;
    Workspace workspace{};
    Snapshot output{};
    Result result{};
    const bool captured = names::capture(
        fixture.reader, guard, kBase, kImageSize, kCombat, 7u, 56564064,
        kind, workspace, output, result);
    check.expect(captured, "valid raw name sources capture");
    check.expect(result.failed_stage == FailureStage::none,
                 "success has no failure stage");
    check.expect(output.sequence == 7u && output.raw_date == 56564064
                     && output.kind == kind,
                 "identity metadata copied");
    check.expect(text_equals(output.owner_name, owner_text),
                 "owner source bytes copied");
    check.expect(text_equals(output.global_name, global_text),
                 "global source bytes copied");
    check.expect(guard.calls == 3, "guard sampled before/between/after");
    check.expect(result.read_calls == fixture.reader.read_calls
                     && result.read_calls <= names::kMaxReadCalls
                     && result.bytes_read <= names::kMaxReadBytes,
                 "shared read budget accounted");
    check.expect(workspace_cleared(workspace),
                 "successful workspace contains no pointers");
}

void test_empty_heap(Check& check) {
    test_success(check, 1u, true, false, "", "Global");
}

void test_changed_sources(Check& check, FakeGuard::Mutation mutation) {
    check.begin_case();
    Fixture fixture{};
    fixture.make(1u, false, false, "Owner", "Global");
    FakeGuard guard{};
    guard.reader = &fixture.reader;
    guard.mutate_on_call = 2;
    guard.mutation = mutation;
    Workspace workspace{};
    Snapshot output{};
    Result result{};
    const bool captured = names::capture(
        fixture.reader, guard, kBase, kImageSize, kCombat, 1u, 10,
        1u, workspace, output, result);
    check.expect(!captured && result.failed_stage == FailureStage::source_changed,
                 "two-pass content or pointer change rejected");
    check.expect(snapshot_zero(output) && workspace_cleared(workspace),
                 "changed-source failure clears output and workspace");
}

void test_guard_failure(Check& check, int fail_on,
                        FailureStage expected_stage) {
    check.begin_case();
    Fixture fixture{};
    fixture.make();
    FakeGuard guard{};
    guard.reader = &fixture.reader;
    guard.fail_on_call = fail_on;
    Workspace workspace{};
    Snapshot output{};
    Result result{};
    prime_outputs(workspace, output, result);
    const bool captured = names::capture(
        fixture.reader, guard, kBase, kImageSize, kCombat, 1u, 10,
        1u, workspace, output, result);
    check.expect(!captured && result.failed_stage == expected_stage,
                 "guard failure reported at the correct phase");
    check.expect(snapshot_zero(output) && workspace_cleared(workspace),
                 "guard failure clears outputs and pointer workspace");
    check.expect(guard.calls == fail_on,
                 "capture stops at the failed guard checkpoint");
}

void test_invalid_arguments(Check& check) {
    const struct Invalid final {
        std::uint64_t sequence;
        std::int32_t date;
        std::uint8_t kind;
        Address base;
        std::size_t image_size;
        Address combat;
        FailureStage expected;
    } inputs[] = {
        {1u, 0, 3u, kBase, kImageSize, kCombat, FailureStage::invalid_kind},
        {0u, 0, 1u, kBase, kImageSize, kCombat,
         FailureStage::invalid_sequence},
        {1u, -1, 1u, kBase, kImageSize, kCombat,
         FailureStage::invalid_date},
        {1u, 0, 1u, 1u, kImageSize, kCombat,
         FailureStage::invalid_base_or_image},
        {1u, 0, 1u, kBase, title::kGlobalStringRva, kCombat,
         FailureStage::invalid_base_or_image},
        {1u, 0, 1u, kBase, kImageSize, 1u,
         FailureStage::invalid_combat},
    };
    for (const Invalid& input : inputs) {
        check.begin_case();
        Fixture fixture{};
        fixture.make();
        FakeGuard guard{};
        guard.reader = &fixture.reader;
        Workspace workspace{};
        Snapshot output{};
        Result result{};
        prime_outputs(workspace, output, result);
        const bool captured = names::capture(
            fixture.reader, guard, input.base, input.image_size,
            input.combat, input.sequence, input.date, input.kind,
            workspace, output, result);
        check.expect(!captured && result.failed_stage == input.expected,
                     "invalid argument rejected");
        check.expect(guard.calls == 0 && fixture.reader.read_calls == 0u,
                     "invalid argument rejected before guard or read");
        check.expect(snapshot_zero(output) && workspace_cleared(workspace),
                     "invalid argument clears output and workspace");
    }
}

void test_source_failures(Check& check) {
    // A valid instruction body carrying the other expected kind fails during
    // the first source graph pass.
    check.begin_case();
    Fixture wrong_selector{};
    wrong_selector.make(2u);
    FakeGuard guard{};
    guard.reader = &wrong_selector.reader;
    Workspace workspace{};
    Snapshot output{};
    Result result{};
    const bool selector_ok = names::capture(
        wrong_selector.reader, guard, kBase, kImageSize, kCombat, 1u, 0,
        1u, workspace, output, result);
    check.expect(!selector_ok
                     && result.failed_stage == FailureStage::source_before,
                 "selector kind mismatch rejected");
    check.expect(snapshot_zero(output) && workspace_cleared(workspace),
                 "selector failure clears partial graph pointers");

    // The fifth source read is the owner pointer read; its failed attempt is
    // charged to the shared result budget and partial graph addresses clear.
    check.begin_case();
    Fixture read_failure{};
    read_failure.make();
    read_failure.reader.fail_on_call = 5u;
    FakeGuard read_guard{};
    read_guard.reader = &read_failure.reader;
    Workspace read_workspace{};
    Snapshot read_output{};
    Result read_result{};
    const bool read_ok = names::capture(
        read_failure.reader, read_guard, kBase, kImageSize, kCombat,
        1u, 0, 1u, read_workspace, read_output, read_result);
    check.expect(!read_ok
                     && read_result.failed_stage == FailureStage::source_before,
                 "Reader failure is reported");
    check.expect(read_result.read_calls == 5u
                     && read_result.bytes_read == 38u
                     && read_failure.reader.read_calls == 5u,
                 "failed Reader read is charged before the call");
    check.expect(snapshot_zero(read_output)
                     && workspace_cleared(read_workspace),
                 "partial first graph is cleared after Reader failure");
}

void test_bad_text(Check& check) {
    check.begin_case();
    Fixture embedded_inline{};
    embedded_inline.make(1u, false, false, "Owner", "Global");
    const unsigned char nul = 0u;
    (void)embedded_inline.reader.write(
        embedded_inline.owner_string + 1u, &nul, 1u);
    FakeGuard inline_guard{};
    inline_guard.reader = &embedded_inline.reader;
    Workspace inline_workspace{};
    Snapshot inline_output{};
    Result inline_result{};
    const bool inline_ok = names::capture(
        embedded_inline.reader, inline_guard, kBase, kImageSize, kCombat,
        1u, 0, 1u, inline_workspace, inline_output, inline_result);
    check.expect(!inline_ok
                     && inline_result.failed_stage == FailureStage::source_before,
                 "embedded inline NUL rejected");
    check.expect(snapshot_zero(inline_output)
                     && workspace_cleared(inline_workspace),
                 "inline NUL failure clears outputs");

    check.begin_case();
    Fixture embedded_heap{};
    embedded_heap.make(2u, true, false, "HeapName", "Global");
    (void)embedded_heap.reader.write(kOwnerHeap + 2u, &nul, 1u);
    FakeGuard heap_guard{};
    heap_guard.reader = &embedded_heap.reader;
    Workspace heap_workspace{};
    Snapshot heap_output{};
    Result heap_result{};
    const bool heap_ok = names::capture(
        embedded_heap.reader, heap_guard, kBase, kImageSize, kCombat,
        1u, 0, 2u, heap_workspace, heap_output, heap_result);
    check.expect(!heap_ok
                     && heap_result.failed_stage == FailureStage::source_before,
                 "embedded heap NUL rejected");
    check.expect(snapshot_zero(heap_output)
                     && workspace_cleared(heap_workspace),
                 "heap NUL failure clears outputs");

    check.begin_case();
    Fixture oversized{};
    oversized.make(1u, true, false, "Text", "Global");
    const std::uint64_t too_long = names::kMaxTextBytes + 1u;
    oversized.reader.put(
        oversized.owner_string
            + information::battle::owned_native_text::kStringLengthOffset,
        too_long);
    FakeGuard long_guard{};
    long_guard.reader = &oversized.reader;
    Workspace long_workspace{};
    Snapshot long_output{};
    Result long_result{};
    const bool long_ok = names::capture(
        oversized.reader, long_guard, kBase, kImageSize, kCombat,
        1u, 0, 1u, long_workspace, long_output, long_result);
    check.expect(!long_ok
                     && long_result.failed_stage == FailureStage::source_before,
                 "oversized source text rejected");
    check.expect(snapshot_zero(long_output)
                     && workspace_cleared(long_workspace),
                 "oversized source failure clears outputs");
}

void test_source_alias(Check& check, int target_kind) {
    check.begin_case();
    Fixture fixture{};
    fixture.make(1u, false, false, "Owner", "Global");
    Workspace workspace{};
    Snapshot output{};
    Result result{};
    Address target = 0u;
    if (target_kind == 0) {
        target = reinterpret_cast<Address>(&workspace);
    } else if (target_kind == 1) {
        target = reinterpret_cast<Address>(&output);
    } else {
        target = reinterpret_cast<Address>(&result);
    }
    fixture.set_owner_heap_alias(target, "", false);  // empty heap still reads NUL
    FakeGuard guard{};
    guard.reader = &fixture.reader;
    const bool captured = names::capture(
        fixture.reader, guard, kBase, kImageSize, kCombat, 1u, 0,
        1u, workspace, output, result);
    check.expect(!captured && result.failed_stage == FailureStage::source_before,
                 "source alias into caller-owned storage rejected");
    check.expect(!fixture.reader.read_address_seen(target),
                 "aliased source range rejected before Reader::read");
    check.expect(snapshot_zero(output) && workspace_cleared(workspace),
                 "source alias failure clears output and workspace");
}

union WorkspaceSnapshot final {
    Workspace workspace;
    Snapshot output;
    WorkspaceSnapshot() noexcept {}
    ~WorkspaceSnapshot() {}
};

union WorkspaceResult final {
    Workspace workspace;
    Result result;
    WorkspaceResult() noexcept {}
    ~WorkspaceResult() {}
};

union SnapshotResult final {
    Snapshot output;
    Result result;
    SnapshotResult() noexcept {}
    ~SnapshotResult() {}
};

void test_parameter_aliases(Check& check) {
    // These unions deliberately present overlapping caller storage.  The
    // capture preflight must return before clearing or reading either object.
    check.begin_case();
    Fixture f1{};
    f1.make();
    WorkspaceSnapshot a{};
    std::memset(static_cast<void*>(&a), 0x5a, sizeof(a));
    new (&a.workspace) Workspace{};
    a.workspace.before.combat_vtable = UINT64_C(0x12345678);
    const auto before_a = [&]() {
        std::array<unsigned char, sizeof(WorkspaceSnapshot)> bytes{};
        std::memcpy(bytes.data(), &a, sizeof(a));
        return bytes;
    }();
    Result r1{};
    FakeGuard g1{};
    g1.reader = &f1.reader;
    const bool a_ok = names::capture(
        f1.reader, g1, kBase, kImageSize, kCombat, 1u, 0, 1u,
        a.workspace, *reinterpret_cast<Snapshot*>(&a), r1);
    std::array<unsigned char, sizeof(WorkspaceSnapshot)> after_a{};
    std::memcpy(after_a.data(), &a, sizeof(a));
    check.expect(!a_ok && before_a == after_a,
                 "workspace/output alias leaves storage unchanged");
    check.expect(f1.reader.read_calls == 0u && g1.calls == 0,
                 "workspace/output alias rejected before work");

    check.begin_case();
    Fixture f2{};
    f2.make();
    WorkspaceResult b{};
    std::memset(static_cast<void*>(&b), 0x6b, sizeof(b));
    new (&b.workspace) Workspace{};
    b.workspace.after.global_string = UINT64_C(0x87654321);
    const auto before_b = [&]() {
        std::array<unsigned char, sizeof(WorkspaceResult)> bytes{};
        std::memcpy(bytes.data(), &b, sizeof(b));
        return bytes;
    }();
    Snapshot out2{};
    FakeGuard g2{};
    g2.reader = &f2.reader;
    const bool b_ok = names::capture(
        f2.reader, g2, kBase, kImageSize, kCombat, 1u, 0, 1u,
        b.workspace, out2, *reinterpret_cast<Result*>(&b));
    std::array<unsigned char, sizeof(WorkspaceResult)> after_b{};
    std::memcpy(after_b.data(), &b, sizeof(b));
    check.expect(!b_ok && before_b == after_b && snapshot_zero(out2),
                 "workspace/result alias leaves caller storage unchanged");
    check.expect(f2.reader.read_calls == 0u && g2.calls == 0,
                 "workspace/result alias rejected before work");

    check.begin_case();
    Fixture f3{};
    f3.make();
    Workspace w3{};
    SnapshotResult c{};
    std::memset(static_cast<void*>(&c), 0x7c, sizeof(c));
    new (&c.output) Snapshot{};
    c.output.sequence = 42u;
    const auto before_c = [&]() {
        std::array<unsigned char, sizeof(SnapshotResult)> bytes{};
        std::memcpy(bytes.data(), &c, sizeof(c));
        return bytes;
    }();
    FakeGuard g3{};
    g3.reader = &f3.reader;
    const bool c_ok = names::capture(
        f3.reader, g3, kBase, kImageSize, kCombat, 1u, 0, 1u,
        w3, c.output, *reinterpret_cast<Result*>(&c));
    std::array<unsigned char, sizeof(SnapshotResult)> after_c{};
    std::memcpy(after_c.data(), &c, sizeof(c));
    check.expect(!c_ok && before_c == after_c,
                 "output/result alias leaves storage unchanged");
    check.expect(f3.reader.read_calls == 0u && g3.calls == 0,
                 "output/result alias rejected before work");
}

void test_budget(Check& check) {
    check.begin_case();
    Workspace workspace{};
    Snapshot output{};
    Result result{};
    names::detail::StorageRanges ranges{};
    check.expect(names::detail::independent_storage(
                     workspace, output, result, ranges),
                 "test budget storage is independent");
    FakeReader reader{};
    reader.add(kBudgetRegion, names::kMaxReadCalls + 1u);
    std::array<unsigned char, names::kMaxReadBytes> destination{};
    names::detail::BudgetReader<FakeReader> budget(reader, result, ranges);
    bool first_64_ok = true;
    for (std::uint32_t index = 0u; index < names::kMaxReadCalls; ++index) {
        first_64_ok = budget.read(kBudgetRegion + index,
                                  destination.data(), 1u) && first_64_ok;
    }
    const bool sixty_fifth_ok = budget.read(
        kBudgetRegion + names::kMaxReadCalls, destination.data(), 1u);
    check.expect(first_64_ok && !sixty_fifth_ok
                     && result.read_calls == names::kMaxReadCalls
                     && result.bytes_read == names::kMaxReadCalls
                     && reader.read_calls == names::kMaxReadCalls,
                 "64-call cap rejects the next read before Reader");

    check.begin_case();
    Workspace byte_workspace{};
    Snapshot byte_output{};
    Result byte_result{};
    names::detail::StorageRanges byte_ranges{};
    (void)names::detail::independent_storage(
        byte_workspace, byte_output, byte_result, byte_ranges);
    FakeReader byte_reader{};
    byte_reader.add(kBudgetRegion, names::kMaxReadBytes + 1u);
    std::array<unsigned char, names::kMaxReadBytes> byte_destination{};
    names::detail::BudgetReader<FakeReader> byte_budget(
        byte_reader, byte_result, byte_ranges);
    const bool full_budget_ok = byte_budget.read(
        kBudgetRegion, byte_destination.data(), names::kMaxReadBytes);
    const bool one_extra_byte_ok = byte_budget.read(
        kBudgetRegion + names::kMaxReadBytes,
        byte_destination.data(), 1u);
    check.expect(full_budget_ok && !one_extra_byte_ok
                     && byte_result.read_calls == 1u
                     && byte_result.bytes_read == names::kMaxReadBytes
                     && byte_reader.read_calls == 1u,
                 "128 KiB cap rejects a read beyond its remaining bytes");
}

}  // namespace

int main() {
    Check check{};
    test_success(check, 1u, false, false, "LandOwner", "LandGlobal");
    test_success(check, 2u, true, true, "NavalOwner", "NavalGlobal");
    test_empty_heap(check);
    test_changed_sources(check, FakeGuard::Mutation::owner_text);
    test_changed_sources(check, FakeGuard::Mutation::owner_pointer);
    test_guard_failure(check, 1, FailureStage::guard_before);
    test_guard_failure(check, 2, FailureStage::guard_between);
    test_guard_failure(check, 3, FailureStage::guard_after);
    test_invalid_arguments(check);
    test_source_failures(check);
    test_bad_text(check);
    test_source_alias(check, 0);
    test_source_alias(check, 1);
    test_source_alias(check, 2);
    test_parameter_aliases(check);
    test_budget(check);

    if (check.failures != 0u) {
        std::cerr << "{\"ok\":false,\"cases\":" << check.cases
                  << ",\"checks\":" << check.checks
                  << ",\"failures\":" << check.failures << "}\n";
        return 1;
    }
    std::cout << "{\"ok\":true,\"cases\":" << check.cases
              << ",\"checks\":" << check.checks << "}\n";
    return 0;
}
