#include "../information-battle-owned-name-handoff.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>

namespace handoff = information::battle::owned_name_handoff;

namespace {

struct Segment final {
    handoff::Address address = 0u;
    std::size_t size = 0u;
    std::array<unsigned char, handoff::kMaxValueBytes + 1u> bytes{};
};

struct BoundedReader final {
    static constexpr std::size_t kSegmentCount = 16u;

    std::array<Segment, kSegmentCount> segments{};
    std::size_t segment_count = 0u;
    std::size_t read_calls = 0u;
    std::size_t read_bytes = 0u;
    std::size_t max_calls = std::numeric_limits<std::size_t>::max();
    bool short_next = false;
    std::size_t mutate_on_call = 0u;
    handoff::Address mutate_address = 0u;
    std::array<unsigned char, handoff::kMaxValueBytes + 1u> mutate_bytes{};
    std::size_t mutate_size = 0u;
    bool mutated = false;
    std::array<handoff::Address, 32u> addresses{};
    std::size_t address_count = 0u;

    bool put(handoff::Address address, const void* source,
             std::size_t size) noexcept {
        if (size == 0u || size > handoff::kMaxValueBytes + 1u) return false;
        for (std::size_t index = 0u; index < segment_count; ++index) {
            Segment& segment = segments[index];
            if (address < segment.address
                    || address - segment.address > segment.size
                    || size > segment.size - (address - segment.address)) {
                continue;
            }
            std::memcpy(segment.bytes.data() +
                            static_cast<std::size_t>(address - segment.address),
                        source, size);
            return true;
        }
        if (segment_count >= segments.size()) return false;
        Segment& segment = segments[segment_count++];
        segment.address = address;
        segment.size = size;
        std::memcpy(segment.bytes.data(), source, size);
        return true;
    }

    bool put_u64(handoff::Address address, handoff::Address value) noexcept {
        return put(address, &value, sizeof(value));
    }

    bool has_address(handoff::Address address) const noexcept {
        for (std::size_t index = 0u; index < address_count; ++index) {
            if (addresses[index] == address) return true;
        }
        return false;
    }

    bool read(handoff::Address address, unsigned char* destination,
              std::size_t size) noexcept {
        if (address_count < addresses.size()) addresses[address_count++] = address;
        if (read_calls >= max_calls) return false;
        ++read_calls;
        read_bytes += size;
        if (!mutated && mutate_on_call != 0u && read_calls == mutate_on_call) {
            mutated = true;
            (void)put(mutate_address, mutate_bytes.data(), mutate_size);
        }
        if (short_next) {
            short_next = false;
            return false;
        }
        for (std::size_t index = 0u; index < segment_count; ++index) {
            const Segment& segment = segments[index];
            if (address < segment.address
                    || address - segment.address > segment.size
                    || size > segment.size - (address - segment.address)) {
                continue;
            }
            std::memcpy(destination,
                        segment.bytes.data() +
                            static_cast<std::size_t>(address - segment.address),
                        size);
            return true;
        }
        return false;
    }
};

struct Fixture final {
    static constexpr handoff::Address kBase = 0x140000000ull;
    static constexpr handoff::Address kEntryRsp = 0x200000000ull;
    static constexpr handoff::Address kRbp = 0x210000000ull;
    static constexpr handoff::Address kCombat = 0x220000000ull;
    static constexpr handoff::Address kHeap = 0x230000000ull;

    BoundedReader reader{};
    handoff::Request request{};
    handoff::ScopeIdentity scope{};
    handoff::Workspace workspace{};
    handoff::Snapshot output{};
    handoff::Result result{};

    static std::size_t caller_offset(std::uint32_t kind) noexcept {
        return kind == handoff::kLandKind
            ? handoff::kLandFormatterCallerOffset
            : handoff::kNavalFormatterCallerOffset;
    }

    static std::size_t key_offset(std::uint32_t kind) noexcept {
        return kind == handoff::kLandKind
            ? handoff::kLandKeyEntryOffset
            : handoff::kNavalKeyEntryOffset;
    }

    static std::size_t value_offset(std::uint32_t kind) noexcept {
        return kind == handoff::kLandKind
            ? handoff::kLandValueOffset
            : handoff::kNavalValueOffset;
    }

    static std::size_t destination_back_offset(std::uint32_t kind) noexcept {
        return kind == handoff::kLandKind
            ? handoff::kLandDestinationBackOffset
            : handoff::kNavalDestinationBackOffset;
    }

    static std::size_t return_rva(std::uint32_t kind) noexcept {
        return kind == handoff::kLandKind
            ? handoff::kLandReturnRva
            : handoff::kNavalReturnRva;
    }

    static std::size_t caller_rva(std::uint32_t kind) noexcept {
        return kind == handoff::kLandKind
            ? handoff::kLandFormatterCallerRva
            : handoff::kNavalFormatterCallerRva;
    }

    bool init(std::uint32_t kind, bool heap, const char* text) noexcept {
        reader = BoundedReader{};
        request = handoff::Request{};
        scope = handoff::ScopeIdentity{};
        workspace = handoff::Workspace{};
        output = handoff::Snapshot{};
        result = handoff::Result{};

        request.module_base = kBase;
        request.image_size = 0x300000u;
        request.entry_rsp = kEntryRsp;
        request.original_rbp = kRbp;
        request.key = kEntryRsp + key_offset(kind);
        request.value = kRbp + value_offset(kind);
        request.destination = kRbp - destination_back_offset(kind);
        request.return_pc = kBase + return_rva(kind);

        scope.sequence = 42u;
        scope.raw_date = 56557824;
        scope.combat = kCombat;
        scope.kind = kind;
        scope.parent_guards_verified = true;

        const handoff::Address caller_slot =
            kRbp + caller_offset(kind);
        const handoff::Address caller = kBase + caller_rva(kind);
        // The combat owner is a value in the caller's stack frame: the
        // caller-slot address (RBP+1d8/198), not the echoed code PC, minus
        // 0x20.  Keep this distinction visible in the fixture.
        const handoff::Address owner_slot =
            caller_slot - handoff::kFormatterOwnerBackOffset;
        if (!reader.put_u64(request.entry_rsp, request.return_pc)
                || !reader.put_u64(caller_slot, caller)
                || !reader.put_u64(owner_slot, kCombat)) {
            return false;
        }

        handoff::String32 key{};
        key.length = 4u;
        key.capacity = handoff::kInlineCapacity;
        std::memcpy(key.storage.data(), "NAME", 4u);
        if (!reader.put(request.key, &key, sizeof(key))) return false;

        handoff::String32 value{};
        const std::size_t length = std::strlen(text);
        if (length > handoff::kMaxValueBytes) return false;
        value.length = length;
        if (!heap) {
            value.capacity = handoff::kInlineCapacity;
            std::memcpy(value.storage.data(), text, length);
            value.storage[length] = 0u;
            return reader.put(request.value, &value, sizeof(value));
        }
        value.capacity = 31u;
        std::memcpy(value.storage.data(), &kHeap, sizeof(kHeap));
        if (!reader.put(request.value, &value, sizeof(value))) return false;
        std::array<unsigned char, handoff::kMaxValueBytes + 1u> bytes{};
        std::memcpy(bytes.data(), text, length);
        bytes[length] = 0u;
        return reader.put(kHeap, bytes.data(), length + 1u);
    }

    bool capture() noexcept {
        return handoff::capture(reader, request, scope, workspace, output,
                                result);
    }
};

struct TestState final {
    int checks = 0;
    int failures = 0;

    void check(bool condition, const char* message) noexcept {
        ++checks;
        if (!condition) {
            ++failures;
            std::printf("FAIL: %s\n", message);
        }
    }
};

void test_land_sso_and_copy(TestState& test) noexcept {
    Fixture fixture;
    test.check(fixture.init(handoff::kLandKind, false, "Victory"),
               "land fixture");
    test.check(fixture.capture(), "land SSO capture");
    test.check(fixture.result.observed && fixture.result.source_unchanged,
               "land observed/source stable");
    test.check(fixture.output.state == handoff::SnapshotState::known
                   && fixture.output.kind == handoff::kLandKind
                   && fixture.output.length == 7u
                   && std::memcmp(fixture.output.bytes.data(), "Victory", 7u) == 0
                   && fixture.output.bytes[7] == 0u,
               "land value-only output");
    test.check(fixture.result.calls == 10u
                   && fixture.result.total_bytes == 176u,
               "land bounded budget");

    const handoff::Snapshot saved = fixture.output;
    const char changed[] = "Changed";
    handoff::String32 changed_header{};
    changed_header.length = 7u;
    changed_header.capacity = handoff::kInlineCapacity;
    std::memcpy(changed_header.storage.data(), changed, 7u);
    changed_header.storage[7] = 0u;
    (void)fixture.reader.put(fixture.request.value, &changed_header,
                             sizeof(changed_header));
    test.check(std::memcmp(&saved, &fixture.output, sizeof(saved)) == 0,
               "copied output does not retain source");
}

void test_naval_heap_and_empty(TestState& test) noexcept {
    Fixture heap;
    test.check(heap.init(handoff::kNavalKind, true, "NavalName"),
               "naval fixture");
    test.check(heap.capture(), "naval heap capture");
    test.check(heap.output.kind == handoff::kNavalKind
                   && heap.output.length == 9u
                   && std::memcmp(heap.output.bytes.data(), "NavalName", 9u) == 0,
               "naval heap value");
    test.check(heap.result.calls == 12u
                   && heap.result.total_bytes == 196u,
               "naval heap budget");

    Fixture empty;
    test.check(empty.init(handoff::kLandKind, false, ""), "empty fixture");
    test.check(empty.capture(), "empty value known");
    test.check(empty.output.state == handoff::SnapshotState::known
                   && empty.output.length == 0u && empty.output.bytes[0] == 0u,
               "empty value output");
}

void test_guards_and_frame_rejections(TestState& test) noexcept {
    Fixture scope;
    test.check(scope.init(handoff::kLandKind, false, "x"), "scope fixture");
    scope.scope.parent_guards_verified = false;
    test.check(!scope.capture() && scope.reader.read_calls == 0u,
               "scope guard rejects before read");

    Fixture sequence;
    test.check(sequence.init(handoff::kLandKind, false, "x"),
               "sequence fixture");
    sequence.scope.sequence = 0u;
    test.check(!sequence.capture() && sequence.reader.read_calls == 0u,
               "zero sequence rejects before read");

    Fixture return_pc;
    test.check(return_pc.init(handoff::kLandKind, false, "x"),
               "return fixture");
    (void)return_pc.reader.put_u64(return_pc.request.entry_rsp,
                                   return_pc.request.return_pc + 8u);
    test.check(!return_pc.capture() && return_pc.reader.read_calls == 1u
                   && !return_pc.reader.has_address(return_pc.request.key)
                   && !return_pc.reader.has_address(return_pc.request.value),
               "wrong return rejects before strings");

    Fixture caller;
    test.check(caller.init(handoff::kLandKind, false, "x"),
               "caller fixture");
    (void)caller.reader.put_u64(
        caller.request.original_rbp + Fixture::caller_offset(handoff::kLandKind),
        Fixture::kBase + Fixture::caller_rva(handoff::kLandKind) + 8u);
    test.check(!caller.capture() && caller.reader.read_calls == 2u
                   && !caller.reader.has_address(caller.request.key),
               "wrong formatter caller rejects before strings");

    Fixture owner;
    test.check(owner.init(handoff::kLandKind, false, "x"), "owner fixture");
    const handoff::Address caller_slot =
        owner.request.original_rbp + Fixture::caller_offset(handoff::kLandKind);
    const handoff::Address code_pc =
        Fixture::kBase + Fixture::caller_rva(handoff::kLandKind);
    // A stale/incorrect implementation might read code_pc-0x20.  Put the
    // expected combat there while making the real frame owner disagree; the
    // adapter must reject and must never read the code-PC alias.
    (void)owner.reader.put_u64(
        code_pc - handoff::kFormatterOwnerBackOffset, Fixture::kCombat);
    (void)owner.reader.put_u64(caller_slot - handoff::kFormatterOwnerBackOffset,
                               Fixture::kCombat + 8u);
    test.check(!owner.capture() && owner.reader.read_calls == 3u
                   && !owner.reader.has_address(owner.request.key)
                   && !owner.reader.has_address(
                       code_pc - handoff::kFormatterOwnerBackOffset),
               "frame owner rejects code-PC alias before strings");

    Fixture frame;
    test.check(frame.init(handoff::kLandKind, false, "x"), "frame fixture");
    frame.request.destination += 8u;
    test.check(!frame.capture() && frame.reader.read_calls == 0u,
               "wrong frame args reject before read");
}

void test_two_pass_changes(TestState& test) noexcept {
    Fixture header;
    test.check(header.init(handoff::kLandKind, false, "before"),
               "header mutation fixture");
    handoff::String32 changed{};
    changed.length = 6u;
    changed.capacity = handoff::kInlineCapacity;
    std::memcpy(changed.storage.data(), "after!", 6u);
    changed.storage[6] = 0u;
    header.reader.mutate_on_call = 6u;
    header.reader.mutate_address = header.request.value;
    header.reader.mutate_size = sizeof(changed);
    std::memcpy(header.reader.mutate_bytes.data(), &changed, sizeof(changed));
    test.check(!header.capture() && !header.result.observed
                   && header.output.state == handoff::SnapshotState::unknown,
               "header change retracts value");

    Fixture payload;
    test.check(payload.init(handoff::kNavalKind, true, "before"),
               "payload mutation fixture");
    const char after[] = "after!";
    payload.reader.mutate_on_call = 7u;
    payload.reader.mutate_address = Fixture::kHeap;
    payload.reader.mutate_size = sizeof(after);
    std::memcpy(payload.reader.mutate_bytes.data(), after, sizeof(after));
    test.check(!payload.capture() && !payload.result.observed
                   && payload.output.state == handoff::SnapshotState::unknown,
               "payload change retracts value");
}

void test_alias_overflow_and_budgets(TestState& test) noexcept {
    Fixture key_alias;
    test.check(key_alias.init(handoff::kLandKind, false, "x"),
               "key alias fixture");
    key_alias.request.key = key_alias.request.destination;
    test.check(!key_alias.capture() && key_alias.reader.read_calls == 0u,
               "source destination alias rejects");

    Fixture heap_alias;
    test.check(heap_alias.init(handoff::kLandKind, true, "heap"),
               "heap alias fixture");
    handoff::String32 alias_header{};
    alias_header.length = 4u;
    alias_header.capacity = 31u;
    std::memcpy(alias_header.storage.data(), &heap_alias.request.destination,
                sizeof(heap_alias.request.destination));
    (void)heap_alias.reader.put(heap_alias.request.value, &alias_header,
                                sizeof(alias_header));
    test.check(!heap_alias.capture()
                   && heap_alias.output.state == handoff::SnapshotState::unknown,
               "heap alias rejects");

    Fixture workspace_heap_alias;
    test.check(workspace_heap_alias.init(handoff::kLandKind, true, "heap"),
               "workspace heap alias fixture");
    const handoff::Address workspace_address =
        reinterpret_cast<handoff::Address>(&workspace_heap_alias.workspace);
    handoff::String32 workspace_alias_header{};
    workspace_alias_header.length = 4u;
    workspace_alias_header.capacity = 31u;
    std::memcpy(workspace_alias_header.storage.data(), &workspace_address,
                sizeof(workspace_address));
    (void)workspace_heap_alias.reader.put(workspace_heap_alias.request.value,
                                          &workspace_alias_header,
                                          sizeof(workspace_alias_header));
    std::array<unsigned char, sizeof(handoff::Workspace)> workspace_sentinel{};
    workspace_sentinel.fill(0xa5u);
    std::memcpy(&workspace_heap_alias.workspace, workspace_sentinel.data(),
                workspace_sentinel.size());
    test.check(!workspace_heap_alias.capture()
                   && std::memcmp(&workspace_heap_alias.workspace,
                                  workspace_sentinel.data(),
                                  workspace_sentinel.size()) == 0,
               "heap payload workspace alias rejects before clear");

    Fixture output_heap_alias;
    test.check(output_heap_alias.init(handoff::kLandKind, true, "heap"),
               "output heap alias fixture");
    const handoff::Address output_address =
        reinterpret_cast<handoff::Address>(&output_heap_alias.output);
    handoff::String32 output_alias_header{};
    output_alias_header.length = 4u;
    output_alias_header.capacity = 31u;
    std::memcpy(output_alias_header.storage.data(), &output_address,
                sizeof(output_address));
    (void)output_heap_alias.reader.put(output_heap_alias.request.value,
                                       &output_alias_header,
                                       sizeof(output_alias_header));
    std::array<unsigned char, sizeof(handoff::Snapshot)> output_sentinel{};
    output_sentinel.fill(0x5au);
    std::memcpy(&output_heap_alias.output, output_sentinel.data(),
                output_sentinel.size());
    test.check(!output_heap_alias.capture()
                   && std::memcmp(&output_heap_alias.output,
                                  output_sentinel.data(),
                                  output_sentinel.size()) == 0,
               "heap payload output alias rejects before clear");

    Fixture overflow;
    test.check(overflow.init(handoff::kLandKind, false, "x"),
               "overflow fixture");
    overflow.request.entry_rsp =
        std::numeric_limits<handoff::Address>::max() - 0x10u;
    test.check(!overflow.capture() && overflow.reader.read_calls == 0u,
               "frame arithmetic overflow rejects");

    Fixture limited;
    test.check(limited.init(handoff::kLandKind, false, "x"),
               "budget fixture");
    limited.reader.max_calls = 4u;
    test.check(!limited.capture() && limited.reader.read_calls == 4u
                   && limited.output.state == handoff::SnapshotState::unknown,
               "call budget rejects");

    Fixture short_read;
    test.check(short_read.init(handoff::kLandKind, false, "x"),
               "short fixture");
    short_read.reader.short_next = true;
    test.check(!short_read.capture() && short_read.reader.read_calls == 1u,
               "short read rejects");
}

void test_output_workspace_alias(TestState& test) noexcept {
    Fixture workspace_alias;
    test.check(workspace_alias.init(handoff::kLandKind, false, "x"),
               "workspace alias fixture");
    const handoff::Address workspace_address =
        reinterpret_cast<handoff::Address>(&workspace_alias.workspace);
    workspace_alias.request.entry_rsp =
        workspace_address - Fixture::key_offset(handoff::kLandKind);
    workspace_alias.request.key = workspace_address;
    test.check(!workspace_alias.capture()
                   && workspace_alias.reader.read_calls == 0u,
               "workspace/source alias rejects before clear");

    Fixture output_alias;
    test.check(output_alias.init(handoff::kLandKind, false, "x"),
               "output alias fixture");
    const handoff::Address output_address =
        reinterpret_cast<handoff::Address>(&output_alias.output);
    output_alias.request.entry_rsp =
        output_address - Fixture::key_offset(handoff::kLandKind);
    output_alias.request.key = output_address;
    test.check(!output_alias.capture() && output_alias.reader.read_calls == 0u,
               "output/source alias rejects before clear");
}

}  // namespace

int main() {
    TestState test;
    test_land_sso_and_copy(test);
    test_naval_heap_and_empty(test);
    test_guards_and_frame_rejections(test);
    test_two_pass_changes(test);
    test_alias_overflow_and_budgets(test);
    test_output_workspace_alias(test);
    std::printf("SUMMARY checks=%d failures=%d\n", test.checks, test.failures);
    return test.failures == 0 ? 0 : 1;
}
