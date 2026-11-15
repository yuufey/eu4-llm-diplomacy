#include "information-battle-owned-flag-inputs.h"
#include <cassert>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

namespace owned = information::battle::owned_flag_inputs;
namespace text = information::battle::owned_template;
namespace wire = information::battle::flag_input_wire;
constexpr std::uintptr_t kBase = 0x100000;
constexpr auto kRebel = kBase + 0x800;

struct Memory final {
    std::vector<unsigned char> bytes = std::vector<unsigned char>(65536);
    unsigned rebel_reads = 0;
    bool fail_rebel = false;
    bool change_rebel = false;
    bool read(std::uintptr_t address, unsigned char* output, std::size_t size) noexcept {
        if (address < kBase || address - kBase > bytes.size() || size > bytes.size() - (address - kBase)) return false;
        if (address == kRebel + 0x38 && size == 4) {
            ++rebel_reads;
            if (fail_rebel) return false;
        }
        std::memcpy(output, bytes.data() + address - kBase, size);
        if (address == kRebel + 0x38 && size == 4 && change_rebel && !(rebel_reads & 1)) output[0] ^= 1;
        return true;
    }
    template <typename T> void put(std::uintptr_t address, T value) {
        std::memcpy(bytes.data() + address - kBase, &value, sizeof(value));
    }
    void string(std::uintptr_t address, const char* value) {
        const auto length = std::strlen(value);
        assert(length <= 15);
        std::memcpy(bytes.data() + address - kBase, value, length + 1);
        put<std::uint64_t>(address + 0x10, length);
        put<std::uint64_t>(address + 0x18, 15);
    }
    void setup(std::uint64_t ref) {
        std::fill(bytes.begin(), bytes.end(), 0);
        put<std::uint64_t>(kBase, kBase + 0x100);
        put<std::uint64_t>(kBase + 8, kBase + 0x300);
        for (unsigned index = 0; index < 3; ++index) {
            const auto node = kBase + 0x100 + index * 0x100;
            string(node, index == 1 ? "ENEMYFLAG" : "OURFLAG");
            string(node + 0x20, index == 2 ? "123" : "");
            put<std::uint64_t>(node + 0x60, index == 2 ? 0 : node + 0x100);
        }
        put<std::uint64_t>(kBase + 0x140, ref);
        put<std::uint64_t>(kBase + 0x250, kRebel);
        put<std::uint32_t>(kRebel + 0x38, 77);
        rebel_reads = 0; fail_rebel = false; change_rebel = false;
    }
};

int main(int argc, char** argv) {
    assert(argc == 4);
    std::ifstream base_file(argv[1], std::ios::binary);
    std::vector<unsigned char> base((std::istreambuf_iterator<char>(base_file)), {});
    wire::detail::Identity identity{};
    assert(wire::detail::base_identity(base.data(), base.size(), identity));
    const auto ref = std::stoull(argv[3], nullptr, 16);
    Memory memory;
    memory.setup(ref);
    auto snapshot = std::make_unique<text::Snapshot>();
    auto original = std::make_unique<text::Snapshot>();
    auto log = std::make_unique<text::detail::ReadLog>();
    auto workspace = std::make_unique<owned::Workspace>();
    auto output = std::make_unique<wire::Snapshot>();
    assert(text::capture_container(memory, kBase, *original));
    assert(text::capture_container(memory, kBase, *snapshot, log.get()));
    assert(text::detail::same_snapshot(*original, *snapshot));
    assert(log->record_count == 4);
    auto message = *snapshot;
    message.native_date = 99;
    message.raw_flag_8c = 1;
    std::memmove(message.arena.data() + 3, message.arena.data(), message.arena.size() - 3);
    std::memcpy(message.arena.data(), "aux", 3);
    message.auxiliary_text = {0, 3};
    for (unsigned index = 0; index < message.pair_count; ++index) {
        message.pairs[index].key.offset += 3;
        message.pairs[index].value.offset += 3;
    }
    assert(owned::same_pairs(message, *snapshot));
    message.pairs[0].key.length -= 1;
    assert(!owned::same_pairs(message, *snapshot));
    assert(owned::capture(memory, *log, *snapshot, identity.sequence, identity.raw_date, 1, *workspace, *output));
    assert(output->entry_count == 3 && output->state == wire::State::known);
    assert(output->entries[0].mode == wire::Mode::country && output->entries[0].country_ref == ref);
    assert(output->entries[1].mode == wire::Mode::rebel && output->entries[1].rebel_raw == 77);
    assert(output->entries[2].mode == wire::Mode::numeric && memory.rebel_reads == 2);
    std::vector<unsigned char> encoded(wire::kMaxWireBytes);
    auto result = wire::encode(base.data(), base.size(), *output, encoded.data(), encoded.size());
    assert(result.succeeded() && wire::validate(encoded.data(), result.written_bytes));
    std::ofstream file(argv[2], std::ios::binary);
    file.write(reinterpret_cast<const char*>(encoded.data()), result.written_bytes);
    file.close();
    const auto before_failure = encoded;
    assert(!wire::encode(base.data(), base.size(), *output, encoded.data(), result.written_bytes - 1).succeeded());
    assert(encoded == before_failure);
    for (const auto offset : {std::size_t(4), std::size_t(10 + base.size()), result.written_bytes - 1}) {
        auto corrupt = encoded;
        corrupt[offset] ^= 255;
        assert(!wire::validate(corrupt.data(), result.written_bytes));
    }
    memory.fail_rebel = true;
    assert(!owned::capture(memory, *log, *snapshot, identity.sequence, identity.raw_date, 1, *workspace, *output));
    assert(output->failure == 5 && output->entry_count == 0);
    assert(text::detail::same_snapshot(*original, *snapshot));
    memory.fail_rebel = false; memory.change_rebel = true; memory.rebel_reads = 0;
    assert(!owned::capture(memory, *log, *snapshot, identity.sequence, identity.raw_date, 1, *workspace, *output));
    assert(output->failure == 5);
    memory.change_rebel = false;
    assert(owned::capture(memory, *log, *snapshot, identity.sequence, identity.raw_date, 2, *workspace, *output));
    assert(output->state == wire::State::not_applicable && output->entry_count == 0);
    assert(!wire::encode(base.data(), base.size(), *output, encoded.data(), encoded.size()).succeeded());
    --log->record_count;
    assert(!owned::capture(memory, *log, *snapshot, identity.sequence, identity.raw_date, 1, *workspace, *output));
    assert(output->failure == 4);
    ++log->record_count;
    auto* alias = reinterpret_cast<wire::Snapshot*>(snapshot.get());
    assert(!owned::capture(memory, *log, *snapshot, identity.sequence, identity.raw_date, 1, *workspace, *alias));
    assert(text::detail::same_snapshot(*original, *snapshot));
    assert(!text::capture_container(memory, kBase, *snapshot,
                                    reinterpret_cast<text::detail::ReadLog*>(snapshot.get())));
    assert(text::detail::same_snapshot(*original, *snapshot));
    memory.setup(ref);
    // A heap String32 in the container adds one logged read after its node.
    memory.put<std::uint64_t>(kBase + 0x320, kBase + 0xf000);
    memory.put<std::uint64_t>(kBase + 0x330, 20);
    memory.put<std::uint64_t>(kBase + 0x338, 31);
    std::memcpy(memory.bytes.data() + 0xf000, "12345678901234567890", 21);
    assert(text::capture_container(memory, kBase, *snapshot, log.get()));
    assert(log->record_count == 5);
    assert(owned::capture(memory, *log, *snapshot, identity.sequence, identity.raw_date, 1, *workspace, *output));
    assert(output->entry_count == 3);
    // Empty flag lists remain a known empty set after the list-reset inputs.
    memory.setup(ref);
    for (unsigned index = 0; index < 3; ++index) {
        const auto node = kBase + 0x100 + index * 0x100;
        std::memset(memory.bytes.data() + node - kBase, 0, 32);
        memory.string(node, "OTHER");
    }
    assert(text::capture_container(memory, kBase, *snapshot, log.get()));
    assert(owned::capture(memory, *log, *snapshot, identity.sequence, identity.raw_date, 1, *workspace, *output));
    assert(output->entry_count == 0 && output->state == wire::State::known);
    return 0;
}
