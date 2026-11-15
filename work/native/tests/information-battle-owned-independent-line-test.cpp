#include "../information-battle-owned-independent-line.h"
#include "../information-battle-independent-line-plan.h"
#include <cassert>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace owned = information::battle::owned_independent_line;
namespace wire = information::battle::independent_line_wire;
namespace model = information::battle::display_context;
namespace names = information::battle::name_sources_wire;
namespace plan = information::battle::independent_line_plan;
struct PlanReader {
    std::array<unsigned char, 32> prefix = plan::kFormatterPrefix;
    bool read(std::uintptr_t address, unsigned char* output, std::size_t size) noexcept {
        if (address != UINT64_C(0x140000000) + plan::kFormatterRva || size != prefix.size()) return false;
        std::memcpy(output, prefix.data(), size);
        return true;
    }
};
struct Reader {
    bool read(std::uintptr_t address, unsigned char* output, std::size_t size) noexcept {
        if (!address || !output || size > 32768) return false;
        std::memcpy(output, reinterpret_cast<const void*>(address), size);
        return true;
    }
};
struct Invoker {
    int guards = 0, invokes = 0, destroys = 0, fail_guard = 0;
    bool foreign_return = false, bad_size = false, mutate_argument = false;
    std::string rendered;
    owned::String32 foreign{};
    bool guard(const model::Snapshot&) noexcept { return ++guards != fail_guard; }
    owned::String32* invoke(owned::String32* output, const char* key,
                           const battle_format_input::NativeArg104* arguments, std::int32_t count) noexcept {
        ++invokes;
        assert(count == 1);
        assert(std::string_view(key) == "LANDBATTLEOVER_1" || std::string_view(key) == "NAVALBATTLEOVER_1");
        assert(std::strcmp(battle_format_input::cstr_pointer(*arguments, 0), "NAME") == 0);
        rendered = battle_format_input::cstr_pointer(*arguments, 0x60);
        *output = owned::String32{};
        output->size = bad_size ? 8193 : rendered.size();
        if (rendered.size() < 16) std::memcpy(output->storage.data(), rendered.c_str(), rendered.size() + 1);
        else {
            auto* data = rendered.data();
            std::memcpy(output->storage.data(), &data, sizeof(data));
            output->capacity = rendered.capacity();
        }
        if (mutate_argument) const_cast<battle_format_input::NativeArg104*>(arguments)->bytes[0x28] = 3;
        return foreign_return ? &foreign : output;
    }
    void destroy(owned::String32* output) noexcept {
        assert(output != &foreign);
        ++destroys;
        *output = owned::String32{};
        rendered.clear();
    }
};
void set(model::Snapshot& context, std::size_t index, std::string_view value) {
    auto& field = context.fields[index];
    field.state = model::State::observed;
    field.offset = context.arena_used;
    field.length = static_cast<std::uint32_t>(value.size());
    std::memcpy(context.arena.data() + context.arena_used, value.data(), value.size());
    context.arena_used += field.length;
}
void set(names::Text& field, std::string_view value) {
    field.state = names::State::known;
    field.length = static_cast<std::uint32_t>(value.size());
    std::memcpy(field.bytes.data(), value.data(), value.size());
}
void inputs(model::Snapshot& context, names::Snapshot& source, std::uint8_t kind = 1,
            std::uint8_t transform = 1, std::uint64_t sequence = 1, std::int32_t date = 100) {
    context = model::Snapshot{};
    context.state = model::State::observed;
    context.failure = model::Failure::none;
    context.identity = {sequence, date, kind, 3};
    set(context, 0, kind == 1 ? "LANDBATTLEOVER" : "NAVALBATTLEOVER");
    set(context, 1, "l_english");
    set(context, 2, "$NAME$");
    source = names::Snapshot{};
    source.sequence = sequence; source.raw_date = date; source.kind = kind;
    source.raw_failure = 0; source.prefix_failure = 0; source.transform_mode = transform;
    set(source.fields[0], "Paris");
    set(source.fields[1], transform == 2 ? " " : "");
    set(source.fields[2], transform == 2 ? " Battle" : "Battle of ");
    set(source.fields[3], "l_english");
}
int main(int argc, char** argv) {
    PlanReader code;
    assert(plan::guard(code, UINT64_C(0x140000000), 0x3000000));
    code.prefix[0] ^= 1;
    assert(!plan::guard(code, UINT64_C(0x140000000), 0x3000000));
    assert(!plan::guard(code, UINT64_MAX, 0x3000000));
    assert(!plan::guard(code, UINT64_C(0x140000000), 1));
    static owned::Workspace workspace;
    static model::Snapshot context;
    static names::Snapshot source;
    static wire::Snapshot output;
    Reader reader;
    for (std::uint8_t kind : {1, 2}) {
        for (std::uint8_t mode : {1, 2}) {
            inputs(context, source, kind, mode);
            Invoker invoker;
            assert(owned::capture(reader, invoker, context, source, workspace, output));
            assert(output.state == wire::State::known && output.flags == 15 && output.failure == 0);
            assert(invoker.invokes == 1 && invoker.destroys == 1);
            const auto& text = output.fields[wire::output];
            assert(std::string_view(reinterpret_cast<const char*>(text.bytes.data()), text.length)
                == (mode == 2 ? "Paris Battle" : "Battle of Paris"));
        }
    }
    for (std::size_t length : {std::size_t(0), std::size_t(8188)}) {
        inputs(context, source);
        set(source.fields[0], std::string(length, 'x'));
        set(source.fields[1], "");
        set(source.fields[2], "");
        Invoker invoker;
        assert(owned::capture(reader, invoker, context, source, workspace, output));
        assert(output.fields[wire::output].length == length);
        assert(invoker.destroys == 1);
        if (length) assert(output.fields[wire::output].bytes[length - 1] == 'x');
    }
    for (int bad_guard : {1, 2, 3}) {
        inputs(context, source);
        Invoker invoker; invoker.fail_guard = bad_guard;
        assert(!owned::capture(reader, invoker, context, source, workspace, output));
        assert(output.state == wire::State::unknown && output.failure);
        assert(invoker.invokes == (bad_guard == 1 ? 0 : 1));
        assert(invoker.destroys == invoker.invokes);
        assert(wire::detail::valid_fields(output));
    }
    for (int failure : {0, 1, 2}) {
        inputs(context, source);
        Invoker invoker;
        invoker.foreign_return = failure == 0;
        invoker.bad_size = failure == 1;
        invoker.mutate_argument = failure == 2;
        assert(!owned::capture(reader, invoker, context, source, workspace, output));
        assert(invoker.invokes == 1 && invoker.destroys == 1);
        assert(output.failure == (failure == 0 ? 7 : failure == 1 ? 9 : 11));
        assert(wire::detail::valid_fields(output));
    }
    inputs(context, source);
    Invoker never;
    ++source.sequence;
    assert(!owned::capture(reader, never, context, source, workspace, output));
    assert(!never.invokes && !never.destroys);
    inputs(context, source);
    source.fields[3].bytes[2] = 'x';
    assert(!owned::capture(reader, never, context, source, workspace, output));
    inputs(context, source);
    source.fields[0].length = 8189;
    source.fields[0].bytes.fill('x');
    assert(!owned::capture(reader, never, context, source, workspace, output));
    assert(output.failure == 5 && !never.invokes);

    if (argc == 3) {
        std::ifstream input(argv[1], std::ios::binary);
        const std::vector<unsigned char> base((std::istreambuf_iterator<char>(input)), {});
        wire::detail::Identity identity{};
        assert(wire::detail::base_identity(base.data(), base.size(), identity));
        inputs(context, source, identity.kind, 1, identity.sequence, identity.raw_date);
        set(source.fields[0], "");
        set(source.fields[1], "PARIS");
        set(source.fields[2], "BATTLE_OF_");
        Invoker invoker;
        assert(owned::capture(reader, invoker, context, source, workspace, output));
        std::vector<unsigned char> encoded(wire::kMaxWireBytes);
        const auto size = wire::encode(base.data(), base.size(), output, encoded.data(), encoded.size()).written_bytes;
        assert(size && wire::validate(encoded.data(), size));
        std::ofstream result(argv[2], std::ios::binary);
        result.write(reinterpret_cast<const char*>(encoded.data()), size);
    }
}
