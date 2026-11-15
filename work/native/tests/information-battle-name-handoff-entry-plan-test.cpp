#define NOMINMAX
#include <windows.h>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include "information-battle-name-handoff-entry-plan.h"

namespace plan = information::battle::name_handoff_entry;
static unsigned checks = 0;
static void check(bool value, const char* label) {
    ++checks;
    if (!value) { std::fprintf(stderr, "FAILED %s\n", label); std::exit(1); }
}
static bool cleared(const plan::Plan& value) {
    for (auto byte : value.image) if (byte) return false;
    for (auto byte : value.patch) if (byte) return false;
    return !value.image_bytes && !value.patch_bytes && !value.original_entry
        && !value.continuation && !value.hook && !value.runtime.begin
        && !value.runtime.end && !value.runtime.unwind;
}
static std::uintptr_t target(const unsigned char* bytes) {
    std::uintptr_t result{};
    std::memcpy(&result, bytes + 6, sizeof(result));
    return result;
}
int main(int argc, char** argv) {
    check(argc == 2, "data-only ROM input path");
    std::array<unsigned char, 155> original{};
    std::ifstream input(argv[1], std::ios::binary);
    input.read(reinterpret_cast<char*>(original.data()), original.size());
    check(input.gcount() == 155 && input.peek() == std::char_traits<char>::eof(), "exact ROM width");
    const auto preserved = original;
    constexpr std::uintptr_t base = 0x140000000ull;
    constexpr std::uintptr_t hook = 0x7ff612340000ull;
    plan::Plan result{};
    check(plan::prepare(original.data(), original.size(), base, 0x2600000u, hook, true, result)
        == plan::Status::prepared, "valid copied leaf plan");
    const std::array<unsigned char, 17> expected{{
        0x45,0x33,0xc9,0x66,0xc7,0x44,0x24,0x08,0x2d,0x2d,
        0x4c,0x89,0x09,0x4c,0x89,0x49,0x10}};
    check(!std::memcmp(result.image.data(), expected.data(), expected.size()), "whole original instructions copied");
    check(target(result.image.data()+17) == base+0x1af6b1u, "absolute continuation address");
    check(target(result.patch.data()) == hook, "absolute hook address");
    check(result.patch[0] == 0xff && result.patch[1] == 0x25, "RIP indirect jump encoding");
    check(result.patch[14] == 0x90 && result.patch[15] == 0x90 && result.patch[16] == 0x90, "whole prefix patched");
    check(result.image_bytes == 68 && result.patch_bytes == 17, "bounded image sizes");
    check(result.runtime.begin == 0 && result.runtime.end == 31 && result.runtime.unwind == 64, "runtime range");
    check(result.image[64] == 1 && !result.image[65] && !result.image[66] && !result.image[67], "leaf UNWIND_INFO");
    check(original == preserved, "source code was never modified");

    // This only interprets owned unwind metadata against an owned fake stack.
    // It does not execute the copied native bytes or register/patch anything.
    std::array<DWORD64, 8> fake_stack{};
    fake_stack[2] = 0x1122334455667788ull;
    const auto image_base = reinterpret_cast<DWORD64>(result.image.data());
    RUNTIME_FUNCTION function{0u, 31u, 64u};
    for (DWORD64 offset : {0ull, 3ull, 10ull, 13ull, 16ull, 17ull, 30ull}) {
        CONTEXT context{};
        context.ContextFlags = CONTEXT_FULL;
        context.Rip = image_base + offset;
        context.Rsp = reinterpret_cast<DWORD64>(&fake_stack[2]);
        context.Rbx = 0x1234;
        context.Rbp = 0x5678;
        PVOID handler_data{};
        DWORD64 establisher{};
        RtlVirtualUnwind(UNW_FLAG_NHANDLER, image_base, context.Rip, &function,
                        &context, &handler_data, &establisher, nullptr);
        check(context.Rip == fake_stack[2] && context.Rsp == reinterpret_cast<DWORD64>(&fake_stack[3]), "leaf unwind restores caller");
        check(context.Rbx == 0x1234 && context.Rbp == 0x5678, "leaf unwind preserves nonvolatile GPR");
    }
    auto changed = original;
    changed.back() ^= 1;
    check(plan::prepare(changed.data(), changed.size(), base, 0x2600000u, hook, true, result)
        == plan::Status::code_mismatch && cleared(result), "tail change refused, not just prefix checked");
    check(plan::prepare(original.data(), original.size(), base, 0x2600000u, hook, false, result)
        == plan::Status::unexpected_original_unwind && cleared(result), "unexpected source unwind refused");
    check(plan::prepare(original.data(), 154, base, 0x2600000u, hook, true, result)
        == plan::Status::invalid_input && cleared(result), "short code refused");
    check(plan::prepare(original.data(), original.size(), base+1, 0x2600000u, hook, true, result)
        == plan::Status::invalid_address && cleared(result), "unaligned base refused");
    check(plan::prepare(original.data(), original.size(), base, 0x2600000u, base+0x1af6a1u, true, result)
        == plan::Status::invalid_address && cleared(result), "hook into own prefix refused");
    check(plan::prepare(original.data(), original.size(), UINTPTR_MAX-20, 0x2600000u, hook, true, result)
        == plan::Status::invalid_address && cleared(result), "overflow refused");
    result.image.fill(0x5a);
    std::array<unsigned char, sizeof(result)> before{};
    std::memcpy(before.data(), &result, before.size());
    check(plan::prepare(result.image.data(), 155, base, 0x2600000u, hook, true, result)
        == plan::Status::input_output_alias, "input output alias refused");
    check(!std::memcmp(before.data(), &result, before.size()), "alias rejection cannot overwrite input");
    std::printf("name-handoff entry plan checks=%u; game_calls=0; copied_native_execution=0; patches=0\n", checks);
}
