#define INFORMATION_BATTLE_TEMPLATE 1
#define INFORMATION_BATTLE_NAVAL 1
#define INFORMATION_BATTLE_WAR_IDENTITY 1
#define INFORMATION_BATTLE_NATIVE_TEXT 1

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

// The production include normally obtains this registry callback from the
// observer translation unit.  This fixture supplies the same value-only ABI;
// the fixed code guards intentionally make the synthetic war binding absent.
static bool observation_register_battle_war(std::uintptr_t, char* output,
                                            std::size_t capacity) noexcept {
    if (output == nullptr || capacity < 30u) return false;
    const char id[] = "war_0123456789abcdef_01234567";
    if (std::strlen(id) != 29u) return false;
    std::memcpy(output, id, sizeof(id));
    return true;
}

// The observer's v29 capture path passes the process creation value to the
// existing war-binding seam.  The production translation unit owns this
// variable; the private context fixture supplies it explicitly.
std::uint64_t observation_creation = 0u;

#define main legacy_context_fixture_main
#include "../test-information-battle-observer-context.cpp"
#undef main

// This fixture drives the actual v29 message callback and observer flush in a
// private process.  It does not call EU4, install a DLL, or construct a v6
// frame directly; the observer's v5->v6 path produces every FRAME_HEX value.
namespace {

namespace native_owned = information::battle::owned_native_text;
namespace template_owned = information::battle::owned_template;

constexpr std::size_t kMessageOffset = 0x190000u;
constexpr std::size_t kDefinitionOffset = 0x194000u;
constexpr std::size_t kMessageNodeAOffset = 0x191000u;
constexpr std::size_t kMessageNodeBOffset = 0x192000u;
constexpr std::size_t kMessageManagerOffset = 0x193000u;
constexpr std::size_t kLandMessageWrapperOffset = 0x2366e0u;
constexpr std::size_t kNavalMessageWrapperOffset = 0x2329b0u;
constexpr std::size_t kLandFormatterFrameOffset = 0x2700000u;
constexpr std::size_t kNavalFormatterFrameOffset = 0x2710000u;
// The real observer checks the original return address against the fixed
// land callsite base+8c9f82.  This private wrapper places its `call rax` at
// offset 0x30 so the returned PC is exactly that value.
constexpr std::size_t kLine1WrapperOffset = 0x8c9f50u;
constexpr std::size_t kLine1WidgetOffset = 0x1a0000u;
constexpr std::size_t kLine1TextOffset = 0x1a1000u;
constexpr std::size_t kLine1ConflictTextOffset = 0x1a5000u;
constexpr std::size_t kLine1FormatterFrameOffset = 0x1a2000u;
constexpr std::size_t kLine1PopupOffset = 0x1a3000u;
constexpr std::size_t kLine1WrongPopupOffset = 0x1a4000u;
constexpr std::uintptr_t kLandReturnRva = 0x236721u;
constexpr std::uintptr_t kNavalReturnRva = 0x232a13u;
constexpr std::uintptr_t kLandFormatterCallerRva = 0x23a446u;
constexpr std::uintptr_t kNavalFormatterCallerRva = 0x23a42au;
constexpr std::uintptr_t kKnownRouterReturnRva = 0x23a40du;
constexpr std::uintptr_t kMessageCallbackRva = 0x2ec0a0u;

using MessageCaller = void (*)(void*, void*, void*, void*);
using Line1Caller = void (*)(void*, void*, unsigned char);

enum class Case : unsigned {
    valid,
    wrong_owner,
    wrong_date,
    duplicate,
    conflict,
    wrong_parent,
    wrong_popup,
    no_scope,
};

std::uintptr_t g_message = 0;
std::uintptr_t g_message_node_a = 0;
std::uintptr_t g_message_node_b = 0;
std::uintptr_t g_message_manager = 0;
std::uintptr_t g_definition = 0;
std::uintptr_t g_line1_formatter_frame = 0;
std::uintptr_t g_line1_popup = 0;
std::uintptr_t g_line1_wrong_popup = 0;
Case g_case = Case::valid;
unsigned g_router_original_calls = 0;
unsigned g_message_original_calls = 0;
unsigned g_line1_original_calls = 0;
unsigned g_line1_native_calls = 0;
bool g_conflict_line1_invalid = false;
unsigned g_conflict_binding_rejected = 0u;
RUNTIME_FUNCTION* g_private_function_rows = nullptr;
bool g_private_function_table_registered = false;

void write_u32(unsigned char* destination, std::uint32_t value) noexcept {
    std::memcpy(destination, &value, sizeof(value));
}

void set_message_node(std::uintptr_t node_address, std::uintptr_t next,
                      const char* key, const char* value) noexcept {
    unsigned char* node = reinterpret_cast<unsigned char*>(node_address);
    std::memset(node, 0, template_owned::kNodeBytes);
    set_inline_string(node + template_owned::kKeyOffset, key, std::strlen(key));
    set_inline_string(node + template_owned::kValueOffset, value,
                      std::strlen(value));
    write_u64(node + template_owned::kNodeNextOffset, next);
}

void set_template_message(std::int32_t date = static_cast<std::int32_t>(kDate))
    noexcept {
    unsigned char* message = reinterpret_cast<unsigned char*>(g_message);
    std::memset(message, 0, template_owned::kMessageHeaderBytes);
    write_u64(message + native_owned::kMessageDefinitionPointerOffset,
              g_definition);
    write_u64(message + template_owned::kContainerHeadOffset, g_message_node_a);
    write_u64(message + template_owned::kContainerTailOffset, g_message_node_b);
    write_u32(message + template_owned::kContainerRawWord20Offset, 0xa1b2c3d4u);
    message[template_owned::kContainerRawFlag24Offset] = 0x5au;
    set_inline_string(message + template_owned::kAuxiliaryTextOffset, "AUX", 3u);
    write_i32(message + template_owned::kNativeDateOffset, date);
    message[template_owned::kRawFlag8COffset] = 0x11u;
    message[template_owned::kRawFlag8DOffset] = 0x22u;
    set_message_node(g_message_node_a, g_message_node_b, "KEY_ONE", "VALUE_ONE");
    set_message_node(g_message_node_b, 0u, "KEY_TWO", "VALUE_TWO");
    set_inline_string(reinterpret_cast<unsigned char*>(g_definition)
                          + native_owned::kDefinitionKeyOffset,
                      "LANDBATTLEOVER", 14u);
}

void initialize_line1_objects() noexcept {
    // The real capture validates both the formatter frame and the popup
    // message copy before it reads the Line1 SSO string.  Keep all of these
    // objects in the private committed region; no native pointer escapes the
    // fixture process.
    std::memset(reinterpret_cast<void*>(g_line1_formatter_frame), 0, 0x1000u);
    std::memset(reinterpret_cast<void*>(g_line1_popup), 0, 0x400u);
    std::memset(reinterpret_cast<void*>(g_line1_wrong_popup), 0, 0x400u);
    std::memcpy(reinterpret_cast<void*>(g_line1_popup + 0x1c0u),
                reinterpret_cast<const void*>(g_message),
                template_owned::kMessageHeaderBytes);
    std::memcpy(reinterpret_cast<void*>(g_line1_wrong_popup + 0x1c0u),
                reinterpret_cast<const void*>(g_message),
                template_owned::kMessageHeaderBytes);
    set_inline_string(reinterpret_cast<unsigned char*>(base + kLine1TextOffset),
                      "LINE1", 5u);
    set_inline_string(
        reinterpret_cast<unsigned char*>(base + kLine1ConflictTextOffset),
        "OTHER", 5u);
    write_u64(reinterpret_cast<unsigned char*>(g_line1_formatter_frame) + 0xad8u,
              base + 0x8c2059u);
    write_u64(reinterpret_cast<unsigned char*>(g_line1_formatter_frame) + 0xae0u,
              g_line1_popup);
}

std::uintptr_t formatter_frame_for(bool land) noexcept {
    return base + (land ? kLandFormatterFrameOffset : kNavalFormatterFrameOffset);
}

void initialize_formatter_frames() noexcept {
    const std::uintptr_t land = formatter_frame_for(true);
    const std::uintptr_t naval = formatter_frame_for(false);
    std::memset(reinterpret_cast<void*>(land), 0, 0x200u);
    std::memset(reinterpret_cast<void*>(naval), 0, 0x200u);
    write_u64(reinterpret_cast<unsigned char*>(land) + 0x1b8u, g_combat);
    write_u64(reinterpret_cast<unsigned char*>(land) + 0x1d8u,
              base + kLandFormatterCallerRva);
    write_u64(reinterpret_cast<unsigned char*>(naval) + 0x178u, g_combat);
    write_u64(reinterpret_cast<unsigned char*>(naval) + 0x198u,
              base + kNavalFormatterCallerRva);
}

void build_message_call_site(std::size_t wrapper_offset,
                             std::uintptr_t return_rva) noexcept {
    unsigned char* destination = g_region + wrapper_offset;
    std::memset(destination, 0x90, 0x100u);
    const bool land = return_rva == kLandReturnRva;
    const std::uintptr_t formatter_frame = formatter_frame_for(land);
    std::size_t cursor = 0u;
    const unsigned char prologue[] = {0x55u, 0x48u, 0xbdu};
    std::memcpy(destination + cursor, prologue, sizeof(prologue));
    cursor += sizeof(prologue);
    std::memcpy(destination + cursor, &formatter_frame, sizeof(formatter_frame));
    cursor += sizeof(formatter_frame);
    const unsigned char shadow_space[] = {0x48u, 0x83u, 0xecu, 0x20u, 0x48u, 0xb8u};
    std::memcpy(destination + cursor, shadow_space, sizeof(shadow_space));
    cursor += sizeof(shadow_space);
    const std::uintptr_t hook = reinterpret_cast<std::uintptr_t>(
        &information_battle_message_hook);
    std::memcpy(destination + cursor, &hook, sizeof(hook));
    cursor += sizeof(hook);
    const std::uintptr_t call_rva = return_rva - 2u;
    const std::size_t call_offset = static_cast<std::size_t>(call_rva)
        - wrapper_offset;
    check(cursor < call_offset, "message_wrapper_call_offset_ordered");
    while (cursor < call_offset) destination[cursor++] = 0x90u;
    destination[cursor++] = 0xffu;
    destination[cursor++] = 0xd0u;
    const unsigned char epilogue[] = {0x48u, 0x83u, 0xc4u, 0x20u, 0x5du, 0xc3u};
    std::memcpy(destination + cursor, epilogue, sizeof(epilogue));
    cursor += sizeof(epilogue);
    check(base + wrapper_offset + call_offset + 2u == base + return_rva,
          "message_wrapper_exact_return_pc");
    check(cursor <= 0x100u, "message_wrapper_bounded");
    DWORD old = 0u;
    const std::uintptr_t page = (base + wrapper_offset) & ~UINT64_C(0xfff);
    check(VirtualProtect(reinterpret_cast<void*>(page), 0x1000u,
                         PAGE_EXECUTE_READ, &old) != FALSE,
          "message_wrapper_rx");
    check(FlushInstructionCache(GetCurrentProcess(),
                                reinterpret_cast<void*>(page), 0x1000u)
              != FALSE,
          "message_wrapper_icache_flush");
}

void initialize_message_entry_bytes() noexcept {
    for (unsigned index = 0u; index != source::kMessageEntryCount; ++index) {
        const auto kind = static_cast<information::battle::message_entry::EntryKind>(index);
        const auto& spec = information::battle::message_entry::spec(kind);
        std::memcpy(g_region + spec.rva, spec.prefix.data(), spec.prefix_bytes);
        std::memcpy(g_region + spec.unwind_rva, spec.unwind_expected.data(),
                    spec.unwind_bytes);
    }
}

extern "C" void fixture_line1_native(void*, void*, unsigned char) noexcept {
    // The original continuation is intentionally a value-only seam.  This
    // proves that the real Line1 hook/trampoline is reached without assigning
    // native text semantics to it.
    ++g_line1_native_calls;
    ++g_line1_original_calls;
}

void initialize_line1_entry_bytes() noexcept {
    const auto& spec = information::battle::line1_entry::spec();
    std::memset(g_region + spec.entry_rva, 0x90u,
                spec.function_end_rva - spec.entry_rva);
    std::memcpy(g_region + spec.entry_rva, spec.prefix.data(),
                spec.prefix_bytes);
    std::memcpy(g_region + spec.unwind_rva, spec.unwind_expected.data(),
                spec.unwind_bytes);
    // Keep the exact fixed row at the private .pdata anchor.  Additional
    // rows are appended by register_private_function_table below.
    std::memcpy(g_region + spec.pdata_rva, spec.pdata_row.data(),
                spec.pdata_row.size());

    unsigned char* continuation = g_region + spec.continuation_rva;
    std::size_t cursor = 0u;
    continuation[cursor++] = 0x48u;
    continuation[cursor++] = 0xb8u;
    const std::uintptr_t native = reinterpret_cast<std::uintptr_t>(
        &fixture_line1_native);
    std::memcpy(continuation + cursor, &native, sizeof(native));
    cursor += sizeof(native);
    continuation[cursor++] = 0xffu;
    continuation[cursor++] = 0xd0u;
    const unsigned char epilogue[] = {
        0x48u, 0x83u, 0xc4u, 0x20u,  // release the fixed prologue frame
        0x5fu,                         // pop rdi
        0xc3u,                         // return to the private caller
    };
    std::memcpy(continuation + cursor, epilogue, sizeof(epilogue));
    cursor += sizeof(epilogue);
    check(cursor <= spec.function_end_rva - spec.continuation_rva,
          "line1_continuation_fits_fixed_function");
}

void register_private_function_table() noexcept {
    const auto& line1 = information::battle::line1_entry::spec();
    const auto& router = information::battle::message_entry::spec(
        information::battle::message_entry::EntryKind::router);
    const auto& message = information::battle::message_entry::spec(
        information::battle::message_entry::EntryKind::message);
    // Rows are strictly sorted by BeginAddress, as required by the dynamic
    // PE function-table API.  The first row is the exact fixed Line1 .pdata
    // row; the following rows cover the scoped source/message entries.
    RUNTIME_FUNCTION rows[4]{};
    rows[0] = {line1.entry_rva, line1.function_end_rva, line1.unwind_rva};
    rows[1] = {static_cast<DWORD>(source::kEntryRva), 0x23a015u,
               static_cast<DWORD>(source::kUnwindRva)};
    rows[2] = {router.rva, router.end_rva, router.unwind_rva};
    rows[3] = {message.rva, message.end_rva, message.unwind_rva};
    g_private_function_rows = reinterpret_cast<RUNTIME_FUNCTION*>(
        g_region + line1.pdata_rva);
    std::memcpy(g_private_function_rows, rows, sizeof(rows));
    check(std::memcmp(g_private_function_rows, line1.pdata_row.data(),
                      line1.pdata_row.size()) == 0,
          "line1_private_pdata_row_exact");
    g_private_function_table_registered = RtlAddFunctionTable(
        g_private_function_rows, 4u, static_cast<DWORD64>(base)) != FALSE;
    check(g_private_function_table_registered,
          "line1_private_pdata_table_registered");
    if (!g_private_function_table_registered) return;

    source::source_row_address = reinterpret_cast<std::uintptr_t>(
        &g_private_function_rows[1]);
    source::message_entries[0].source_row = reinterpret_cast<std::uintptr_t>(
        &g_private_function_rows[2]);
    source::message_entries[1].source_row = reinterpret_cast<std::uintptr_t>(
        &g_private_function_rows[3]);
    source::line1_entry.source_row = reinterpret_cast<std::uintptr_t>(
        &g_private_function_rows[0]);
}

void protect_line1_entry_pages() noexcept {
    const auto& spec = information::battle::line1_entry::spec();
    DWORD old = 0u;
    check(VirtualProtect(reinterpret_cast<void*>(
                             (base + spec.entry_rva) & ~UINT64_C(0xfff)),
                         0x1000u, PAGE_EXECUTE_READ, &old) != FALSE,
          "line1_entry_fixture_rx");
    check(VirtualProtect(reinterpret_cast<void*>(
                             (base + spec.unwind_rva) & ~UINT64_C(0xfff)),
                         0x1000u, PAGE_READONLY, &old) != FALSE,
          "line1_unwind_fixture_readonly");
    check(VirtualProtect(reinterpret_cast<void*>(
                             (base + spec.pdata_rva) & ~UINT64_C(0xfff)),
                         0x1000u, PAGE_READONLY, &old) != FALSE,
          "line1_pdata_fixture_readonly");
}

void build_line1_call_site() noexcept {
    unsigned char* destination = g_region + kLine1WrapperOffset;
    std::memset(destination, 0x90, 0x100u);
    std::size_t cursor = 0u;
    destination[cursor++] = 0x55u;  // preserve the C++ caller's RBP
    destination[cursor++] = 0x48u;
    destination[cursor++] = 0xbdu;  // RBP = the validated formatter frame
    std::memcpy(destination + cursor, &g_line1_formatter_frame,
                sizeof(g_line1_formatter_frame));
    cursor += sizeof(g_line1_formatter_frame);
    const unsigned char setup[] = {
        0x48u, 0x83u, 0xecu, 0x20u,              // shadow/local space
        0x4cu, 0x89u, 0xe8u,                    // mov rax,r13
        0x48u, 0x89u, 0x44u, 0x24u, 0x18u,      // save caller R13
        0x49u, 0xbdu,                            // mov r13,popup
    };
    std::memcpy(destination + cursor, setup, sizeof(setup));
    cursor += sizeof(setup);
    std::memcpy(destination + cursor, &g_line1_popup,
                sizeof(g_line1_popup));
    cursor += sizeof(g_line1_popup);
    destination[cursor++] = 0x48u;
    destination[cursor++] = 0xb8u;              // mov rax,line1 entry
    const std::uintptr_t target = base
        + information::battle::line1_entry::spec().entry_rva;
    std::memcpy(destination + cursor, &target, sizeof(target));
    cursor += sizeof(target);
    constexpr std::size_t kCallOffset = 0x30u;
    check(cursor <= kCallOffset, "line1_wrapper_call_offset_layout");
    while (cursor < kCallOffset) destination[cursor++] = 0x90u;
    destination[cursor++] = 0xffu;
    destination[cursor++] = 0xd0u;
    const unsigned char epilogue[] = {
        0x4cu, 0x8bu, 0x6cu, 0x24u, 0x18u,      // restore caller R13
        0x48u, 0x83u, 0xc4u, 0x20u,
        0x5du, 0xc3u,
    };
    std::memcpy(destination + cursor, epilogue, sizeof(epilogue));
    cursor += sizeof(epilogue);
    check(base + kLine1WrapperOffset + kCallOffset + 2u
              == base + 0x8c9f82u,
          "line1_wrapper_exact_return_pc");
    check(cursor <= 0x100u, "line1_wrapper_bounded");
    DWORD old = 0u;
    check(VirtualProtect(destination, 0x1000u, PAGE_EXECUTE_READ, &old)
              != FALSE,
          "line1_wrapper_rx");
    check(FlushInstructionCache(GetCurrentProcess(), destination, 0x100u)
              != FALSE,
          "line1_wrapper_icache_flushed");
}

void call_line1_site(std::uintptr_t text_address) noexcept {
    const Line1Caller target = reinterpret_cast<Line1Caller>(
        g_region + kLine1WrapperOffset);
    target(reinterpret_cast<void*>(g_region + kLine1WidgetOffset),
           reinterpret_cast<void*>(text_address), 0u);
}

void protect_message_entry_pages() noexcept {
    for (unsigned index = 1u; index != source::kMessageEntryCount; ++index) {
        const auto kind = static_cast<information::battle::message_entry::EntryKind>(index);
        const auto& spec = information::battle::message_entry::spec(kind);
        const std::uintptr_t page = (base + spec.rva) & ~UINT64_C(0xfff);
        DWORD old = 0u;
        check(VirtualProtect(reinterpret_cast<void*>(page), 0x1000u,
                             PAGE_EXECUTE_READ, &old) != FALSE,
              "message_entry_fixture_rx");
        check(FlushInstructionCache(GetCurrentProcess(),
                                    reinterpret_cast<void*>(page), 0x1000u)
                  != FALSE,
              "message_entry_fixture_icache_flush");
    }
}

void call_message_site() noexcept {
    const MessageCaller target = reinterpret_cast<MessageCaller>(
        g_region + kLandMessageWrapperOffset);
    target(reinterpret_cast<void*>(g_message_manager),
           reinterpret_cast<void*>(g_message), nullptr,
           reinterpret_cast<void*>(base + kMessageCallbackRva));
}

extern "C" void fixture_message_original(void*, void*, void*, void*) noexcept {
    ++g_message_original_calls;
}

extern "C" void fixture_router_original(void* combat, unsigned direction) noexcept {
    (void)direction;
    ++g_router_original_calls;
    information_battle_entry_capture(
        combat, reinterpret_cast<void*>(g_summary), reinterpret_cast<void*>(g_result),
        reinterpret_cast<void*>(base + kKnownRouterReturnRva), g_war);
    if (g_case == Case::wrong_owner) {
        write_u64(reinterpret_cast<unsigned char*>(formatter_frame_for(true)) + 0x1b8u,
                  g_result);
    }
    call_message_site();
    if (g_case == Case::duplicate) call_message_site();
    if (g_case == Case::wrong_parent) {
        write_u64(reinterpret_cast<unsigned char*>(g_line1_formatter_frame) + 0xad8u,
                  base + 0x8c205au);
    } else if (g_case == Case::wrong_popup) {
        write_u64(reinterpret_cast<unsigned char*>(g_line1_formatter_frame) + 0xae0u,
                  g_line1_wrong_popup);
    }
    if (g_case == Case::conflict) {
        const auto rejected_before = source::line1_binding_rejected.load();
        call_line1_site(base + kLine1TextOffset);
        call_line1_site(base + kLine1ConflictTextOffset);
        // A later copy of the original text must not revive a field that was
        // invalidated by the conflicting source value.
        call_line1_site(base + kLine1TextOffset);
        g_conflict_binding_rejected = static_cast<unsigned>(
            source::line1_binding_rejected.load() - rejected_before);
    } else if (g_case != Case::no_scope) {
        call_line1_site(base + kLine1TextOffset);
    }
}

void reset_case(Case selected, std::int32_t date) noexcept {
    g_case = selected;
    initialize_observed_objects();
    initialize_context_objects(1u, true);
    initialize_formatter_frames();
    set_template_message(date);
    initialize_line1_objects();
    source::encoded_bytes = 0u;
    source::fragment_index = 0u;
}

void emit_frame(const char* name) noexcept {
    source::encoded_bytes = 0u;
    source::flush();
    check(source::encoded_bytes != 0u, "observer_flush_writes_v6");
    std::printf("FRAME_HEX %s ", name);
    for (std::size_t index = 0u; index < source::encoded_bytes; ++index)
        std::printf("%02x", static_cast<unsigned>(source::encoded[index]));
    std::printf("\n");
}

void run_case(Case selected, const char* name, std::int32_t date) noexcept {
    reset_case(selected, date);
    if (selected == Case::no_scope) call_line1_site(base + kLine1TextOffset);
    const unsigned before = g_message_original_calls;
    information_battle_router_hook(reinterpret_cast<void*>(g_combat), 7u);
    check(g_message_original_calls == before + (selected == Case::duplicate ? 2u : 1u),
          "message_original_called_for_each_callback");
    check(source::count == 1u && source::scope_depth == 0u,
          "base_record_survives_message_guard");
    if (selected == Case::conflict) {
        g_conflict_line1_invalid = source::count == 1u
            && source::slots[source::head].line1_invalid;
        check(g_conflict_line1_invalid,
              "conflicting_line1_latches_record_invalid");
    }
    emit_frame(name);
}

bool prepare_manager() noexcept {
    self_module = GetModuleHandleW(nullptr);
    std::uint64_t creation = 0u;
    if (!self_module || !process_creation(creation) || !make_directory_and_paths()) return false;
    g_region = static_cast<unsigned char*>(VirtualAlloc(
        nullptr, kRegionBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!g_region) return false;
    base = reinterpret_cast<std::uintptr_t>(g_region);
    g_message = reinterpret_cast<std::uintptr_t>(g_region + kMessageOffset);
    g_message_node_a = reinterpret_cast<std::uintptr_t>(g_region + kMessageNodeAOffset);
    g_message_node_b = reinterpret_cast<std::uintptr_t>(g_region + kMessageNodeBOffset);
    g_message_manager = reinterpret_cast<std::uintptr_t>(g_region + kMessageManagerOffset);
    g_definition = reinterpret_cast<std::uintptr_t>(g_region + kDefinitionOffset);
    g_line1_formatter_frame = reinterpret_cast<std::uintptr_t>(
        g_region + kLine1FormatterFrameOffset);
    g_line1_popup = reinterpret_cast<std::uintptr_t>(
        g_region + kLine1PopupOffset);
    g_line1_wrong_popup = reinterpret_cast<std::uintptr_t>(
        g_region + kLine1WrongPopupOffset);
    g_source_code = g_region + source::kEntryRva;
    initialize_context();
    initialize_observed_objects();
    initialize_context_objects();
    initialize_formatter_frames();
    build_source_body(g_source_code);
    initialize_message_entry_bytes();
    initialize_line1_entry_bytes();
    protect_message_entry_pages();
    build_caller_wrappers();
    register_private_function_table();
    protect_line1_entry_pages();
    build_line1_call_site();
    std::memset(g_region + source::kUnwindRva, 0, entry::kOriginalUnwind.size());
    std::memcpy(g_region + source::kUnwindRva, entry::kOriginalUnwind.data(),
                entry::kOriginalUnwind.size());
    if (!protect_source()) return false;
    build_message_call_site(kLandMessageWrapperOffset, kLandReturnRva);
    build_message_call_site(kNavalMessageWrapperOffset, kNavalReturnRva);
    set_template_message();
    initialize_line1_objects();

    const bool startup = information_battle_start(g_fixture_directory.data(), creation);
    check(!startup && source::state.load() == source::fault,
          "native_text_fixture_startup_hash_guard_rejects_private_exe");
    check(source::exe_lease == INVALID_HANDLE_VALUE
              && source::dll_lease == INVALID_HANDLE_VALUE,
          "native_text_fixture_startup_leases_closed");
    frame_thread = GetCurrentThreadId();
    source::identity = {kInstallation, creation};
    source::creation = creation;
    observation_creation = creation;
    source::game_image_size = kRegionBytes;
    source::game = g_game;
    source::player = kPlayer;
    source::bound_thread = frame_thread;
    source::last_date = static_cast<std::int32_t>(kDate);
    source::state.store(source::ready, std::memory_order_release);
    if (!source::drain.reset(source::identity).succeeded()) return false;
    wchar_t log_path[MAX_PATH]{};
    if (swprintf(log_path, MAX_PATH, L"%ls\\native-text-observer.jsonl",
                 g_fixture_directory.data()) <= 0) return false;
    std::memcpy(source::log_path, log_path, sizeof(log_path));
    if (!source::writer.open(source::log_path, source::identity)) return false;
    if (!source::code_guard() || !source::install()) return false;
    source::state.store(source::enabled, std::memory_order_release);
    information_battle_router_original = reinterpret_cast<void*>(&fixture_router_original);
    information_battle_message_original = reinterpret_cast<void*>(&fixture_message_original);
    return source::patched && source::table_registered
        && source::message_entries[1].trampoline
        && source::line1_entry.patched
        && source::line1_entry.source_row != 0u;
}

}  // namespace

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("TEST information-battle-native-text-observer\n");
    (void)&legacy_context_fixture_main;
    (void)&bridge_entry_patch::guarded_patch_rollback;
    (void)&information_battle_tick;
    if (!prepare_manager()) {
        std::printf("RESULT FAIL prepare_manager\n");
        return 1;
    }
    run_case(Case::valid, "valid_0", static_cast<std::int32_t>(kDate));
    run_case(Case::wrong_owner, "wrong_owner_0", static_cast<std::int32_t>(kDate));
    run_case(Case::wrong_date, "wrong_date_0", static_cast<std::int32_t>(kDate - 1u));
    run_case(Case::duplicate, "duplicate_0", static_cast<std::int32_t>(kDate));
    run_case(Case::conflict, "conflict_0", static_cast<std::int32_t>(kDate));
    run_case(Case::wrong_parent, "wrong_parent_0", static_cast<std::int32_t>(kDate));
    run_case(Case::wrong_popup, "wrong_popup_0", static_cast<std::int32_t>(kDate));
    run_case(Case::no_scope, "no_scope_0", static_cast<std::int32_t>(kDate));
    check(source::line1_copied.load() == 2u,
          "line1_real_capture_positive_cases");
    check(source::line1_no_scope.load() >= 1u,
          "line1_real_capture_no_scope_rejected");
    check(source::line1_binding_rejected.load() >= 6u
              && g_conflict_binding_rejected == 1u,
          "line1_real_capture_negative_bindings_rejected");
    check(source::line1_copy_failed.load() == 1u,
          "line1_real_capture_conflict_copy_failure");
    check(g_line1_native_calls == 10u && g_line1_original_calls == 10u,
          "line1_continuation_count_matches_real_calls");
    const bool passed = g_failures == 0u;
    std::printf(
        "RESULT %s\n{\"passed\":%s,\"router_original_calls\":%u,"
        "\"message_original_calls\":%u,\"native_metadata_copied\":%llu,"
        "\"native_metadata_failed\":%llu,\"native_text_invalid\":true,"
        "\"line1_candidates\":%llu,\"line1_no_scope\":%llu,"
        "\"line1_binding_rejected\":%llu,\"line1_copied\":%llu,"
        "\"line1_copy_failed\":%llu,\"line1_original_calls\":%u,"
        "\"line1_native_continuation_calls\":%u,"
        "\"conflict_line1_invalid\":%s,"
        "\"conflict_binding_rejected\":%u,"
        "\"production_modified\":false,\"game_access\":false,"
        "\"fixture_private_initialization\":true}\n",
        passed ? "PASS" : "FAIL", passed ? "true" : "false",
        g_router_original_calls, g_message_original_calls,
        static_cast<unsigned long long>(source::native_metadata_copied.load()),
        static_cast<unsigned long long>(source::native_metadata_failed.load()),
        static_cast<unsigned long long>(source::line1_candidates.load()),
        static_cast<unsigned long long>(source::line1_no_scope.load()),
        static_cast<unsigned long long>(source::line1_binding_rejected.load()),
        static_cast<unsigned long long>(source::line1_copied.load()),
        static_cast<unsigned long long>(source::line1_copy_failed.load()),
        g_line1_original_calls, g_line1_native_calls,
        g_conflict_line1_invalid ? "true" : "false",
        g_conflict_binding_rejected);
    return passed ? 0 : 1;
}
