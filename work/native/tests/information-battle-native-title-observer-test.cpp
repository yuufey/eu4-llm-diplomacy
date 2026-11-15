#define INFORMATION_BATTLE_TEMPLATE 1
#define INFORMATION_BATTLE_NAVAL 1
#define INFORMATION_BATTLE_WAR_IDENTITY 1
#define INFORMATION_BATTLE_NATIVE_TEXT 1
#define INFORMATION_BATTLE_NATIVE_TITLE_QUERY 1

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

// v30 title-helper fixture objects live beside the existing private battle
// objects.  The graph is attached at combat+30, which is unused by the v29
// context reader (its side pointers remain at +20/+28).
constexpr std::size_t kTitleProvinceOffset = 0x1b0000u;
constexpr std::size_t kTitleNameOwnerOffset = 0x1b1000u;
constexpr std::uintptr_t kTitleDestructorRva = 0x95660u;
constexpr std::uintptr_t kTitleLocalizeShimRva = 0x14b33a0u;
constexpr std::uintptr_t kTitleAppendShimRva = 0x932f0u;
constexpr std::uintptr_t kTitleGlobalAppendShimRva = 0x95110u;
constexpr std::uintptr_t kTitleHelperUnwindRva = 0x1de6e3cu;
constexpr std::uintptr_t kTitleDestructorUnwindRva = 0x1dc9790u;
constexpr std::uintptr_t kTitleKindCodeRva = 0x102000u;
constexpr std::size_t kPluginImageBytes =
    information::battle::title_query_plan::kPluginSize;

using TitleString = information::battle::owned_title_query::String32;

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
std::uint32_t g_title_kind = 1u;
bool g_conflict_line1_invalid = false;
unsigned g_conflict_binding_rejected = 0u;
RUNTIME_FUNCTION* g_private_function_rows = nullptr;
bool g_private_function_table_registered = false;
unsigned char* g_plugin_region = nullptr;
std::uintptr_t g_plugin_base = 0u;
RUNTIME_FUNCTION* g_plugin_function_row = nullptr;
bool g_plugin_function_table_registered = false;
bool g_plugin_guard_positive = false;
bool g_plugin_guard_negative = false;
bool g_plugin_guard_restored = false;
bool g_plugin_cleanup = false;
bool g_plugin_callee_executed = false;

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

void set_title_string(std::uintptr_t object, const char* text,
                      std::size_t length) noexcept {
    unsigned char* bytes = reinterpret_cast<unsigned char*>(object);
    std::memset(bytes, 0, sizeof(TitleString));
    if (length > 15u) length = 15u;
    if (length != 0u) std::memcpy(bytes, text, length);
    bytes[length] = 0u;
    write_u64(bytes + 0x10u, static_cast<std::uint64_t>(length));
    // Keep the native inline-capacity convention even for a one-byte global
    // separator; this is the exact shape consumed by the helper's SSO path.
    write_u64(bytes + 0x18u, 15u);
}

extern "C" void fixture_title_localize(TitleString* destination,
                                         const void*, std::uintptr_t,
                                         std::uintptr_t) noexcept {
    if (destination == nullptr) return;
    *destination = TitleString{};
    destination->storage[0] = static_cast<unsigned char>('B');
    destination->size = 1u;
    destination->capacity = 15u;
}

extern "C" void fixture_title_append(TitleString* destination,
                                      const unsigned char* source,
                                      std::uintptr_t length) noexcept {
    if (destination == nullptr) return;
    std::size_t old_length = destination->size <= 15u
        ? static_cast<std::size_t>(destination->size) : 0u;
    std::size_t remaining = 15u - old_length;
    std::size_t count = length < static_cast<std::uintptr_t>(remaining)
        ? static_cast<std::size_t>(length) : remaining;
    if (count != 0u && source != nullptr)
        std::memcpy(destination->storage.data() + old_length, source, count);
    destination->storage[old_length + count] = 0u;
    destination->size = static_cast<std::uint64_t>(old_length + count);
    destination->capacity = 15u;
}

void write_absolute_jump(std::uintptr_t rva, const void* target) noexcept {
    unsigned char* destination = g_region + rva;
    std::memset(destination, 0xcc, 16u);
    destination[0] = 0x48u;
    destination[1] = 0xb8u;
    const auto address = reinterpret_cast<std::uintptr_t>(target);
    std::memcpy(destination + 2u, &address, sizeof(address));
    destination[10] = 0xffu;
    destination[11] = 0xe0u;
}

void write_plugin_detour() noexcept {
    namespace plan = information::battle::title_query_plan;
    std::array<unsigned char, plan::kHelperPluginPatchBytes> patch{};
    patch[0] = 0xffu;
    patch[1] = 0x25u;
    const std::uintptr_t target =
        g_plugin_base + plan::kPluginTargetRva;
    std::memcpy(patch.data() + 6u, &target, sizeof(target));
    std::memcpy(g_region + plan::kHelperRva
                    + plan::kHelperPluginPatchOffset,
                patch.data(), patch.size());
}

bool initialize_plugin_image() noexcept {
    namespace plan = information::battle::title_query_plan;
    g_plugin_region = static_cast<unsigned char*>(VirtualAlloc(
        nullptr, kPluginImageBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (g_plugin_region == nullptr) return false;
    g_plugin_base = reinterpret_cast<std::uintptr_t>(g_plugin_region);
    std::memset(g_plugin_region, 0, kPluginImageBytes);
    std::memcpy(g_plugin_region + plan::kPluginBridgeRva,
                plan::kPluginBridgeBytes.data(), plan::kPluginBridgeBytes.size());
    std::memcpy(g_plugin_region + plan::kPluginHelperRva,
                plan::kPluginHelperBytes.data(), plan::kPluginHelperBytes.size());
    std::memcpy(g_plugin_region + plan::kPluginPdataRva,
                plan::kPluginPdataBytes.data(), plan::kPluginPdataBytes.size());
    std::memcpy(g_plugin_region + plan::kPluginUnwindRva,
                plan::kPluginUnwindBytes.data(), plan::kPluginUnwindBytes.size());
    write_u64(g_plugin_region + plan::kPluginCallSlotRva,
              g_plugin_base + plan::kPluginHelperRva);
    write_u64(g_plugin_region + plan::kPluginReturnSlotRva,
              base + plan::kPluginReturnGameRva);
    g_plugin_function_row = reinterpret_cast<RUNTIME_FUNCTION*>(
        g_plugin_region + plan::kPluginPdataRva);
    g_plugin_function_table_registered = RtlAddFunctionTable(
        g_plugin_function_row, 1u, static_cast<DWORD64>(g_plugin_base)) != FALSE;
    check(g_plugin_function_table_registered,
          "plugin_private_pdata_table_registered");
    if (!g_plugin_function_table_registered) return false;
    source::title_plugin_base = g_plugin_base;
    source::title_plugin_image_size = kPluginImageBytes;
    write_plugin_detour();
    return true;
}

void protect_plugin_image() noexcept {
    namespace plan = information::battle::title_query_plan;
    const std::uintptr_t code_pages[] = {
        g_plugin_base + plan::kPluginBridgeRva,
        g_plugin_base + plan::kPluginHelperRva,
    };
    for (const auto address : code_pages) {
        DWORD old = 0u;
        check(VirtualProtect(reinterpret_cast<void*>(address & ~UINT64_C(0xfff)),
                             0x1000u, PAGE_EXECUTE_READ, &old) != FALSE,
              "plugin_fixture_code_rx");
        check(FlushInstructionCache(GetCurrentProcess(),
                                    reinterpret_cast<void*>(address & ~UINT64_C(0xfff)),
                                    0x1000u) != FALSE,
              "plugin_fixture_code_icache_flush");
    }
    const std::uintptr_t read_only_pages[] = {
        g_plugin_base + plan::kPluginUnwindRva,
        g_plugin_base + plan::kPluginPdataRva,
        g_plugin_base + plan::kPluginCallSlotRva,
    };
    for (const auto address : read_only_pages) {
        DWORD old = 0u;
        check(VirtualProtect(reinterpret_cast<void*>(address & ~UINT64_C(0xfff)),
                             0x1000u, PAGE_READONLY, &old) != FALSE,
              "plugin_fixture_metadata_readonly");
    }
}

bool make_plugin_page_writable(std::uintptr_t address, DWORD& old) noexcept {
    return VirtualProtect(reinterpret_cast<void*>(address & ~UINT64_C(0xfff)),
                          0x1000u, PAGE_READWRITE, &old) != FALSE;
}

void restore_plugin_code_page(std::uintptr_t address) noexcept {
    DWORD old = 0u;
    check(VirtualProtect(reinterpret_cast<void*>(address & ~UINT64_C(0xfff)),
                         0x1000u, PAGE_EXECUTE_READ, &old) != FALSE,
          "plugin_fixture_code_restore_rx");
    check(FlushInstructionCache(GetCurrentProcess(),
                                reinterpret_cast<void*>(address & ~UINT64_C(0xfff)),
                                0x1000u) != FALSE,
          "plugin_fixture_code_restore_icache_flush");
}

void restore_vanilla_title_helper() noexcept {
    namespace plan = information::battle::title_query_plan;
    const std::uintptr_t page =
        (base + plan::kHelperRva) & ~UINT64_C(0xfff);
    DWORD old = 0u;
    check(VirtualProtect(reinterpret_cast<void*>(page), 0x1000u,
                         PAGE_READWRITE, &old) != FALSE,
          "plugin_fixture_restore_helper_rw");
    std::memcpy(g_region + plan::kHelperRva, plan::kHelperBytes.data(),
                plan::kHelperBytes.size());
    g_region[plan::kHelperEndRva - 1u] = 0xccu;
    check(FlushInstructionCache(GetCurrentProcess(),
                                reinterpret_cast<void*>(page), 0x1000u)
              != FALSE,
          "plugin_fixture_restore_helper_icache_flush");
    check(VirtualProtect(reinterpret_cast<void*>(page), 0x1000u,
                         PAGE_EXECUTE_READ, &old) != FALSE,
          "plugin_fixture_restore_helper_rx");
}

void release_plugin_image() noexcept {
    if (g_plugin_function_table_registered) {
        check(RtlDeleteFunctionTable(g_plugin_function_row) != FALSE,
              "plugin_private_pdata_table_deleted");
        g_plugin_function_table_registered = false;
    }
    source::title_plugin_base = 0u;
    source::title_plugin_image_size = 0u;
    if (g_plugin_region != nullptr) {
        check(VirtualFree(g_plugin_region, 0u, MEM_RELEASE) != FALSE,
              "plugin_private_image_released");
    }
    g_plugin_region = nullptr;
    g_plugin_base = 0u;
    g_plugin_function_row = nullptr;
    g_plugin_cleanup = true;
}

void run_plugin_guard_checks() noexcept {
    namespace plan = information::battle::title_query_plan;
    check(g_plugin_region != nullptr && g_plugin_base != 0u,
          "plugin_private_image_ready");
    g_plugin_guard_positive = source::title_query_code_guard();
    check(g_plugin_guard_positive, "plugin_title_guard_positive");
    const std::uintptr_t page =
        (g_plugin_base + plan::kPluginBridgeRva) & ~UINT64_C(0xfff);
    DWORD old = 0u;
    check(make_plugin_page_writable(g_plugin_base + plan::kPluginBridgeRva, old),
          "plugin_guard_negative_page_rw");
    const unsigned char saved = g_plugin_region[plan::kPluginBridgeRva];
    g_plugin_region[plan::kPluginBridgeRva] = static_cast<unsigned char>(saved ^ 0x01u);
    check(FlushInstructionCache(GetCurrentProcess(),
                                reinterpret_cast<void*>(page), 0x1000u)
              != FALSE,
          "plugin_guard_negative_icache_flush");
    g_plugin_guard_negative = !source::title_query_code_guard();
    check(g_plugin_guard_negative, "plugin_title_guard_rejects_tamper");
    g_plugin_region[plan::kPluginBridgeRva] = saved;
    restore_plugin_code_page(g_plugin_base + plan::kPluginBridgeRva);
    g_plugin_guard_restored = source::title_query_code_guard();
    check(g_plugin_guard_restored, "plugin_title_guard_restored");
    check(source::title_query_attempted.load() == 0u
              && source::title_query_destroyed.load() == 0u,
          "plugin_guard_does_not_execute_plugin_callee");
}

void initialize_title_code() noexcept {
    namespace plan = information::battle::title_query_plan;
    std::memcpy(g_region + plan::kHelperRva, plan::kHelperBytes.data(),
                plan::kHelperBytes.size());
    // The exact .pdata end is one byte after the selected 515-byte body.
    g_region[plan::kHelperEndRva - 1u] = 0xccu;
    std::memcpy(g_region + plan::kDestructorRva, plan::kDestructorBytes.data(),
                plan::kDestructorBytes.size());

    // These are the complete bounded UNWIND_INFO records from the ordinary
    // PE.  The helper record includes its chained RUNTIME_FUNCTION (32 bytes
    // total); the destructor record has two unwind codes (8 bytes).
    static constexpr unsigned char helper_unwind[] = {
        0x11u,0x1au,0x08u,0x00u,0x1au,0x64u,0x10u,0x00u,
        0x1au,0x34u,0x0eu,0x00u,0x1au,0x92u,0x13u,0xe0u,
        0x11u,0x70u,0x10u,0x50u,0x9cu,0x4du,0xa3u,0x01u,
        0x58u,0x6eu,0xdeu,0x01u,0x28u,0x61u,0x6eu,0xdeu,
    };
    static constexpr unsigned char destructor_unwind[] = {
        0x01u,0x06u,0x02u,0x00u,0x06u,0x32u,0x02u,0x30u,
    };
    std::memcpy(g_region + plan::kHelperUnwindRva, helper_unwind,
                sizeof(helper_unwind));
    std::memcpy(g_region + plan::kDestructorUnwindRva, destructor_unwind,
                sizeof(destructor_unwind));

    // The original helper keeps direct E8 calls and RIP-relative data
    // references.  Installing shims at the original RVAs preserves those
    // exact helper/destructor bytes while making each call local and safe.
    write_absolute_jump(kTitleLocalizeShimRva,
                        reinterpret_cast<const void*>(&fixture_title_localize));
    write_absolute_jump(kTitleAppendShimRva,
                        reinterpret_cast<const void*>(&fixture_title_append));
    write_absolute_jump(kTitleGlobalAppendShimRva,
                        reinterpret_cast<const void*>(&fixture_title_append));
}

void initialize_title_graph() noexcept {
    namespace plan = information::battle::title_query_plan;
    const std::uintptr_t province = base + kTitleProvinceOffset;
    const std::uintptr_t owner = base + kTitleNameOwnerOffset;
    std::memset(reinterpret_cast<void*>(province), 0, 0x1000u);
    std::memset(reinterpret_cast<void*>(owner), 0, 0x1000u);
    write_u64(reinterpret_cast<unsigned char*>(g_combat) + 0x30u, province);
    write_u64(reinterpret_cast<unsigned char*>(province) + 0x28u, owner);
    set_title_string(owner + 0x10u, "Dover", 5u);
    set_title_string(base + plan::kGlobalStringRva, " ", 1u);
    // initialize_context_objects already writes the slot pointer, but repeat
    // it here so the fixture documents the real vtable->slot->code graph.
    DWORD writable_old = 0u;
    check(VirtualProtect(reinterpret_cast<void*>(
                             g_kind_vtable & ~UINT64_C(0xfff)),
                         0x1000u, PAGE_READWRITE, &writable_old) != FALSE,
          "title_kind_slot_rw");
    write_u64(reinterpret_cast<unsigned char*>(g_kind_vtable) + 0x60u,
              base + kTitleKindCodeRva);
    DWORD old = 0u;
    check(VirtualProtect(reinterpret_cast<void*>(
                             (base + kTitleKindCodeRva) & ~UINT64_C(0xfff)),
                         0x1000u, PAGE_EXECUTE_READ, &old) != FALSE,
          "title_kind_selector_rx");
}

void protect_title_code_pages() noexcept {
    const std::uintptr_t code_pages[] = {
        base + information::battle::title_query_plan::kHelperRva,
        base + kTitleDestructorRva,
        base + kTitleLocalizeShimRva,
        base + kTitleAppendShimRva,
    };
    for (const auto address : code_pages) {
        DWORD old = 0u;
        check(VirtualProtect(reinterpret_cast<void*>(address & ~UINT64_C(0xfff)),
                             0x1000u, PAGE_EXECUTE_READ, &old) != FALSE,
              "title_fixture_code_rx");
    }
    const std::uintptr_t unwind_pages[] = {
        base + kTitleHelperUnwindRva, base + kTitleDestructorUnwindRva,
    };
    for (const auto address : unwind_pages) {
        DWORD old = 0u;
        check(VirtualProtect(reinterpret_cast<void*>(address & ~UINT64_C(0xfff)),
                             0x1000u, PAGE_READONLY, &old) != FALSE,
              "title_fixture_unwind_readonly");
    }
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
    // Rows are strictly sorted by BeginAddress.  The v30 helper/destructor
    // rows are in the same image table as the four existing observer rows;
    // this makes RtlLookupFunctionEntry resolve the production code guard
    // without changing any frozen source plan.
    RUNTIME_FUNCTION rows[6]{};
    rows[0] = {static_cast<DWORD>(kTitleDestructorRva),
               static_cast<DWORD>(information::battle::title_query_plan::kDestructorEndRva),
               static_cast<DWORD>(kTitleDestructorUnwindRva)};
    rows[1] = {line1.entry_rva, line1.function_end_rva, line1.unwind_rva};
    rows[2] = {static_cast<DWORD>(source::kEntryRva), 0x23a015u,
               static_cast<DWORD>(source::kUnwindRva)};
    rows[3] = {router.rva, router.end_rva, router.unwind_rva};
    rows[4] = {static_cast<DWORD>(information::battle::title_query_plan::kHelperRva),
               static_cast<DWORD>(information::battle::title_query_plan::kHelperEndRva),
               static_cast<DWORD>(information::battle::title_query_plan::kHelperUnwindRva)};
    rows[5] = {message.rva, message.end_rva, message.unwind_rva};
    g_private_function_rows = reinterpret_cast<RUNTIME_FUNCTION*>(
        g_region + line1.pdata_rva);
    std::memcpy(g_private_function_rows, rows, sizeof(rows));
    check(std::memcmp(&g_private_function_rows[1], line1.pdata_row.data(),
                      line1.pdata_row.size()) == 0,
          "line1_private_pdata_row_exact");
    g_private_function_table_registered = RtlAddFunctionTable(
        g_private_function_rows, 6u, static_cast<DWORD64>(base)) != FALSE;
    check(g_private_function_table_registered,
          "line1_private_pdata_table_registered");
    if (!g_private_function_table_registered) return;

    source::source_row_address = reinterpret_cast<std::uintptr_t>(
        &g_private_function_rows[2]);
    source::message_entries[0].source_row = reinterpret_cast<std::uintptr_t>(
        &g_private_function_rows[3]);
    source::message_entries[1].source_row = reinterpret_cast<std::uintptr_t>(
        &g_private_function_rows[5]);
    source::line1_entry.source_row = reinterpret_cast<std::uintptr_t>(
        &g_private_function_rows[1]);
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
    initialize_context_objects(g_title_kind, true);
    initialize_title_graph();
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
    initialize_title_code();
    if (!initialize_plugin_image()) return false;
    check(g_plugin_region != nullptr && source::title_plugin_base == g_plugin_base
              && source::title_plugin_image_size == kPluginImageBytes,
          "plugin_private_image_initialized");
    protect_message_entry_pages();
    build_caller_wrappers();
    register_private_function_table();
    protect_line1_entry_pages();
    build_line1_call_site();
    std::memset(g_region + source::kUnwindRva, 0, entry::kOriginalUnwind.size());
    std::memcpy(g_region + source::kUnwindRva, entry::kOriginalUnwind.data(),
                entry::kOriginalUnwind.size());
    protect_title_code_pages();
    protect_plugin_image();
    if (!protect_source()) return false;
    build_message_call_site(kLandMessageWrapperOffset, kLandReturnRva);
    build_message_call_site(kNavalMessageWrapperOffset, kNavalReturnRva);
    set_template_message();
    initialize_line1_objects();

    // The plugin path is exercised only through the production code guard.
    // Its indirect callee is deliberately never entered because its
    // transitive string/allocator effects are outside this fixture.
    source::game_image_size = kRegionBytes;
    run_plugin_guard_checks();
    restore_vanilla_title_helper();
    release_plugin_image();
    check(source::title_query_code_guard(),
          "plugin_cleanup_restores_vanilla_title_guard");

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

bool read_heartbeat_diagnostics() noexcept {
    wchar_t path[MAX_PATH]{};
    if (swprintf(path, MAX_PATH, L"%ls\\information-battle-status.json",
                 source::directory) < 0) return false;
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                              nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER size{};
    char bytes[8192]{};
    DWORD actual = 0;
    const bool readable = GetFileSizeEx(file, &size) && size.QuadPart > 0
        && size.QuadPart < static_cast<LONGLONG>(sizeof(bytes))
        && ReadFile(file, bytes, static_cast<DWORD>(size.QuadPart), &actual,
                    nullptr)
        && actual == static_cast<DWORD>(size.QuadPart);
    const bool closed = CloseHandle(file) != FALSE;
    if (!readable || !closed) return false;
    return std::strstr(bytes, "\"status_publication_pending\":false") != nullptr
        && std::strstr(bytes, "\"status_publication_failures\":2") != nullptr
        && std::strstr(bytes, "\"status_write_stage\":\"heartbeat_publication_timeout\"") != nullptr;
}

void run_heartbeat_publication_retry() noexcept {
    source::state.store(source::disabled, std::memory_order_release);
    source::heartbeat_publication_pending = false;
    source::heartbeat_retry_next = 0u;
    source::heartbeat_retry_deadline = 0u;
    source::heartbeat_publication_failures = 0u;
    source::last_status_write_stage = "none";
    source::last_status_write_error = ERROR_SUCCESS;
    check(source::status("", "fixture", true, "observed", false),
          "heartbeat_fixture_status_seeded");

    wchar_t status_path[MAX_PATH]{};
    check(swprintf(status_path, MAX_PATH,
                   L"%ls\\information-battle-status.json", source::directory) > 0,
          "heartbeat_fixture_status_path_built");
    HANDLE held = CreateFileW(status_path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                              nullptr);
    check(held != INVALID_HANDLE_VALUE,
          "heartbeat_fixture_target_held_without_delete_share");
    OVERLAPPED held_lock{};
    const bool locked = held != INVALID_HANDLE_VALUE
        && LockFileEx(held, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                      0, MAXDWORD, MAXDWORD, &held_lock) != FALSE;
    check(locked, "heartbeat_fixture_target_locked");
    const auto last_poll_before = source::last_poll;
    const auto target_failure = source::heartbeat_status(true, "observed", 1000u);
    check(target_failure == source::HeartbeatPublicationResult::retry_pending
              && source::state.load(std::memory_order_acquire) == source::disabled,
          "heartbeat_replace_failure_keeps_disabled_state");
    check(std::strcmp(source::last_status_write_stage, "replace") == 0
              && source::last_status_write_error == ERROR_ACCESS_DENIED,
          "heartbeat_replace_access_denied_records_stage_and_error");
    check(source::heartbeat_publication_pending
              && source::heartbeat_publication_failures == 1u,
          "heartbeat_replace_access_denied_schedules_retry");
    const auto target_throttled = source::heartbeat_status(true, "observed", 1050u);
    check(target_throttled == source::HeartbeatPublicationResult::retry_pending
              && source::heartbeat_publication_failures == 1u,
          "heartbeat_replace_retry_respects_frame_interval");
    const auto target_second = source::heartbeat_status(true, "observed", 1100u);
    check(target_second == source::HeartbeatPublicationResult::retry_pending
              && source::heartbeat_publication_pending
              && source::heartbeat_publication_failures == 2u,
          "heartbeat_replace_retry_remains_bounded_without_control");
    check(source::last_poll == last_poll_before,
          "heartbeat_replace_failure_does_not_poll_control");
    if (held != INVALID_HANDLE_VALUE) {
        if (locked) UnlockFileEx(held, 0, MAXDWORD, MAXDWORD, &held_lock);
        check(CloseHandle(held) != FALSE,
              "heartbeat_fixture_target_release");
        held = INVALID_HANDLE_VALUE;
    }
    const auto target_recovered = source::heartbeat_status(true, "observed", 1200u);
    check(target_recovered == source::HeartbeatPublicationResult::published
              && !source::heartbeat_publication_pending
              && source::state.load(std::memory_order_acquire) == source::disabled,
          "heartbeat_status_recovers_after_target_release");
    check(source::last_poll == last_poll_before,
          "heartbeat_replace_recovery_does_not_poll_control");
    wchar_t temporary_path[MAX_PATH]{};
    check(swprintf(temporary_path, MAX_PATH,
                   L"%ls\\information-battle-status.tmp", source::directory) > 0,
          "heartbeat_fixture_temporary_path_built");
    const DWORD temporary_attributes = GetFileAttributesW(temporary_path);
    if (temporary_attributes != INVALID_FILE_ATTRIBUTES) {
        if ((temporary_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
            RemoveDirectoryW(temporary_path);
        else
            DeleteFileW(temporary_path);
    }
    check(CreateDirectoryW(temporary_path, nullptr) != FALSE,
          "heartbeat_fixture_nonreplace_access_denied_target_created");
    source::heartbeat_publication_pending = false;
    source::heartbeat_retry_next = 0u;
    source::heartbeat_retry_deadline = 0u;
    source::heartbeat_publication_failures = 0u;
    source::last_status_write_stage = "none";
    source::last_status_write_error = ERROR_SUCCESS;
    const auto nonreplace_access_denied = source::heartbeat_status(true, "observed", 1500u);
    check(nonreplace_access_denied == source::HeartbeatPublicationResult::terminal_failure
              && !source::heartbeat_publication_pending
              && source::heartbeat_publication_failures == 1u
              && source::state.load(std::memory_order_acquire) == source::disabled,
          "heartbeat_nonreplace_access_denied_stops");
    check(std::strcmp(source::last_status_write_stage, "open") == 0
              && source::last_status_write_error == ERROR_ACCESS_DENIED,
          "heartbeat_nonreplace_access_denied_records_open_stage");
    check(source::last_poll == last_poll_before,
          "heartbeat_nonreplace_access_denied_does_not_poll_control");
    check(RemoveDirectoryW(temporary_path) != FALSE,
          "heartbeat_fixture_nonreplace_access_denied_target_release");
    HANDLE temporary = CreateFileW(temporary_path, GENERIC_READ | GENERIC_WRITE, 0,
                                   nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                                   nullptr);
    check(temporary != INVALID_HANDLE_VALUE,
          "heartbeat_fixture_temporary_held_without_share");
    source::heartbeat_publication_pending = false;
    source::heartbeat_retry_next = 0u;
    source::heartbeat_retry_deadline = 0u;
    source::heartbeat_publication_failures = 0u;
    source::last_status_write_stage = "none";
    source::last_status_write_error = ERROR_SUCCESS;
    const auto first = source::heartbeat_status(true, "observed", 2000u);
    check(first == source::HeartbeatPublicationResult::retry_pending
              && source::heartbeat_publication_pending
              && source::heartbeat_publication_failures == 1u,
          "heartbeat_transient_failure_schedules_bounded_retry");
    check(std::strcmp(source::last_status_write_stage, "open") == 0
              && (source::last_status_write_error == ERROR_SHARING_VIOLATION
                  || source::last_status_write_error == ERROR_LOCK_VIOLATION),
          "heartbeat_transient_failure_records_stage_and_error");
    const auto throttled = source::heartbeat_status(true, "observed", 2050u);
    check(throttled == source::HeartbeatPublicationResult::retry_pending
              && source::heartbeat_publication_failures == 1u,
          "heartbeat_retry_respects_frame_interval");
    const auto second = source::heartbeat_status(true, "observed", 2100u);
    check(second == source::HeartbeatPublicationResult::retry_pending
              && source::heartbeat_publication_failures == 2u,
          "heartbeat_retry_has_no_control_dispatch");
    check(source::last_poll == last_poll_before,
          "heartbeat_retry_does_not_poll_control");
    if (temporary != INVALID_HANDLE_VALUE) {
        check(CloseHandle(temporary) != FALSE,
              "heartbeat_fixture_temporary_release");
        temporary = INVALID_HANDLE_VALUE;
    }
    const auto recovered = source::heartbeat_status(true, "observed", 2200u);
    check(recovered == source::HeartbeatPublicationResult::published
              && !source::heartbeat_publication_pending
              && source::state.load(std::memory_order_acquire) == source::disabled,
          "heartbeat_retry_recovers_after_temporary_release");
    temporary = CreateFileW(temporary_path, GENERIC_READ | GENERIC_WRITE, 0,
                            nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                            nullptr);
    check(temporary != INVALID_HANDLE_VALUE,
          "heartbeat_fixture_timeout_target_held");
    source::heartbeat_publication_pending = false;
    source::heartbeat_retry_next = 0u;
    source::heartbeat_retry_deadline = 0u;
    source::heartbeat_publication_failures = 0u;
    source::last_status_write_stage = "none";
    source::last_status_write_error = ERROR_SUCCESS;
    const auto timeout_first = source::heartbeat_status(true, "observed", 3000u);
    const auto timeout = source::heartbeat_status(true, "observed", 6000u);
    check(timeout_first == source::HeartbeatPublicationResult::retry_pending
              && timeout == source::HeartbeatPublicationResult::terminal_failure
              && !source::heartbeat_publication_pending
              && source::heartbeat_publication_failures == 2u
              && std::strcmp(source::last_status_write_stage,
                             "heartbeat_publication_timeout") == 0,
          "heartbeat_retry_timeout_is_bounded_and_diagnostic");
    if (temporary != INVALID_HANDLE_VALUE) {
        check(CloseHandle(temporary) != FALSE,
              "heartbeat_fixture_timeout_target_release");
        temporary = INVALID_HANDLE_VALUE;
    }
    check(source::heartbeat_status(true, "observed", 6100u)
              == source::HeartbeatPublicationResult::published,
          "heartbeat_status_publishes_timeout_diagnostic");
    check(read_heartbeat_diagnostics(),
          "heartbeat_status_publishes_failure_diagnostics");
    source::state.store(source::enabled, std::memory_order_release);
}

void run_title_guard_failure() noexcept {
    const auto attempted_before = source::title_query_attempted.load();
    const auto destroyed_before = source::title_query_destroyed.load();
    const std::uintptr_t page =
        (base + information::battle::title_query_plan::kHelperRva)
        & ~UINT64_C(0xfff);
    DWORD old = 0u;
    check(VirtualProtect(reinterpret_cast<void*>(page), 0x1000u,
                         PAGE_READWRITE, &old) != FALSE,
          "title_guard_failure_page_rw");
    const unsigned char saved = g_region[
        information::battle::title_query_plan::kHelperRva];
    g_region[information::battle::title_query_plan::kHelperRva] =
        static_cast<unsigned char>(saved ^ 0x01u);
    check(FlushInstructionCache(GetCurrentProcess(),
                                reinterpret_cast<void*>(page), 0x1000u)
              != FALSE,
          "title_guard_failure_icache_flush");
    check(VirtualProtect(reinterpret_cast<void*>(page), 0x1000u,
                         PAGE_EXECUTE_READ, &old) != FALSE,
          "title_guard_failure_page_restore");

    // This is the production entry seam.  code_guard() fails before the
    // title Invoker is reached, so the existing v5/base result is untouched.
    information_battle_entry_capture(
        reinterpret_cast<void*>(g_combat), reinterpret_cast<void*>(g_summary),
        reinterpret_cast<void*>(g_result),
        reinterpret_cast<void*>(base + kKnownRouterReturnRva), g_war);
    check(source::state.load(std::memory_order_acquire)
              == source::source_changed,
          "title_guard_failure_latches_source_changed");
    check(source::title_query_attempted.load() == attempted_before,
          "title_guard_failure_does_not_invoke");
    check(source::title_query_destroyed.load() == destroyed_before,
          "title_guard_failure_does_not_destroy_new_output");
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
    run_heartbeat_publication_retry();
    g_title_kind = 1u;
    run_case(Case::valid, "valid_0", static_cast<std::int32_t>(kDate));
    g_title_kind = 2u;
    run_case(Case::valid, "valid_kind2_0", static_cast<std::int32_t>(kDate));
    g_title_kind = 1u;
    run_case(Case::wrong_owner, "wrong_owner_0", static_cast<std::int32_t>(kDate));
    run_case(Case::wrong_date, "wrong_date_0", static_cast<std::int32_t>(kDate - 1u));
    run_case(Case::duplicate, "duplicate_0", static_cast<std::int32_t>(kDate));
    run_case(Case::conflict, "conflict_0", static_cast<std::int32_t>(kDate));
    run_case(Case::wrong_parent, "wrong_parent_0", static_cast<std::int32_t>(kDate));
    run_case(Case::wrong_popup, "wrong_popup_0", static_cast<std::int32_t>(kDate));
    run_case(Case::no_scope, "no_scope_0", static_cast<std::int32_t>(kDate));
    check(source::line1_copied.load() >= 2u,
          "line1_real_capture_positive_cases");
    check(source::line1_no_scope.load() >= 1u,
          "line1_real_capture_no_scope_rejected");
    check(source::line1_binding_rejected.load() >= 6u
              && g_conflict_binding_rejected == 1u,
          "line1_real_capture_negative_bindings_rejected");
    check(source::line1_copy_failed.load() == 1u,
          "line1_real_capture_conflict_copy_failure");
    check(g_line1_native_calls == 11u && g_line1_original_calls == 11u,
          "line1_continuation_count_matches_real_calls");
    check(source::title_query_candidates.load() >= 2u,
          "title_query_candidates_for_two_kinds");
    check(source::title_query_attempted.load() >= 2u
              && source::title_query_destroyed.load()
                     == source::title_query_attempted.load(),
          "title_query_real_invoker_destroy_count");
    check(source::title_query_copied.load() >= 2u,
          "title_query_copied_for_two_kinds");
    run_title_guard_failure();
    const bool passed = g_failures == 0u;
    std::printf(
        "RESULT %s\n{\"passed\":%s,\"router_original_calls\":%u,"
        "\"message_original_calls\":%u,\"native_metadata_copied\":%llu,"
        "\"native_metadata_failed\":%llu,\"native_text_invalid\":true,"
        "\"line1_candidates\":%llu,\"line1_no_scope\":%llu,"
        "\"line1_binding_rejected\":%llu,\"line1_copied\":%llu,"
        "\"line1_copy_failed\":%llu,\"line1_original_calls\":%u,"
        "\"line1_native_continuation_calls\":%u,"
        "\"title_query_candidates\":%llu,\"title_query_attempted\":%llu,"
        "\"title_query_destroyed\":%llu,\"title_query_copied\":%llu,"
        "\"title_query_failures\":%llu,\"title_guard_failure\":true,"
        "\"plugin_guard_positive\":%s,\"plugin_guard_negative\":%s,"
        "\"plugin_guard_restored\":%s,\"plugin_cleanup\":%s,"
        "\"plugin_callee_executed\":%s,"
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
        static_cast<unsigned long long>(source::title_query_candidates.load()),
        static_cast<unsigned long long>(source::title_query_attempted.load()),
        static_cast<unsigned long long>(source::title_query_destroyed.load()),
        static_cast<unsigned long long>(source::title_query_copied.load()),
        static_cast<unsigned long long>(source::title_query_failed.load()),
        g_plugin_guard_positive ? "true" : "false",
        g_plugin_guard_negative ? "true" : "false",
        g_plugin_guard_restored ? "true" : "false",
        g_plugin_cleanup ? "true" : "false",
        g_plugin_callee_executed ? "true" : "false",
        g_conflict_line1_invalid ? "true" : "false",
        g_conflict_binding_rejected);
    return passed ? 0 : 1;
}
