#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <vector>
#include "../information-support-subject-record-entry-plan.h"
#include "../information-war-declaration.h"

namespace plan = information::support_subject_record::entry;
namespace declaration = information::war_declaration::entry;
namespace birth_entry = information::war_declaration::birth_entry;
namespace retirement_entry = information::war_declaration::retirement_entry;
using Call = uint64_t(*)(uint64_t,uint64_t,uint64_t,uint64_t);
extern "C" void support_subject_entry_registers(Call,uint64_t*,uint64_t);
static unsigned checks = 0, failures = 0, positions = 0, hook_calls = 0;
static Call original = nullptr;
static uint64_t observed[9]{}, record[6]{};
constexpr uint64_t kGlobalValue = UINT64_C(0x1234567812345678);
constexpr uint64_t kReturned = UINT64_C(0xfedcba9876543210);
constexpr uint64_t kSaved[] = {UINT64_C(0x1111111122222222),UINT64_C(0x3333333344444444),
    UINT64_C(0x5555555566666666),UINT64_C(0x7777777788888888),UINT64_C(0xbbbbbbbbcccccccc),
    UINT64_C(0xddddddddeeeeeeee),UINT64_C(0x99999999aaaaaaaa),UINT64_C(0xffff000011112222)};
#define CHECK(value) do { ++checks; if (!(value)) { ++failures; std::printf("FAIL line %d\n",__LINE__); } } while (0)

static uint64_t hook(uint64_t first,uint64_t second,uint64_t third,uint64_t fourth) {
    ++hook_calls;
    return original(first,second,third,fourth);
}
static void verify_call(Call call,unsigned index,bool birth = false) {
    uint64_t output[9]{};
    const auto before = observed[7];
    SetLastError(7781);
    support_subject_entry_registers(call,output,reinterpret_cast<uint64_t>(record));
    CHECK(GetLastError() == 7781);
    CHECK(output[0] == kReturned);
    for (unsigned reg = 0; reg < 8; ++reg) CHECK(output[reg+1] == kSaved[reg]);
    CHECK(observed[0] == (index == 1 ? kGlobalValue : reinterpret_cast<uint64_t>(record)));
    CHECK(observed[1] == UINT64_C(0x1200000100415246));
    CHECK(observed[2] == UINT64_C(0x9876543210123456));
    CHECK(observed[3] == UINT64_C(0x8877665544332211));
    CHECK(observed[4] == (index < 2 || index == 5 ? reinterpret_cast<uint64_t>(record) : kSaved[0]));
    if (index == 0) {
        CHECK(observed[5] == record[2]);
        CHECK(observed[6] == record[3]);
    }
    if (index == 2 || index == 4) CHECK(observed[8] == reinterpret_cast<uint64_t>(record));
    if (index == 3) CHECK(observed[8] == (birth ? reinterpret_cast<uint64_t>(record) : 0x46));
    CHECK(observed[7] == before+1);
}
static bool prepare(unsigned mode,plan::Kind kind,const std::array<unsigned char,17>& prefix,
                    const std::array<unsigned char,40>& unwind,uintptr_t entry,uintptr_t target,
                    plan::Plan& output) {
    if (!mode) return plan::prepare(kind,prefix,unwind,entry,target,output);
    declaration::Plan value{};
    if (mode == 1) {
        if (kind != plan::Kind::support_action || !declaration::prepare(prefix,unwind,entry,target,value)) return false;
    } else if (mode == 2) {
        if (kind != plan::Kind::subject_disable || !birth_entry::prepare(prefix,unwind,entry,target,value)) return false;
    } else {
        if (kind != plan::Kind::subject_disable || !retirement_entry::prepare(prefix,unwind,entry,target,value)) return false;
    }
    output.image = value.image;
    output.patch = value.patch;
    output.runtime = {value.runtime.begin,value.runtime.end,value.runtime.unwind};
    return true;
}
static void reject(unsigned mode,plan::Kind kind,const std::array<unsigned char,17>& prefix,
                   const std::array<unsigned char,40>& unwind,uintptr_t entry,uintptr_t target) {
    plan::Plan output{};
    output.image.fill(0xa5);
    output.patch.fill(0x5a);
    output.runtime = {1,2,3};
    const auto saved = output;
    CHECK(!prepare(mode,kind,prefix,unwind,entry,target,output));
    CHECK(output.image == saved.image && output.patch == saved.patch
        && output.runtime.begin == saved.runtime.begin && output.runtime.end == saved.runtime.end
        && output.runtime.unwind == saved.runtime.unwind);
}
static uint64_t* context_registers(CONTEXT& context,unsigned index) {
    uint64_t* values[] = {&context.Rbx,&context.Rsi,&context.Rdi,&context.Rbp,
                         &context.R12,&context.R13,&context.R14,&context.R15};
    return values[index];
}
static void verify_unwind(unsigned index,unsigned char* image,RUNTIME_FUNCTION& function,bool birth = false) {
    const std::vector<std::vector<unsigned>> offsets{
        {0,2,6,10,13,17,28,39,45}, {0,2,6,9,19,22,33,44,50},
        {0,5,6,7,8,9,11,13,15,26,37,43}, {0,5,10,15,26,37,43},
        {0,5,6,7,8,9,11,13,15,26,37,43}, {0,5,6,10,13,24,35,42}};
    for (const auto offset : offsets[index]) {
        ++positions;
        alignas(16) uint64_t stack[48]{};
        auto* initial = stack+24;
        initial[0] = 0x12345678;
        CONTEXT context{};
        context.ContextFlags = CONTEXT_FULL;
        context.Rip = reinterpret_cast<DWORD64>(image)+offset;
        for (unsigned reg = 0; reg < 8; ++reg) *context_registers(context,reg) = 11*(reg+1);
        uint64_t expected[8] = {11,22,33,44,55,66,77,88};
        unsigned displacement = 0;
        if (index < 2) {
            initial[-1] = kSaved[0];
            displacement = (offset >= 2 ? 8 : 0)+(offset >= 6 ? 32 : 0);
            if (offset >= 2) expected[0] = kSaved[0];
        } else if (index == 2 || index == 4) {
            constexpr unsigned registers[] = {3,0,1,2,4,5,6};
            constexpr unsigned completed_at[] = {6,7,8,9,11,13,15};
            for (unsigned push = 0; push < 7; ++push) {
                initial[-static_cast<int>(push)-1] = kSaved[registers[push]];
                if (offset >= completed_at[push]) {
                    displacement += 8;
                    expected[registers[push]] = kSaved[registers[push]];
                }
            }
        } else if (index == 5) {
            initial[1] = kSaved[0];
            initial[-1] = kSaved[2];
            displacement = (offset >= 6 ? 8 : 0)+(offset >= 10 ? 32 : 0);
            // The native SAVE_NONVOL is recorded at offset 10, after the
            // stack allocation. RBX itself is unchanged before that point.
            if (offset >= 10) expected[0] = kSaved[0];
            if (offset >= 6) expected[2] = kSaved[2];
        } else if (birth) {
            initial[3] = kSaved[0];
            initial[4] = kSaved[1];
            if (offset >= 5) expected[0] = kSaved[0];
            if (offset >= 10) expected[1] = kSaved[1];
        } else {
            initial[1] = kSaved[0];
            initial[3] = kSaved[1];
            initial[4] = kSaved[2];
            if (offset >= 5) expected[0] = kSaved[0];
            if (offset >= 10) expected[1] = kSaved[1];
            if (offset >= 15) expected[2] = kSaved[2];
        }
        context.Rsp = reinterpret_cast<DWORD64>(initial)-displacement;
        void* data = nullptr;
        DWORD64 establisher = 0;
        KNONVOLATILE_CONTEXT_POINTERS pointers{};
        CHECK(RtlVirtualUnwind(UNW_FLAG_NHANDLER,reinterpret_cast<DWORD64>(image),context.Rip,
            &function,&context,&data,&establisher,&pointers) == nullptr);
        CHECK(context.Rip == initial[0]);
        CHECK(context.Rsp == reinterpret_cast<DWORD64>(initial)+8);
        for (unsigned reg = 0; reg < 8; ++reg) CHECK(*context_registers(context,reg) == expected[reg]);
    }
}
static void test(unsigned index,unsigned mode = 0) {
    const bool birth = mode == 2;
    const auto kind = static_cast<plan::Kind>(index == 5 ? 3 : index);
    auto spec = plan::kSpecs[index == 5 ? 3 : index];
    if (mode == 1) {
        spec.rva = declaration::kRva;
        spec.end_rva = declaration::kEndRva;
        spec.unwind_rva = declaration::kUnwindRva;
        spec.prefix = declaration::kPrefix;
        spec.unwind = declaration::kUnwind;
    } else if (mode == 3) {
        spec.rva = retirement_entry::kRva;
        spec.end_rva = retirement_entry::kEndRva;
        spec.unwind_rva = retirement_entry::kUnwindRva;
        spec.prefix_bytes = retirement_entry::kPrefixBytes;
        spec.unwind_bytes = retirement_entry::kUnwindBytes;
        spec.prefix = retirement_entry::kPrefix;
        spec.unwind = retirement_entry::kUnwind;
    } else if (birth) {
        spec.rva = birth_entry::kRva;
        spec.end_rva = birth_entry::kEndRva;
        spec.unwind_rva = birth_entry::kUnwindRva;
        spec.prefix_bytes = birth_entry::kPrefixBytes;
        spec.unwind_bytes = birth_entry::kUnwindBytes;
        spec.prefix = birth_entry::kPrefix;
        spec.unwind = birth_entry::kUnwind;
    }
    auto* arena = static_cast<unsigned char*>(VirtualAlloc(nullptr,64*1024*1024,MEM_RESERVE,PAGE_NOACCESS));
    if (!arena) { CHECK(false); return; }
    auto* source = static_cast<unsigned char*>(VirtualAlloc(arena,4096,MEM_COMMIT,PAGE_READWRITE));
    auto* copied = static_cast<unsigned char*>(VirtualAlloc(nullptr,4096,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE));
    if (!source || !copied) { CHECK(false); return; }
    const auto entry = reinterpret_cast<uintptr_t>(source);
    const auto global = entry-spec.rva+0x233fe58;
    CHECK(global >= entry && global+8 < entry+64*1024*1024);
    CHECK(VirtualAlloc(reinterpret_cast<void*>(global&~uintptr_t(0xfff)),4096,MEM_COMMIT,PAGE_READWRITE) != nullptr);
    std::memcpy(reinterpret_cast<void*>(global),&kGlobalValue,8);
    unsigned cursor = 0;
    auto append = [&](const unsigned char* bytes,size_t size) {
        std::memcpy(source+cursor,bytes,size);
        cursor += static_cast<unsigned>(size);
    };
    append(spec.prefix.data(),spec.prefix_bytes);
    if (index == 3) {
        const unsigned char next_store[] = {0x88,0x54,0x24,0x10};
        append(next_store,sizeof(next_store));
    }
    const unsigned char load_output[] = {0x49,0xbb};
    append(load_output,sizeof(load_output));
    const auto output_address = reinterpret_cast<uint64_t>(observed);
    append(reinterpret_cast<const unsigned char*>(&output_address),8);
    const unsigned char capture[] = {0x49,0x89,0x0b,0x49,0x89,0x53,0x08,
        0x4d,0x89,0x43,0x10,0x4d,0x89,0x4b,0x18,0x49,0x89,0x5b,0x20,
        0x49,0x89,0x43,0x28,0x4d,0x89,0x53,0x30,0x49,0xff,0x43,0x38};
    append(capture,sizeof(capture));
    if (index == 2 || index == 4) {
        const unsigned char home[] = {0x48,0x8b,0x44,0x24,0x40,0x49,0x89,0x43,0x40};
        append(home,sizeof(home));
    } else if (index == 3 && birth) {
        const unsigned char home[] = {0x48,0x8b,0x44,0x24,0x08,0x49,0x89,0x43,0x40};
        append(home,sizeof(home));
    } else if (index == 3) {
        const unsigned char home[] = {0x0f,0xb6,0x44,0x24,0x10,0x49,0x89,0x43,0x40};
        append(home,sizeof(home));
    }
    const unsigned char returned[] = {0x48,0xb8};
    append(returned,sizeof(returned));
    append(reinterpret_cast<const unsigned char*>(&kReturned),8);
    if (index == 5) {
        const unsigned char restore[] = {0x48,0x83,0xc4,0x20,0x5f,
                                         0x48,0x8b,0x5c,0x24,0x08,0xc3};
        append(restore,sizeof(restore));
    } else if (index < 2) {
        const unsigned char restore[] = {0x48,0x83,0xc4,0x20,0x5b,0xc3};
        append(restore,sizeof(restore));
    } else if (index == 2 || index == 4) {
        const unsigned char restore[] = {0x41,0x5e,0x41,0x5d,0x41,0x5c,0x5f,0x5e,0x5b,0x5d,0xc3};
        append(restore,sizeof(restore));
    } else if (birth) {
        const unsigned char restore[] = {0x48,0x8b,0x5c,0x24,0x18,
                                         0x48,0x8b,0x74,0x24,0x20,0xc3};
        append(restore,sizeof(restore));
    } else {
        const unsigned char restore[] = {0x48,0x8b,0x5c,0x24,0x08,0x48,0x8b,0x74,0x24,0x18,
                                         0x48,0x8b,0x7c,0x24,0x20,0xc3};
        append(restore,sizeof(restore));
    }
    plan::Plan image{};
    CHECK(prepare(mode,kind,spec.prefix,spec.unwind,entry,reinterpret_cast<uintptr_t>(&hook),image));
    std::memcpy(copied,image.image.data(),image.image.size());
    DWORD old = 0;
    CHECK(VirtualProtect(source,4096,PAGE_EXECUTE_READ,&old));
    CHECK(VirtualProtect(copied,4096,PAGE_EXECUTE_READ,&old));
    CHECK(FlushInstructionCache(GetCurrentProcess(),source,4096));
    CHECK(FlushInstructionCache(GetCurrentProcess(),copied,4096));
    RUNTIME_FUNCTION function{image.runtime.begin,image.runtime.end,image.runtime.unwind};
    CHECK(RtlAddFunctionTable(&function,1,reinterpret_cast<DWORD64>(copied)));
    DWORD64 found_base = 0;
    CHECK(RtlLookupFunctionEntry(reinterpret_cast<DWORD64>(copied),&found_base,nullptr) == &function);
    CHECK(found_base == reinterpret_cast<DWORD64>(copied));
    verify_call(reinterpret_cast<Call>(source),index,birth);
    original = reinterpret_cast<Call>(copied);
    verify_call(original,index,birth);
    CHECK(VirtualProtect(source,4096,PAGE_READWRITE,&old));
    std::memcpy(source,image.patch.data(),spec.prefix_bytes);
    CHECK(VirtualProtect(source,4096,PAGE_EXECUTE_READ,&old));
    CHECK(FlushInstructionCache(GetCurrentProcess(),source,4096));
    hook_calls = 0;
    verify_call(reinterpret_cast<Call>(source),index,birth);
    CHECK(hook_calls == 1);
    verify_unwind(index,copied,function,birth);
    auto bad_prefix = spec.prefix;
    bad_prefix[0] ^= 1;
    reject(mode,kind,bad_prefix,spec.unwind,entry,reinterpret_cast<uintptr_t>(&hook));
    auto bad_unwind = spec.unwind;
    bad_unwind[6] ^= 1;
    reject(mode,kind,spec.prefix,bad_unwind,entry,reinterpret_cast<uintptr_t>(&hook));
    reject(mode,static_cast<plan::Kind>(5),spec.prefix,spec.unwind,entry,reinterpret_cast<uintptr_t>(&hook));
    reject(mode,kind,spec.prefix,spec.unwind,entry,entry+spec.prefix_bytes);
    CHECK(RtlDeleteFunctionTable(&function));
    CHECK(VirtualFree(copied,0,MEM_RELEASE));
    CHECK(VirtualFree(arena,0,MEM_RELEASE));
}
static void dump_specs() {
    std::printf("[");
    for (unsigned index = 0; index < plan::kSpecs.size(); ++index) {
        const auto& spec = plan::kSpecs[index];
        std::printf("%s{\"rva\":%u,\"end_rva\":%u,\"unwind_rva\":%u,\"prefix\":\"",
            index ? "," : "",spec.rva,spec.end_rva,spec.unwind_rva);
        for (unsigned byte = 0; byte < spec.prefix_bytes; ++byte) std::printf("%02x",spec.prefix[byte]);
        std::printf("\",\"unwind\":\"");
        for (unsigned byte = 0; byte < spec.unwind_bytes; ++byte) std::printf("%02x",spec.unwind[byte]);
        std::printf("\"}");
    }
    std::printf("]\n");
}
int main(int argc,char**) {
    if (argc > 1) { dump_specs(); return 0; }
    record[2] = UINT64_C(0x1200000100415246);
    record[3] = UINT64_C(0x2300000200474e45);
    for (unsigned index = 0; index < plan::kSpecs.size(); ++index) test(index);
    test(4,1);
    test(3,2);
    test(5,3);
    std::printf("{\"checks\":%u,\"failures\":%u,\"unwind_positions\":%u,\"game_access\":false}\n",checks,failures,positions);
    return failures ? 1 : 0;
}
