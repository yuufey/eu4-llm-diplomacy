// Synthetic memory only. Exercise the production copy/queue/JSONL code.
#include <windows.h>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <map>
#include <string>

static uintptr_t base=UINT64_C(0x140000000);
static uint64_t observation_creation=1234;
static std::map<uintptr_t,unsigned char> memory;
static unsigned vector_reads=0;
static unsigned emitted=0;
template<class T> static void seed(uintptr_t address,const T& value) {
    const auto* bytes=reinterpret_cast<const unsigned char*>(&value);
    for (size_t index=0;index<sizeof(T);++index) memory[address+index]=bytes[index];
}
template<class T> static bool read(uintptr_t address,T& value) {
    if (address>=0x300000 && address<0x301000) ++vector_reads;
    auto* bytes=reinterpret_cast<unsigned char*>(&value);
    for (size_t index=0;index<sizeof(T);++index) {
        const auto found=memory.find(address+index);
        if (found==memory.end()) return false;
        bytes[index]=found->second;
    }
    return true;
}
static uint64_t country(const char* tag) {
    return UINT64_C(0x0100004500000000) | static_cast<uint64_t>(tag[0])
        | (static_cast<uint64_t>(tag[1])<<8) | (static_cast<uint64_t>(tag[2])<<16);
}
static bool observation_country_handle(uint64_t value) {
    return value==country("ENG") || value==country("FRA") || value==country("BUR") || value==country("POR");
}
static void line(const char* value) { ++emitted; std::cout<<value; }
namespace bridge_alliance_inbound_detail {
static bool inbound_read_country(uint64_t value,uintptr_t& result) {
    result=0x400000;
    return observation_country_handle(value);
}
static bool inbound_is_controlled(uint64_t value,uintptr_t& result) {
    return value==country("FRA") && inbound_read_country(value,result);
}
static void inbound_tag(char (&result)[4],uint64_t value) {
    result[0]=static_cast<char>(value&0xff);
    result[1]=static_cast<char>((value>>8)&0xff);
    result[2]=static_cast<char>((value>>16)&0xff);
    result[3]=0;
}
}
struct ProtocolWrapperShape { bool identity=true,readable=true; uintptr_t action=0x200000; };
#include "call-to-arms-observer.inc"

int main(int argc,char** argv) {
    const uintptr_t action=0x200000,game=0x500000,entries=0x300000;
    seed(action,base+bridge_call_to_arms::kVtableRva);
    seed(action+0x08,int32_t{0x165});
    seed(action+0x10,country("ENG")); seed(action+0x20,country("FRA"));
    seed(action+0x28,int32_t{56567000}); seed(action+0x2c,int32_t{56566584});
    seed(action+0x34,int32_t{0}); seed(action+0x3c,int32_t{7});
    seed(action+0x40,country("BUR")); seed(action+0x4c,int32_t{2});
    const unsigned char flags[]={0,1,1,0,0,0,1};
    const uintptr_t offsets[]={0x48,0x49,0x50,0x51,0x52,0x53,0x56};
    for (unsigned index=0;index<7;++index) seed(action+offsets[index],flags[index]);
    seed(action+0x58,entries); seed(action+0x60,entries+8); seed(entries,country("BUR"));
    seed(base+0x233fe58,game); seed(game+0x1dd0,int32_t{56566584});
    ProtocolWrapperShape wrapper{};
    if (argc>1 && std::string(argv[1])=="full") {
        for (uintptr_t index=0;index<128;++index) seed(entries+index*8,country("BUR"));
        seed(action+0x60,entries+128*8);
        bridge_call_to_arms::observe(wrapper); bridge_call_to_arms::flush();
        assert(emitted==1); return 0;
    }
    if (argc>1 && std::string(argv[1])=="overflow") {
        for (unsigned index=0;index<65;++index) bridge_call_to_arms::observe(wrapper);
        bridge_call_to_arms::flush(); assert(emitted==65); return 0;
    }
    bridge_call_to_arms::observe(wrapper);
    bridge_call_to_arms::observe(wrapper);
    bridge_call_to_arms::flush();
    assert(emitted==2);
    seed(action+0x34,int32_t{1}); bridge_call_to_arms::observe(wrapper);
    seed(action+0x34,int32_t{0}); seed(action+0x20,country("POR"));
    bridge_call_to_arms::observe(wrapper); bridge_call_to_arms::flush();
    assert(emitted==2);
    seed(action+0x20,country("FRA")); seed(action+0x60,entries+7);
    vector_reads=0; bridge_call_to_arms::observe(wrapper);
    assert(vector_reads==0);
    bridge_call_to_arms::flush(); assert(emitted==3);
    seed(action+0x60,entries+129*8);
    vector_reads=0; bridge_call_to_arms::observe(wrapper); assert(vector_reads==0);
    bridge_call_to_arms::flush(); assert(emitted==4);
    seed(action+0x58,uintptr_t{0}); seed(action+0x60,uintptr_t{0});
    bridge_call_to_arms::observe(wrapper); bridge_call_to_arms::flush();
    assert(emitted==5);
    return 0;
}
