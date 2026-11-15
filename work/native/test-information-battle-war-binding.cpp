#include "information-battle-war-binding.h"
#include <cassert>
#include <cstdio>
#include <map>
#include <vector>
#include <cstring>

using namespace information::battle;
using Address=std::uintptr_t;
constexpr Address base=UINT64_C(0x140000000);
constexpr Address database=0x500000,table=0x510000,country_a=0x600000,country_b=0x610000;
constexpr Address rows_a=0x700000,rows_b=0x710000,war=0x800000,other_war=0x810000;
constexpr Address members_a=0x900000,members_b=0x910000;
constexpr std::uint64_t ref_a=UINT64_C(0x0100007a00415246); // FRA, slot122
constexpr std::uint64_t ref_b=UINT64_C(0x0100002e00474e45); // ENG, slot46
constexpr std::uint64_t creation=UINT64_C(134374886912306555);

struct Memory {
    std::map<Address,unsigned char> bytes;
    std::map<Address,unsigned> reads;
    bool change_second_pair=false;
    bool read(Address p,unsigned char* out,std::size_t n) noexcept {
        ++reads[p];
        for (std::size_t i=0;i<n;++i) {
            const auto it=bytes.find(p+i);
            if (it==bytes.end()) return false;
            out[i]=it->second;
        }
        if (change_second_pair && p==rows_a && reads[p]==2) out[8]^=0x10;
        return true;
    }
    template<class T> void value(Address p,const T& value) {
        const auto* raw=reinterpret_cast<const unsigned char*>(&value);
        for (std::size_t i=0;i<sizeof(value);++i) bytes[p+i]=raw[i];
    }
    template<std::size_t N> void raw(Address p,const std::array<unsigned char,N>& raw) {
        for (std::size_t i=0;i<N;++i) bytes[p+i]=raw[i];
    }
};

struct Registry {
    unsigned calls=0; Address selected=0; bool full=false;
    bool operator()(Address p,char* out,std::size_t capacity) noexcept {
        ++calls;selected=p;
        if (full || capacity<30) return false;
        std::uint64_t epoch=creation+UINT64_C(0x9e3779b97f4a7c15);
        epoch=(epoch^(epoch>>30))*UINT64_C(0xbf58476d1ce4e5b9);
        epoch=(epoch^(epoch>>27))*UINT64_C(0x94d049bb133111eb);
        epoch^=epoch>>31;
        return std::snprintf(out,capacity,"war_%016llx_00000002",static_cast<unsigned long long>(epoch))==29;
    }
};

struct Fixture {
    Memory memory;
    owned_context::Snapshot context{};
    owned_result::Snapshot result{};
    Registry registry;
    Fixture() {
        memory.raw(base+war_binding::kGuardRva0,war_binding::kGuard0);
        memory.raw(base+war_binding::kGuardRva1,war_binding::kGuard1);
        memory.raw(base+war_binding::kGuardRva2,war_binding::kGuard2);
        memory.value(base+0x233d8b0,Address(database));
        memory.value(database+0x118,Address(table));
        memory.value(database+0x124,std::int32_t(1379));
        memory.value(table+122*8,Address(country_a));
        memory.value(table+46*8,Address(country_b));
        memory.value(country_a+0x20,ref_a);memory.value(country_b+0x20,ref_b);
        memory.value(country_a+0x1548,Address(rows_a));memory.value(country_b+0x1548,Address(rows_b));
        memory.value(country_a+0x1554,std::int32_t(2));memory.value(country_b+0x1554,std::int32_t(2));
        // Equal multi-war sets in different order. The native candidate must
        // win over insertion/row order and cannot be replaced by first row.
        pair_row(rows_a,46,other_war);pair_row(rows_a+16,46,war);
        pair_row(rows_b,122,war);pair_row(rows_b+16,122,other_war);
        memory.value(war+0x108,Address(base+0x1d20be0));
        for (auto offset:{0x48,0x50,0x58}) memory.value(war+offset,Address(members_a+(offset==0x48?0:8)));
        for (auto offset:{0x78,0x80,0x88}) memory.value(war+offset,Address(members_b+(offset==0x78?0:8)));
        memory.value(members_a,ref_a);memory.value(members_b,ref_b);
        context.known_router=true;
        context.war_context_status=owned_context::WarContextStatus::observed;
        context.war_members.vectors_complete=true;
        context.war_members.side_a_count=1;context.war_members.side_b_count=1;
        context.war_members.side_a_full_refs[0]=ref_a;context.war_members.side_b_full_refs[0]=ref_b;
        for (unsigned i=0;i<2;++i) {
            context.sides[i].present=true;context.sides[i].participants.complete=true;
            context.sides[i].participants.count=1;
        }
        context.sides[0].participants.full_refs[0]=ref_b;
        context.sides[1].participants.full_refs[0]=ref_a;
        result.raw_date=56557728;
        result.sides[0].country=ref_a;result.sides[1].country=ref_b;
    }
    void pair_row(Address p,std::int32_t slot,Address reference) {
        std::array<unsigned char,16> row{};
        std::memcpy(row.data(),&slot,4);std::memcpy(row.data()+8,&reference,8);
        memory.raw(p,row);
    }
    war_identity_wire::Identity capture() {
        return war_binding::capture(memory,base,war,true,context,result,creation,registry);
    }
};

int main() {
    unsigned passed=0;
    {Fixture f;const auto v=f.capture();assert(v.status==1 && v.reason==0 && v.binding_flags==63);
     assert(v.pair_full_refs[0]==ref_a && v.pair_full_refs[1]==ref_b);
     assert(f.registry.calls==1 && f.registry.selected==war);
     assert(std::strlen(v.war_id.data())==29);++passed;}
    {Fixture f;f.memory.value(country_a+0x20,ref_a^(UINT64_C(1)<<48));
     const auto v=f.capture();assert(v.status==2 && v.reason==4 && f.registry.calls==0 && v.war_id[0]==0);++passed;}
    {Fixture f;f.pair_row(rows_b+16,122,0x820000);
     const auto v=f.capture();assert(v.reason==4 && f.registry.calls==0);++passed;}
    {Fixture f;f.memory.change_second_pair=true;
     const auto v=f.capture();assert(v.reason==5 && f.registry.calls==0);++passed;}
    {Fixture f;f.context.sides[0].participants.count=2;f.context.sides[0].participants.full_refs[1]=ref_a;
     const auto v=f.capture();assert(v.reason==3 && f.registry.calls==0);++passed;}
    {Fixture f;f.registry.full=true;const auto v=f.capture();
     assert(v.reason==6 && v.binding_flags==0 && v.war_id[0]==0 && v.pair_full_refs[0]==0);++passed;}
    {Fixture f;f.memory.bytes[base+war_binding::kGuardRva0]^=1;const auto v=f.capture();
     assert(v.reason==4 && f.registry.calls==0);++passed;}
    {Fixture f;f.memory.value(members_b,ref_a);const auto v=f.capture();
     assert(v.reason==4 && f.registry.calls==0);++passed;}
    std::printf("{\"status\":\"passed\",\"checks\":%u,\"native_game_calls\":false}\n",passed);
}

