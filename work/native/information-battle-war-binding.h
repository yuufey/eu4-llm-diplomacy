#ifndef INFORMATION_BATTLE_WAR_BINDING_H
#define INFORMATION_BATTLE_WAR_BINDING_H

// Fixed EU4 1.37.4. Bounded value-only binding of the known caller's RBX
// candidate to both current country association sets and copied battle sides.
// No game function, allocation or I/O. Register only writes the shared owned
// observer registry; its native address never enters Identity or the wire.
// Native allocation generation and cross-save identity remain unproven.
#include "information-battle-owned-context.h"
#include "information-battle-owned-result.h"
#include "information-battle-war-identity-wire.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace information::battle::war_binding {
using Address=std::uintptr_t;
using Identity=war_identity_wire::Identity;
constexpr std::size_t kMaxReadBytes=64u*1024u;
constexpr std::uint32_t kBoundFlags=63u;
inline constexpr std::uintptr_t kGuardRva0=0x23a228u;
inline constexpr std::array<unsigned char,86> kGuard0{{0x48,0x8d,0x55,0x40,0x48,0x8b,0x4f,0x20,0xe8,0x9b,0x25,0xfe,0xff,0x48,0x8b,0x08,0x48,0x8b,0x05,0x71,0x36,0x10,0x02,0x48,0xc1,0xe9,0x20,0x48,0x0f,0xbf,0xc9,0x48,0x8b,0x80,0x18,0x01,0x00,0x00,0x48,0x8b,0x1c,0xc8,0x48,0x8d,0x55,0x50,0x49,0x8b,0x0c,0x24,0xe8,0x71,0x25,0xfe,0xff,0x48,0x8b,0x00,0x48,0xc1,0xe8,0x20,0x98,0x48,0x8d,0x0c,0xc0,0x48,0x8b,0x83,0x10,0x15,0x00,0x00,0x48,0x8d,0x0c,0xc8,0xe8,0x35,0xe6,0x82,0x00,0x48,0x8b,0xd8}};
inline constexpr std::uintptr_t kGuardRva1=0x23a3d6u;
inline constexpr std::array<unsigned char,55> kGuard1{{0x0f,0xb6,0xc1,0x48,0x85,0xdb,0x0f,0x45,0xf0,0x40,0x84,0xf6,0x74,0x1a,0x48,0x8b,0xd3,0x49,0x8b,0xce,0xe8,0xd1,0x2f,0xfa,0xff,0x44,0x0f,0xb6,0xc6,0x49,0x8b,0xd6,0x48,0x8b,0xcb,0xe8,0x82,0xf6,0xb4,0x00,0x4d,0x8b,0xc6,0x48,0x8d,0x55,0xb0,0x48,0x8b,0xcf,0xe8,0x13,0xe2,0xff,0xff}};
inline constexpr std::uintptr_t kGuardRva2=0xa688b0u;
inline constexpr std::array<unsigned char,53> kGuard2{{0x48,0x8b,0x11,0x48,0x8b,0x41,0x10,0x48,0xc1,0xe8,0x20,0x98,0x48,0x8b,0x4a,0x50,0x4c,0x63,0x42,0x5c,0x49,0xc1,0xe0,0x04,0x4c,0x03,0xc1,0x49,0x3b,0xc8,0x74,0x0d,0x39,0x01,0x74,0x0c,0x48,0x83,0xc1,0x10,0x49,0x3b,0xc8,0x75,0xf3,0x33,0xc0,0xc3,0x48,0x8b,0x41,0x08,0xc3}};

namespace detail {
inline bool pointer(Address value) noexcept {
    return value>=0x10000u && value<UINT64_C(0x800000000000);
}
inline bool fullref(std::uint64_t value) noexcept {
    if (((value>>24)&0xffu)!=0 || ((value>>32)&0xffffu)>=4096u) return false;
    for (unsigned i=0;i<3;++i) {
        const auto c=static_cast<unsigned char>(value>>(i*8));
        if (!((c>='A' && c<='Z') || (c>='0' && c<='9'))) return false;
    }
    return true;
}
template<class Reader> class Budget {
public:
    explicit Budget(Reader& reader) noexcept:reader_(reader) {}
    bool read(Address address,void* out,std::size_t size) noexcept {
        if (!out || !size || size>65536u || !pointer(address)
            || size>UINT64_C(0x800000000000)-address || used_>kMaxReadBytes-size) return false;
        used_+=size; // Failed reads retain their reservation.
        return reader_.read(address,static_cast<unsigned char*>(out),size);
    }
    template<class T> bool value(Address address,T& out) noexcept {
        return read(address,&out,sizeof(out));
    }
private:
    Reader& reader_;
    std::size_t used_=0;
};
template<class Reader,std::size_t N>
bool guard(Budget<Reader>& reader,Address base,Address rva,
           const std::array<unsigned char,N>& expected) noexcept {
    std::array<unsigned char,N> actual{};
    return reader.read(base+rva,actual.data(),N) && actual==expected;
}
template<class Reader> bool code(Budget<Reader>& reader,Address base) noexcept {
    return pointer(base) && base<UINT64_C(0x800000000000)-0xa68900u
        && guard(reader,base,kGuardRva0,kGuard0)
        && guard(reader,base,kGuardRva1,kGuard1)
        && guard(reader,base,kGuardRva2,kGuard2);
}
inline bool contains(const std::uint64_t* values,std::uint32_t count,
                     std::uint64_t ref) noexcept {
    for (std::uint32_t i=0;i<count;++i) if (values[i]==ref) return true;
    return false;
}
inline bool opposing_participants(const owned_context::Snapshot& context,
                                  const owned_result::Snapshot& result) noexcept {
    const auto a=result.sides[0].country,b=result.sides[1].country;
    if (!fullref(a) || !fullref(b) || a==b) return false;
    bool found[2][2]{};
    for (unsigned side=0;side<2;++side) {
        const auto& p=context.sides[side].participants;
        if (!context.sides[side].present || !p.complete || p.count>owned_context::kMaxParticipants) return false;
        found[side][0]=contains(p.full_refs.data(),p.count,a);
        found[side][1]=contains(p.full_refs.data(),p.count,b);
    }
    const bool opposite=(found[0][0] && !found[1][0] && found[1][1] && !found[0][1])
        || (found[1][0] && !found[0][0] && found[0][1] && !found[1][1]);
    const auto& w=context.war_members;
    if (!w.vectors_complete || w.side_a_count>owned_context::kMaxWarMembers
        || w.side_b_count>owned_context::kMaxWarMembers) return false;
    const bool aa=contains(w.side_a_full_refs.data(),w.side_a_count,a);
    const bool ab=contains(w.side_b_full_refs.data(),w.side_b_count,a);
    const bool ba=contains(w.side_a_full_refs.data(),w.side_a_count,b);
    const bool bb=contains(w.side_b_full_refs.data(),w.side_b_count,b);
    return opposite && ((aa && !ab && bb && !ba) || (ab && !aa && ba && !bb));
}
struct Pair {
    std::array<Address,32> refs{};
    std::uint32_t count=0;
};
inline bool same(const Pair& a,const Pair& b) noexcept {
    if (a.count!=b.count) return false;
    for (std::uint32_t i=0;i<a.count;++i) {
        bool found=false;
        for (std::uint32_t j=0;j<b.count;++j) found=found || a.refs[i]==b.refs[j];
        if (!found) return false;
    }
    return true;
}
inline bool has(const Pair& pair,Address candidate) noexcept {
    for (std::uint32_t i=0;i<pair.count;++i) if (pair.refs[i]==candidate) return true;
    return false;
}
template<class Reader> bool country(Budget<Reader>& reader,Address base,
    std::uint64_t ref,Address& out) noexcept {
    Address database=0,table=0; std::int32_t count=0; std::uint64_t actual=0;
    const auto slot=static_cast<unsigned>((ref>>32)&0xffffu);
    return fullref(ref) && reader.value(base+0x233d8b0u,database) && pointer(database)
        && reader.value(database+0x118u,table) && pointer(table)
        && reader.value(database+0x124u,count) && count>0 && count<=4096
        && slot<static_cast<unsigned>(count) && reader.value(table+slot*8u,out) && pointer(out)
        && reader.value(out+0x20u,actual) && actual==ref;
}
template<class Reader> bool associations(Budget<Reader>& reader,Address country,
    std::uint64_t other,Pair& out) noexcept {
    Address rows=0; std::int32_t count=0;
    if (!reader.value(country+0x1548u,rows) || !reader.value(country+0x1554u,count)
        || count<0 || count>256 || (count && !pointer(rows))) return false;
    for (std::int32_t i=0;i<count;++i) {
        std::array<unsigned char,16> row{};
        if (!reader.read(rows+static_cast<Address>(i)*16u,row.data(),row.size())) return false;
        std::int32_t slot=-1; Address reference=0;
        std::memcpy(&slot,row.data(),4); std::memcpy(&reference,row.data()+8,8);
        if (slot!=static_cast<std::int32_t>((other>>32)&0xffffu)) continue;
        if (!pointer(reference)) return false;
        if (has(out,reference)) continue;
        if (out.count==out.refs.size()) return false;
        out.refs[out.count++]=reference;
    }
    return true;
}
template<class Reader> bool war_snapshot(Budget<Reader>& reader,Address base,
    Address candidate,const owned_context::WarMembers& members) noexcept {
    Address root_vtable=0;
    if (!pointer(candidate) || !reader.value(candidate+0x108u,root_vtable)
        || root_vtable!=base+owned_context::kWarHistoryRootVtableRva) return false;
    for (unsigned side=0;side<2;++side) {
        const auto& offsets=side?owned_context::kWarSideBBounds:owned_context::kWarSideABounds;
        const auto& expected=side?members.side_b_full_refs:members.side_a_full_refs;
        const auto count=side?members.side_b_count:members.side_a_count;
        std::array<Address,3> bounds{};
        if (count>owned_context::kMaxWarMembers
            || !reader.read(candidate+offsets[0],bounds.data(),sizeof(bounds))
            || bounds[1]<bounds[0] || bounds[2]<bounds[1]
            || bounds[1]-bounds[0]!=static_cast<Address>(count)*8u
            || (count && (!pointer(bounds[0]) || bounds[0]%8u))) return false;
        std::array<std::uint64_t,owned_context::kMaxWarMembers> actual{};
        if (count && !reader.read(bounds[0],actual.data(),static_cast<std::size_t>(count)*8u)) return false;
        for (std::uint32_t i=0;i<count;++i) if (actual[i]!=expected[i]) return false;
    }
    return true;
}
inline bool id_valid(const std::array<char,30>& id) noexcept {
    if (id[0]!='w' || id[1]!='a' || id[2]!='r' || id[3]!='_' || id[20]!='_' || id[29]!=0) return false;
    for (unsigned i=4;i<29;++i) {
        if (i==20) continue;
        if (!((id[i]>='0' && id[i]<='9') || (id[i]>='a' && id[i]<='f'))) return false;
    }
    return true;
}
} // namespace detail

// Register signature: bool(Address candidate, char* public_id, size_t capacity).
// It must copy an existing/new shared registry ID without a game call or I/O.
template<class Reader,class Register>
Identity capture(Reader& source,Address base,Address candidate,bool known_router,
    const owned_context::Snapshot& context,const owned_result::Snapshot& result,
    std::uint64_t creation,Register& register_war) noexcept {
    Identity out{};
    out.process_creation_filetime=creation;
    out.raw_date=result.raw_date;
    auto fail=[&](std::uint8_t reason) noexcept {
        out.status=2;out.reason=reason;out.binding_flags=0;
        out.pair_full_refs={};out.war_id={};
        return out;
    };
    if (!known_router || !context.known_router) return fail(1);
    if (!creation || !candidate || context.war_context_status!=owned_context::WarContextStatus::observed
        || !context.war_members.vectors_complete) return fail(2);
    if (!detail::opposing_participants(context,result)) return fail(3);
    detail::Budget<Reader> reader(source);
    Address countries[2]{}; detail::Pair first[2]{};
    if (!detail::code(reader,base)
        || !detail::country(reader,base,result.sides[0].country,countries[0])
        || !detail::country(reader,base,result.sides[1].country,countries[1])
        || !detail::war_snapshot(reader,base,candidate,context.war_members)
        || !detail::associations(reader,countries[0],result.sides[1].country,first[0])
        || !detail::associations(reader,countries[1],result.sides[0].country,first[1])
        || !detail::same(first[0],first[1]) || !detail::has(first[0],candidate)) return fail(4);
    Address after_countries[2]{}; detail::Pair second[2]{};
    if (!detail::code(reader,base)
        || !detail::country(reader,base,result.sides[0].country,after_countries[0])
        || !detail::country(reader,base,result.sides[1].country,after_countries[1])
        || countries[0]!=after_countries[0] || countries[1]!=after_countries[1]
        || !detail::war_snapshot(reader,base,candidate,context.war_members)
        || !detail::associations(reader,after_countries[0],result.sides[1].country,second[0])
        || !detail::associations(reader,after_countries[1],result.sides[0].country,second[1])
        || !detail::same(second[0],second[1])
        || !detail::same(first[0],second[0]) || !detail::same(first[1],second[1])) return fail(5);
    if (!register_war(candidate,out.war_id.data(),out.war_id.size()) || !detail::id_valid(out.war_id)) return fail(6);
    out.status=1;out.reason=0;out.binding_flags=kBoundFlags;
    out.pair_full_refs={result.sides[0].country,result.sides[1].country};
    return out;
}
} // namespace information::battle::war_binding
#endif

