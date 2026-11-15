#include "information-battle-outcome-tail-record.h"
#include <cstdio>
#include <limits>

namespace owned = information::battle::owned_outcome_tail;
namespace wire = information::battle::outcome_tail_wire;
namespace record = information::battle::outcome_tail_record;
namespace model = information::battle::display_context;
static owned::Snapshot source;
static wire::Snapshot target;
static owned::Result result;
static unsigned checks=0, failures=0;
static void check(bool value) { ++checks; if (!value) ++failures; }
static void setup() {
    source={}; result={};
    source.sequence=17; source.raw_date=12345; source.kind=2;
    source.reserved_slots={{(std::numeric_limits<std::int32_t>::min)(),-1,
                            (std::numeric_limits<std::int32_t>::max)()}};
    source.language.state=model::State::observed;
    source.language.length=9;
    std::memcpy(source.language.bytes.data(),"l_english",9);
    for (auto& field:source.fields) field.state=model::State::observed;
    source.fields[0].length=8192;
    source.fields[0].bytes.fill('A'); source.fields[0].bytes[8192]=0;
    source.fields[1].state=model::State::absent;
    result.attempted=true; result.observed=true; result.two_pass_consistent=true;
    result.failure=model::Failure::none;
}
static void cleared() {
    check(target.failure!=0);
    check(target.reserved_slots==std::array<std::int32_t,3>{});
    for (const auto& field:target.fields) {
        check(field.state==wire::State::unknown && field.length==0);
        check(field.bytes.front()==0 && field.bytes.back()==0);
    }
}
int main() {
    setup();
    check(record::assign(17,12345,2,true,source,result,target));
    check(target.failure==0 && target.reserved_slots==source.reserved_slots);
    check(target.fields[0].length==9 && target.fields[1].length==8192);
    check(target.fields[1].bytes.front()=='A' && target.fields[1].bytes.back()=='A');
    check(target.fields[2].state==wire::State::absent);
    check(target.fields[3].state==wire::State::known && target.fields[3].length==0);
    check(record::assign(17,12345,2,false,source,result,target)); cleared();
    setup(); source.sequence=18;
    check(record::assign(17,12345,2,true,source,result,target)); cleared();
    setup(); source.language.bytes[0]=0;
    check(record::assign(17,12345,2,true,source,result,target)); cleared();
    setup(); result.failure=model::Failure::guard;
    check(record::assign(17,12345,2,false,source,result,target));
    check(target.failure==static_cast<std::uint16_t>(model::Failure::guard)); cleared();
    setup(); source.reserved_slots={{7,7,7}};
    check(record::assign(17,12345,2,true,source,result,target));
    check(target.failure==0 && target.reserved_slots==source.reserved_slots);
    std::printf("{\"checks\":%u,\"failures\":%u,\"scenarios\":6}\n",checks,failures);
    return failures ? 1 : 0;
}
