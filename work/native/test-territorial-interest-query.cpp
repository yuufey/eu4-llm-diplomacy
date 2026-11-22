#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cassert>
#include <string>

static uintptr_t base=0;
static uint64_t observation_creation=0;
template<class T> static bool read(uintptr_t,T&) { return false; }
static bool alliance_query_country(const char* tag,uint64_t& reference) {
    if (!strcmp(tag,"TUR")) reference=42;
    else if (!strcmp(tag,"ENG")) reference=43;
    else if (!strcmp(tag,"CAS")) reference=44;
    else return false;
    return true;
}
static std::string failure;
static void alliance_query_failure(const char*,const char* code) { failure=code; }
static void line(const char*) {}
#include "territorial-interest-query.inc"

int main() {
    unsigned ids[32]{},count=0;
    assert(territorial_interest_parse("1,65535",ids,count) && count==2 && ids[1]==65535);
    const char* invalid[]={"","0","01","1,","1,,2","1,1","65536","999999999999","-1","+1","1 2"};
    for (const char* text:invalid) assert(!territorial_interest_parse(text,ids,count));
    std::string csv;
    for (unsigned id=1;id<=32;++id) csv+=(id==1?"":",")+std::to_string(id);
    assert(territorial_interest_parse(csv.c_str(),ids,count) && count==32);
    csv+=",33";
    assert(!territorial_interest_parse(csv.c_str(),ids,count));
    territorial_interest_query("test","TUR","ENG","TUR","0",0);
    assert(failure=="QUERY_INTEREST_SCOPE_INVALID");
    territorial_interest_query("test","TUR","ENG","CAS","1",0);
    assert(failure=="QUERY_INTEREST_SCOPE_INVALID");
    territorial_interest_query("test","TUR","ENG","ENG","1",0);
    assert(failure=="QUERY_INTEREST_CODE_MISMATCH");
    std::puts("territorial interest parser cases passed");
}
