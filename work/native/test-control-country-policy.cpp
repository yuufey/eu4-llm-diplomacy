#include "control-country-policy.h"

#include <cstdio>
#include <cstring>
#include <string>

namespace policy=bridge::control_country_policy;

static unsigned checks=0;
static unsigned failures=0;

static void check(bool value,const char* name) {
    ++checks;
    if (!value) {
        ++failures;
        std::printf("fixture_check_failed:%s\n",name);
    }
}

static policy::ParseResult parse(const std::string& wire,
    policy::Request& request) {
    return policy::parse_request(wire.data(),wire.size(),request);
}

static void test_tag_and_handle() {
    check(policy::valid_tag("FRA"),"alpha_tag_valid");
    check(policy::valid_tag("K00"),"numeric_tag_valid");
    check(!policy::valid_tag("k00"),"lowercase_tag_rejected");
    check(!policy::valid_tag("K0"),"short_tag_rejected");
    check(!policy::valid_tag("K0-"),"punctuation_tag_rejected");
    char tag[4]{};
    const std::uint64_t handle=(std::uint64_t(0x1234)<<32)
        | (std::uint64_t('A')<<16) | (std::uint64_t('0')<<8) | 'K';
    check(policy::tag_from_handle(handle,tag)
        && std::strcmp(tag,"K0A")==0,"handle_tag_extracted_low_byte_first");
    check(policy::tag_matches_handle("K0A",handle),"tag_handle_identity_match");
    check(!policy::tag_matches_handle("K00",handle),"tag_handle_identity_mismatch");
}

static void test_parse_and_replace() {
    const std::string wire="EU4CONTROL1\t1234-1abc\t7\tK00,E00,FRA\n";
    policy::Request request{};
    const policy::ParseResult parsed=parse(wire,request);
    check(parsed.ok(),"dynamic_country_set_parses");
    check(std::strcmp(request.session_id,"1234-1abc")==0,"session_copied");
    check(request.revision==7,"revision_parsed");
    check(request.countries.count==3
        && request.countries.contains("K00")
        && request.countries.contains("E00")
        && request.countries.contains("FRA"),"country_set_parsed");

    policy::PolicyState state{};
    check(state.countries.count==1 && state.countries.contains("FRA"),
        "default_legacy_country_is_fra");
    check(state.apply(request,"1234-1abc")==policy::ApplyError::ok,
        "session_bound_set_replaced");
    check(state.revision==7 && state.countries.count==3
        && state.countries.contains("K00") && !state.countries.contains("POR"),
        "full_set_replace_is_atomic_value");

    policy::Request empty{};
    check(parse("EU4CONTROL1\t1234-1abc\t8\t-\n",empty).ok()
        && empty.countries.count==0,"empty_set_parses");
    check(state.apply(empty,"1234-1abc")==policy::ApplyError::ok
        && state.countries.count==0,"empty_set_replaces_all");
}

static void test_policy_binding() {
    policy::Request request{};
    check(parse("EU4CONTROL1\t1234-1abc\t2\tK00\n",request).ok(),
        "request_for_policy_binding");
    policy::PolicyState state{};
    check(state.apply(request,"9999-1abc")==policy::ApplyError::invalid_session,
        "wrong_session_rejected");
    check(state.revision==0 && state.countries.contains("FRA"),
        "wrong_session_preserves_default");
    check(state.apply(request,"1234-1abc")==policy::ApplyError::ok,
        "correct_session_accepted");
    check(state.apply(request,"1234-1abc")==policy::ApplyError::stale_revision,
        "same_revision_rejected");
    request.revision=1;
    check(state.apply(request,"1234-1abc")==policy::ApplyError::stale_revision,
        "older_revision_rejected");
    check(state.revision==2 && state.countries.contains("K00"),
        "stale_revision_preserves_active_set");
}

static void test_malformed_requests() {
    const char* bad[]={
        "EU4CONTROL2\t1234-1abc\t1\tFRA\n",
        "EU4CONTROL1\t1234-1abc\t0\tFRA\n",
        "EU4CONTROL1\tpid-1abc\t1\tFRA\n",
        "EU4CONTROL1\t1234-\t1\tFRA\n",
        "EU4CONTROL1\t1234-1ABC\t1\tFRA\n",
        "EU4CONTROL1\t1234-1abc\t1\tfra\n",
        "EU4CONTROL1\t1234-1abc\t1\tFRA,FRA\n",
        "EU4CONTROL1\t1234-1abc\t1\tFRA,\n",
        "EU4CONTROL1\t1234-1abc\t18446744073709551616\tFRA\n",
        "EU4CONTROL1\t1234-1abc\t1\tFRA\r\n",
        "EU4CONTROL1\t1234-1abc\t1\tFRA"
    };
    for (unsigned index=0;index<sizeof(bad)/sizeof(bad[0]);++index) {
        policy::Request request{};
        check(!parse(bad[index],request).ok(),"malformed_control_request_rejected");
    }
    policy::Request request{};
    check(!parse("EU4CONTROL1\t1234-1abc\t1\tFRA\textra\n",request).ok(),
        "extra_field_rejected");
}

int main() {
    test_tag_and_handle();
    test_parse_and_replace();
    test_policy_binding();
    test_malformed_requests();
    std::printf("checks=%u failures=%u status=%s\n",checks,failures,
        failures==0?"passed":"failed");
    return failures==0?0:1;
}
