#include "../information-current-country-control-policy.h"

#include <cstdint>
#include <iostream>
#include <string>
#include <string_view>

namespace policy=information::current_country_control;

struct Checks {
    int passed=0;
    int failed=0;

    void expect(const char* name,bool actual,bool wanted=true) {
        if (actual==wanted) {
            ++passed;
            std::cout<<"PASS "<<name<<"\n";
        } else {
            ++failed;
            std::cout<<"FAIL "<<name<<" actual="<<(actual?"true":"false")
                     <<" wanted="<<(wanted?"true":"false")<<"\n";
        }
    }

    void expect_reason(const char* name,policy::Reason actual,policy::Reason wanted) {
        expect(name,actual==wanted);
    }
};

static void copy_text(std::array<char,65>& destination,std::string_view source) {
    destination.fill('\0');
    for (std::size_t index=0; index<source.size() && index<destination.size(); ++index)
        destination[index]=source[index];
}

static std::string sha_text(char value='a') {
    return std::string(64u,value);
}

static std::string request_text(std::string_view id="request_1",
                                std::string_view pid="123",
                                std::string_view creation="456",
                                std::string_view date="789",
                                std::string_view sha=std::string_view{},
                                std::string_view from="POR",
                                std::string_view to="FRA") {
    const std::string digest=sha.empty()?sha_text():std::string(sha);
    return "EU4COUNTRY1 TEST_ONLY "+std::string(id)+" "+std::string(pid)+" "+
        std::string(creation)+" "+std::string(date)+" "+digest+" "+
        std::string(from)+" "+std::string(to)+"\n";
}

static std::uint64_t make_ref(policy::Country country,std::uint16_t slot=189u,
                              std::uint8_t high=1u) {
    const char* value=policy::tag(country);
    const std::uint64_t low=static_cast<std::uint64_t>(static_cast<unsigned char>(value[0]))
        | (static_cast<std::uint64_t>(static_cast<unsigned char>(value[1]))<<8u)
        | (static_cast<std::uint64_t>(static_cast<unsigned char>(value[2]))<<16u);
    return (static_cast<std::uint64_t>(high)<<56u)
        | (static_cast<std::uint64_t>(slot)<<32u) | low;
}

static policy::Request make_request() {
    policy::Request result{};
    copy_text(result.id,"request_1");
    copy_text(result.dll_sha,sha_text());
    result.pid=123u;
    result.creation=456u;
    result.date=789;
    result.from=policy::Country::por;
    result.to=policy::Country::fra;
    return result;
}

static policy::Identity make_identity(const policy::Request& request) {
    return policy::Identity{request.pid,request.creation,request.dll_sha};
}

static policy::Snapshot make_snapshot() {
    return policy::Snapshot{
        static_cast<std::uintptr_t>(UINT64_C(0x0000000140001000)),
        static_cast<std::uintptr_t>(UINT64_C(0x0000000200001000)),
        static_cast<std::uintptr_t>(UINT64_C(0x0000000300001000)),
        make_ref(policy::Country::por,189u,1u),
        make_ref(policy::Country::fra,44u,2u),
        789,0,300,1,true,false,true,
    };
}

static void test_parser(Checks& checks) {
    policy::Request parsed{};
    const auto valid=request_text();
    checks.expect("parse-exact-lf-request",policy::parse_request(valid,parsed));
    checks.expect("parse-id",std::string(parsed.id.data())=="request_1");
    checks.expect("parse-exact-numeric-values",parsed.pid==123u && parsed.creation==456u
                  && parsed.date==789);
    checks.expect("parse-sha-lowercase",std::string(parsed.dll_sha.data())==sha_text());
    checks.expect("parse-country-direction",parsed.from==policy::Country::por
                  && parsed.to==policy::Country::fra);

    const auto rejected=[&checks](const char* name,const std::string& packet) {
        policy::Request output{};
        checks.expect(name,!policy::parse_request(packet,output));
    };
    rejected("reject-missing-final-lf",valid.substr(0,valid.size()-1u));
    rejected("reject-crlf",valid.substr(0,valid.size()-1u)+"\r\n");
    rejected("reject-embedded-nul",valid.substr(0,20u)+std::string(1u,'\0')+valid.substr(20u));
    rejected("reject-extra-token",valid.substr(0,valid.size()-1u)+" extra\n");
    rejected("reject-double-space",valid.substr(0,12u)+" "+valid.substr(12u));
    rejected("reject-overlong-packet",valid.substr(0,valid.size()-1u)+std::string(321u,'x')+"\n");
    rejected("reject-empty-id",request_text(""));
    rejected("reject-invalid-id-character",request_text("bad.id"));
    rejected("reject-id-over-64",request_text(std::string(65u,'x')));
    rejected("reject-pid-overflow",request_text("id","4294967296"));
    rejected("reject-creation-overflow",request_text("id","123","18446744073709551616"));
    rejected("reject-date-overflow",request_text("id","123","456","2147483648"));
    rejected("reject-zero-pid",request_text("id","0"));
    rejected("reject-zero-creation",request_text("id","123","0"));
    rejected("reject-zero-date",request_text("id","123","456","0"));
    rejected("reject-signed-numeric",request_text("id","+123"));
    rejected("reject-nonnumeric-suffix",request_text("id","123x"));
    rejected("reject-uppercase-sha",request_text("id","123","456","789",sha_text('A')));
    rejected("reject-nonhex-sha",request_text("id","123","456","789",std::string(63u,'a')+"g"));
    rejected("reject-unknown-from-country",request_text("id","123","456","789",{},"ENG","FRA"));
    rejected("reject-unknown-to-country",request_text("id","123","456","789",{},"POR","ENG"));
    rejected("reject-same-country",request_text("id","123","456","789",{},"POR","POR"));
    rejected("reject-reversed-unsupported-country-pair",request_text("id","123","456","789",{},"FRA","ENG"));
}

static void test_admission(Checks& checks) {
    const auto request=make_request();
    const auto identity=make_identity(request);
    const auto snapshot=make_snapshot();
    checks.expect_reason("admit-valid-transition",
        policy::admit(request,identity,snapshot,true,true,0u),policy::Reason::ok);
    checks.expect("country-tags-and-bits",std::string(policy::tag(policy::Country::por))=="POR"
        && std::string(policy::tag(policy::Country::fra))=="FRA"
        && policy::bit(policy::Country::fra)==1u && policy::bit(policy::Country::por)==2u);
    checks.expect("admission-ok-name",std::string(policy::reason_name(policy::Reason::ok))=="ok");

    auto changed_identity=identity;
    changed_identity.pid++;
    checks.expect_reason("reject-identity-mismatch",
        policy::admit(request,changed_identity,snapshot,true,true,0u),policy::Reason::identity_mismatch);
    checks.expect_reason("reject-already-attempted-destination",
        policy::admit(request,identity,snapshot,true,true,policy::bit(request.to)),
        policy::Reason::direction_already_attempted);
    checks.expect_reason("reject-code-guard-failure",
        policy::admit(request,identity,snapshot,false,true,0u),policy::Reason::code_guard_failed);
    checks.expect_reason("reject-active-capture",
        policy::admit(request,identity,snapshot,true,false,0u),policy::Reason::capture_not_idle);

    auto changed=snapshot;
    changed.read_ok=false;
    checks.expect_reason("reject-unreadable-snapshot",
        policy::admit(request,identity,changed,true,true,0u),policy::Reason::snapshot_read_failed);
    changed=snapshot; changed.date++;
    checks.expect_reason("reject-stale-date",
        policy::admit(request,identity,changed,true,true,0u),policy::Reason::stale_date);
    changed=snapshot; changed.paused=false;
    checks.expect_reason("reject-not-paused",
        policy::admit(request,identity,changed,true,true,0u),policy::Reason::game_not_paused);
    changed=snapshot; changed.speed=1;
    checks.expect_reason("reject-nonzero-speed",
        policy::admit(request,identity,changed,true,true,0u),policy::Reason::game_not_paused);
    changed=snapshot; changed.alternate_current=true;
    checks.expect_reason("reject-alternate-current",
        policy::admit(request,identity,changed,true,true,0u),policy::Reason::alternate_current_active);
    changed=snapshot; changed.human_count=0;
    checks.expect_reason("reject-zero-human-bootstrap-state",
        policy::admit(request,identity,changed,true,true,0u),policy::Reason::human_count_not_single_player);
    changed=snapshot; changed.human_count=2;
    checks.expect_reason("reject-multiple-humans",
        policy::admit(request,identity,changed,true,true,0u),policy::Reason::human_count_not_single_player);
    changed=snapshot; changed.human_count=-1;
    checks.expect_reason("reject-negative-human-count",
        policy::admit(request,identity,changed,true,true,0u),policy::Reason::human_count_not_single_player);
    checks.expect("human-count-rejection-reason-name",
        std::string(policy::reason_name(policy::Reason::human_count_not_single_player))
            =="human_count_not_single_player");
    changed=snapshot; changed.province_count=0;
    checks.expect_reason("reject-empty-province-table",
        policy::admit(request,identity,changed,true,true,0u),policy::Reason::province_count_invalid);
    changed=snapshot; changed.game=0x1000u;
    checks.expect_reason("reject-noncanonical-game-pointer",
        policy::admit(request,identity,changed,true,true,0u),policy::Reason::game_pointer_invalid);
    changed=snapshot; changed.player_country=0;
    checks.expect_reason("reject-null-country-pointer",
        policy::admit(request,identity,changed,true,true,0u),policy::Reason::country_pointer_invalid);
    changed=snapshot; changed.target_country=changed.player_country;
    checks.expect_reason("reject-identical-country-pointers",
        policy::admit(request,identity,changed,true,true,0u),policy::Reason::country_pointers_not_distinct);
    changed=snapshot; changed.player_ref=make_ref(policy::Country::por,189u,0u);
    checks.expect_reason("reject-zero-fullref-generation-byte",
        policy::admit(request,identity,changed,true,true,0u),policy::Reason::player_reference_invalid);
    changed=snapshot; changed.player_ref=make_ref(policy::Country::fra,189u,1u);
    checks.expect_reason("reject-player-fullref-tag-mismatch",
        policy::admit(request,identity,changed,true,true,0u),policy::Reason::player_tag_mismatch);
    changed=snapshot; changed.target_ref=make_ref(policy::Country::por,44u,2u);
    checks.expect_reason("reject-target-fullref-tag-mismatch",
        policy::admit(request,identity,changed,true,true,0u),policy::Reason::target_tag_mismatch);

    auto invalid_request=request;
    invalid_request.from=policy::Country::fra;
    checks.expect_reason("reject-invalid-request-direction",
        policy::admit(invalid_request,identity,snapshot,true,true,0u),policy::Reason::invalid_request);
}

static void test_precondition_and_effect(Checks& checks) {
    const auto request=make_request();
    const auto before=make_snapshot();
    checks.expect("same-precondition-equal-snapshots",policy::same_precondition(before,before));
    auto changed=before; changed.game++;
    checks.expect("same-precondition-compares-game",!policy::same_precondition(before,changed));
    changed=before; changed.player_country++;
    checks.expect("same-precondition-compares-player-country",!policy::same_precondition(before,changed));
    changed=before; changed.target_country++;
    checks.expect("same-precondition-compares-target-country",!policy::same_precondition(before,changed));
    changed=before; changed.player_ref++;
    checks.expect("same-precondition-compares-player-fullref",!policy::same_precondition(before,changed));
    changed=before; changed.target_ref++;
    checks.expect("same-precondition-compares-target-fullref",!policy::same_precondition(before,changed));
    changed=before; changed.date++;
    checks.expect("same-precondition-compares-date",!policy::same_precondition(before,changed));
    changed=before; changed.speed++;
    checks.expect("same-precondition-compares-speed",!policy::same_precondition(before,changed));
    changed=before; changed.province_count++;
    checks.expect("same-precondition-compares-province-count",!policy::same_precondition(before,changed));
    changed=before; changed.human_count++;
    checks.expect("same-precondition-compares-human-count",!policy::same_precondition(before,changed));
    changed=before; changed.paused=false;
    checks.expect("same-precondition-compares-paused",!policy::same_precondition(before,changed));
    changed=before; changed.alternate_current=true;
    checks.expect("same-precondition-compares-alternate-current",!policy::same_precondition(before,changed));
    changed=before; changed.read_ok=false;
    checks.expect("same-precondition-compares-read-status",!policy::same_precondition(before,changed));

    auto after=before;
    after.player_country=static_cast<std::uintptr_t>(UINT64_C(0x0000000400001000));
    after.player_ref=before.target_ref;
    checks.expect("confirm-following-frame-effect-with-new-player-pointer",
        policy::effect_confirmed(request,before,after,1u));
    auto changed_before=before; changed_before.human_count=0;
    checks.expect("reject-effect-with-zero-human-before",
        !policy::effect_confirmed(request,changed_before,after,1u));
    changed_before=before; changed_before.human_count=2;
    checks.expect("reject-effect-with-multiple-humans-before",
        !policy::effect_confirmed(request,changed_before,after,1u));
    changed_before=before; changed_before.human_count=-1;
    checks.expect("reject-effect-with-negative-human-count-before",
        !policy::effect_confirmed(request,changed_before,after,1u));
    auto changed_after=after; changed_after.human_count=0;
    checks.expect("reject-effect-with-zero-human-after",
        !policy::effect_confirmed(request,before,changed_after,1u));
    changed_after=after; changed_after.human_count=2;
    checks.expect("reject-effect-with-multiple-humans-after",
        !policy::effect_confirmed(request,before,changed_after,1u));
    changed_after=after; changed_after.human_count=-1;
    checks.expect("reject-effect-with-negative-human-count-after",
        !policy::effect_confirmed(request,before,changed_after,1u));
    checks.expect("reject-native-return-not-one",
        !policy::effect_confirmed(request,before,after,0u));
    changed_after=after; changed_after.date++;
    checks.expect("reject-following-frame-date-change",
        !policy::effect_confirmed(request,before,changed_after,1u));
    changed_after=after; changed_after.paused=false;
    checks.expect("reject-following-frame-unpaused",
        !policy::effect_confirmed(request,before,changed_after,1u));
    changed_after=after; changed_after.speed=1;
    checks.expect("reject-following-frame-nonzero-speed",
        !policy::effect_confirmed(request,before,changed_after,1u));
    changed_after=after; changed_after.game++;
    checks.expect("reject-following-frame-game-change",
        !policy::effect_confirmed(request,before,changed_after,1u));
    changed_after=after; changed_after.target_ref=make_ref(policy::Country::fra,44u,3u);
    checks.expect("reject-fullref-generation-mismatch",
        !policy::effect_confirmed(request,before,changed_after,1u));
    changed_after=after; changed_after.player_ref=make_ref(policy::Country::fra,44u,3u);
    checks.expect("reject-player-fullref-generation-mismatch",
        !policy::effect_confirmed(request,before,changed_after,1u));
    changed_after=after; changed_after.read_ok=false;
    checks.expect("reject-unreadable-following-frame",
        !policy::effect_confirmed(request,before,changed_after,1u));
}

static void test_automation_policy(Checks& checks) {
    const auto por=make_ref(policy::Country::por,189u,0u);
    const auto por_wrong_slot=make_ref(policy::Country::por,190u,0u);
    const auto fra=make_ref(policy::Country::fra,44u,2u);
    checks.expect("preserve-por-slot-189-automation",policy::allow_automation(por,0u));
    checks.expect("reject-por-other-slot",!policy::allow_automation(por_wrong_slot,0u));
    checks.expect("block-fra-without-authorization",!policy::allow_automation(fra,0u));
    checks.expect("allow-exact-authorized-fra-reference",policy::allow_automation(fra,fra));
    checks.expect("reject-authorized-fra-generation-mismatch",
        !policy::allow_automation(fra,make_ref(policy::Country::fra,44u,3u)));
    checks.expect("reject-zero-reference",!policy::allow_automation(0u,fra));
}

int main() {
    Checks checks;
    test_parser(checks);
    test_admission(checks);
    test_precondition_and_effect(checks);
    test_automation_policy(checks);
    std::cout<<"SUMMARY passed="<<checks.passed<<" failed="<<checks.failed<<"\n";
    return checks.failed==0?0:1;
}
