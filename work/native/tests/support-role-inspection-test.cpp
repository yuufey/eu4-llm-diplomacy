#include "../alliance-inbound-inspection-event.h"
#include <cstdio>
#include <cstring>

int main() {
    namespace wire = bridge::alliance_inbound_response_wire;
    namespace events = bridge::alliance_inbound_inspection_event;
    wire::InspectionRequest request{};
    std::strcpy(request.query_id, "support-role-fixture");
    std::strcpy(request.session_id, "20816-1dd5ca22c2f96c4");
    std::strcpy(request.action_id, "support_independence");
    std::strcpy(request.original_actor, "SAV");
    std::strcpy(request.decision_country, "FRA");
    std::strcpy(request.decision, "accept");
    request.native_proposal_id = 1;
    request.date_raw = 56463888;
    events::Observation observed{};
    observed.pending_active = true;
    observed.decision_country_verified = true;
    observed.native_validity = true;
    observed.response_rules_complete = true;
    observed.support_independence = true;
    observed.alliance_readable = true;
    observed.date28 = request.date_raw;
    observed.date2c = request.date_raw;
    observed.envoy30 = 2;
    observed.variant38 = 1;
    observed.proposal3c = 7;
    char output[8192]{};
    for (unsigned index = 0; index < 5; ++index) {
#ifdef BRIDGE_SUPPORT_ROLE_CONTEXT
        observed.support_roles_readable = index < 4;
        observed.support_actor_is_subject = (index & 1u) == 0;
        observed.support_recipient_is_subject = (index & 2u) == 0;
#endif
        if (!events::format(output, sizeof(output), request, observed)) return 1;
        std::fputs(output, stdout);
    }
    observed.support_independence = false;
    std::strcpy(request.action_id, "offer_alliance");
    if (!events::format(output, sizeof(output), request, observed)) return 2;
    std::fputs(output, stdout);
    char small[2]{};
    return events::format(small, sizeof(small), request, observed) ? 3 : 0;
}
