#include "filter.h"
#include "pkts/udp.h"
#include "pkts/dns.h"

// dns_dec: Decode UDP header
int dns_dec_perform(Agnode_t * node, void * filter, struct ln_pkt * pkt) {
    struct ln_pkt_dns * dns = LN_PKT_DEC(pkt, dns);
    if (dns == NULL) return -1;

    int rc = 0; 
    for (AG_EACH_EDGEOUT(node, edge)) {
        rc |= ln_filter_push(edge, &dns->dns_pkt);
    }

    ln_pkt_decref(&dns->dns_pkt);
    return rc;
}
LN_FILTER_TYPE_DECLARE_STATELESS(dns_dec)
