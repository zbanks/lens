#include "filter.h"

// eth_dec: Decode Ethernet header from a raw packet

int eth_dec_perform(Agnode_t * node, void * filter, struct ln_pkt * pkt) {
    struct ln_pkt * eth_pkt = ln_pkt_eth_dec(pkt);
    if (eth_pkt == NULL) return -1;

    int rc = 0; 
    for (AG_EACH_EDGEOUT(node, edge)) {
        rc |= ln_filter_push(edge, eth_pkt);
    }

    ln_pkt_decref(eth_pkt);
    return rc;
}
LN_FILTER_TYPE_DECLARE_STATELESS(eth_dec);

// ipv4_dec: Decode IPv4 header from ethernet packet (if applicable) (FIXME)

int ipv4_dec_perform(Agnode_t * node, void * filter, struct ln_pkt * pkt) {
    // Only take ethernet packets with ethertype IPv4
    struct ln_pkt_eth * eth_pkt = LN_PKT_CAST(pkt, eth);
    if (eth_pkt == NULL) return 0;
    if (eth_pkt->eth_type != LN_PROTO_ETH_TYPE_IPV4) return 0;

    struct ln_pkt * ipv4_pkt = ln_pkt_ipv4_dec(pkt);
    if (ipv4_pkt == NULL) return -1;

    int rc = 0; 
    for (AG_EACH_EDGEOUT(node, edge)) {
        rc |= ln_filter_push(edge, ipv4_pkt);
    }

    ln_pkt_decref(ipv4_pkt);
    return rc;
}
LN_FILTER_TYPE_DECLARE_STATELESS(ipv4_dec);

//

LN_ATTRIBUTE_CONSTRUCTOR
static void init() {
    ln_filter_type_register(&eth_dec);
    ln_filter_type_register(&ipv4_dec);
}
