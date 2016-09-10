#include "filter.h"

// eth_dec: Decode Ethernet header from a raw packet
int eth_dec_perform(Agnode_t * node, void * filter, struct ln_pkt * pkt) {
    struct ln_pkt * eth_pkt = ln_pkt_eth_dec(pkt);
    if (eth_pkt == NULL) return -1;
    struct ln_pkt_eth * eth = LN_PKT_CAST(eth_pkt, eth);
    if (eth == NULL) return -1;

    int rc = 0; 
    for (AG_EACH_EDGEOUT(node, edge)) {
        int type = ln_pkt_eth_parse_type(agget(edge, "ethertype"));
        if (type < 0 || (int) eth->eth_type == type)
            rc |= ln_filter_push(edge, eth_pkt);
    }

    ln_pkt_decref(eth_pkt);
    return rc;
}
LN_FILTER_TYPE_DECLARE_STATELESS(eth_dec);

// ipv4_dec: Decode IPv4 header from ethernet packet (if applicable) (FIXME)
int ipv4_dec_perform(Agnode_t * node, void * filter, struct ln_pkt * pkt) {
    struct ln_pkt * ipv4_pkt = ln_pkt_ipv4_dec(pkt);
    if (ipv4_pkt == NULL) return -1;
    struct ln_pkt_ipv4 * ipv4 = LN_PKT_CAST(ipv4_pkt, ipv4);
    if (ipv4 == NULL) return -1;

    int rc = 0; 
    for (AG_EACH_EDGEOUT(node, edge)) {
        int proto = ln_pkt_ipv4_parse_proto(agget(edge, "proto"));
        if (proto < 0 || (int) ipv4->ipv4_proto == proto)
            rc |= ln_filter_push(edge, ipv4_pkt);
    }

    ln_pkt_decref(ipv4_pkt);
    return rc;
}
LN_FILTER_TYPE_DECLARE_STATELESS(ipv4_dec);

// udp_dec: Decode UDP header
int udp_dec_perform(Agnode_t * node, void * filter, struct ln_pkt * pkt) {
    struct ln_pkt * udp_pkt = ln_pkt_udp_dec(pkt);
    if (udp_pkt == NULL) return -1;

    struct ln_pkt_udp * udp = LN_PKT_CAST(udp_pkt, udp);
    if (udp == NULL) return -1;

    int rc = 0; 
    for (AG_EACH_EDGEOUT(node, edge)) {
        int port = ln_pkt_udp_parse_port(agget(edge, "port"));
        int dst = ln_pkt_udp_parse_port(agget(edge, "dst"));
        int src = ln_pkt_udp_parse_port(agget(edge, "src"));
        bool is_match = false;
        is_match |= dst < 0 && src < 0 && port < 0;
        is_match |= dst >= 0 && dst == (int) udp->udp_dst;
        is_match |= src >= 0 && src == (int) udp->udp_src;
        is_match |= port >= 0 && port == (int) udp->udp_dst;
        is_match |= port >= 0 && port == (int) udp->udp_src;

        if (is_match)
            rc |= ln_filter_push(edge, udp_pkt);
    }

    ln_pkt_decref(udp_pkt);
    return rc;
}
LN_FILTER_TYPE_DECLARE_STATELESS(udp_dec);

//

LN_ATTRIBUTE_CONSTRUCTOR
static void init() {
    ln_filter_type_register(&eth_dec);
    ln_filter_type_register(&ipv4_dec);
    ln_filter_type_register(&udp_dec);
}
