#include "filter.h"
#include "pkts/lowlevel.h"
#include "pkts/udp.h"

// eth_dec: Decode Ethernet header from a raw packet
int eth_dec_perform(Agnode_t * node, void * filter, struct ln_pkt * pkt) {
    struct ln_pkt_eth * eth = LN_PKT_DEC(pkt, eth);
    if (eth == NULL) return -1;

    int rc = 0; 
    for (AG_EACH_EDGEOUT(node, edge)) {
        int type = ln_pkt_eth_parse_type(agget(edge, "ethertype"));
        if (type < 0 || (int) eth->eth_type == type)
            rc |= ln_filter_push(edge, &eth->eth_pkt);
    }

    ln_pkt_decref(&eth->eth_pkt);
    return rc;
}
LN_FILTER_TYPE_DECLARE_STATELESS(eth_dec)

// ipv4_dec: Decode IPv4 header from ethernet packet (if applicable) (FIXME)
int ipv4_dec_perform(Agnode_t * node, void * filter, struct ln_pkt * pkt) {
    struct ln_pkt_ipv4 * ipv4 = LN_PKT_DEC(pkt, ipv4);
    if (ipv4 == NULL) return -1;

    int rc = 0; 
    for (AG_EACH_EDGEOUT(node, edge)) {
        int proto = ln_pkt_ipv4_parse_proto(agget(edge, "proto"));
        if (proto < 0 || (int) ipv4->ipv4_proto == proto)
            rc |= ln_filter_push(edge, &ipv4->ipv4_pkt);
    }

    ln_pkt_decref(&ipv4->ipv4_pkt);
    return rc;
}
LN_FILTER_TYPE_DECLARE_STATELESS(ipv4_dec)

// udp_dec: Decode UDP header & route based on port
int udp_dec_perform(Agnode_t * node, void * filter, struct ln_pkt * pkt) {
    struct ln_pkt_udp * udp = LN_PKT_DEC(pkt, udp);
    if (udp == NULL) return -1;

    int rc = 0; 
    int match_count = 0;
    Agedge_t * unmatched = NULL;

    for (AG_EACH_EDGEOUT(node, edge)) {
        const char * unmatched_str = agget(edge, "unmatched");
        if (unmatched_str != NULL && unmatched_str[0] != '\0') {
            if (unmatched != NULL)
                WARN("Multiple 'unmatched' edges on node '%s'", agnameof(node));
            unmatched = edge;
            continue;
        }

        int port = ln_pkt_udp_parse_port(agget(edge, "port"));
        int dst = ln_pkt_udp_parse_port(agget(edge, "dst"));
        int src = ln_pkt_udp_parse_port(agget(edge, "src"));
        bool is_match = false;
        is_match |= dst < 0 && src < 0 && port < 0;
        is_match |= dst >= 0 && dst == (int) udp->udp_dst;
        is_match |= src >= 0 && src == (int) udp->udp_src;
        is_match |= port >= 0 && port == (int) udp->udp_dst;
        is_match |= port >= 0 && port == (int) udp->udp_src;

        if (is_match) {
            rc |= ln_filter_push(edge, &udp->udp_pkt);
            match_count++;
        }
    }
    if (match_count == 0 && unmatched != NULL) {
        rc |= ln_filter_push(unmatched, &udp->udp_pkt);
    }

    ln_pkt_decref(&udp->udp_pkt);
    return rc;
}
LN_FILTER_TYPE_DECLARE_STATELESS(udp_dec)

//
