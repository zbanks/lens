#include "filter.h"

// print: Print a dump of every packet that passes through

int print_perform(Agnode_t * node, void * filter, struct ln_pkt * pkt) {
    const char * prefix = agget(node, "prefix");
    if (prefix != NULL && prefix[0] != '\0')
        fprintf(stderr, "%s: ", prefix);
    else
        fprintf(stderr, "Debug %s: ", agnameof(node));

    int len = 0;
    if (ln_ag_attr_bool(node, "all", true))
        len = ln_pkt_fdumpall(pkt, stderr);
    else
        len = ln_pkt_fdump(pkt, stderr);
    len += fprintf(stderr, "\n");
    if (ln_ag_attr_bool(node, "data", false))
        len += ln_data_fdump(pkt->pkt_data, stderr);

    int rc = 0;
    for (AG_EACH_EDGEOUT(node, edge)) {
        rc += ln_filter_push(edge, pkt);
    }

    return rc;
}
LN_FILTER_TYPE_DECLARE_STATELESS(print)
