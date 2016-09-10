#include "filter.h"

// print: Print a dump of every packet that passes through

int print_perform(Agnode_t * node, void * filter, struct ln_pkt * pkt) {
    fprintf(stderr, "%s: ", agnameof(node));
    int len = ln_pkt_fdumpall(pkt, stderr);
    fprintf(stderr, "\n");

    int rc = len < 0 ? -1 : 0;
    for (AG_EACH_EDGEOUT(node, edge)) {
        rc |= ln_filter_push(edge, pkt);
    }

    return rc;
}
LN_FILTER_TYPE_DECLARE_STATELESS(print);

LN_ATTRIBUTE_CONSTRUCTOR
static void init() {
    ln_filter_type_register(&print);
}
