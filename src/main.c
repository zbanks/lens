#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

#include "pkt.h"
#include "base.h"
#include "filter.h"
#include "libdill/libdill.h"
#include "pkts/lowlevel.h"
#include "pkts/udp.h"

enum loglevel loglevel = LOGLEVEL_INFO;

void coroutine ln_run_read_sock(int sock, int pkt_out) {
    int * sock_src = calloc(1, 1); // random id; memory leak is ok
    if (sock_src == NULL) goto fail;

    while (1) {
        int rc = fdin(sock, -1);
        if (rc < 0) goto fail;

        struct ln_pkt_raw * raw = ln_pkt_raw_frecv(sock);
        if (raw == NULL && errno == EAGAIN) continue; // Not ready; retry
        if (raw == NULL && errno == EMSGSIZE) continue; // Too big; skip
        if (raw == NULL) goto fail;

        rc = chsend(pkt_out, &raw, sizeof raw, -1);
        if (rc < 0) goto fail;
    }

fail:
    PERROR("fail");
    return;
}

void coroutine ln_run_write_sock(int sock, int pkt_in) {
    while (1) {
        int rc = fdout(sock, -1);
        if (rc < 0) goto fail;

        struct ln_pkt * pkt = NULL;
        rc = chrecv(pkt_in, &pkt, sizeof pkt, -1);
        if (rc < 0) goto fail;

        struct ln_pkt * enc_pkt = ln_pkt_enc(pkt);
        if (enc_pkt == NULL) goto fail;
        struct ln_pkt_raw * pkt_raw = LN_PKT_CAST(enc_pkt, raw);
        if (pkt_raw == NULL) goto fail;
        ln_pkt_decref(pkt);

        do {
            //rc = ln_pkt_raw_fsend(pkt_raw);
            rc = 0;
        } while (rc < 0 && errno == EAGAIN);
        if (rc < 0) goto fail;
    }

fail:
    PERROR("fail");
    return;
}

int main(int argc, char ** argv) {
    const char * filename = "lens.dot";

    // Load filter graph
    FILE * f = fopen(filename, "r");
    if (f == NULL) PFAIL("Unable to open file '%s' for reading", filename);

    struct ln_graph * graph = ln_graph_load(f);
    if (graph == NULL) PFAIL("Unable to load graph from file '%s'", filename);

    if (fclose(f) < 0) PFAIL("Unable to close file '%s'", filename);

    int raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_sock < 0) PFAIL("Unable to open socket");

    go(ln_run_read_sock(raw_sock, graph->graph_input));
    go(ln_run_write_sock(raw_sock, graph->graph_output));
    go(ln_filter_run(128));
    go(ln_graph_run(graph));

    msleep(-1);

    return 0;
}
