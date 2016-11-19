#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <signal.h>
#include <malloc.h>

#include "pkt.h"
#include "base.h"
#include "filter.h"
#include "driver.h"
#include "libdill/libdill.h"
#include "pkts/lowlevel.h"
#include "pkts/udp.h"

enum loglevel loglevel = LOGLEVEL_INFO;
static size_t rx_count = 0;
static size_t tx_count = 0;

void coroutine ln_run_read_sock(int sock_src, int sock_dst, int pkt_out) {
    //int * sock_src = calloc(1, 1); // random id; memory leak is ok
    //if (sock_src == NULL) goto fail;

    while (1) {
        int rc = fdin(sock_src, -1);
        if (rc < 0) goto fail;

        struct ln_pkt_raw * raw = ln_pkt_raw_frecv(sock_src);
        if (raw == NULL && errno == EAGAIN) continue; // Not ready; retry
        if (raw == NULL && errno == EMSGSIZE) continue; // Too big; skip
        if (raw == NULL) goto fail;

        // Set destination
        raw->raw_dst = sock_dst;

        rx_count++;
        rc = chsend(pkt_out, &raw, sizeof raw, now() + 100);
        if (rc < 0 && errno == ETIMEDOUT) FAIL("STALL");
        if (rc < 0) goto fail;
    }

fail:
    PFAIL("fail");
    return;
}

void coroutine ln_run_write_sock(int pkt_in) {
    while (1) {
        struct ln_pkt * pkt = NULL;
        int rc = chrecv(pkt_in, &pkt, sizeof pkt, -1);
        if (rc < 0) goto fail;

        struct ln_pkt * enc_pkt = ln_pkt_enc(pkt);
        if (enc_pkt == NULL) goto fail;
        struct ln_pkt_raw * pkt_raw = LN_PKT_CAST(enc_pkt, raw);
        if (pkt_raw == NULL) goto fail;

        if (pkt_raw->raw_dst < 0) {
            WARN("Skipping packet");
            continue;
        }

        while (1) {
            rc = ln_pkt_raw_fsend(pkt_raw);
            if (rc >= 0) break;

            PERROR("fsend failed");
            if (errno != EAGAIN) goto fail; 

            rc = fdout(pkt_raw->raw_dst, now() + 100);
            if (rc < 0 && errno == ETIMEDOUT) PERROR("STALL");
            else if (rc < 0) goto fail;
        }
        if (rc < 0) goto fail;

        tx_count++;
        fprintf(stderr, "tx: %d->%d %d in %0.3lf ms\n",
                pkt_raw->raw_src, pkt_raw->raw_dst,
                rc, (nanos() - pkt_raw->raw_nanos) * (double) 1e-6);
        ln_pkt_decref(&pkt_raw->raw_pkt);
    }

fail:
    PFAIL("fail");
    return;
}

static int get_raw_sock(const char * ifname) {
    char ip_command[512];
    snprintf(ip_command, sizeof(ip_command), "ip link set up promisc on dev '%s'", ifname);
    int rc = system(ip_command);
    if (rc != 0) PFAIL("Unable to set up interface %s", ifname);

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) PFAIL("Unable to open socket for %s", ifname);

    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    rc = ioctl(fd, SIOCGIFINDEX, &ifr);
    if (rc < 0) PFAIL("Unable to lookup interface '%s'", ifname);

    struct sockaddr_ll addr = {
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_ALL),
        .sll_ifindex = ifr.ifr_ifindex, 
    };
    rc = bind(fd, (struct sockaddr *) &addr, sizeof addr);
    if (rc < 0) PFAIL("Unable to bind to interface '%s'", ifname);

    return fd;
}

void coroutine ln_run_tap(void) {
    struct tap_driver * tap = tap_driver_create();
    if (tap == NULL) PFAIL("Unable to open tap device");

    tap_driver_heartbeat(tap, 1000);
    tap_driver_set_led(tap, true);
    tap_driver_set_relays(tap, TAP_DRIVER_RELAYS_MITM);
    tap_driver_set_fault(tap, TAP_DRIVER_RELAYS_PASSTHRU);
    INFO("Set up tap board for MITM mode");

    while (1) {
        tap_driver_heartbeat(tap, 500);
        msleep(now() + 100);
    }
    PFAIL("exit");
}

static void handle_sigsegv(int signal) {
    BACKTRACE("Segmentation Fault");
    raise(signal);
    exit(EXIT_FAILURE);
}

int main(int argc, char ** argv) {
    mallopt(M_CHECK_ACTION, 1);
    signal(SIGSEGV, handle_sigsegv);

    const char * filename = "lens.dot";

    // Load filter graph
    FILE * f = fopen(filename, "r");
    if (f == NULL) PFAIL("Unable to open file '%s' for reading", filename);

    struct ln_graph * graph = ln_graph_load(f);
    if (graph == NULL) PFAIL("Unable to load graph from file '%s'", filename);

    if (fclose(f) < 0) PFAIL("Unable to close file '%s'", filename);

    int raw_sock_a = get_raw_sock("tapa");
    int raw_sock_b = get_raw_sock("tapb");

    go(ln_run_tap());
    go(ln_run_read_sock(raw_sock_a, raw_sock_b, graph->graph_input));
    go(ln_run_read_sock(raw_sock_b, raw_sock_a, graph->graph_input));
    go(ln_run_write_sock(graph->graph_output));
    go(ln_filter_run(128));
    go(ln_graph_run(graph));

    while (1) {
        msleep(1000 + now());
        INFO("%#zx/%#zx data=%#zx raw=%#zx eth=%#zx ipv4=%#zx", 
                rx_count, tx_count,
                data_count, ln_pkt_type_raw->pkt_type_count, ln_pkt_type_eth->pkt_type_count, ln_pkt_type_ipv4->pkt_type_count);
    }

    return 0;
}
