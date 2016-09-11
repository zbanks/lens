#include "filter.h"
#include "pkts/lowlevel.h"
#include "pkts/tcp.h"

struct tcp_conn_manager {
    struct tcp_conn * conn_head;
};

struct tcp_conn_key {
    uchar key_srv[34];
    uchar key_cli[34];
};

struct tcp_conn {
    struct tcp_conn * conn_next;
    struct tcp_conn_key conn_key;
};

struct tcp_conn * tcp_conn_lookup(struct tcp_conn_manager * mgr, struct ln_pkt_tcp * tcp, bool * is_srv) {
    struct tcp_conn_key key;
    memset(&key, 0, sizeof key);

    struct ln_pkt_ipv4 * ipv4 = LN_PKT_CAST(tcp->tcp_pkt.pkt_parent, ipv4);
    //struct ln_pkt_ipv6 * ipv6 = LN_PKT_CAST(tcp->tcp_pkt->pkt_parent, ipv6);
    if (ipv4 != NULL) {
        memcpy(&key.key_srv[2], &ipv4->ipv4_src, sizeof ipv4->ipv4_src);
        memcpy(&key.key_cli[2], &ipv4->ipv4_dst, sizeof ipv4->ipv4_dst);
        /*
    } else if (ipv6 != NULL) {
        memcpy(&key.key_srv[2], &ipv6->ipv6_src, sizeof ipv6->ipv6_src);
        memcpy(&key.key_cli[2], &ipv6->ipv6_dst, sizeof ipv6->ipv6_dst);
        */
    } else {
        ERROR("TCP parent is neither IPv4 nor IPv6");
        return NULL;
    }

    for (struct tcp_conn * conn = mgr->conn_head; conn != NULL; conn = conn->conn_next) {
        if (memcmp(conn->conn_key.key_srv, key.key_srv, sizeof key.key_srv) == 0
         && memcmp(conn->conn_key.key_cli, key.key_cli, sizeof key.key_cli) == 0) {
            *is_srv = true;
            return conn;
        }
        if (memcmp(conn->conn_key.key_cli, key.key_srv, sizeof key.key_srv) == 0
         && memcmp(conn->conn_key.key_srv, key.key_cli, sizeof key.key_cli) == 0) {
            *is_srv = false;
            return conn;
        }
    }
    
    struct tcp_conn * conn = calloc(1, sizeof *conn);
    if (conn == NULL) return NULL;
    conn->conn_next = mgr->conn_head;
    mgr->conn_head = conn;

    INFO("New tcp connection");
    ln_pkt_fdump(&tcp->tcp_pkt, stderr);
    fprintf(stderr, "\n");

    memcpy(&conn->conn_key, &key, sizeof key);
    return conn;
}

// tcp_dec: Decode TCP header and associate with connection
void * tcp_dec_create(Agnode_t * node) {
    struct tcp_conn_manager * mgr = calloc(1, sizeof(struct tcp_conn_manager));
    return mgr;
}

void tcp_dec_destroy(Agnode_t * node, void * filter) {
    if (filter == NULL) return;

    struct tcp_conn_manager * mgr = filter;
    while (mgr->conn_head != NULL) {
        struct tcp_conn * conn = mgr->conn_head;
        mgr->conn_head = conn->conn_next;
        // TODO: Dangling conn pointers?
        free(conn);
    }
    free(mgr);
}

int tcp_dec_perform(Agnode_t * node, void * filter, struct ln_pkt * pkt) {
    struct tcp_conn_manager * mgr = filter;

    struct ln_pkt_tcp * tcp = LN_PKT_DEC(pkt, tcp);
    if (tcp == NULL) return -1;

    bool is_srv = false;
    tcp->tcp_conn = tcp_conn_lookup(mgr, tcp, &is_srv);

    int rc = 0; 
    for (AG_EACH_EDGEOUT(node, edge)) {
        rc |= ln_filter_push(edge, &tcp->tcp_pkt);
    }

    ln_pkt_decref(&tcp->tcp_pkt);
    return rc;
}
LN_FILTER_TYPE_DECLARE(tcp_dec)
