#include "filter.h"
#include "pkts/lowlevel.h"
#include "pkts/tcp.h"

/* 
Generate state transition diagram
---------------------------------

echo 'digraph tcp_states {' > tcp_states.dot
grep -o 'TCP_[A-Z0-9_]*,' tcp.c | tr ',' ';' >> tcp_states.dot
echo '{ edge [color=blue];' >> tcp_states.dot
grep '#src\:' tcp.c | cut -f2 -d: >> tcp_states.dot
echo '} { edge [color=red];' >> tcp_states.dot
grep '#dst\:' tcp.c | cut -f2 -d: >> tcp_states.dot
echo '}}' >> tcp_states.dot
dot -O -Tpng tcp_states.dot

open tcp_states.dot.png

*/

struct tcp_conn_manager {
    struct tcp_conn * conn_head;
};

struct tcp_conn_key {
    uchar key_srv[34];
    uchar key_cli[34];
};

struct tcp_buffer {
    struct tcp_buffer * next;
    struct tcp_buffer * prev;
    uint64_t timestamp;
    struct ln_pkt_tcp * tcp_pkt;
};

#define SERVER 0
#define CLIENT 1
struct tcp_conn {
    struct tcp_conn * conn_next;
    struct tcp_conn_key conn_key;

    Agedge_t * conn_out;
    Agedge_t * conn_pass;

    struct tcp_party {
        struct ln_pkt * party_base_pkt;

        Agedge_t * party_out;

        size_t party_pkt_count;
        enum tcp_state {
            TCP_UNINITIALIZED = 0,
            TCP_RESET,
            TCP_LISTEN,
            TCP_SYN_SENT,
            TCP_SYN_RECEIVED,
            TCP_ESTABLISHED,
            TCP_FIN_WAIT_1,
            TCP_FIN_WAIT_2,
            TCP_CLOSE_WAIT,
            TCP_LAST_ACK,
            TCP_TIME_WAIT,
            TCP_CLOSED,
        } party_state;

        uint16_t party_src;
        uint16_t party_dst;
        uint32_t party_seq;
        uint32_t party_ack;
        // For debugging (relative sequence numbers)
        uint32_t party_seq_start;

        struct ln_data * party_sendq;
        struct ln_data * party_recvq;

        // Sent messages which have not been acknowledged
        struct tcp_buffer party_unacked;
        // Received messages which were out of order
        struct tcp_buffer party_reorder;

        // SYN options
        uint32_t party_min_segment_size;
        uint32_t party_max_segment_size;
        uint32_t party_window_scale;
        uint16_t party_window;

        //struct ln_timebase party_time;
    } conn_parties[2];
};

/*
//TODO
struct ln_timebase {
    double tb_offset;
    double tb_rate;

    size_t tb_count;
    double tb_claims[16];
    double tb_stamps[16];
}
*/

struct tcp_conn * tcp_conn_lookup(struct tcp_conn_manager * mgr, struct ln_pkt_tcp * tcp, uchar * source_id) {
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
            *source_id = SERVER;
            return conn;
        }
        if (memcmp(conn->conn_key.key_cli, key.key_srv, sizeof key.key_srv) == 0
         && memcmp(conn->conn_key.key_srv, key.key_cli, sizeof key.key_cli) == 0) {
            *source_id = CLIENT;
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

static int tcp_conn_pass(struct tcp_conn * conn, struct ln_pkt_tcp * tcp) {
    ASSERT(conn->conn_pass != NULL);
    return ln_filter_push(conn->conn_pass, &tcp->tcp_pkt);
}

static int tcp_conn_send(struct tcp_conn * conn, uchar destination_id, uint8_t tcp_flags) {
    ASSERT(destination_id == SERVER || destination_id == CLIENT);
    uchar dst_id = destination_id;
    //uchar src_id = 1 - destination_id;
    //struct tcp_party * src_party = &conn->conn_parties[src_id];
    struct tcp_party * dst_party = &conn->conn_parties[dst_id];

    //

    size_t payload_size = dst_party->party_max_segment_size;
    struct ln_data * payload = NULL;
    if (dst_party->party_sendq != NULL) {
        struct ln_data * next = NULL;
        while (dst_party->party_sendq && ln_data_len(payload) <= payload_size) {
            if (next == NULL) {
                payload = dst_party->party_sendq;
                next = payload;
            } else {
                next->data_next = dst_party->party_sendq;
            }
            dst_party->party_sendq = next->data_next;
            next->data_next = NULL;
        }
        tcp_flags |= LN_PROTO_TCP_FLAG_PSH;
    }
    payload_size = ln_data_len(payload);
    ASSERT(payload_size <= dst_party->party_max_segment_size);

    //

    struct ln_pkt_tcp * tcp = calloc(1, sizeof *tcp);
    if (tcp == NULL) MEMFAIL();

    tcp->tcp_pkt.pkt_type = ln_pkt_type_tcp;
    tcp->tcp_pkt.pkt_data = payload;
    tcp->tcp_pkt.pkt_parent = dst_party->party_base_pkt;
    ln_pkt_incref(dst_party->party_base_pkt);

    tcp->tcp_src = dst_party->party_src;
    tcp->tcp_dst = dst_party->party_dst;
    tcp->tcp_seq = dst_party->party_seq;
    tcp->tcp_ack = dst_party->party_ack;
    tcp->tcp_flags = tcp_flags;
    tcp->tcp_window = dst_party->party_window;
    // TODO: options; urgent

    //
    if (payload_size > 0) {
        struct tcp_buffer * unacked = calloc(1, sizeof *unacked);
        if (unacked == NULL) MEMFAIL();
        if (dst_party->party_unacked.prev == NULL)
            dst_party->party_unacked.prev = unacked;
        unacked->prev = NULL;
        unacked->next = dst_party->party_unacked.next;
        dst_party->party_unacked.next = unacked;

        unacked->timestamp = now();
        unacked->tcp_pkt = tcp;
        ln_pkt_incref(&tcp->tcp_pkt);
    }

    dst_party->party_seq += payload_size;

    return ln_filter_push(conn->conn_out, &tcp->tcp_pkt);
}

static int tcp_conn_recv(struct tcp_conn * conn, uchar source_id, struct ln_pkt_tcp * tcp) {
    ASSERT(source_id == SERVER || source_id == CLIENT);
    uchar src_id = source_id;
    uchar dst_id = 1 - source_id;
    struct tcp_party * src_party = &conn->conn_parties[src_id];
    struct tcp_party * dst_party = &conn->conn_parties[dst_id];

    int rc = 0;

    // TODO: Update timestamp estimator

    size_t data_len = ln_data_len(tcp->tcp_pkt.pkt_data);
    if (data_len > 0) { // Has data
        if (src_party->party_state == TCP_ESTABLISHED) {
            // Recieve data into buffer
            
            // TODO: Add to party_reorder instead of to sendq
            if (src_party->party_ack != tcp->tcp_seq)
                WARN("Expected seq %u; got %u", src_party->party_ack, tcp->tcp_seq);

            ln_data_extend(&src_party->party_sendq, tcp->tcp_pkt.pkt_data);
            src_party->party_ack += data_len;

            rc |= tcp_conn_send(conn, src_id, LN_PROTO_TCP_FLAG_ACK);
        }
    }

    if (tcp->tcp_flags & LN_PROTO_TCP_FLAG_SYN) {
        dst_party->party_base_pkt = &tcp->tcp_pkt;
        ln_pkt_incref(&tcp->tcp_pkt);

        dst_party->party_dst = src_party->party_src = tcp->tcp_src;
        dst_party->party_src = src_party->party_dst = tcp->tcp_dst;

        dst_party->party_seq = tcp->tcp_seq;
        src_party->party_ack = tcp->tcp_seq + 1;
        dst_party->party_seq_start = tcp->tcp_seq;

        dst_party->party_window = tcp->tcp_window;
        dst_party->party_window_scale = 0;

        src_party->party_min_segment_size = 1;
        src_party->party_max_segment_size = LN_PROTO_TCP_DEFAULT_MSS; //536

        uchar * opt = tcp->tcp_opts;
        while (opt < tcp->tcp_opts + tcp->tcp_optlen) {
            uchar opt_type = *opt++;
            if (opt_type == 0) continue;
            uchar opt_len = *opt++;
            switch (opt_type) {
            case LN_PROTO_TCP_OPT_NOP:
                break;
            case LN_PROTO_TCP_OPT_MSS:
                //TODO: Set MSS
                break;
            case LN_PROTO_TCP_OPT_WSCALE:
                //TODO: Set WSCALE
                break;
            default:
                INFO("Unknown tcp option '%#02x'", opt_type);
                break;
            }
            opt += opt_len;
        }

        if (src_party->party_state == TCP_SYN_SENT) {
            // #src: TCP_SYN_SENT -> TCP_ESTABLISHED;
            src_party->party_state = TCP_ESTABLISHED;
            INFO("Established connection");
            // The ACK reply gets handled later on

            // Forward SYNACK
            // #dst: TCP_UNINITIALIZED -> TCP_SYN_RECEIVED;
            dst_party->party_state = TCP_SYN_RECEIVED;
            rc |= tcp_conn_send(conn, dst_id, LN_PROTO_TCP_FLAG_SYN | LN_PROTO_TCP_FLAG_ACK);
        } else {
            // #dst: TCP_UNINITIALIZED -> TCP_SYN_SENT;
            dst_party->party_state = TCP_SYN_SENT;
            // Forward SYN
            rc |= tcp_conn_send(conn, dst_id, LN_PROTO_TCP_FLAG_SYN);
        }
    }

    if (tcp->tcp_flags & LN_PROTO_TCP_FLAG_FIN) {
        if (src_party->party_state == TCP_ESTABLISHED) {
            src_party->party_ack++;
            // #src: TCP_ESTABLISHED -> TCP_LAST_ACK;
            src_party->party_state = TCP_LAST_ACK;

            if (dst_party->party_state == TCP_ESTABLISHED) {
                // #dst: TCP_ESTABLISHED -> TCP_FIN_WAIT_1;
                dst_party->party_state = TCP_FIN_WAIT_1;

                // Forward FIN - nope! send a close msg
                // TODO: Handle close
                rc |= tcp_conn_send(conn, dst_id, LN_PROTO_TCP_FLAG_FIN | LN_PROTO_TCP_FLAG_ACK);
                dst_party->party_seq++;
            }

            // Reply with FINACK
            rc |= tcp_conn_send(conn, src_id, LN_PROTO_TCP_FLAG_FIN | LN_PROTO_TCP_FLAG_ACK);
            // TODO: Clean up connection
        }
    } else if (tcp->tcp_flags & LN_PROTO_TCP_FLAG_ACK) {
        if (src_party->party_state == TCP_SYN_RECEIVED) {
            // #src: TCP_SYN_RECEIVED -> TCP_ESTABLISHED;
            src_party->party_state = TCP_ESTABLISHED;
            INFO("TCP connection established");
        }

        if (src_party->party_state == TCP_ESTABLISHED) {
            src_party->party_seq = LN_MAX(src_party->party_seq, tcp->tcp_ack);
            // We don't need to ACK unless it's a SYNACK
            if (tcp->tcp_flags & LN_PROTO_TCP_FLAG_SYN) {
                rc |= tcp_conn_send(conn, src_id, LN_PROTO_TCP_FLAG_ACK);
            }
        }

        if (src_party->party_state == TCP_LAST_ACK) {
            // #src: TCP_LAST_ACK -> TCP_CLOSED
            src_party->party_seq = TCP_CLOSED;
            // TODO: Handle close (but the conn is already 'closed')
        }
    }

    if (tcp->tcp_flags & LN_PROTO_TCP_FLAG_RST) {
        if (src_party->party_state == TCP_UNINITIALIZED
         && dst_party->party_state == TCP_UNINITIALIZED) {
            // Pass through unhandled
            rc |= tcp_conn_pass(conn, tcp);
        } else {
            INFO("RST on connection");
            uchar old_dst_state = dst_party->party_state;

            dst_party->party_state = TCP_RESET;
            src_party->party_state = TCP_CLOSED;

            if (old_dst_state == TCP_UNINITIALIZED) {
                INFO("Invalid RST; dst uninitialized");
                // Pass through
                rc |= tcp_conn_pass(conn, tcp);
            } else {
                rc |= tcp_conn_send(conn, dst_id, LN_PROTO_TCP_FLAG_RST);
            }

            // TODO: Handle close
        }
    }

    if (dst_party->party_state == TCP_UNINITIALIZED) {
        // Pass through unhandled
        rc |= tcp_conn_pass(conn, tcp);
    }

    return rc;
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
        // TODO: Implement tcp_conn_destroy
        //tcp_conn_destroy(conn);
        free(conn);
    }
    free(mgr);
}

int tcp_dec_perform(Agnode_t * node, void * filter, struct ln_pkt * pkt) {
    struct tcp_conn_manager * mgr = filter;

    struct ln_pkt_tcp * tcp = LN_PKT_DEC(pkt, tcp);
    if (tcp == NULL) return -1;

    uchar src = 0;
    struct tcp_conn * conn = tcp->tcp_conn = tcp_conn_lookup(mgr, tcp, &src);

    ASSERT(conn != NULL);
    if (conn->conn_out == NULL) {
        for (AG_EACH_EDGEOUT(node, edge)) {
            if (ln_ag_attr_bool(edge, "output", false)) {
                conn->conn_out = edge;
                continue;
            }
            if (ln_ag_attr_bool(edge, "pass", false)) {
                conn->conn_pass = edge;
                continue;
            }
            // TODO: Parse ports to find party_out edges
        }
    }

    int rc = tcp_conn_recv(conn, src, tcp);

    ln_pkt_decref(&tcp->tcp_pkt);
    return rc;
}
LN_FILTER_TYPE_DECLARE(tcp_dec)
