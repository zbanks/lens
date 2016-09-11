#include "pkt.h"

#define LN_PROTO_TCP_HEADER_LEN_MIN 20
#define LN_PROTO_TCP_HEADER_LEN_MAX 64

struct ln_pkt_tcp {
    struct ln_pkt tcp_pkt;
    void * tcp_conn;

    uint16_t tcp_src;
    uint16_t tcp_dst;
    uint32_t tcp_seq;
    uint32_t tcp_ack;
    uint16_t tcp_flags;
    uint16_t tcp_window;
    uint16_t tcp_crc;
    uint16_t tcp_urg;
    //struct ln_chain tcp_opts_chain;
};

extern struct ln_pkt_type * ln_pkt_type_tcp;
struct ln_pkt * ln_pkt_tcp_dec(struct ln_pkt * parent_pkt);
int ln_pkt_tcp_parse_port(const char * port_str);
