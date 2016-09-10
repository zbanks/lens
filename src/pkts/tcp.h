#include "pkt.h"

struct ln_pkt_tcp {
    struct ln_pkt tcp_pkt;

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

struct ln_pkt * ln_pkt_tcp_dec(struct ln_pkt * parent_pkt);
