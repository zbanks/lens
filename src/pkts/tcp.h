#include "pkt.h"

//

#define LN_PROTO_TCP_HEADER_LEN_MIN 20
#define LN_PROTO_TCP_HEADER_LEN_MAX 64
#define LN_PROTO_TCP_DEFAULT_MSS 536

#define LN_PROTO_TCP_FLAGS_MAP(FN, ARG) \
    FN(ARG, FIN, (1 << 0)) \
    FN(ARG, SYN, (1 << 1)) \
    FN(ARG, RST, (1 << 2)) \
    FN(ARG, PSH, (1 << 3)) \
    FN(ARG, ACK, (1 << 4)) \
    FN(ARG, URG, (1 << 5)) \
    FN(ARG, ECE, (1 << 6)) \
    FN(ARG, CWR, (1 << 7)) \
    FN(ARG,  NS, (1 << 8))
#define LN_PROTO_TCP_FLAGS_GEN(FN) FN(ln_proto_tcp_flags, LN_PROTO_TCP_FLAG, LN_PROTO_TCP_FLAGS_MAP)

LN_PROTO_TCP_FLAGS_GEN(LN_MAP_ENUM_DEFINE);
//LN_PROTO_TCP_FLAGS_GEN(LN_MAP_ENUM_PRINT_PROTO);
//LN_PROTO_TCP_FLAGS_GEN(LN_MAP_ENUM_SCAN_PROTO);

#define LN_PROTO_TCP_OPTS_MAP(FN, ARG) \
    FN(ARG, NOP, 1) \
    FN(ARG, MSS, 2) \
    FN(ARG, WSCALE, 3) \

#define LN_PROTO_TCP_OPTS_GEN(FN) FN(ln_proto_tcp_opts, LN_PROTO_TCP_OPT, LN_PROTO_TCP_OPTS_MAP)
LN_PROTO_TCP_OPTS_GEN(LN_MAP_ENUM_DEFINE);

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

    uint8_t tcp_optlen;
    uchar tcp_opts[44];
};

extern struct ln_pkt_type * ln_pkt_type_tcp;
struct ln_pkt * ln_pkt_tcp_dec(struct ln_pkt * parent_pkt);
int ln_pkt_tcp_parse_port(const char * port_str);

int ln_pkt_tcp_read_opt(const struct ln_pkt_tcp * tcp, uint8_t opt_type, void * out_buf, size_t opt_len);

