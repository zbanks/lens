#include "pkt.h"

#define LN_PROTO_UDP_PAYLOAD_LEN_MAX ((size_t) 65535)
#define LN_PROTO_UDP_HEADER_LEN ((size_t) 8)
#define LN_PROTO_UDP_PORT_DNS 53

struct ln_pkt_udp {
    struct ln_pkt udp_pkt;

    uint16_t udp_src;
    uint16_t udp_dst;
    uint16_t udp_crc;
};

extern struct ln_pkt_type * ln_pkt_type_udp;
struct ln_pkt * ln_pkt_udp_dec(struct ln_pkt * parent_pkt);
int ln_pkt_udp_parse_port(const char * port_str);
