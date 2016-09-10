#include "pkt.h"

//

struct ln_pkt_raw {
    struct ln_pkt raw_pkt;
    int raw_fd;
};

extern struct ln_pkt_type * ln_pkt_type_raw;
struct ln_pkt_raw * ln_pkt_raw_frecv(int fd);
int ln_pkt_raw_fsend(struct ln_pkt_raw * raw);

//

#define LN_PROTO_ETH_PAYLOAD_LEN_MIN 46
#define LN_PROTO_ETH_PAYLOAD_LEN_MAX 1500
#define LN_PROTO_ETH_HEADER_LEN (6 + 6 + 2) // Does not include tag or CRC
#define LN_PROTO_ETH_TYPE_IPV4 0x0800
#define LN_PROTO_ETH_TYPE_ARP  0x0806
#define LN_PROTO_ETH_TYPE_IPV6 0x86DD
#define LN_PROTO_ETH_TYPE_TAG  0x8100
#define LN_PROTO_ETH_TAG_NULL 0

struct ln_pkt_eth {
    struct ln_pkt eth_pkt;

    uint8_t eth_src[6];
    uint8_t eth_dst[6];
    uint32_t eth_tag;
    uint16_t eth_type;
    //uint32_t eth_crc;
};

extern struct ln_pkt_type * ln_pkt_type_eth;
struct ln_pkt * ln_pkt_eth_dec(struct ln_pkt * parent_pkt);
int ln_pkt_eth_parse_type(const char * type_str);

//

#define LN_PROTO_IPV4_PAYLOAD_LEN_MAX 65535
#define LN_PROTO_IPV4_HEADER_LEN_MIN 20 // Does not include options
#define LN_PROTO_IPV4_HEADER_LEN_MAX (16 * 4)
#define LN_PROTO_IPV4_PROTO_ICMP 0x01
#define LN_PROTO_IPV4_PROTO_TCP  0x06
#define LN_PROTO_IPV4_PROTO_UDP  0x11

struct ln_pkt_ipv4 {
    struct ln_pkt ipv4_pkt;

    uint8_t ipv4_ihl;
    uchar ipv4_opts[65]; // fixme...
    uint8_t ipv4_dscp_ecn;
    uint16_t ipv4_id;
    uint8_t ipv4_flags;
    uint16_t ipv4_fragoff;
    uint8_t ipv4_ttl;
    uint8_t ipv4_proto;
    uint16_t ipv4_crc;
    uint32_t ipv4_src;
    uint32_t ipv4_dst;
};

extern struct ln_pkt_type * ln_pkt_type_ipv4;
struct ln_pkt * ln_pkt_ipv4_dec(struct ln_pkt * parent_pkt);
int ln_pkt_ipv4_parse_proto(const char * proto_str);

