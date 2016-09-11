#include "pkt.h"

#define LN_PROTO_DNS_HEADER_LEN ((size_t) 12)
#define LN_PROTO_DNS_TYPES \
    X(A,     1)  \
    X(NS,    2)  \
    X(CNAME, 5)  \
    X(SOA,   6)  \
    X(PTR,   12) \
    X(HINFO, 13) \
    X(AAAA,  28) \
    X(TXT,   16) \
    X(SRV,   33) \
    X(ANY,   255) \

#define LN_PROTO_DNS_FLAGS_OPCODE_MASK 0x7800
#define LN_PROTO_DNS_FLAGS_OPCODE_OFFSET 11
#define LN_PROTO_DNS_FLAGS_RCODE_MASK 0x000F
#define LN_PROTO_DNS_FLAGS_RCODE_OFFSET 0
#define LN_PROTO_DNS_FLAGS \
    X(CD, 0x0010) /* Checking disabled      */ \
    X(AD, 0x0020) /* Authenticated data     */ \
    X(Z,  0x0040) /* Unused                 */ \
    X(RA, 0x0080) /* Recursion available    */ \
    X(RD, 0x0100) /* Recursion desired      */ \
    X(TC, 0x0200) /* Truncated              */ \
    X(AA, 0x0400) /* Authoratative answer   */ \
    X(QR, 0x8000) /* Response (vs. query)   */ \

#define LN_PROTO_DNS_OPCODES \
    X(QUERY,    0) \
    X(IQUERY,   1) \
    X(STATUS,   2) \
    X(NOTIFY,   4) \
    X(UPDATE,   5) \

#define LN_PROTO_DNS_RCODES \
    X(NO_ERROR,         0) \
    X(FORMAT_ERROR,     1) \
    X(SERVER_FAILURE,   2) \
    X(NAME_ERROR,       3) \
    X(NOT_IMPLEMENTED,  4) \
    X(REFUSED,          5) \
    X(YX_DOMAIN,        6) \
    X(YX_RR_SET,        7) \
    X(NX_RR_SET,        8) \
    X(NOT_AUTH,         9) \
    X(NOT_ZONE,         10) \


enum LN_PROTO_DNS_TYPE {
#define X(NAME, VALUE) LN_PROTO_DNS_TYPE_##NAME = VALUE,
LN_PROTO_DNS_TYPES
#undef X
};

enum LN_PROTO_DNS_FLAG {
#define X(NAME, VALUE) LN_PROTO_DNS_FLAG_##NAME = VALUE,
LN_PROTO_DNS_FLAGS
#undef X
};

enum LN_PROTO_DNS_OPCODE {
#define X(NAME, VALUE) LN_PROTO_DNS_OPCODE_##NAME = VALUE,
LN_PROTO_DNS_OPCODES
#undef X
};

enum LN_PROTO_DNS_RCODE {
#define X(NAME, VALUE) LN_PROTO_DNS_RCODE_##NAME = VALUE,
LN_PROTO_DNS_RCODES
#undef X
};

struct ln_pkt_dns {
    struct ln_pkt dns_pkt;

    uint16_t dns_id;
    uint16_t dns_flags;
    uint8_t dns_opcode;
    uint8_t dns_rcode;
    uint16_t dns_qdc; // Question count
    uint16_t dns_anc; // Answer Record count
    uint16_t dns_nsc; // Name Server count
    uint16_t dns_arc; // Additional Record count

    struct ln_pkt_dns_q {
        const uchar * q_name;
        uint16_t q_type;
        uint16_t q_class;
    } * dns_qs;

    struct ln_pkt_dns_rr {
        const uchar * rr_name;
        uint16_t rr_type;
        uint16_t rr_class;
        uint32_t rr_ttl;
        uint16_t rr_rdlength;
        const uchar * rr_rdata;
    } * dns_rrs;
};

extern struct ln_pkt_type * ln_pkt_type_dns;
struct ln_pkt * ln_pkt_dns_dec(struct ln_pkt * parent_pkt);
int ln_pkt_dns_parse_type(const char * type_str);
