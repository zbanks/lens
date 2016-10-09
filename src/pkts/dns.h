#include "pkt.h"

#define LN_PROTO_DNS_HEADER_LEN ((size_t) 12)

enum ln_proto_dns_type {
    LN_PROTO_DNS_TYPE_A     = 1,
    LN_PROTO_DNS_TYPE_NS    = 2,
    LN_PROTO_DNS_TYPE_CNAME = 5,
    LN_PROTO_DNS_TYPE_SOA   = 6,
    LN_PROTO_DNS_TYPE_PTR   = 12,
    LN_PROTO_DNS_TYPE_HINFO = 13,
    LN_PROTO_DNS_TYPE_AAAA  = 28,
    LN_PROTO_DNS_TYPE_TXT   = 16,
    LN_PROTO_DNS_TYPE_SRV   = 33,
    LN_PROTO_DNS_TYPE_ANY   = 255,
};

struct ln_enum ln_proto_dns_type_enum[] = {
    {LN_PROTO_DNS_TYPE_A     , "A"},
    {LN_PROTO_DNS_TYPE_NS    , "NS"},
    {LN_PROTO_DNS_TYPE_CNAME , "CNAME"},
    {LN_PROTO_DNS_TYPE_SOA   , "SOA"},
    {LN_PROTO_DNS_TYPE_PTR   , "PTR"},
    {LN_PROTO_DNS_TYPE_HINFO , "HINFO"},
    {LN_PROTO_DNS_TYPE_AAAA  , "AAAA"},
    {LN_PROTO_DNS_TYPE_TXT   , "TXT"},
    {LN_PROTO_DNS_TYPE_SRV   , "SRV"},
    {LN_PROTO_DNS_TYPE_ANY   , "ANY"},
    {0, 0},
};

/*
#define LN_PROTO_DNS_TYPE_MAP(FN, ARG) \
    FN(ARG, A,     1)  \
    FN(ARG, NS,    2)  \
    FN(ARG, CNAME, 5)  \
    FN(ARG, SOA,   6)  \
    FN(ARG, PTR,   12) \
    FN(ARG, HINFO, 13) \
    FN(ARG, AAAA,  28) \
    FN(ARG, TXT,   16) \
    FN(ARG, SRV,   33) \
    FN(ARG, ANY,   255) \

#define LN_PROTO_DNS_TYPE_GEN(FN) FN(ln_proto_dns_type, LN_PROTO_DNS_TYPE, LN_PROTO_DNS_TYPE_MAP)

LN_PROTO_DNS_TYPE_GEN(LN_MAP_ENUM_DEFINE);
LN_PROTO_DNS_TYPE_GEN(LN_MAP_ENUM_PRINT_PROTO);
LN_PROTO_DNS_TYPE_GEN(LN_MAP_ENUM_SCAN_PROTO);
*/

#define LN_PROTO_DNS_FLAGS_OPCODE_MASK 0x7800
#define LN_PROTO_DNS_FLAGS_OPCODE_OFFSET 11
#define LN_PROTO_DNS_FLAGS_RCODE_MASK 0x000F
#define LN_PROTO_DNS_FLAGS_RCODE_OFFSET 0
#define LN_PROTO_DNS_FLAG_MAP(FN, ARG) \
    FN(ARG, CD, 0x0010) /* Checking disabled      */ \
    FN(ARG, AD, 0x0020) /* Authenticated data     */ \
    FN(ARG, Z,  0x0040) /* Unused                 */ \
    FN(ARG, RA, 0x0080) /* Recursion available    */ \
    FN(ARG, RD, 0x0100) /* Recursion desired      */ \
    FN(ARG, TC, 0x0200) /* Truncated              */ \
    FN(ARG, AA, 0x0400) /* Authoratative answer   */ \
    FN(ARG, QR, 0x8000) /* Response (vs. query)   */ \

#define LN_PROTO_DNS_FLAG_GEN(FN) FN(ln_proto_dns_flag, LN_PROTO_DNS_FLAG, LN_PROTO_DNS_FLAG_MAP)

LN_PROTO_DNS_FLAG_GEN(LN_MAP_ENUM_DEFINE);
LN_PROTO_DNS_FLAG_GEN(LN_MAP_ENUM_PRINT_PROTO);
LN_PROTO_DNS_FLAG_GEN(LN_MAP_ENUM_SCAN_PROTO);

#define LN_PROTO_DNS_OPCODE_MAP(FN, ARG) \
    FN(ARG, QUERY,    0) \
    FN(ARG, IQUERY,   1) \
    FN(ARG, STATUS,   2) \
    FN(ARG, NOTIFY,   4) \
    FN(ARG, UPDATE,   5) \

#define LN_PROTO_DNS_OPCODE_GEN(FN) FN(ln_proto_dns_opcode, LN_PROTO_DNS_OPCODE, LN_PROTO_DNS_OPCODE_MAP)

LN_PROTO_DNS_OPCODE_GEN(LN_MAP_ENUM_DEFINE);
LN_PROTO_DNS_OPCODE_GEN(LN_MAP_ENUM_PRINT_PROTO);
LN_PROTO_DNS_OPCODE_GEN(LN_MAP_ENUM_SCAN_PROTO);

#define LN_PROTO_DNS_RCODE_MAP(FN, ARG) \
    FN(ARG, NO_ERROR,         0) \
    FN(ARG, FORMAT_ERROR,     1) \
    FN(ARG, SERVER_FAILURE,   2) \
    FN(ARG, NAME_ERROR,       3) \
    FN(ARG, NOT_IMPLEMENTED,  4) \
    FN(ARG, REFUSED,          5) \
    FN(ARG, YX_DOMAIN,        6) \
    FN(ARG, YX_RR_SET,        7) \
    FN(ARG, NX_RR_SET,        8) \
    FN(ARG, NOT_AUTH,         9) \
    FN(ARG, NOT_ZONE,         10) \

#define LN_PROTO_DNS_RCODE_GEN(FN) FN(ln_proto_dns_rcode, LN_PROTO_DNS_RCODE, LN_PROTO_DNS_RCODE_MAP)

LN_PROTO_DNS_RCODE_GEN(LN_MAP_ENUM_DEFINE);
LN_PROTO_DNS_RCODE_GEN(LN_MAP_ENUM_PRINT_PROTO);
LN_PROTO_DNS_RCODE_GEN(LN_MAP_ENUM_SCAN_PROTO);

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
