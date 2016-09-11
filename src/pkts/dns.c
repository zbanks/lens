#include "pkts/dns.h"
#include <strings.h>

struct ln_pkt * ln_pkt_dns_dec(struct ln_pkt * parent_pkt) {
    struct ln_data * data = parent_pkt->pkt_data;
    uchar * rpos = data->data_pos;

    if (data->data_next != NULL) // Unsupported
        return SET_ERRNO(EINVAL), NULL;
    if (data->data_pos + LN_PROTO_DNS_HEADER_LEN >= data->data_last)
        return SET_ERRNO(EMSGSIZE), NULL;

    struct ln_pkt_dns * dns = calloc(1, sizeof *dns);
    if (dns == NULL) return NULL;

    dns->dns_id = ln_read16(&rpos, LN_NTOH);
    dns->dns_flags = ln_read16(&rpos, LN_NTOH);
    dns->dns_qdc = ln_read16(&rpos, LN_NTOH);
    dns->dns_anc = ln_read16(&rpos, LN_NTOH);
    dns->dns_nsc = ln_read16(&rpos, LN_NTOH);
    dns->dns_arc = ln_read16(&rpos, LN_NTOH);

    dns->dns_opcode = (dns->dns_flags & LN_PROTO_DNS_FLAGS_OPCODE_MASK) >> LN_PROTO_DNS_FLAGS_OPCODE_OFFSET;
    dns->dns_rcode = (dns->dns_flags & LN_PROTO_DNS_FLAGS_RCODE_MASK) >> LN_PROTO_DNS_FLAGS_RCODE_OFFSET;
    
    data->data_pos = rpos;
    dns->dns_pkt.pkt_data = data;
    parent_pkt->pkt_data = NULL;

    dns->dns_pkt.pkt_type = ln_pkt_type_dns;
    dns->dns_pkt.pkt_parent = parent_pkt;
    ln_pkt_incref(parent_pkt);

    return &dns->dns_pkt;
}

static int ln_pkt_dns_len(struct ln_pkt * pkt, size_t * header_len, size_t * footer_len) {
    struct ln_pkt_dns * dns = LN_PKT_CAST(pkt, dns);
    if (dns == NULL) return SET_ERRNO(EINVAL), -1;

    *header_len = LN_PROTO_DNS_HEADER_LEN;
    *footer_len = 0;
    return 0;
}

static int ln_pkt_dns_enc(struct ln_pkt * pkt, struct ln_data * data) {
    return -1; // TODO
}

/*
static const char * ln_pkt_dns_str_type(struct ln_pkt_dns * dns) {
    switch(dns->dns_type) {
#define X(NAME, VALUE) \
    case LN_PROTO_DNS_TYPE_##NAME: \
        return #NAME;
LN_PROTO_DNS_TYPES;
#undef X
    default:
        return "???";
    }
}
*/

static const char * ln_pkt_dns_str_flags(struct ln_pkt_dns * dns) {
    static char str[128];
    char * ptr = str;
    uint16_t flags = dns->dns_flags;

#define X(NAME, VALUE) \
    if (flags & LN_PROTO_DNS_FLAG_##NAME) { \
        *ptr++ = #NAME[0]; \
        if(#NAME[1]) *ptr++ = #NAME[1]; \
        *ptr++ = '|'; \
    }
LN_PROTO_DNS_FLAGS
#undef X
    *--ptr = '\0';
    return str;
}

static const char * ln_pkt_dns_str_opcode(struct ln_pkt_dns * dns) {
    switch(dns->dns_opcode) {
#define X(NAME, VALUE) \
    case LN_PROTO_DNS_OPCODE_##NAME: \
        return #NAME;
LN_PROTO_DNS_OPCODES;
#undef X
    default:
        return "???";
    }
}

static const char * ln_pkt_dns_str_rcode(struct ln_pkt_dns * dns) {
    switch(dns->dns_rcode) {
#define X(NAME, VALUE) \
    case LN_PROTO_DNS_RCODE_##NAME: \
        return #NAME;
LN_PROTO_DNS_RCODES;
#undef X
    default:
        return "???";
    }
}

int ln_pkt_dns_fdump(struct ln_pkt * pkt, FILE * stream) {
    struct ln_pkt_dns * dns = LN_PKT_CAST(pkt, dns);
    if (dns == NULL) return SET_ERRNO(EINVAL), -1;
    return fprintf(stream, "[dns"
                           " len=%zu"
                           " id=%hu"
                           " flags=%s"
                           " opcode=%s"
                           " rcode=%s"
                           "]",
                    ln_data_len(dns->dns_pkt.pkt_data),
                    dns->dns_id,
                    ln_pkt_dns_str_flags(dns),
                    ln_pkt_dns_str_opcode(dns),
                    ln_pkt_dns_str_rcode(dns));
}

int ln_pkt_dns_parse_type(const char * type_str) {
    if (type_str == NULL)
        return -1;
    if (type_str[0] == '\0')
        return -1;
#define X(NAME, VALUE) if (strcasecmp(type_str, #NAME) == 0) return LN_PROTO_DNS_TYPE_##NAME;
LN_PROTO_DNS_TYPES
#undef X

    errno = 0;
    int type = strtol(type_str, NULL, 0);
    if (errno != 0)
        return -1;
    return type;
}

LN_PKT_TYPE_DECLARE(dns);
