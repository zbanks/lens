#include "pkts/dns.h"
#include <strings.h>

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

#define ln_proto_dns_type_str(VAL) ln_enum_str(ln_proto_dns_type_enum, 0, VAL)
#define ln_proto_dns_type_scan(VAL) ln_enum_scan(ln_proto_dns_type_enum, 0, VAL)

//LN_PROTO_DNS_TYPE_GEN(LN_MAP_ENUM_PRINT_DEFINE);
//LN_PROTO_DNS_TYPE_GEN(LN_MAP_ENUM_SCAN_DEFINE);

LN_PROTO_DNS_FLAG_GEN(LN_MAP_ENUM_BITMAP_PRINT_DEFINE);
LN_PROTO_DNS_FLAG_GEN(LN_MAP_ENUM_SCAN_DEFINE);

LN_PROTO_DNS_OPCODE_GEN(LN_MAP_ENUM_PRINT_DEFINE);
LN_PROTO_DNS_OPCODE_GEN(LN_MAP_ENUM_SCAN_DEFINE);

LN_PROTO_DNS_RCODE_GEN(LN_MAP_ENUM_PRINT_DEFINE);
LN_PROTO_DNS_RCODE_GEN(LN_MAP_ENUM_SCAN_DEFINE);

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

    dns->dns_qs = calloc(dns->dns_qdc, sizeof *dns->dns_qs);
    if (dns->dns_qs == NULL) MEMFAIL();
    dns->dns_rrs = calloc(dns->dns_anc + dns->dns_nsc + dns->dns_arc, sizeof *dns->dns_rrs);
    if (dns->dns_rrs == NULL) MEMFAIL();

    data->data_pos = rpos;
    dns->dns_pkt.pkt_data = data;
    parent_pkt->pkt_data = NULL;

    for (size_t i = 0; i < dns->dns_qdc; i++) {
        uchar len = *rpos;
        if (len > 63) WARN("Long len in fqdn: %u", len);
        dns->dns_qs[i].q_name = ++rpos;
        while (len) {
            rpos += len;
            len = *rpos;
            if (len != 0) *rpos++ = '.';
        }
        while ((uintptr_t) rpos & 0x1) rpos++;
        dns->dns_qs[i].q_type = ln_read16(&rpos, LN_NTOH);
        dns->dns_qs[i].q_class = ln_read16(&rpos, LN_NTOH);
    }

    dns->dns_pkt.pkt_type = ln_pkt_type_dns;
    dns->dns_pkt.pkt_parent = parent_pkt;
    ln_pkt_incref(parent_pkt);

    return &dns->dns_pkt;
}

static void ln_pkt_dns_term(struct ln_pkt * pkt) {
    struct ln_pkt_dns * dns = LN_PKT_CAST(pkt, dns);
    if (dns == NULL) {
        SET_ERRNO(EINVAL);
        return;
    }
    free(dns->dns_qs);
    free(dns->dns_rrs);
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

int ln_pkt_dns_fdump(struct ln_pkt * pkt, FILE * stream) {
    struct ln_pkt_dns * dns = LN_PKT_CAST(pkt, dns);
    if (dns == NULL) return SET_ERRNO(EINVAL), -1;
    int rc = fprintf(stream, "[dns"
                             " len=%zu"
                             " id=%hu"
                             " flags=%s"
                             " opcode=%s"
                             " rcode=%s",
                    ln_data_len(dns->dns_pkt.pkt_data),
                    dns->dns_id,
                    ln_proto_dns_type_str(dns->dns_flags),
                    ln_proto_dns_opcode_print(dns->dns_opcode),
                    ln_proto_dns_rcode_print(dns->dns_rcode));
    for (uint16_t i = 0; i < dns->dns_qdc; i++) {
        rc += fprintf(stream, " q_%hu=[name=%s type=%hu class=%hx]",
                        i,
                        dns->dns_qs[i].q_name,
                        dns->dns_qs[i].q_type,
                        dns->dns_qs[i].q_class);
    }
    rc += fprintf(stream, "]");
    return rc;
}

LN_PKT_TYPE_DECLARE(dns);
