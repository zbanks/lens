#include "pkts/tcp.h"
#include <strings.h>

LN_PROTO_TCP_FLAGS_GEN(LN_MAP_ENUM_BITMAP_PRINT_DEFINE);
//LN_PROTO_TCP_FLAGS_GEN(LN_MAP_ENUM_SCAN_PROTO);

struct ln_pkt * ln_pkt_tcp_dec(struct ln_pkt * parent_pkt) {
    struct ln_data * data = parent_pkt->pkt_data;
    uchar * rpos = data->data_pos;

    if (data->data_next != NULL) // Unsupported
        return SET_ERRNO(EINVAL), NULL;
    if (data->data_pos + LN_PROTO_TCP_HEADER_LEN_MIN > data->data_last)
        return SET_ERRNO(EMSGSIZE), NULL;

    struct ln_pkt_tcp * tcp = calloc(1, sizeof *tcp);
    if (tcp == NULL) return NULL;

    tcp->tcp_src = ln_read16(&rpos, LN_NTOH);
    tcp->tcp_dst = ln_read16(&rpos, LN_NTOH);
    tcp->tcp_seq = ln_read32(&rpos, LN_NTOH);
    tcp->tcp_ack = ln_read32(&rpos, LN_NTOH);
    tcp->tcp_flags = ln_read16(&rpos, LN_NTOH);
    tcp->tcp_window = ln_read16(&rpos, LN_NTOH);
    tcp->tcp_crc = ln_read16(&rpos, LN_NTOH);
    tcp->tcp_urg = ln_read16(&rpos, LN_NTOH);

    uint8_t data_offset = (tcp->tcp_flags >> 12) * 4;
    if (data->data_pos + data_offset > data->data_last) {
        SET_ERRNO(EMSGSIZE);
        goto fail;
    }
    tcp->tcp_flags &= 0x00FFFFFF;

    tcp->tcp_optlen = data_offset - LN_PROTO_TCP_HEADER_LEN_MIN;
    ASSERT(tcp->tcp_optlen <= sizeof tcp->tcp_opts);
    memcpy(tcp->tcp_opts, rpos, tcp->tcp_optlen);

    data->data_pos += data_offset;
    tcp->tcp_pkt.pkt_data = data;
    parent_pkt->pkt_data = NULL;

    tcp->tcp_pkt.pkt_type = ln_pkt_type_tcp;
    tcp->tcp_pkt.pkt_parent = parent_pkt;
    ln_pkt_incref(parent_pkt);

    return &tcp->tcp_pkt;

fail:
    free(tcp);
    return NULL;
}

static int ln_pkt_tcp_len(struct ln_pkt * pkt, size_t * header_len, size_t * footer_len) {
    struct ln_pkt_tcp * tcp = LN_PKT_CAST(pkt, tcp);
    if (tcp == NULL) return SET_ERRNO(EINVAL), -1;

    while (tcp->tcp_optlen & 0x3)
        tcp->tcp_opts[tcp->tcp_optlen++] = 0;

    *header_len = LN_PROTO_TCP_HEADER_LEN_MIN + tcp->tcp_optlen;
    *footer_len = 0;
    return 0;
}

static int ln_pkt_tcp_enc(struct ln_pkt * pkt, struct ln_data * data) {
    struct ln_pkt_tcp * tcp = LN_PKT_CAST(pkt, tcp);
    if (tcp == NULL) return SET_ERRNO(EINVAL), -1;

    uchar * new_pos = data->data_pos - (LN_PROTO_TCP_HEADER_LEN_MIN + tcp->tcp_optlen);
    uchar * rpos = new_pos;
    ASSERT(new_pos >= data->data_start);

    uint16_t flags = tcp->tcp_flags;
    flags |= (LN_PROTO_TCP_HEADER_LEN_MIN + tcp->tcp_optlen) << 10;

    ln_write16(&rpos, tcp->tcp_src, LN_HTON);
    ln_write16(&rpos, tcp->tcp_dst, LN_HTON);
    ln_write32(&rpos, tcp->tcp_seq, LN_HTON);
    ln_write32(&rpos, tcp->tcp_ack, LN_HTON);
    ln_write16(&rpos, flags, LN_HTON);
    ln_write16(&rpos, tcp->tcp_window, LN_HTON);
    ln_write16(&rpos, tcp->tcp_crc, LN_HTON);
    ln_write16(&rpos, tcp->tcp_urg, LN_HTON);

    memcpy(rpos, tcp->tcp_opts, tcp->tcp_optlen);
    rpos += tcp->tcp_optlen;

    ASSERT(rpos == data->data_pos);
    data->data_pos = new_pos;
    return 0;
}

int ln_pkt_tcp_fdump(struct ln_pkt * pkt, FILE * stream) {
    struct ln_pkt_tcp * tcp = LN_PKT_CAST(pkt, tcp);
    if (tcp == NULL) return SET_ERRNO(EINVAL), -1;
    return fprintf(stream, "[tcp"
                           " len=%zu"
                           " src=%hu"
                           " dst=%hu"
                           " flags=%s"
                           " seq=%u"
                           " ack=%u"
                           " window=%hu"
                           "]",
                    ln_data_len(tcp->tcp_pkt.pkt_data),
                    tcp->tcp_src,
                    tcp->tcp_dst,
                    ln_proto_tcp_flags_print(tcp->tcp_flags),
                    tcp->tcp_seq,
                    tcp->tcp_ack,
                    tcp->tcp_window);
}

int ln_pkt_tcp_parse_port(const char * port_str) {
    if (port_str == NULL)
        return -1;
    if (port_str[0] == '\0')
        return -1;
    if (strcasecmp(port_str, "http") == 0)
        return 80;
    errno = 0;
    int port = strtol(port_str, NULL, 10);
    if (errno != 0)
        return -1;
    return port;
}

#define ln_pkt_tcp_term NULL
LN_PKT_TYPE_DECLARE(tcp);
