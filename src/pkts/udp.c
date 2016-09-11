#include "pkts/udp.h"
#include <strings.h>

struct ln_pkt * ln_pkt_udp_dec(struct ln_pkt * parent_pkt) {
    struct ln_data * data = parent_pkt->pkt_data;
    uchar * rpos = data->data_pos;

    if (data->data_next != NULL) // Unsupported
        return SET_ERRNO(EINVAL), NULL;
    if (data->data_pos + LN_PROTO_UDP_HEADER_LEN > data->data_last)
        return SET_ERRNO(EMSGSIZE), NULL;

    struct ln_pkt_udp * udp = calloc(1, sizeof *udp);
    if (udp == NULL) return NULL;

    uint16_t udp_len = 0;
    udp->udp_src = ln_read16(&rpos, LN_NTOH);
    udp->udp_dst = ln_read16(&rpos, LN_NTOH);
    udp_len = ln_read16(&rpos, LN_NTOH);
    udp->udp_crc = ln_read16(&rpos, LN_NTOH);
    
    // Check packet size
    if (data->data_pos + udp_len > data->data_last) {
        SET_ERRNO(EMSGSIZE);
        goto fail;
    }
    if (data->data_pos + udp_len < data->data_last)
        INFO("Extra bytes: %zu", data->data_pos + udp_len - data->data_last);

    data->data_last = data->data_pos + udp_len;
    data->data_pos = rpos;
    udp->udp_pkt.pkt_data = data;
    parent_pkt->pkt_data = NULL;

    udp->udp_pkt.pkt_type = ln_pkt_type_udp;
    udp->udp_pkt.pkt_parent = parent_pkt;
    ln_pkt_incref(parent_pkt);

    return &udp->udp_pkt;

fail:
    free(udp);
    return NULL;
}

static int ln_pkt_udp_len(struct ln_pkt * pkt, size_t * header_len, size_t * footer_len) {
    struct ln_pkt_udp * udp = LN_PKT_CAST(pkt, udp);
    if (udp == NULL) return SET_ERRNO(EINVAL), -1;

    *header_len = LN_PROTO_UDP_HEADER_LEN;
    *footer_len = 0;
    return 0;
}

static int ln_pkt_udp_enc(struct ln_pkt * pkt, struct ln_data * data) {
    struct ln_pkt_udp * udp = LN_PKT_CAST(pkt, udp);
    if (udp == NULL) return SET_ERRNO(EINVAL), -1;

    uchar * new_pos = data->data_pos - LN_PROTO_UDP_HEADER_LEN;
    uchar * rpos = new_pos;
    ASSERT(new_pos >= data->data_start);

    ln_write16(&rpos, udp->udp_src, LN_HTON);
    ln_write16(&rpos, udp->udp_src, LN_HTON);
    ln_write16(&rpos, ln_data_len(data), LN_HTON);
    ln_write16(&rpos, udp->udp_crc, LN_HTON); // TODO: Calculate CRC

    ASSERT(rpos == data->data_pos);
    data->data_pos = new_pos;

    return 0;
}

int ln_pkt_udp_fdump(struct ln_pkt * pkt, FILE * stream) {
    struct ln_pkt_udp * udp = LN_PKT_CAST(pkt, udp);
    if (udp == NULL) return SET_ERRNO(EINVAL), -1;
    return fprintf(stream, "[udp"
                           " len=%zu"
                           " src=%hu"
                           " dst=%hu]",
                    ln_data_len(udp->udp_pkt.pkt_data),
                    udp->udp_src,
                    udp->udp_dst);
}

int ln_pkt_udp_parse_port(const char * port_str) {
    if (port_str == NULL)
        return -1;
    if (port_str[0] == '\0')
        return -1;
    if (strcasecmp(port_str, "dns") == 0)
        return LN_PROTO_UDP_PORT_DNS;
    errno = 0;
    int port = strtol(port_str, NULL, 10);
    if (errno != 0)
        return -1;
    return port;
}

#define ln_pkt_udp_term NULL
LN_PKT_TYPE_DECLARE(udp);
