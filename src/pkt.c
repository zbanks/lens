#include "pkt.h"

struct ln_pkt_vtbl {
    struct ln_pkt * (*pkt_vtbl_dec)(struct ln_pkt * parent_pkt);
    int (*pkt_vtbl_len)(struct ln_pkt * pkt, size_t * header_len, size_t * footer_len);
    int (*pkt_vtbl_enc)(struct ln_pkt * pkt, struct ln_data * payload_data);
    int (*pkt_vtbl_fdump)(struct ln_pkt * pkt, FILE * stream);
    void (*pkt_vtbl_term)(struct ln_pkt * pkt);
};

static struct ln_pkt_vtbl ln_pkt_vtbl[];

static struct ln_pkt_vtbl * ln_pkt_get_vtbl(struct ln_pkt * pkt) {
    if (pkt->pkt_type <= ln_pkt_type_none || pkt->pkt_type >= ln_pkt_type_max)
        return NULL;
    return &ln_pkt_vtbl[pkt->pkt_type];
}

// struct ln_pkt

void ln_pkt_decref(struct ln_pkt * pkt) {
    if(!pkt->pkt_refcnt--) {
        if (pkt->pkt_parent != NULL)
            ln_pkt_decref(pkt->pkt_parent);

        struct ln_pkt_vtbl * pkt_vtbl = ln_pkt_get_vtbl(pkt);
        if (pkt_vtbl != NULL && pkt_vtbl->pkt_vtbl_term != NULL)
            pkt_vtbl->pkt_vtbl_term(pkt);

        if (pkt->pkt_data != NULL)
            free(pkt->pkt_data);

        free(pkt);
    }
}

void ln_pkt_incref(struct ln_pkt * pkt) {
    pkt->pkt_refcnt++;
}

int ln_pkt_fdump(struct ln_pkt * pkt, FILE * stream) {
    struct ln_pkt_vtbl * pkt_vtbl = ln_pkt_get_vtbl(pkt);
    if (pkt_vtbl == NULL || pkt_vtbl->pkt_vtbl_fdump == NULL)
        return fprintf(stream, "[unknown]");
    return pkt_vtbl->pkt_vtbl_fdump(pkt, stream);
}

int ln_pkt_fdumpall(struct ln_pkt * pkt, FILE * stream) {
    int sum = 0;
    while (pkt != NULL) {
        int rc = ln_pkt_fdump(pkt, stream);
        if (rc < 0) return rc;
        sum += rc;

        pkt = pkt->pkt_parent;
        if (pkt != NULL) {
            rc = fprintf(stream, " --> ");
            if (rc < 0) return rc;
            sum += rc;
        }
    }
    return sum;
}

/*
static int ln_pkt_prep(struct ln_pkt * pkt, struct ln_chain * payload_chain) {
    struct ln_pkt_vtbl * pkt_vtbl = ln_pkt_get_vtbl(pkt);
    if (pkt_vtbl == NULL || pkt_vtbl->pkt_vtbl_prep == NULL)
        return -1;

    ln_chain_term(&pkt->pkt_chain)

    if (pkt->pkt_parent == NULL) {
        pkt->pkt_chain.chain_buf = ln_buf_create();
        if (pkt->pkt_chain.chain_buf == NULL)
            return -1;
        pkt->pkt_chain.chain_pos = pkt->pkt_chain.chain_buf->buf_start;
        pkt->pkt_chain.chain_last = pkt->pkt_chain.chain_pos;
        pkt->pkt_chain.chain_next = NULL;
    } else {
        int rc = ln_pkt_prep(pkt->pkt_parent, &pkt->pkt_chain);
        if (rc < 0) return rc;
    }

    ssize_t reserve_len = pkt_vtbl->pkt_vtbl_prep(pkt);
    if (reserve_len < 0) return reserve_len;

    payload_chain->chain_buf = pkt->pkt_chain.chain_buf;
    ln_buf_incref(payload_chain->chain_buf);
    payload_chain->chain_pos = pkt->pkt_chain.chain_pos + reserve_len;
    payload_chain->chain_last = payload_chain->chain_pos;
    payload_chain->chain_next = NULL;

    ASSERT(pkt->pkt_chain->chain_next == NULL, "Unimplemented");
    ASSERT(payload_chain->chain_last < LN_BUF_LAST(payload_chain->chain_buf), "Unimplemented");

    return 0;
}
*/

// Utility function
/*
static int ln_pkt_copy_data(struct ln_pkt * pkt, struct ln_data * payload_data) {
    if (pkt->pkt_data == NULL)
        return 0;
    if (pkt->pkt_data == payload_data || payload_data == NULL)
        return (errno = EINVAL), -1;

    size_t len = pkt->pkt_data->data_last - pkt->pkt_data->data_pos;
    if (payload_data->data_last + len >= payload_data->data_end)
        return (errno = EMSGSIZE), -1;

    memcpy(payload_data->data_last, pkt->pkt_data->data_pos, len);
    payload_data->data_last += len;

    return 0;
}
*/

static ssize_t ln_pkt_enc_len(struct ln_pkt * pkt, size_t * header_len) {
    size_t total_len = ln_data_len(pkt->pkt_data);
    *header_len = 0;
    while (pkt != NULL) {
        struct ln_pkt_vtbl * pkt_vtbl = ln_pkt_get_vtbl(pkt);
        if (pkt_vtbl != NULL && pkt_vtbl->pkt_vtbl_len != NULL) {
            size_t ret_header_len;
            size_t ret_footer_len;
            int rc = pkt_vtbl->pkt_vtbl_len(pkt, &ret_header_len, &ret_footer_len);
            if (rc < 0) return -1;

            total_len += ret_header_len + ret_footer_len;
            *header_len += ret_header_len;
        }

        pkt = pkt->pkt_parent;
    }
    return total_len;
}

struct ln_pkt * ln_pkt_enc(struct ln_pkt * pkt) {
    size_t header_len = 0;
    ssize_t data_len = ln_pkt_enc_len(pkt, &header_len);
    if (data_len < 0) return NULL;
    ASSERT(pkt->pkt_parent != NULL); // a `raw` should always be at the bottom

    // TODO: For now we don't support data chaining (e.g. data->data_next)
    struct ln_data * data = NULL;

    if (   (pkt->pkt_data == NULL)
        || (pkt->pkt_data->data_pos - header_len < pkt->pkt_data->data_start)
        || (pkt->pkt_data->data_pos - header_len + data_len >= pkt->pkt_data->data_end)) {
        // Ignore it and make a new one
        data = ln_data_create(data_len);
        if (data == NULL) return NULL;

        data->data_pos = data->data_start + header_len;
        data->data_last = data->data_pos;
        if (pkt->pkt_data != NULL) {
            size_t pkt_data_len = pkt->pkt_data->data_last - pkt->pkt_data->data_pos;
            memcpy(data->data_pos, pkt->pkt_data->data_pos, pkt_data_len);
            data->data_last += pkt_data_len;
        }
    } else {
        // Transfer ownership
        data = pkt->pkt_data;
        pkt->pkt_data = NULL;
    }

    while (1) {
        struct ln_pkt_vtbl * pkt_vtbl = ln_pkt_get_vtbl(pkt);
        if (pkt_vtbl != NULL && pkt_vtbl->pkt_vtbl_enc != NULL) {
            int rc = pkt_vtbl->pkt_vtbl_enc(pkt, data);
            if (rc < 0) FAIL("Unrecoverable while encoding"); // TODO: recover from this error
        }

        if (pkt->pkt_parent == NULL)
            break;

        ln_pkt_decref(pkt);
        pkt = pkt->pkt_parent;
    }


    return pkt;
}

// struct ln_pkt_raw

struct ln_pkt_raw * ln_pkt_raw_frecv(int fd) {
    static struct ln_data * data = NULL; // If we don't use the buffer; cache it
    if (data == NULL)
        data = ln_data_create(0);
    if (data == NULL) return NULL;

    int rc = recv(fd, data->data_start, data->data_end - data->data_start, MSG_DONTWAIT | MSG_TRUNC);
    if (rc < 0) return NULL;
    data->data_pos = data->data_start;
    data->data_last = data->data_pos + rc;
    if (data->data_last > data->data_end) // Jumbo frame or something weird?
        return SET_ERRNO(EMSGSIZE), NULL;

    struct ln_pkt_raw * raw = calloc(1, sizeof *raw);
    if (raw == NULL) return NULL;

    raw->raw_fd = fd;
    raw->raw_pkt.pkt_parent = NULL;
    raw->raw_pkt.pkt_type = ln_pkt_type_raw;
    raw->raw_pkt.pkt_data = data;

    data = NULL;
    return raw;
}

int ln_pkt_raw_fsend(struct ln_pkt_raw * raw) {
    struct ln_data * data = raw->raw_pkt.pkt_data;
    return send(raw->raw_fd, data->data_pos, data->data_last - data->data_pos, MSG_DONTWAIT);
}

struct ln_pkt * ln_pkt_raw_dec(struct ln_pkt * parent_pkt) {
    // copy/no-op, not very useful
    struct ln_pkt_raw * raw = calloc(1, sizeof *raw);
    if (raw == NULL) return NULL;

    raw->raw_fd = -1;
    raw->raw_pkt.pkt_type = ln_pkt_type_raw;

    raw->raw_pkt.pkt_data = parent_pkt->pkt_data;
    parent_pkt->pkt_data = NULL;

    raw->raw_pkt.pkt_parent = parent_pkt;
    ln_pkt_incref(parent_pkt);
    return &raw->raw_pkt;
}

static int ln_pkt_raw_len(struct ln_pkt * pkt, size_t * header_len, size_t * footer_len) {
    *header_len = 0;
    *footer_len = 0;
    return 0;
}

static int ln_pkt_raw_enc(struct ln_pkt * pkt, struct ln_data * payload_data) {
    return 0; // no-op
}

int ln_pkt_raw_fdump(struct ln_pkt * pkt, FILE * stream) {
    struct ln_pkt_raw * raw = LN_PKT_CAST(pkt, raw);
    if (raw == NULL) return SET_ERRNO(EINVAL), -1;
    return fprintf(stream, "[raw len=%zu fd=%d]",
                    ln_data_len(pkt->pkt_data),
                    raw->raw_fd);
}

// struct ln_pkt_eth

//TODO: There's at least 2 bytes missing, maybe CRC? 
struct ln_pkt * ln_pkt_eth_dec(struct ln_pkt * parent_pkt) {
    struct ln_data * data = parent_pkt->pkt_data;
    uchar * rpos = data->data_pos;

    if (data->data_next != NULL) // Unsupported
        return SET_ERRNO(EINVAL), NULL;

    size_t raw_len = data->data_last - data->data_pos;
    //if (raw_len < LN_PROTO_ETH_HEADER_LEN + LN_PROTO_ETH_PAYLOAD_LEN_MIN)
    //  return SET_ERRNO(EINVAL), NULL;
    if (raw_len > LN_PROTO_ETH_HEADER_LEN + LN_PROTO_ETH_PAYLOAD_LEN_MAX)
        return SET_ERRNO(EINVAL), NULL;

    struct ln_pkt_eth * eth = calloc(1, sizeof *eth);
    if (eth == NULL) return NULL;

    memcpy(eth->eth_dst, rpos, sizeof eth->eth_dst);
    rpos += sizeof eth->eth_dst;
    memcpy(eth->eth_src, rpos, sizeof eth->eth_src);
    rpos += sizeof eth->eth_src;
    eth->eth_type = ln_read16(&rpos, LN_NTOH);
    if (eth->eth_type == LN_PROTO_ETH_TYPE_TAG) {
        eth->eth_tag = ln_read16(&rpos, LN_NTOH);
        eth->eth_tag |= eth->eth_type << 16;
        eth->eth_type = ln_read16(&rpos, LN_NTOH);
    } else {
        eth->eth_tag = LN_PROTO_ETH_TAG_NULL;
    }
    // CRC stuff would go here

    data->data_pos = rpos;
    eth->eth_pkt.pkt_data = data;
    parent_pkt->pkt_data = NULL;

    eth->eth_pkt.pkt_type = ln_pkt_type_eth;
    eth->eth_pkt.pkt_parent = parent_pkt;
    ln_pkt_incref(parent_pkt);

    // Higher-level decode
    struct ln_pkt * ret_pkt = &eth->eth_pkt;
    switch (eth->eth_type) {
    case LN_PROTO_ETH_TYPE_IPV4:
        ret_pkt = ln_pkt_ipv4_dec(&eth->eth_pkt);
        if (ret_pkt == NULL) ret_pkt = &eth->eth_pkt;
        break;
    case LN_PROTO_ETH_TYPE_ARP:
    case LN_PROTO_ETH_TYPE_IPV6:
        break;
    default:
        INFO("Unknown ethertype %#04x", eth->eth_type);
        break;
    }

    return ret_pkt;
}

static int ln_pkt_eth_len(struct ln_pkt * pkt, size_t * header_len, size_t * footer_len) {
    struct ln_pkt_eth * eth = LN_PKT_CAST(pkt, eth);
    if (eth == NULL) return SET_ERRNO(EINVAL), -1;

    *header_len = 14;
    if (eth->eth_tag != LN_PROTO_ETH_TAG_NULL)
        *header_len = 18;

    *footer_len = 0; // maybe 4?
    return 0;
}

static int ln_pkt_eth_enc(struct ln_pkt * pkt, struct ln_data * data) {
    struct ln_pkt_eth * eth = LN_PKT_CAST(pkt, eth);
    if (eth == NULL) return SET_ERRNO(EINVAL), -1;
    
    size_t header_len = 14;
    if (eth->eth_tag != 0)
        header_len = 18;

    data->data_pos -= header_len;
    ASSERT(data->data_pos >= data->data_start);
    uchar * rpos = data->data_pos;

    memcpy(rpos, eth->eth_dst, sizeof eth->eth_dst);
    rpos += sizeof eth->eth_dst;
    memcpy(rpos, eth->eth_src, sizeof eth->eth_src);
    rpos += sizeof eth->eth_src;
    if (eth->eth_tag != 0)
        ln_write32(&rpos, eth->eth_tag, LN_HTON);
    ln_write16(&rpos, eth->eth_type, LN_HTON);

    // TODO: write CRC?

    return 0;
}

static int ln_pkt_eth_fdump(struct ln_pkt * pkt, FILE * stream) {
    struct ln_pkt_eth * eth = LN_PKT_CAST(pkt, eth);
    if (eth == NULL) return SET_ERRNO(EINVAL), -1;
    return fprintf(stream, "[eth"
                           " len=%zu"
                           " src=%02x:%02x:%02x:%02x:%02x:%02x"
                           " dst=%02x:%02x:%02x:%02x:%02x:%02x"
                           " type=%#04x]",
                    ln_data_len(eth->eth_pkt.pkt_data),
                    eth->eth_src[0], eth->eth_src[1], eth->eth_src[2],
                    eth->eth_src[3], eth->eth_src[4], eth->eth_src[5],
                    eth->eth_dst[0], eth->eth_dst[1], eth->eth_dst[2],
                    eth->eth_dst[3], eth->eth_dst[4], eth->eth_dst[5],
                    eth->eth_type);
}


// struct ln_pkt_ipv4

struct ln_pkt * ln_pkt_ipv4_dec(struct ln_pkt * parent_pkt) {
    struct ln_data * data = parent_pkt->pkt_data;
    uchar * rpos = data->data_pos;

    if (data->data_next != NULL) // Unsupported
        return SET_ERRNO(EINVAL), NULL;

    size_t eth_len = data->data_last - data->data_pos;
    if (eth_len < LN_PROTO_IPV4_HEADER_LEN_MIN)
        return SET_ERRNO(EINVAL), NULL;
    if (eth_len > LN_PROTO_IPV4_HEADER_LEN_MAX + LN_PROTO_IPV4_PAYLOAD_LEN_MAX)
        return SET_ERRNO(EINVAL), NULL;
    if ((*rpos & 0xF0) != 0x40)
        return SET_ERRNO(EINVAL), NULL;

    struct ln_pkt_ipv4 * ipv4 = calloc(1, sizeof *ipv4);
    if (ipv4 == NULL) return NULL;

    ipv4->ipv4_ihl = ln_read8(&rpos, LN_NTOH);
    ipv4->ipv4_ihl = (ipv4->ipv4_ihl & 0xF) * 4; // Translate from words to bytes
    ipv4->ipv4_dscp_ecn = ln_read8(&rpos, LN_NTOH);
    uint16_t len = ln_read16(&rpos, LN_NTOH);
    if (len < ipv4->ipv4_ihl) {
        SET_ERRNO(EINVAL); goto fail; }
    //len -= ipv4->ipv4_ihl;
    ipv4->ipv4_id = ln_read16(&rpos, LN_NTOH);
    uint16_t flags_fragoff = ln_read16(&rpos, LN_NTOH);
    ipv4->ipv4_flags = flags_fragoff >> 13;
    ipv4->ipv4_fragoff = flags_fragoff & 0x1FFF;
    ipv4->ipv4_ttl = ln_read8(&rpos, LN_NTOH);
    ipv4->ipv4_proto = ln_read8(&rpos, LN_NTOH);
    ipv4->ipv4_crc = ln_read16(&rpos, LN_NTOH);
    ipv4->ipv4_src = ln_read32(&rpos, LN_NTOH);
    ipv4->ipv4_dst = ln_read32(&rpos, LN_NTOH);
    memcpy(ipv4->ipv4_opts, rpos, ipv4->ipv4_ihl - 20);
    rpos += ipv4->ipv4_ihl - 20;

    // Check packet size
    if (eth_len < len)
        goto fail;
    if (eth_len > len)
        INFO("Extra bytes: %zu", eth_len - len);

    data->data_pos = rpos;
    data->data_last = rpos + len - ipv4->ipv4_ihl;
    ipv4->ipv4_pkt.pkt_data = data;
    parent_pkt->pkt_data = NULL;

    ipv4->ipv4_pkt.pkt_type = ln_pkt_type_ipv4;
    ipv4->ipv4_pkt.pkt_parent = parent_pkt;
    ln_pkt_incref(parent_pkt);

    // Higher-level decode
    struct ln_pkt * ret_pkt = &ipv4->ipv4_pkt;
    switch (ipv4->ipv4_proto) {
    case LN_PROTO_IPV4_PROTO_UDP:
        ret_pkt = ln_pkt_udp_dec(&ipv4->ipv4_pkt);
        if (ret_pkt == NULL) ret_pkt = &ipv4->ipv4_pkt;
        break;
    case LN_PROTO_IPV4_PROTO_TCP:
    case LN_PROTO_IPV4_PROTO_ICMP:
        break;
    default:
        INFO("Unknown IP proto %#02x", ipv4->ipv4_proto);
        break;
    }

    return ret_pkt;

fail:
    free(ipv4);
    return NULL;
}

static int ln_pkt_ipv4_len(struct ln_pkt * pkt, size_t * header_len, size_t * footer_len) {
    struct ln_pkt_ipv4 * ipv4 = LN_PKT_CAST(pkt, ipv4);
    if (ipv4 == NULL) return SET_ERRNO(EINVAL), -1;

    *header_len = ipv4->ipv4_ihl;
    *footer_len = 0;
    return 0;
}

static int ln_pkt_ipv4_enc(struct ln_pkt * pkt, struct ln_data * data) {
    struct ln_pkt_ipv4 * ipv4 = LN_PKT_CAST(pkt, ipv4);
    if (ipv4 == NULL) return SET_ERRNO(EINVAL), -1;

    if (ipv4->ipv4_ihl < LN_PROTO_IPV4_HEADER_LEN_MIN || ipv4->ipv4_ihl > LN_PROTO_IPV4_HEADER_LEN_MAX)
        return SET_ERRNO(EINVAL), -1;

    uchar * new_pos = data->data_pos - ipv4->ipv4_ihl;
    uchar * rpos = new_pos;
    ASSERT(new_pos >= data->data_start);

    uint8_t b = ((ipv4->ipv4_ihl / 4) & 0xF) | 0x40;
    ln_write8(&rpos, b, LN_HTON);
    ln_write8(&rpos, ipv4->ipv4_dscp_ecn, LN_HTON);
    ln_write16(&rpos, ln_data_len(data), LN_HTON);
    ln_write16(&rpos, ipv4->ipv4_id, LN_HTON);
    uint16_t flags_fragoff = ((ipv4->ipv4_flags & 0x7) << 13) | (ipv4->ipv4_fragoff & 0x1FFF);
    ln_write16(&rpos, flags_fragoff, LN_HTON);
    ln_write8(&rpos, ipv4->ipv4_ttl, LN_HTON);
    ln_write8(&rpos, ipv4->ipv4_proto, LN_HTON);
    ln_write16(&rpos, ipv4->ipv4_crc, LN_HTON); // TODO: Calculate checksum
    ln_write32(&rpos, ipv4->ipv4_src, LN_HTON);
    ln_write32(&rpos, ipv4->ipv4_dst, LN_HTON);
    memcpy(rpos, ipv4->ipv4_opts, ipv4->ipv4_ihl - 20);
    rpos += ipv4->ipv4_ihl - 20;

    ASSERT(rpos == data->data_pos);
    data->data_pos = new_pos;

    return 0;
}

int ln_pkt_ipv4_fdump(struct ln_pkt * pkt, FILE * stream) {
    struct ln_pkt_ipv4 * ipv4 = LN_PKT_CAST(pkt, ipv4);
    if (ipv4 == NULL) return SET_ERRNO(EINVAL), -1;
    uint8_t src_ip[4];
    uint8_t dst_ip[4];
    memcpy(src_ip, &ipv4->ipv4_src, 4);
    memcpy(dst_ip, &ipv4->ipv4_dst, 4);
    return fprintf(stream, "[ipv4"
                           " len=%zu"
                           " src=%hhu.%hhu.%hhu.%hhu"
                           " dst=%hhu.%hhu.%hhu.%hhu"
                           " proto=%#04x]",
                    ln_data_len(ipv4->ipv4_pkt.pkt_data),
                    src_ip[3], src_ip[2], src_ip[1], src_ip[0],
                    dst_ip[3], dst_ip[2], dst_ip[1], dst_ip[0],
                    ipv4->ipv4_proto);
}

// struct ln_pkt_udp

struct ln_pkt * ln_pkt_udp_dec(struct ln_pkt * parent_pkt) {
    struct ln_data * data = parent_pkt->pkt_data;
    uchar * rpos = data->data_pos;

    if (data->data_next != NULL) // Unsupported
        return SET_ERRNO(EINVAL), NULL;
    if (data->data_pos + LN_PROTO_UDP_HEADER_LEN >= data->data_last)
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

    // Higher-level decode: TODO
    struct ln_pkt * ret_pkt = &udp->udp_pkt;
    return ret_pkt;

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

// vtable setup

#define LN_PKT_VTBL_DEFAULT(TYPE) \
    [LN_PKT_TYPE_NAME(TYPE)] = (struct ln_pkt_vtbl) { \
        .pkt_vtbl_dec       = ln_pkt_##TYPE##_dec, \
        .pkt_vtbl_len       = ln_pkt_##TYPE##_len, \
        .pkt_vtbl_enc       = ln_pkt_##TYPE##_enc, \
        .pkt_vtbl_fdump     = ln_pkt_##TYPE##_fdump, \
        .pkt_vtbl_term      = NULL, \
    }

static struct ln_pkt_vtbl ln_pkt_vtbl[ln_pkt_type_max] = {
    LN_PKT_VTBL_DEFAULT(raw),
    LN_PKT_VTBL_DEFAULT(eth),
    LN_PKT_VTBL_DEFAULT(ipv4),
    LN_PKT_VTBL_DEFAULT(udp),
};
