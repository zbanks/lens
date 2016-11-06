#include "pkt.h"
#include "pkts/lowlevel.h"
#include <strings.h>

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

    raw->raw_src = fd;
    raw->raw_dst = -1;
    raw->raw_pkt.pkt_parent = NULL;
    raw->raw_pkt.pkt_type = ln_pkt_type_raw;
    raw->raw_pkt.pkt_data = data;

    data = NULL;
    return raw;
}

int ln_pkt_raw_fsend(struct ln_pkt_raw * raw) {
    struct ln_data * data = raw->raw_pkt.pkt_data;
    return send(raw->raw_dst, data->data_pos, data->data_last - data->data_pos, MSG_DONTWAIT);
}

struct ln_pkt * ln_pkt_raw_dec(struct ln_pkt * parent_pkt) {
    // copy/no-op, not very useful
    struct ln_pkt_raw * raw = calloc(1, sizeof *raw);
    if (raw == NULL) return NULL;

    raw->raw_src = -1;
    raw->raw_dst = -1;
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
    return fprintf(stream, "[raw len=%zu src_fd=%d dst_fd=%d]",
                    ln_data_len(pkt->pkt_data),
                    raw->raw_src,
                    raw->raw_dst);
}

#define ln_pkt_raw_term NULL
LN_PKT_TYPE_DECLARE(raw);

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

    /*
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
    */

    return &eth->eth_pkt;
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

int ln_pkt_eth_parse_type(const char * type_str) {
    if (type_str == NULL)
        return -1;
    if (type_str[0] == '\0')
        return -1;
    if (strcasecmp(type_str, "arp") == 0)
        return LN_PROTO_ETH_TYPE_ARP;
    if (strcasecmp(type_str, "ipv4") == 0)
        return LN_PROTO_ETH_TYPE_IPV4;
    if (strcasecmp(type_str, "ipv6") == 0)
        return LN_PROTO_ETH_TYPE_IPV6;
    errno = 0;
    int type = strtol(type_str, NULL, 0);
    if (errno != 0)
        return -1;
    return type;
}

#define ln_pkt_eth_term NULL
LN_PKT_TYPE_DECLARE(eth);

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
    if (eth_len > len) {
        INFO("Extra bytes: %zu", eth_len - len);
        //fhexdump(stderr, data->data_start, data->data_last - data->data_start);
        //fprintf(stderr, "\n");
    }

    data->data_pos = rpos;
    data->data_last = rpos + len - ipv4->ipv4_ihl;
    ipv4->ipv4_pkt.pkt_data = data;
    parent_pkt->pkt_data = NULL;

    ipv4->ipv4_pkt.pkt_type = ln_pkt_type_ipv4;
    ipv4->ipv4_pkt.pkt_parent = parent_pkt;
    ln_pkt_incref(parent_pkt);

    /*
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
    */

    return &ipv4->ipv4_pkt;

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
    ln_write16(&rpos, ln_data_len(data) + ipv4->ipv4_ihl, LN_HTON);
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

int ln_pkt_ipv4_parse_proto(const char * proto_str) {
    if (proto_str == NULL)
        return -1;
    if (proto_str[0] == '\0')
        return -1;
    if (strcasecmp(proto_str, "ICMP") == 0)
        return LN_PROTO_IPV4_PROTO_ICMP;
    if (strcasecmp(proto_str, "TCP") == 0)
        return LN_PROTO_IPV4_PROTO_TCP;
    if (strcasecmp(proto_str, "UDP") == 0)
        return LN_PROTO_IPV4_PROTO_UDP;
    errno = 0;
    int proto = strtol(proto_str, NULL, 0);
    if (errno != 0)
        return -1;
    return proto;
}

#define ln_pkt_ipv4_term NULL
LN_PKT_TYPE_DECLARE(ipv4);
