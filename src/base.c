#include "base.h"

extern inline uint8_t ln_read8(uchar ** buf, bool flip);
extern inline void ln_write8(uchar ** buf, uint8_t val, bool flip);
extern inline uint16_t ln_read16(uchar **buf, bool flip);
extern inline void ln_write16(uchar **buf, uint16_t val, bool flip);
extern inline uint32_t ln_read32(uchar **buf, bool flip);
extern inline void ln_write32(uchar **buf, uint32_t val, bool flip);

//extern inline void ntoh(void * buf, size_t len);

size_t ln_data_len(struct ln_data * data) {
    size_t total_len = 0;
    while (data != NULL) {
        total_len += data->data_last - data->data_pos;
        data = data->data_next;
    }
    return total_len;
}

struct ln_data * ln_data_create(size_t size) {
    if (size < LN_DATA_SIZE_MIN)
        size = LN_DATA_SIZE_MIN;

    struct ln_data * data = calloc(1, size + LN_DATA_HEADER_SIZE);
    if (data == NULL) return NULL;

    data->data_pos = data->data_start;
    data->data_last = data->data_pos;
    data->data_next = NULL;
    data->data_end = &data->data_start[size];

    return data;
}

int ln_data_fdump(struct ln_data * data, FILE * stream) {
    return fhexdump(stream, data->data_pos, data->data_last - data->data_pos);
}

/*
// ln_buf

struct ln_buf * ln_buf_create(uint32_t size) {
    if (size < sizeof(struct ln_buf))
        size = sizeof(struct ln_buf);

    //TODO: pool allocator?
    struct ln_buf * buf = calloc(1, size);
    if (buf == NULL) MEMFAIL();

    buf->buf_size = size;
    return buf;
}

void ln_buf_decref(struct ln_buf * buf) {
    if(!buf->buf_refcnt--)
        free(buf);
}

void ln_buf_incref(struct ln_buf * buf) {
    buf->buf_refcnt++;
}
*/

/*
// ln_chain

ssize_t ln_chain_read(struct ln_chain ** chain, uchar ** pos, void * _out, size_t len) {
    if (*chain == NULL || *pos == NULL)
        return -1;

    ssize_t rc = 0;
    uchar * out = _out;
    while (len--) {
        if (out != NULL)
            *out++ = *(*pos)++;
        rc++;
        while (*pos >= (*chain)->chain_last) {
            *chain = (*chain)->chain_next;
            if (*chain == NULL) {
                *pos = NULL;
                return rc;
            } else {
                *pos = (*chain)->chain_pos;
            }
        }
    }
    return rc;
}

ssize_t ln_chain_write(struct ln_chain ** chain, uchar ** pos, const void * _inp, size_t len) {
    if (*chain == NULL || *pos == NULL)
        return -1;

    ssize_t rc = 0;
    const uchar * inp = _inp;
    while (len--) {
        *(*pos)++ = *inp++;
        rc++;
        while (*pos >= (*chain)->chain_last) {
            *chain = (*chain)->chain_next;
            if (*chain == NULL) {
                *pos = NULL;
                break;
            } else {
                *pos = (*chain)->chain_pos;
            }
        }
    }
    return rc;
}

int ln_chain_resize(struct ln_chain * chain, size_t len) {
    if (chain == NULL) return -1;

    while (1) {
        chain->chain_last = LN_BUF_LAST(chain->chain_buf);
        size_t clen = chain->chain_last - chain->chain_pos;
        if (clen >= len) {
            chain->chain_last = chain->chain_pos + len;
            break;
        }
        len -= clen;
        if (chain->chain_next == NULL) {
            // Need to allocate new chain+buf object
            chain->chain_next = calloc(1, sizeof *chain);
            if (chain->chain_next == NULL) MEMFAIL();
            chain = chain->chain_next;

            chain->chain_next->chain_buf = calloc(1, sizeof *chain->chain_buf);
            if (chain->chain_next->chain_buf == NULL) MEMFAIL();
            // Will set pos/last next
        }
        chain = chain->chain_next;
        chain->chain_pos = chain->chain_buf->buf_start;
    }

    // Zero out remaining chain links
    chain = chain->chain_next;
    while (chain != NULL) {
        chain->chain_last = chain->chain_pos;
        chain = chain->chain_next;
    }

    return 0;
}

size_t ln_chain_len(const struct ln_chain * chain) {
    size_t len = 0;
    while (chain != NULL) {
        len += chain->chain_last - chain->chain_pos;
        chain = chain->chain_next;
    }
    return len;
}

uchar * ln_chain_offset(const struct ln_chain * chain, size_t len) {
    while (chain != NULL) {
        size_t blen = chain->chain_last - chain->chain_pos;
        if (len < blen)
            return chain->chain_pos + len;
        len -= blen;
        chain = chain->chain_next;
    }
    return NULL;
}

int ln_chain_readref(struct ln_chain ** in_chain, uchar ** pos, struct ln_chain * out_chain, size_t len) {
    if (out_chain->chain_next != NULL)
        return (errno = EINVAL), -1;
    if (*in_chain == NULL || *pos == NULL)
        return -1;

    do {
        out_chain->chain_buf = (*in_chain)->chain_buf;
        ln_buf_incref((*in_chain)->chain_buf);
        out_chain->chain_pos = *pos;
        out_chain->chain_last = (*in_chain)->chain_last;
        size_t blen = (*in_chain)->chain_last - (*in_chain)->chain_pos;
        if (len < blen) {
            out_chain->chain_last = out_chain->chain_pos + len;
            *pos += len;
            break;
        }
        out_chain->chain_last = (*in_chain)->chain_last;
        len -= blen;
        if (len == 0) break;
        if ((*in_chain)->chain_next == NULL) return (errno = EINVAL), -1;
        *in_chain = (*in_chain)->chain_next;
        *pos = (*in_chain)->chain_pos;

        if (out_chain->chain_next == NULL)
            out_chain->chain_next = calloc(1, sizeof *out_chain->chain_next);
        if (out_chain->chain_next == NULL) return -1;
        out_chain = out_chain->chain_next;
    } while (len);

    // Zero out remaining chain links
    out_chain = out_chain->chain_next;
    while (out_chain != NULL) {
        out_chain->chain_last = out_chain->chain_pos;
        out_chain = out_chain->chain_next;
    }

    return 0;
}

void ln_chain_term(struct ln_chain * chain) {
    bool first = true;
    while (chain != NULL) {
        if (chain->chain_buf != NULL)
            ln_buf_decref(chain->chain_buf);
        struct ln_chain * next = chain->chain_next;
        chain->chain_next = NULL;
        if (!first) free(chain);
        first = false;
        chain = next;
    }
}

struct iovec * ln_chain_iov = NULL;
static size_t n_iovs = 0;

// Not re-entrant
int ln_chain_iovec(struct ln_chain * chain) {
    size_t idx = 0;
    while (chain != NULL) {
        if (idx >= n_iovs) {
            n_iovs = idx * 2;
            ln_chain_iov = realloc(ln_chain_iov, n_iovs * sizeof *ln_chain_iov);
            if (ln_chain_iov == NULL) MEMFAIL();
        }
        ln_chain_iov[idx].iov_base = chain->chain_pos;
        ln_chain_iov[idx].iov_len = chain->chain_last -  chain->chain_pos;
        chain = chain->chain_next;
        idx++;
    }
    return idx;
}
*/

int fhexdump(FILE * stream, uchar * buf, size_t len) {
    const size_t width = 16;
    int outlen = 0;
    size_t idx = 0;
    char hexbuf[64];
    char charbuf[32];
    const char hexdigits[] = "0123456789abcdef";
    while (1) {
        char * hb = hexbuf;
        char * cb = charbuf;
        for (size_t i = 0; i < width; i++) {
            if (i < len) {
                *hb++ = hexdigits[*buf >> 4];
                *hb++ = hexdigits[*buf & 0xF];
                *hb++ = ' ';
                if (*buf >= ' ' && *buf < 0x7F)
                    *cb++ = *buf;
                else
                    *cb++ = '.';
                buf++;
            } else {
                *hb++ = ' ';
                *hb++ = ' ';
                *hb++ = ' ';
                *cb++ = ' ';
            }
        }
        *hb = '\0';
        *cb = '\0';
        int rc = fprintf(stream, "%04zx: %s %s\n", idx, hexbuf, charbuf);
        if (rc < 0) return rc;
        outlen += rc;

        if (len <= width) break;
        len -= width;
        idx += width;
    }
    return outlen;
}

