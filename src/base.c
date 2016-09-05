#include "base.h"

extern inline uint8_t ln_read8(uchar ** buf, bool flip);
extern inline void ln_write8(uchar ** buf, uint8_t val, bool flip);
extern inline uint16_t ln_read16(uchar **buf, bool flip);
extern inline void ln_write16(uchar **buf, uint16_t val, bool flip);
extern inline uint32_t ln_read32(uchar **buf, bool flip);
extern inline void ln_write32(uchar **buf, uint32_t val, bool flip);

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
