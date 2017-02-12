#include "base.h"

size_t data_count = 0;

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

    data_count++;

    return data;
}

void ln_data_destroy(struct ln_data * data) {
    data_count--;
    free(data);
}

ssize_t ln_data_write(struct ln_data ** base, const uchar * buf, size_t len) {
    size_t total_len = 0;
    struct ln_data * data = *base;

    if (data == NULL) {
        data = *base = ln_data_create(len);
    } else {
        while (data->data_next != NULL) {
            total_len += data->data_last - data->data_pos;
            data = data->data_next;
        }
        total_len += data->data_last - data->data_pos;
        size_t len_remaining = data->data_end - data->data_last;
        if (len_remaining < len) {
            data->data_next = ln_data_create(len - len_remaining);
            if (data->data_next == NULL) MEMFAIL();

            memcpy(data->data_last, buf, len_remaining);
            data->data_last += len_remaining;
            buf += len_remaining;
            len -= len_remaining;
            total_len += len_remaining;
            data = data->data_next;
        }
    }

    memcpy(data->data_last, buf, len);
    data->data_last += len;
    total_len += len;

    return total_len;
}

ssize_t ln_data_extend(struct ln_data ** base, const struct ln_data * data) {
    ssize_t rc = -1;
    while (data != NULL) {
        rc = ln_data_write(base, data->data_pos, data->data_last - data->data_pos);
        data = data->data_next;
    }
    return rc;
}

int ln_data_fdump(struct ln_data * data, FILE * stream) {
    return fhexdump(stream, data->data_pos, data->data_last - data->data_pos);
}

//

struct ln_fq {
    char * fq_buf;
    char * fq_end;
    char * fq_r_pos;
    char * fq_w_pos;
    bool fq_w_closed;
    bool fq_r_closed;
};

#define LN_FQ_DEFAULT_SIZE 1024

static ssize_t ln_fq_reader_read(void * cookie, char * buf, size_t size) {
    struct ln_fq * fq = cookie;
    if (fq->fq_r_pos == fq->fq_w_pos)
        return 0;
    ssize_t rc = fq->fq_w_pos - fq->fq_r_pos;
    ASSERT(rc > 0);
    if ((size_t) rc > size)
        rc = size;
    memcpy(buf, fq->fq_r_pos, rc);
    fq->fq_r_pos += rc;
    return rc;
}

static ssize_t ln_fq_writer_write(void * cookie, const char * buf, size_t size) {
    struct ln_fq * fq = cookie;
    if (fq->fq_w_pos + size >= fq->fq_end) {
        size_t new_size = fq->fq_end - fq->fq_buf; 
        while(fq->fq_w_pos + size >= fq->fq_buf + new_size)
            new_size *= 2;
        void * new_buf = realloc(fq->fq_buf, new_size);
        if (new_buf == NULL)
            return -1;
        fq->fq_buf = new_buf;
    }
    memcpy(fq->fq_w_pos, buf, size);
    return size;
}

static int ln_fq_reader_close(void * cookie) {
    struct ln_fq * fq = cookie;
    fq->fq_r_closed = true;
    if (fq->fq_r_closed && fq->fq_w_closed) {
        free(fq->fq_buf);
        free(fq);
    }
    return 0;
}

static int ln_fq_writer_close(void * cookie) {
    struct ln_fq * fq = cookie;
    fq->fq_w_closed = true;
    if (fq->fq_r_closed && fq->fq_w_closed) {
        free(fq->fq_buf);
        free(fq);
    }
    return 0;
}

cookie_io_functions_t ln_fq_reader = {
    .read = ln_fq_reader_read,
    //.seek = ln_fq_reader_seek,
    .close = ln_fq_reader_close,
};

cookie_io_functions_t ln_fq_writer = {
    .write = ln_fq_writer_write,
    //.seek = ln_fq_writer_seek,
    .close = ln_fq_writer_close,
};

int ln_fq_create(FILE ** reader, FILE ** writer) {
    struct ln_fq * fq = calloc(1, sizeof *fq);
    if (fq == NULL) MEMFAIL();
    fq->fq_buf = calloc(1, LN_FQ_DEFAULT_SIZE);
    if (fq->fq_buf == NULL) MEMFAIL();

    *reader = fopencookie(fq, "r", ln_fq_reader);
    *writer = fopencookie(fq, "w", ln_fq_writer);
    if (*reader == NULL || *writer == NULL)
        return -1;
    return 0;
}

//

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

