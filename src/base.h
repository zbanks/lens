#pragma once
#include "libdill/libdill.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <arpa/inet.h>

#include "log.h"

//

// 

typedef uint32_t refcnt_t;
typedef unsigned char uchar;

#define LN_BUF_SIZE_MIN (4096 - sizeof(refcnt_t) - sizeof(uint32_t))
#define LN_BUF_LAST(bufp) (&(bufp)->buf_start[(bufp)->buf_size])

#define LN_DATA_HEADER_SIZE (4 * sizeof(uchar *))
#define LN_DATA_SIZE_MIN (2048 - LN_DATA_HEADER_SIZE)

struct ln_data {
    uchar * data_pos; // `last - pos` == length of segment
    uchar * data_last;
    struct ln_data * data_next;
    uchar * data_end; // `end - start` == capacity of segment
    uchar data_start[LN_DATA_SIZE_MIN];
    uchar data_extra[0]; // `data_end >= data_extra`
};

size_t ln_data_len(struct ln_data * data);
struct ln_data * ln_data_create(size_t size);
int ln_data_fdump(struct ln_data * data, FILE * stream);

// Utils

int fhexdump(FILE * stream, uchar * buf, size_t len);

// Endianness conversions

#define LN_NTOH 1
#define LN_HTON 1
#define LN_NONE 0

inline uint8_t ln_read8(uchar ** buf, bool flip) {
    (void) flip;
    return *(*buf)++;
}

inline void ln_write8(uchar ** buf, uint8_t val, bool flip) {
    (void) flip;
    *(*buf)++ = val;
}

inline uint16_t ln_read16(uchar **buf, bool flip) {
    uint16_t val = 0;
    memcpy(&val, *buf, sizeof val);
    *buf += sizeof val;
    return flip ? ntohs(val) : val;
}

inline void ln_write16(uchar **buf, uint16_t val, bool flip) {
    uint16_t nval = htons(val);
    memcpy(*buf, flip ? &nval : &val, sizeof val);
    *buf += sizeof val;
}

inline uint32_t ln_read32(uchar **buf, bool flip) {
    uint32_t val = 0;
    memcpy(&val, *buf, sizeof val);
    *buf += sizeof val;
    return flip ? ntohl(val) : val;
}

inline void ln_write32(uchar **buf, uint32_t val, bool flip) {
    uint32_t nval = htonl(val);
    memcpy(*buf, flip ? &nval : &val, sizeof val);
    *buf += sizeof val;
}

// Compiler things

#define LN_ATTRIBUTE_CONSTRUCTOR __attribute__ ((constructor))
#define LN_ATTRIBUTE_PACKED __attribute__ ((packed))
