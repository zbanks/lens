#pragma once
#include "libdill/libdill.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

/*
// ln_buf is guarenteed to be at least LN_BUF_SIZE_MIN bytes long
struct ln_buf {
    refcnt_t buf_refcnt;
    uint32_t buf_size;
    uchar buf_start[LN_BUF_SIZE_MIN];
    uchar buf_extra[0];
};

struct ln_chain {
    struct ln_buf * chain_buf;
    uchar * chain_pos;
    uchar * chain_last;
    struct ln_chain * chain_next;
};

#define LN_CHAIN_IS_NULL(chain) ((chain)->chain_buf == NULL)


// ln_buf functions

struct ln_buf * ln_buf_create(uint32_t size);
void ln_buf_decref(struct ln_buf * buf);
void ln_buf_incref(struct ln_buf * buf);
*/

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
    uint32_t nval = htons(val);
    memcpy(*buf, flip ? &nval : &val, sizeof val);
    *buf += sizeof val;
}

/*
#define hton ntoh
inline void ntoh(void * buf, size_t len) {
    if (len <= 1) {
        return;
    } else if (len == 2) {
        uint16_t t;
        memcpy(&t, buf, sizeof t);
        t = ntohs(t);
        memcpy(buf, &t, sizeof t);
    } else if (len == 4) {
        uint32_t t;
        memcpy(&t, buf, sizeof t);
        t = ntohl(t);
        memcpy(buf, &t, sizeof t);
    } else {
        abort();
    }
}
*/


// ln_chain needs rework
/*
// ln_chain functions

#define ln_chain_read_ntoh(CHAIN, POS, TARGET) ({ \
    ssize_t _rv = ln_chain_read((CHAIN), (POS), (TARGET), sizeof *(TARGET)); \
    ntoh((TARGET), sizeof *(TARGET)); \
    _rv; })


#define ln_chain_write_hton(CHAIN, POS, TARGET) ({ \
    hton((TARGET), sizeof *(TARGET)); \
    ssize_t _rv = ln_chain_write((CHAIN), (POS), (TARGET), sizeof *(TARGET)); \
    ntoh((TARGET), sizeof *(TARGET)); \
    _rv; })

// Read data from a flat buffer `out` into a chain
// If `out` is NULL, it advances `pos` `len` bytes
ssize_t ln_chain_read(struct ln_chain ** chain, uchar ** pos, void * out, size_t len);
// Write data from a flat buffer `in` into a chain
ssize_t ln_chain_write(struct ln_chain ** chain, uchar ** pos, const void * inp, size_t len);
// Resize the buffer pointed to by `chain` to be `len` bytes long.
// Will allocate additional `ln_chain`s and `ln_buf`s and move `chain_last`
int ln_chain_resize(struct ln_chain * chain, size_t len);
// Return the total length of the data in bytes pointed to by `chain`
size_t ln_chain_len(const struct ln_chain * chain);
// Return a pointer `len` bytes from the start of the `chain`, or NULL on overrun
uchar * ln_chain_offset(const struct ln_chain * chain, size_t len);
// Weak copy data from `in_chain` to `out_chain` and advance `pos`
int ln_chain_readref(struct ln_chain ** in_chain, uchar ** pos, struct ln_chain * out_chain, size_t len);
// Convert an `ln_chain` to iovec form for use with sendmsg(2)/writev(2)
int ln_chain_iovec(struct ln_chain * chain); // Not re-entrant
extern struct iovec * ln_chain_iov;
void ln_chain_term(struct ln_chain * chain);
*/

int fhexdump(FILE * stream, uchar * buf, size_t len);
