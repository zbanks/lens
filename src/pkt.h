#pragma once
#include "base.h"
#include "util.h"

#define LN_PKT_TYPE_STRUCT(TYPE) struct ln_pkt_##TYPE
#define LN_PKT_TYPE_NAME(TYPE) ln_pkt_type_##TYPE

// Safely convert from generic to ln_pkt.
// Example usage: `struct ln_pkt_raw * my_raw = LN_PKT_CAST(my_pkt, raw);`
#define LN_PKT_CAST(pkt, TYPE) ({ \
        struct ln_pkt * _pkt = (pkt); \
        if (_pkt != NULL && _pkt->pkt_type != LN_PKT_TYPE_NAME(TYPE)) \
            _pkt = NULL; \
        (LN_PKT_TYPE_STRUCT(TYPE) *) _pkt; })

// Decode & cast 
#define LN_PKT_DEC(pkt, TYPE) LN_PKT_CAST(LN_PKT_TYPE_NAME(TYPE)->pkt_type_dec((pkt)), TYPE)

struct ln_pkt_type {
    struct ln_pkt * (*pkt_type_dec)(struct ln_pkt * parent_pkt);
    int (*pkt_type_len)(struct ln_pkt * pkt, size_t * header_len, size_t * footer_len);
    int (*pkt_type_enc)(struct ln_pkt * pkt, struct ln_data * payload_data);
    int (*pkt_type_fdump)(struct ln_pkt * pkt, FILE * stream);
    void (*pkt_type_term)(struct ln_pkt * pkt);
};

#define LN_PKT_TYPE_DECLARE(TYPE) \
    struct ln_pkt_type LN_PKT_TYPE_NAME(TYPE##_) = (struct ln_pkt_type) { \
        .pkt_type_dec       = ln_pkt_##TYPE##_dec, \
        .pkt_type_len       = ln_pkt_##TYPE##_len, \
        .pkt_type_enc       = ln_pkt_##TYPE##_enc, \
        .pkt_type_fdump     = ln_pkt_##TYPE##_fdump, \
        .pkt_type_term      = ln_pkt_##TYPE##_term, \
    }, \
    * LN_PKT_TYPE_NAME(TYPE) = &LN_PKT_TYPE_NAME(TYPE##_)

//

struct ln_pkt {
    // Underlying protocol/header
    struct ln_pkt * pkt_parent;
    // Payload/data
    struct ln_data * pkt_data;
    // Reference count
    refcnt_t pkt_refcnt;
    // Type, vtable information
    struct ln_pkt_type * pkt_type;
};

void ln_pkt_decref(struct ln_pkt * pkt);
void ln_pkt_incref(struct ln_pkt * pkt);
int ln_pkt_fdump(struct ln_pkt * pkt, FILE * stream);
int ln_pkt_fdumpall(struct ln_pkt * pkt, FILE * stream);
struct ln_pkt * ln_pkt_enc(struct ln_pkt * pkt);
