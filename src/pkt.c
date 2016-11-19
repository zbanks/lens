#include "pkt.h"

// struct ln_pkt

void ln_pkt_decref(struct ln_pkt * pkt) {
    //INFO("decref %p %u", pkt, pkt->pkt_refcnt);
    //BACKTRACE("decref");
    if(!pkt->pkt_refcnt--) {
        if (pkt->pkt_parent != NULL)
            ln_pkt_decref(pkt->pkt_parent);
        if (pkt->pkt_type != NULL && pkt->pkt_type->pkt_type_term != NULL)
            pkt->pkt_type->pkt_type_term(pkt);
        pkt->pkt_type->pkt_type_count--;

//#define NOFREE
#ifndef NOFREE
        if (pkt->pkt_data != NULL)
            ln_data_destroy(pkt->pkt_data);

        free(pkt);
#endif
    }
}

void ln_pkt_incref(struct ln_pkt * pkt) {
    //INFO("incref %p %u", pkt, pkt->pkt_refcnt);
    //BACKTRACE("incref");
    pkt->pkt_refcnt++;
}

int ln_pkt_fdump(struct ln_pkt * pkt, FILE * stream) {
    if (pkt == NULL || pkt->pkt_type == NULL || pkt->pkt_type->pkt_type_fdump == NULL)
        return fprintf(stream, "[unknown]");
    return pkt->pkt_type->pkt_type_fdump(pkt, stream);
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

static ssize_t ln_pkt_enc_len(struct ln_pkt * pkt, size_t * header_len) {
    size_t total_len = ln_data_len(pkt->pkt_data);
    *header_len = 0;
    while (pkt != NULL) {
        if (pkt->pkt_type != NULL && pkt->pkt_type->pkt_type_len != NULL) {
            size_t ret_header_len;
            size_t ret_footer_len;
            int rc = pkt->pkt_type->pkt_type_len(pkt, &ret_header_len, &ret_footer_len);
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

    // TODO: For now we don't support data chaining (e.g. data->data_next)
    struct ln_data * data = NULL;

    if (   (pkt->pkt_data == NULL)
        || (pkt->pkt_data->data_pos - header_len < pkt->pkt_data->data_start)
        || (pkt->pkt_data->data_pos - header_len + data_len >= pkt->pkt_data->data_end)) {
        // Ignore it and make a new copy containg the old data but in a bigger buffer
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

    ASSERT(data != NULL);

    while (1) {
        ASSERT(pkt->pkt_type != NULL && pkt->pkt_type->pkt_type_enc != NULL);

        int rc = pkt->pkt_type->pkt_type_enc(pkt, data);
        if (rc < 0) FAIL("Unrecoverable while encoding"); // TODO: recover from this error

        if (pkt->pkt_parent == NULL)
            break;

        struct ln_pkt * old_pkt = pkt;
        pkt = pkt->pkt_parent;
        ln_pkt_incref(pkt);
        ln_pkt_decref(old_pkt);
    }

    // Finish transferring ownership of the ln_data buffer
    pkt->pkt_data = data;
    return pkt;
}

