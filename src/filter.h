#pragma once
#include "pkt.h"
#include "base.h"
#include <graphviz/cgraph.h>

// Filter Graphs

struct ln_graph {
    // "Privates" -- no peeking!
    Agrec_t _graph_header;
    Agnode_t * _graph_start; // Where data starts in the graph

    // This struct is stored as a record on the Agraph_t
    // AGDATA(g->graph_ag) == g
    Agraph_t * graph_ag;

    // Dill channels, each taking (struct ln_pkt *) s
    // chsend() into graph_input; chrecv() from graph_output
    int graph_input;
    int graph_output;
};

struct ln_graph * ln_graph_load(FILE * stream);
void ln_graph_run(struct ln_graph * graph);

#define AG_EACH_EDGEOUT(node, edge) \
    Agedge_t * edge = agfstout(agraphof(node), node); \
    edge != NULL; \
    edge = agnxtout(agraphof(node), edge)

// Filter Types

struct ln_filter_type;
struct ln_filter_type {
    struct ln_filter_type * filter_next; // Singly-linked list

    const char * filter_name;
    void * (*filter_create)(Agnode_t * node);
    void (*filter_destroy)(Agnode_t * node, void * cookie);
    int (*filter_perform)(Agnode_t * node, void * cookie, struct ln_pkt * pkt);
};

void ln_filter_type_register(struct ln_filter_type * filter_type);

#define LN_ATTRIBUTE_CONSTRUCTOR __attribute__ ((constructor))
#define LN_FILTER_EMPTY_COOKIE ((void *) 1)

#define LN_FILTER_TYPE_DECLARE_STATELESS(NAME) \
    static struct ln_filter_type NAME = \
    (struct ln_filter_type) { \
        .filter_next = NULL, \
        .filter_name = #NAME, \
        .filter_create = NULL, \
        .filter_destroy = NULL, \
        .filter_perform = NAME##_perform, \
    }

#define LN_FILTER_TYPE_DECLARE(NAME) \
    static struct ln_filter_type NAME = \
    (struct ln_filter_type) { \
        .filter_next = NULL, \
        .filter_name = #NAME, \
        .filter_create = NAME##_create, \
        .filter_destroy = NAME##_destroy, \
        .filter_perform = NAME##_perform, \
    }

// Filter Utils

int ln_filter_push(Agedge_t * edge, struct ln_pkt * pkt);
void coroutine ln_filter_run();
