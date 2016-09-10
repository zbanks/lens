#include "filter.h"

// Internal Filter Utils

static int ln_filter_create(Agnode_t * node);
//static void ln_filter_destroy(Agnode_t * node);
static int ln_filter_perform(Agnode_t * node, struct ln_pkt * pkt);

// Filter Graphs

struct node_data {
    Agrec_t header;
    struct ln_filter_type * filter_type;
    void * filter_cookie;
};

#define GRAPH_DATA(g) ((struct ln_graph *)AGDATA(g))
#define NODE_DATA(g) ((struct node_data *)AGDATA(g))

struct ln_graph * ln_graph_load(FILE * stream) {
    Agraph_t * gr = agread(stream, NULL);
    if (gr == NULL) {
        ERROR("Unable to read graph");
        return NULL;
    }
    if (agisundirected(gr)) {
        ERROR("Graph is undirected; must be directed");
        return NULL;
    }

    Agnode_t * input_node = agnode(gr, "input", 0);
    if (input_node == NULL) {
        ERROR("Graph does not have a node named 'input'");
        return NULL;
    }

    aginit(gr, AGNODE, "_ln_internal", sizeof(struct node_data), 1);

    for (Agnode_t * node = agfstnode(gr); node != NULL; node = agnxtnode(gr, node)) {
        NODE_DATA(node)->filter_type = NULL;
        NODE_DATA(node)->filter_cookie = NULL;

        if (node == input_node) continue;

        int rc = ln_filter_create(node);
        if (rc < 0) {
            ERROR("Error creating filter");
            return NULL;
        }
    }

    struct ln_graph * graph = agbindrec(gr, "_ln_internal", sizeof *graph, 1);
    if (graph == NULL) MEMFAIL();

    // Weird loop; AGDATA(graph->graph_ag) == graph
    graph->graph_ag = gr;
    graph->_graph_start = input_node;

    graph->graph_input= channel(sizeof(struct ln_pkt_pkt *), 16);
    if (graph->graph_input< 0) PFAIL("Unable to open graph input channel");
    graph->graph_output = channel(sizeof(struct ln_pkt_pkt *), 16);
    if (graph->graph_output < 0) PFAIL("Unable to open graph output channel");

    return graph;
}

void coroutine ln_graph_run(struct ln_graph * graph) {
    while (1) {
        struct ln_pkt * pkt = NULL;
        int rc = chrecv(graph->graph_input, &pkt, sizeof pkt, -1);
        if (rc < 0) break;

        rc = 0; 
        for (AG_EACH_EDGEOUT(graph->_graph_start, edge)) {
            rc |= ln_filter_push(edge, pkt);
        }
        if (rc < 0) break;

        ln_pkt_decref(pkt);
    }
}

//

static struct ln_filter_type * ln_filter_types_head = NULL;

void ln_filter_type_register(struct ln_filter_type * filter_type) {
    filter_type->filter_next = ln_filter_types_head;
    ln_filter_types_head = filter_type;
}

//

static int ln_filter_create(Agnode_t * node) {
    const char * filter_name = agget(node, "type");
    if (filter_name == NULL) {
        ERROR("Filter node '%s' does not have a 'type' attribute", agnameof(node));
        return -1;
    }

    struct ln_filter_type * filter_type = ln_filter_types_head;
    for (; filter_type != NULL; filter_type = filter_type->filter_next) {
        if (strcmp(filter_name, filter_type->filter_name) == 0)
            break;
    }
    if (filter_type == NULL) {
        ERROR("Unknown filter type '%s' for node '%s'", filter_name, agnameof(node));
        return -1;
    }

    void * filter_cookie = NULL;
    if (filter_type->filter_create != NULL) {
        filter_cookie = filter_type->filter_create(node);
        if (filter_cookie == NULL) {
            ERROR("Failed to create filter type '%s' for node '%s'", filter_name, agnameof(node));
            return -1;
        }
    }

    NODE_DATA(node)->filter_cookie = filter_cookie;
    NODE_DATA(node)->filter_type = filter_type;

    DEBUG("Initialized filter type '%s' for node '%s'", filter_name, agnameof(node));

    return 0;
}

/*
static void ln_filter_destroy(Agnode_t * node) {
    if (NODE_DATA(node)->filter_type->filter_destroy != NULL)
        NODE_DATA(node)->filter_type->filter_destroy(node, NODE_DATA(node)->filter_cookie);
}
*/

static int ln_filter_perform(Agnode_t * node, struct ln_pkt * pkt) {
    DEBUG("Performing packet %p with node %s type %s",
            pkt, agnameof(node), NODE_DATA(node)->filter_type->filter_name);

    int rc = NODE_DATA(node)->filter_type->filter_perform(node, NODE_DATA(node)->filter_cookie, pkt);
    if (rc < 0) {
        WARN("Error while performing filter '%s' on node '%s'. Packet dump:",
                NODE_DATA(node)->filter_type->filter_name, agnameof(node));
        ln_pkt_fdumpall(pkt, stderr);
    }
    return 0; // Keep going through errors for now
}

// FIFO queue for handling packet processing

// The same queue is shared by multiple graphs, 
// so the capacity should be chosen carefully.

static int queue_ch = -1;
struct queue_item {
    Agnode_t * node;
    struct ln_pkt * pkt;
};

void coroutine ln_filter_run(size_t capacity) {
    // If the channel is too small, the system can deadlock
    queue_ch = channel(sizeof(struct queue_item), capacity);
    if (queue_ch < 0) FAIL("Unable to create queue channel");
    while (1) {
        struct queue_item item;
        int rc = chrecv(queue_ch, &item, sizeof item, -1);
        if (rc < 0) break;
        // Lookup filter & call
        rc = ln_filter_perform(item.node, item.pkt);
        if (rc < 0) break;
        // Incremented in ln_filter_push
        ln_pkt_decref(item.pkt);
    }
}

int ln_filter_push(Agedge_t * edge, struct ln_pkt * pkt) {
    if (queue_ch == -1) return -1;

    DEBUG("Pushing packet %p from %s to %s",
            pkt, agnameof(agtail(edge)), agnameof(aghead(edge)));

    ln_pkt_incref(pkt); // Decremented in ln_filter_run
    struct queue_item item = {
        .node = aghead(edge),
        .pkt = pkt,
    };
    return chsend(queue_ch, &item, sizeof item, -1);
}

// Special case "filter" for getting data out of the sandwich

// output: Send packets to the `graph_output` channel
int output_perform(Agnode_t * node, void * filter, struct ln_pkt * pkt) {
    Agraph_t * graph = agraphof(node);
    struct ln_graph * graph_data = GRAPH_DATA(graph);
    
    ln_pkt_incref(pkt);
    return chsend(graph_data->graph_output, &pkt, sizeof pkt, -1);
}
LN_FILTER_TYPE_DECLARE_STATELESS(output);

LN_ATTRIBUTE_CONSTRUCTOR
static void init() {
    ln_filter_type_register(&output);
}
