/*
 * Bluetooth L2CAP Fragment Reassembly Use-After-Free
 * Inspired by CVE-2025-21969: Linux Bluetooth L2CAP UAF
 *
 * L2CAP reassembly queues fragments. On a sequence error, the error
 * handler frees the current fragment but doesn't remove it from the
 * reassembly queue. Subsequent processing of the queue dereferences
 * the freed fragment, causing a use-after-free.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MAX_QUEUE_SIZE  16
#define L2CAP_MTU       1024
#define FRAG_HDR_SIZE   4

typedef struct {
    uint16_t cid;       /* channel ID */
    uint16_t length;    /* total PDU length */
} L2capHeader;

typedef struct {
    uint8_t *data;
    uint16_t data_len;
    uint16_t expected_len;
    uint16_t cid;
    int      complete;
} ReassemblyEntry;

typedef struct {
    ReassemblyEntry *queue[MAX_QUEUE_SIZE];
    int              queue_count;
    int              total_reassembled;
} L2capChannel;

/*
 * Find or create a reassembly entry for the given channel ID.
 */
static ReassemblyEntry *find_or_create_entry(L2capChannel *chan,
                                             uint16_t cid,
                                             uint16_t expected_len) {
    /* Search existing entries */
    for (int i = 0; i < chan->queue_count; i++) {
        if (chan->queue[i] && chan->queue[i]->cid == cid)
            return chan->queue[i];
    }

    /* Create new entry */
    if (chan->queue_count >= MAX_QUEUE_SIZE)
        return NULL;

    ReassemblyEntry *entry = (ReassemblyEntry *)calloc(1, sizeof(ReassemblyEntry));
    if (!entry)
        return NULL;

    entry->data = (uint8_t *)malloc(expected_len);
    if (!entry->data) {
        free(entry);
        return NULL;
    }
    entry->expected_len = expected_len;
    entry->cid = cid;
    entry->data_len = 0;
    entry->complete = 0;

    chan->queue[chan->queue_count] = entry;
    chan->queue_count++;
    return entry;
}

/*
 * Handle a reassembly error: free the entry's data.
 * BUG: frees the entry and its data but does NOT remove it from the queue
 * or set the queue slot to NULL.
 */
static void handle_reassembly_error(L2capChannel *chan,
                                    ReassemblyEntry *entry) {
    /* Free the data buffer */
    free(entry->data);
    /* Free the entry itself */
    free(entry);
    /* BUG: queue[i] still points to freed memory.
     * Should set queue[i] = NULL and decrement queue_count. */
}

/*
 * Append a continuation fragment to an existing reassembly entry.
 * Validates fragment size against remaining expected bytes.
 */
static int append_fragment(ReassemblyEntry *entry, const uint8_t *frag_data,
                           uint16_t frag_len) {
    if (entry->complete)
        return -1;

    uint16_t remaining = entry->expected_len - entry->data_len;

    /* Partial validation: checks fragment fits in remaining space */
    if (frag_len > remaining) {
        /* Fragment too large — this is a protocol error */
        return -1;
    }

    memcpy(entry->data + entry->data_len, frag_data, frag_len);
    entry->data_len += frag_len;

    if (entry->data_len == entry->expected_len)
        entry->complete = 1;

    return 0;
}

/*
 * Process completed reassembly entries.
 * Iterates the queue and processes any complete PDUs.
 * BUG: may access freed entries left in the queue by handle_reassembly_error.
 */
static void process_completed_entries(L2capChannel *chan) {
    for (int i = 0; i < chan->queue_count; i++) {
        ReassemblyEntry *entry = chan->queue[i];
        /* VULNERABILITY: entry may have been freed by handle_reassembly_error
         * but the pointer is still in the queue. Accessing entry->complete
         * and entry->data is a use-after-free. */
        if (entry && entry->complete) {
            /* "Process" the reassembled PDU */
            /* UAF: reading entry->data and entry->data_len from freed memory */
            uint8_t first_byte = entry->data[0];
            (void)first_byte;

            /* Clean up after processing */
            free(entry->data);
            free(entry);
            chan->queue[i] = NULL;
            chan->total_reassembled++;
        }
    }
}

/*
 * Receive an L2CAP fragment (start or continuation).
 * is_start: 1 for first fragment (contains L2CAP header), 0 for continuation.
 */
void l2cap_recv_fragment(L2capChannel *chan, const uint8_t *frag,
                         int frag_len, int is_start) {
    if (is_start) {
        if (frag_len < FRAG_HDR_SIZE)
            return;

        L2capHeader *hdr = (L2capHeader *)frag;
        uint16_t pdu_len = hdr->length;
        uint16_t cid = hdr->cid;

        if (pdu_len > L2CAP_MTU)
            return;

        ReassemblyEntry *entry = find_or_create_entry(chan, cid, pdu_len);
        if (!entry)
            return;

        /* Copy initial data after header */
        int initial_data_len = frag_len - FRAG_HDR_SIZE;
        if (initial_data_len > 0) {
            if (append_fragment(entry, frag + FRAG_HDR_SIZE,
                                initial_data_len) != 0) {
                handle_reassembly_error(chan, entry);
                return;
            }
        }
    } else {
        /* Continuation fragment — find matching entry */
        /* Use CID from first 2 bytes of continuation */
        if (frag_len < 2)
            return;

        uint16_t cid = *(uint16_t *)frag;
        ReassemblyEntry *entry = NULL;
        for (int i = 0; i < chan->queue_count; i++) {
            if (chan->queue[i] && chan->queue[i]->cid == cid) {
                entry = chan->queue[i];
                break;
            }
        }

        if (!entry)
            return;

        if (append_fragment(entry, frag + 2, frag_len - 2) != 0) {
            /* Error: fragment doesn't fit. Free and leave dangling. */
            handle_reassembly_error(chan, entry);
            return;
        }
    }

    /* Check for completed PDUs */
    process_completed_entries(chan);
}

int main(void) {
    L2capChannel chan;
    memset(&chan, 0, sizeof(chan));

    /* Send start fragment: cid=1, expected_len=32, initial 16 bytes */
    uint8_t start_frag[20];
    L2capHeader *hdr = (L2capHeader *)start_frag;
    hdr->cid = 1;
    hdr->length = 32;
    memset(start_frag + 4, 'A', 16);
    l2cap_recv_fragment(&chan, start_frag, 20, 1);

    /* Send oversized continuation: cid=1, 20 bytes data (only 16 remaining)
     * This triggers handle_reassembly_error → free but dangling pointer */
    uint8_t cont_frag[22];
    *(uint16_t *)cont_frag = 1; /* cid */
    memset(cont_frag + 2, 'B', 20);
    l2cap_recv_fragment(&chan, cont_frag, 22, 0);

    /* Send another start fragment on same CID.
     * process_completed_entries will iterate queue and hit the
     * dangling pointer from the first entry → UAF */
    uint8_t start2[36];
    L2capHeader *hdr2 = (L2capHeader *)start2;
    hdr2->cid = 2;
    hdr2->length = 32;
    memset(start2 + 4, 'C', 32);
    l2cap_recv_fragment(&chan, start2, 36, 1);

    return 0;
}
