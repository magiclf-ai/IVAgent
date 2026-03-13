/*
 * Baseband RLC Fragment Reassembly Vulnerability
 * Inspired by CVE-2023-41112: Samsung Baseband RLC Data Re-Assembly Heap BOF
 *
 * Fragment descriptor has a fixed-size array. Fragment count is incremented
 * without bounds checking. When the array overflows, it corrupts adjacent
 * fields, causing a size mismatch between allocation and copy.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MAX_FRAGMENTS   8
#define MAX_PDU_SIZE    512
#define FRAG_DATA_SIZE  64

typedef struct {
    uint16_t block_offsets[MAX_FRAGMENTS];
    uint16_t block_sizes[MAX_FRAGMENTS];
    uint8_t *fragments[MAX_FRAGMENTS];
    /* Fields AFTER the arrays — overflow target */
    uint16_t n_blocks;
    uint16_t total_size;
    uint16_t allocated_size;
    int      is_edge_mode;
} FragmentDescriptor;

typedef struct {
    uint8_t *pdu_buffer;
    uint16_t pdu_size;
} ReassembledPDU;

/*
 * Add a fragment to the descriptor.
 * BUG: n_blocks is never checked against MAX_FRAGMENTS.
 */
static void add_fragment(FragmentDescriptor *desc, const uint8_t *data,
                         uint16_t offset, uint16_t size) {
    uint16_t idx = desc->n_blocks;

    /* VULNERABILITY: no bounds check on idx against MAX_FRAGMENTS (8).
     * When idx >= 8, writes corrupt n_blocks, total_size, allocated_size,
     * and is_edge_mode fields that sit after the arrays in memory. */
    desc->block_offsets[idx] = offset;
    desc->block_sizes[idx] = size;

    uint8_t *frag_copy = (uint8_t *)malloc(size);
    if (frag_copy)
        memcpy(frag_copy, data, size);
    desc->fragments[idx] = frag_copy;

    desc->n_blocks++;
    desc->total_size += size;
}

/*
 * Validate fragment consistency.
 * Checks that total_size doesn't exceed MAX_PDU_SIZE.
 * This check may be bypassed if n_blocks/total_size were corrupted
 * by the array overflow.
 */
static int validate_fragments(FragmentDescriptor *desc) {
    if (desc->total_size > MAX_PDU_SIZE)
        return -1;
    if (desc->n_blocks == 0)
        return -1;
    return 0;
}

/*
 * Concatenate fragments into a single PDU buffer.
 * Allocates based on total_size (potentially corrupted),
 * but copies based on actual fragment data.
 */
static ReassembledPDU *concatenate_fragments(FragmentDescriptor *desc) {
    if (validate_fragments(desc) != 0)
        return NULL;

    ReassembledPDU *pdu = (ReassembledPDU *)malloc(sizeof(ReassembledPDU));
    if (!pdu)
        return NULL;

    /* Allocation uses total_size — may be corrupted to a small value */
    pdu->pdu_buffer = (uint8_t *)malloc(desc->total_size);
    pdu->pdu_size = desc->total_size;
    if (!pdu->pdu_buffer) {
        free(pdu);
        return NULL;
    }

    /* Copy loop uses actual fragment sizes — may exceed allocated buffer.
     * BUG: if total_size was corrupted to a small value by the array
     * overflow, but we still copy all n_blocks fragments, the memcpy
     * writes past the allocated buffer. */
    uint16_t write_offset = 0;
    for (int i = 0; i < desc->n_blocks; i++) {
        if (desc->fragments[i]) {
            memcpy(pdu->pdu_buffer + write_offset,
                   desc->fragments[i], desc->block_sizes[i]);
            write_offset += desc->block_sizes[i];
        }
    }

    return pdu;
}

/*
 * Process incoming RLC data blocks.
 * Each block contains a fragment with a header (offset, size).
 */
void rlc_process_data_blocks(const uint8_t *data, int data_len,
                             int num_blocks) {
    FragmentDescriptor *desc =
        (FragmentDescriptor *)calloc(1, sizeof(FragmentDescriptor));
    if (!desc)
        return;

    int pos = 0;
    for (int i = 0; i < num_blocks && pos + 4 < data_len; i++) {
        uint16_t frag_offset = *(uint16_t *)(data + pos);
        uint16_t frag_size   = *(uint16_t *)(data + pos + 2);
        pos += 4;

        if (frag_size > FRAG_DATA_SIZE || pos + frag_size > data_len) {
            pos += frag_size;
            continue;
        }

        /* Individual fragment size is validated (<=64),
         * but fragment COUNT is not checked */
        add_fragment(desc, data + pos, frag_offset, frag_size);
        pos += frag_size;
    }

    ReassembledPDU *pdu = concatenate_fragments(desc);

    /* Cleanup */
    if (pdu) {
        free(pdu->pdu_buffer);
        free(pdu);
    }
    for (int i = 0; i < desc->n_blocks && i < MAX_FRAGMENTS; i++)
        free(desc->fragments[i]);
    free(desc);
}

int main(void) {
    /* Craft 12 fragments (exceeds MAX_FRAGMENTS=8) */
    uint8_t payload[1024];
    int pos = 0;
    for (int i = 0; i < 12; i++) {
        *(uint16_t *)(payload + pos) = (uint16_t)(i * 16); /* offset */
        *(uint16_t *)(payload + pos + 2) = 16;             /* size */
        pos += 4;
        memset(payload + pos, 'A' + i, 16);
        pos += 16;
    }

    rlc_process_data_blocks(payload, pos, 12);
    return 0;
}
