/*
 * Baseband NAS TFT Parsing Vulnerability
 * Inspired by CVE-2023-21517: Samsung Baseband LTE ESM TFT Heap Buffer Overflow
 *
 * Multi-level TLV parsing: the outer TFT IE is length-validated, but the inner
 * component count is only checked against the declared packet filter length,
 * never against the fixed-size component pointer array. A crafted packet filter
 * with many small components overflows the array.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PACKET_FILTERS 16
#define MAX_COMPONENTS     10

typedef struct {
    uint8_t type;
    uint8_t data[32];
    uint8_t data_len;
} ComponentDesc;

typedef struct {
    uint8_t  pf_id;
    uint8_t  pf_precedence;
    uint8_t  num_components;
    ComponentDesc *components[MAX_COMPONENTS]; /* fixed 10-element array */
} PacketFilterDesc;

typedef struct {
    uint8_t  operation;
    uint8_t  num_filters;
    PacketFilterDesc *filters[MAX_PACKET_FILTERS];
} TftDesc;

/*
 * Parse a single component from the byte stream.
 * Returns bytes consumed, or -1 on error.
 */
static int parse_component(const uint8_t *data, int remaining, ComponentDesc **out) {
    if (remaining < 2)
        return -1;

    uint8_t comp_type = data[0];
    uint8_t comp_len  = data[1];

    if (comp_len > 32 || comp_len + 2 > remaining)
        return -1;

    ComponentDesc *comp = (ComponentDesc *)malloc(sizeof(ComponentDesc));
    if (!comp)
        return -1;

    comp->type = comp_type;
    comp->data_len = comp_len;
    memcpy(comp->data, data + 2, comp_len);
    *out = comp;
    return comp_len + 2;
}

/*
 * Parse a single packet filter.
 * Validates total component bytes against declared pf_length,
 * but NEVER checks component count against MAX_COMPONENTS.
 */
static int parse_packet_filter(const uint8_t *data, int remaining,
                               PacketFilterDesc **out) {
    if (remaining < 3)
        return -1;

    uint8_t pf_id         = data[0];
    uint8_t pf_precedence = data[1];
    uint8_t pf_length     = data[2]; /* declared content length */

    if (pf_length + 3 > remaining)
        return -1;

    PacketFilterDesc *pf = (PacketFilterDesc *)calloc(1, sizeof(PacketFilterDesc));
    if (!pf)
        return -1;

    pf->pf_id = pf_id;
    pf->pf_precedence = pf_precedence;

    /* --- First pass: count components and validate total size --- */
    int offset = 0;
    int comp_count = 0;
    const uint8_t *content = data + 3;

    while (offset < pf_length) {
        if (pf_length - offset < 2)
            break;
        uint8_t clen = content[offset + 1];
        offset += clen + 2;
        comp_count++;
    }

    /* Validate total bytes match declared length (this check PASSES) */
    if (offset != pf_length) {
        free(pf);
        return -1;
    }

    /* BUG: comp_count is validated against pf_length (byte budget),
     * but never against MAX_COMPONENTS (array size = 10).
     * A 251-byte filter with 2-byte components yields ~125 components. */

    /* --- Second pass: allocate and store component pointers --- */
    offset = 0;
    int idx = 0;
    while (offset < pf_length) {
        ComponentDesc *comp = NULL;
        int consumed = parse_component(content + offset,
                                       pf_length - offset, &comp);
        if (consumed < 0) {
            free(pf);
            return -1;
        }
        /* VULNERABILITY: idx can exceed MAX_COMPONENTS (10),
         * overwriting memory past the components[] array */
        pf->components[idx] = comp;
        idx++;
        offset += consumed;
    }
    pf->num_components = idx;

    *out = pf;
    return pf_length + 3;
}

/*
 * Top-level TFT IE parser.
 * Validates outer IE length, then iterates packet filters.
 */
void parse_tft_ie(const uint8_t *ie_data, int ie_len) {
    if (ie_len < 1)
        return;

    TftDesc *tft = (TftDesc *)calloc(1, sizeof(TftDesc));
    if (!tft)
        return;

    tft->operation = ie_data[0] >> 5;
    uint8_t num_filters = ie_data[0] & 0x0F;

    /* Outer length check passes — ie_len covers all bytes */
    int offset = 1;
    int filter_idx = 0;

    while (filter_idx < num_filters && offset < ie_len) {
        PacketFilterDesc *pf = NULL;
        int consumed = parse_packet_filter(ie_data + offset,
                                           ie_len - offset, &pf);
        if (consumed < 0)
            break;

        if (filter_idx < MAX_PACKET_FILTERS)
            tft->filters[filter_idx] = pf;
        filter_idx++;
        offset += consumed;
    }
    tft->num_filters = filter_idx;

    /* cleanup omitted for brevity */
    free(tft);
}

int main(void) {
    /* Craft a TFT IE with one packet filter containing 20 tiny components */
    uint8_t ie[256];
    ie[0] = 0x21; /* operation=1, num_filters=1 */

    /* packet filter header: id=0, precedence=0, length=40 (20 * 2-byte components) */
    ie[1] = 0x00;
    ie[2] = 0x00;
    ie[3] = 40;

    /* 20 components, each: type=0x01, len=0 (2 bytes total) */
    for (int i = 0; i < 20; i++) {
        ie[4 + i * 2]     = 0x01;
        ie[4 + i * 2 + 1] = 0x00;
    }

    parse_tft_ie(ie, 44);
    return 0;
}
