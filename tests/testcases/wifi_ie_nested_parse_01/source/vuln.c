/*
 * WiFi Information Element Nested Parsing Vulnerability
 * Inspired by WiFi driver IE parsing bugs (CVE-2024-30078 class)
 *
 * Outer IE length is validated against frame boundary, but nested
 * sub-element parsing trusts the sub-element's declared length without
 * re-checking against the outer IE boundary. A crafted sub-element
 * with an inflated length causes an out-of-bounds read/write.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define IE_TYPE_VENDOR   0xDD
#define IE_TYPE_RSN      0x30
#define SUB_TYPE_PMKID   0x04
#define SUB_TYPE_CIPHER  0x01
#define MAX_PMKIDS       4
#define PMKID_LEN        16
#define MAX_CIPHER_SUITES 4

typedef struct {
    uint8_t oui[3];
    uint8_t oui_type;
    uint8_t pmkid_list[MAX_PMKIDS][PMKID_LEN];
    int     num_pmkids;
    uint8_t cipher_suites[MAX_CIPHER_SUITES][4];
    int     num_ciphers;
} ParsedVendorIE;

/*
 * Parse cipher suite sub-element.
 * Validates cipher count against sub-element length,
 * but NOT against MAX_CIPHER_SUITES.
 */
static int parse_cipher_suites(const uint8_t *data, int sub_len,
                               ParsedVendorIE *result) {
    if (sub_len < 2)
        return -1;

    uint16_t count = *(uint16_t *)data;

    /* Partial validation: checks byte budget only */
    if (count * 4 + 2 > sub_len)
        return -1;

    /* BUG: count is not checked against MAX_CIPHER_SUITES (4).
     * A sub-element with count=10 and matching byte budget passes. */
    for (int i = 0; i < count; i++) {
        memcpy(result->cipher_suites[i], data + 2 + i * 4, 4);
    }
    result->num_ciphers = count;
    return 0;
}

/*
 * Parse PMKID sub-element.
 * Correctly validates count against both byte budget and MAX_PMKIDS.
 * (This is the "partially validated" path — ciphers are not.)
 */
static int parse_pmkid_list(const uint8_t *data, int sub_len,
                            ParsedVendorIE *result) {
    if (sub_len < 2)
        return -1;

    uint16_t count = *(uint16_t *)data;

    if (count > MAX_PMKIDS)
        return -1;
    if (count * PMKID_LEN + 2 > sub_len)
        return -1;

    for (int i = 0; i < count; i++) {
        memcpy(result->pmkid_list[i], data + 2 + i * PMKID_LEN, PMKID_LEN);
    }
    result->num_pmkids = count;
    return 0;
}

/*
 * Parse vendor-specific IE with nested sub-elements.
 * Outer IE length is validated against frame boundary.
 */
static int parse_vendor_ie(const uint8_t *ie_data, int ie_len,
                           ParsedVendorIE *result) {
    if (ie_len < 4)
        return -1;

    memcpy(result->oui, ie_data, 3);
    result->oui_type = ie_data[3];

    int offset = 4;
    while (offset + 2 <= ie_len) {
        uint8_t sub_type = ie_data[offset];
        uint8_t sub_len  = ie_data[offset + 1];

        /* BUG: sub_len is NOT validated against remaining ie_len.
         * A sub-element can declare a length larger than the outer IE,
         * causing sub-parsers to read past the IE boundary.
         * However, the more critical bug is in parse_cipher_suites
         * which doesn't check count against array size. */
        offset += 2;

        switch (sub_type) {
        case SUB_TYPE_PMKID:
            parse_pmkid_list(ie_data + offset, sub_len, result);
            break;
        case SUB_TYPE_CIPHER:
            parse_cipher_suites(ie_data + offset, sub_len, result);
            break;
        default:
            break;
        }
        offset += sub_len;
    }
    return 0;
}

/*
 * Process a WiFi management frame containing IEs.
 * Validates total frame length, then iterates IEs.
 */
void process_mgmt_frame(const uint8_t *frame, int frame_len) {
    if (frame_len < 2)
        return;

    int offset = 0;
    while (offset + 2 <= frame_len) {
        uint8_t ie_type = frame[offset];
        uint8_t ie_len  = frame[offset + 1];

        /* Outer validation: IE must fit within frame */
        if (offset + 2 + ie_len > frame_len)
            break;

        if (ie_type == IE_TYPE_VENDOR) {
            ParsedVendorIE result;
            memset(&result, 0, sizeof(result));
            parse_vendor_ie(frame + offset + 2, ie_len, &result);
        }

        offset += 2 + ie_len;
    }
}

int main(void) {
    /* Craft a frame with a vendor IE containing a cipher sub-element
     * with count=8 (exceeds MAX_CIPHER_SUITES=4) */
    uint8_t frame[256];
    int pos = 0;

    /* IE header: type=0xDD (vendor), length=42 */
    frame[pos++] = IE_TYPE_VENDOR;
    frame[pos++] = 42;

    /* OUI + type */
    frame[pos++] = 0x00; frame[pos++] = 0x50;
    frame[pos++] = 0xF2; frame[pos++] = 0x01;

    /* Cipher sub-element: type=0x01, len=34 (2 + 8*4) */
    frame[pos++] = SUB_TYPE_CIPHER;
    frame[pos++] = 34;
    *(uint16_t *)(frame + pos) = 8; /* count=8, exceeds MAX=4 */
    pos += 2;
    for (int i = 0; i < 8; i++) {
        memset(frame + pos, 0x11 + i, 4);
        pos += 4;
    }

    process_mgmt_frame(frame, pos);
    return 0;
}
