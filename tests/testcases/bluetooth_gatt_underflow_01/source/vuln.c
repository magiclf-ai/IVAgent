/*
 * Bluetooth GATT Multi-Read Response Integer Underflow
 * Inspired by CVE-2023-40129: Android Fluoride GATT integer underflow
 *
 * When building a multi-attribute response, the remaining-space calculation
 * fails to account for a 2-byte length prefix added in variable-length mode.
 * This causes an integer underflow, leading to a massive memcpy.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define GATT_MTU 128
#define MAX_ATTRS 16

typedef struct {
    uint16_t handle;
    uint8_t  data[64];
    uint16_t data_len;
} GattAttribute;

typedef struct {
    uint8_t  *buffer;
    uint16_t  buf_size;
    uint16_t  offset;
} GattResponse;

/* Simulated attribute database */
static GattAttribute g_attr_db[MAX_ATTRS];
static int g_num_attrs = 0;

void gatt_register_attr(uint16_t handle, const uint8_t *data, uint16_t len) {
    if (g_num_attrs >= MAX_ATTRS || len > 64)
        return;
    GattAttribute *attr = &g_attr_db[g_num_attrs];
    attr->handle = handle;
    attr->data_len = len;
    memcpy(attr->data, data, len);
    g_num_attrs++;
}

/*
 * Validate that a single attribute fits in the response.
 * This check is correct for fixed-length mode but WRONG for variable-length.
 */
static int check_attr_fits(uint16_t remaining, uint16_t attr_len,
                           int variable_length_mode) {
    /* In variable-length mode, each attr gets a 2-byte length prefix,
     * but this function only checks the data portion */
    if (attr_len > remaining)
        return 0;
    return 1;
}

/*
 * Build a multi-read response for the requested attribute handles.
 * variable_length_mode adds a 2-byte length prefix per attribute.
 */
void build_read_multi_rsp(const uint16_t *handles, int num_handles,
                          int variable_length_mode) {
    GattResponse rsp;
    rsp.buf_size = GATT_MTU;
    rsp.buffer = (uint8_t *)malloc(GATT_MTU);
    if (!rsp.buffer)
        return;

    rsp.offset = 1; /* 1-byte opcode */
    rsp.buffer[0] = variable_length_mode ? 0x21 : 0x20;

    uint16_t total_written = 1;

    for (int i = 0; i < num_handles; i++) {
        /* Find attribute in database */
        GattAttribute *attr = NULL;
        for (int j = 0; j < g_num_attrs; j++) {
            if (g_attr_db[j].handle == handles[i]) {
                attr = &g_attr_db[j];
                break;
            }
        }
        if (!attr)
            continue;

        uint16_t remaining = rsp.buf_size - total_written;

        /* Partial validation: checks data fits, ignores length prefix overhead */
        if (!check_attr_fits(remaining, attr->data_len, variable_length_mode))
            break;

        if (variable_length_mode) {
            /* Write 2-byte length prefix */
            rsp.buffer[total_written] = attr->data_len & 0xFF;
            rsp.buffer[total_written + 1] = (attr->data_len >> 8) & 0xFF;
            total_written += 2;

            /* BUG: remaining was computed BEFORE adding the 2-byte prefix.
             * Now compute how much data to copy:
             *   len = attr->data_len
             * But if total_written now exceeds buf_size, the subsequent
             * memcpy writes past the buffer. */
        }

        /* VULNERABILITY: when variable_length_mode is on and we're near
         * the MTU boundary, total_written already exceeds buf_size after
         * writing the length prefix, but we still copy attr->data_len bytes */
        memcpy(rsp.buffer + total_written, attr->data, attr->data_len);
        total_written += attr->data_len;
    }

    /* Use response... */
    free(rsp.buffer);
}

int main(void) {
    /* Register attributes that together fill the MTU */
    uint8_t data1[60];
    memset(data1, 'A', 60);
    gatt_register_attr(0x0001, data1, 60);

    uint8_t data2[60];
    memset(data2, 'B', 60);
    gatt_register_attr(0x0002, data2, 60);

    uint8_t data3[10];
    memset(data3, 'C', 10);
    gatt_register_attr(0x0003, data3, 10);

    /* Request all three in variable-length mode.
     * After opcode(1) + attr1(2+60) + attr2(2+60) = 125 bytes,
     * remaining = 3. check_attr_fits sees data_len=10 > 3, but
     * actually the 2-byte prefix makes it need 12 bytes.
     * With careful sizing, the check passes but the write overflows. */
    uint16_t handles[] = {0x0001, 0x0002, 0x0003};
    build_read_multi_rsp(handles, 3, 1);
    return 0;
}
