/*
 * RPC Server Multi-Handler Nested TLV Overflow
 *
 * An RPC server dispatches messages to handlers. The dispatcher validates
 * the outer message envelope (type, length). Each handler parses its own
 * payload using TLV format. The "config update" handler has a nested TLV
 * where the inner parser trusts a length field from the outer TLV without
 * re-validating against the actual remaining buffer.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define RPC_TYPE_PING     0x01
#define RPC_TYPE_QUERY    0x02
#define RPC_TYPE_CONFIG   0x03

#define TLV_TAG_NAME      0x10
#define TLV_TAG_VALUE     0x20
#define TLV_TAG_NESTED    0x30
#define TLV_TAG_ARRAY     0x40

#define MAX_CONFIG_ENTRIES 8
#define MAX_NAME_LEN       32
#define MAX_VALUE_LEN      64

typedef struct {
    uint32_t rpc_type;
    uint32_t rpc_len;   /* payload length (excluding header) */
} RpcHeader;

typedef struct {
    uint8_t tag;
    uint16_t length;
} TlvHeader;

typedef struct {
    char name[MAX_NAME_LEN];
    char value[MAX_VALUE_LEN];
} ConfigEntry;

typedef struct {
    ConfigEntry entries[MAX_CONFIG_ENTRIES];
    int num_entries;
} ConfigUpdate;

/*
 * Parse a single TLV from the buffer.
 * Returns bytes consumed, or -1 on error.
 */
static int parse_tlv(const uint8_t *buf, int remaining,
                     uint8_t *tag, uint16_t *length,
                     const uint8_t **value) {
    if (remaining < 3)
        return -1;

    TlvHeader *hdr = (TlvHeader *)buf;
    *tag = hdr->tag;
    *length = hdr->length;

    if (3 + hdr->length > remaining)
        return -1;

    *value = buf + 3;
    return 3 + hdr->length;
}

/*
 * Handle PING: simple echo, no vulnerability.
 */
static int handle_ping(const uint8_t *payload, int payload_len) {
    /* Just validate and return */
    if (payload_len < 4)
        return -1;
    return 0;
}

/*
 * Handle QUERY: parses a name TLV, validates length. Safe.
 */
static int handle_query(const uint8_t *payload, int payload_len) {
    uint8_t tag;
    uint16_t length;
    const uint8_t *value;

    int consumed = parse_tlv(payload, payload_len, &tag, &length, &value);
    if (consumed < 0 || tag != TLV_TAG_NAME)
        return -1;

    if (length >= MAX_NAME_LEN)
        return -1; /* correct bounds check */

    char name_buf[MAX_NAME_LEN];
    memcpy(name_buf, value, length);
    name_buf[length] = '\0';
    return 0;
}

/*
 * Parse nested config entries from a NESTED TLV's value.
 * Expects alternating NAME and VALUE TLVs inside.
 *
 * BUG: Uses the outer TLV's declared length to bound parsing,
 * but doesn't re-validate inner TLV lengths against the actual
 * remaining bytes in the nested region. Also doesn't check
 * entry count against MAX_CONFIG_ENTRIES.
 */
static int parse_nested_config(const uint8_t *data, int data_len,
                               ConfigUpdate *config) {
    int offset = 0;
    int entry_idx = 0;

    while (offset < data_len) {
        /* Parse name TLV */
        uint8_t name_tag;
        uint16_t name_len;
        const uint8_t *name_val;
        int consumed = parse_tlv(data + offset, data_len - offset,
                                 &name_tag, &name_len, &name_val);
        if (consumed < 0 || name_tag != TLV_TAG_NAME)
            break;
        offset += consumed;

        /* Parse value TLV */
        uint8_t val_tag;
        uint16_t val_len;
        const uint8_t *val_val;
        consumed = parse_tlv(data + offset, data_len - offset,
                             &val_tag, &val_len, &val_val);
        if (consumed < 0 || val_tag != TLV_TAG_VALUE)
            break;
        offset += consumed;

        /* BUG: entry_idx not checked against MAX_CONFIG_ENTRIES (8).
         * Also, name_len and val_len not checked against
         * MAX_NAME_LEN/MAX_VALUE_LEN before memcpy. */
        memcpy(config->entries[entry_idx].name, name_val, name_len);
        config->entries[entry_idx].name[name_len] = '\0';

        /* VULNERABILITY: val_len can be up to 65535 (uint16_t),
         * but value[] in ConfigEntry is only 64 bytes.
         * parse_tlv validates val_len fits in the outer buffer,
         * but not against MAX_VALUE_LEN. */
        memcpy(config->entries[entry_idx].value, val_val, val_len);
        config->entries[entry_idx].value[val_len] = '\0';

        entry_idx++;
    }
    config->num_entries = entry_idx;
    return 0;
}

/*
 * Handle CONFIG: parses top-level TLVs, one of which may be NESTED
 * containing config entries.
 */
static int handle_config(const uint8_t *payload, int payload_len) {
    ConfigUpdate config;
    memset(&config, 0, sizeof(config));

    int offset = 0;
    while (offset < payload_len) {
        uint8_t tag;
        uint16_t length;
        const uint8_t *value;

        int consumed = parse_tlv(payload + offset, payload_len - offset,
                                 &tag, &length, &value);
        if (consumed < 0)
            break;

        if (tag == TLV_TAG_NESTED) {
            /* Parse nested config entries */
            parse_nested_config(value, length, &config);
        }
        /* Other tags ignored */

        offset += consumed;
    }
    return 0;
}

/*
 * Top-level RPC dispatcher.
 * Validates header and routes to handler.
 */
void rpc_dispatch(const uint8_t *msg, int msg_len) {
    if (msg_len < (int)sizeof(RpcHeader))
        return;

    RpcHeader *hdr = (RpcHeader *)msg;

    /* Validate payload length */
    if (sizeof(RpcHeader) + hdr->rpc_len > (uint32_t)msg_len)
        return;

    const uint8_t *payload = msg + sizeof(RpcHeader);
    int payload_len = hdr->rpc_len;

    switch (hdr->rpc_type) {
    case RPC_TYPE_PING:
        handle_ping(payload, payload_len);
        break;
    case RPC_TYPE_QUERY:
        handle_query(payload, payload_len);
        break;
    case RPC_TYPE_CONFIG:
        handle_config(payload, payload_len);
        break;
    default:
        break;
    }
}

int main(void) {
    uint8_t msg[1024];
    RpcHeader *hdr = (RpcHeader *)msg;
    hdr->rpc_type = RPC_TYPE_CONFIG;

    int pos = sizeof(RpcHeader);

    /* Build a NESTED TLV containing 10 config entries with oversized values */
    uint8_t nested_buf[800];
    int npos = 0;

    for (int i = 0; i < 10; i++) {
        /* Name TLV: tag=0x10, len=4, "key\x00" */
        nested_buf[npos++] = TLV_TAG_NAME;
        *(uint16_t *)(nested_buf + npos) = 4;
        npos += 2;
        memcpy(nested_buf + npos, "key", 4);
        npos += 4;

        /* Value TLV: tag=0x20, len=70 (exceeds MAX_VALUE_LEN=64) */
        nested_buf[npos++] = TLV_TAG_VALUE;
        *(uint16_t *)(nested_buf + npos) = 70;
        npos += 2;
        memset(nested_buf + npos, 'V', 70);
        npos += 70;
    }

    /* Wrap in NESTED TLV */
    msg[pos++] = TLV_TAG_NESTED;
    *(uint16_t *)(msg + pos) = npos;
    pos += 2;
    memcpy(msg + pos, nested_buf, npos);
    pos += npos;

    hdr->rpc_len = pos - sizeof(RpcHeader);
    rpc_dispatch(msg, pos);
    return 0;
}
