/*
 * IPC Message Dispatch Type Confusion Vulnerability
 *
 * An IPC server dispatches messages to handlers based on type.
 * The dispatcher validates the message header (type, total length),
 * but each handler parses its own payload. One handler trusts a
 * nested "data_type" field to select a struct layout without
 * validating that the payload size matches the selected layout.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MSG_TYPE_AUTH    1
#define MSG_TYPE_DATA    2
#define MSG_TYPE_CONTROL 3

#define DATA_SUBTYPE_TEXT   0x01
#define DATA_SUBTYPE_BINARY 0x02
#define DATA_SUBTYPE_STRUCT 0x03

typedef struct {
    uint32_t msg_type;
    uint32_t msg_len;    /* total length including header */
} IpcHeader;

typedef struct {
    char username[32];
    char token[64];
} AuthPayload;

typedef struct {
    uint8_t  data_subtype;
    uint8_t  reserved[3];
    uint32_t data_len;
    uint8_t  data[];     /* flexible array */
} DataPayload;

/* "Large" struct layout for STRUCT subtype */
typedef struct {
    uint32_t field_count;
    uint32_t field_offsets[16];
    uint8_t  field_data[256];
} StructuredData;

/* "Small" struct layout for TEXT subtype */
typedef struct {
    uint32_t text_len;
    char     text[64];
} TextData;

/*
 * Auth handler: validates token length, copies safely.
 * This handler is SAFE — included to show partial validation pattern.
 */
static int handle_auth(const uint8_t *payload, int payload_len) {
    if (payload_len < (int)sizeof(AuthPayload))
        return -1;
    if (payload_len > (int)sizeof(AuthPayload))
        return -1;

    AuthPayload auth;
    memcpy(&auth, payload, sizeof(AuthPayload));
    /* Process auth... */
    return 0;
}

/*
 * Sanitize text data: checks for null terminator within bounds.
 * This is a "partial check" — it validates text but not struct data.
 */
static int sanitize_text(const char *text, int max_len) {
    for (int i = 0; i < max_len; i++) {
        if (text[i] == '\0')
            return 0; /* found terminator, safe */
    }
    return -1; /* no terminator */
}

/*
 * Data handler: dispatches based on data_subtype.
 * The dispatcher already validated msg_len, but this handler
 * trusts data_subtype to select a struct layout without checking
 * that payload_len matches the selected layout's size.
 */
static int handle_data(const uint8_t *payload, int payload_len) {
    if (payload_len < (int)sizeof(DataPayload))
        return -1;

    DataPayload *dp = (DataPayload *)payload;

    switch (dp->data_subtype) {
    case DATA_SUBTYPE_TEXT: {
        /* Partial validation: checks text has null terminator */
        TextData *td = (TextData *)(payload + sizeof(DataPayload));
        if (payload_len - sizeof(DataPayload) < sizeof(uint32_t))
            return -1;

        if (sanitize_text(td->text, 64) != 0)
            return -1;

        /* Safe: copies bounded amount */
        char local_buf[64];
        memcpy(local_buf, td->text, td->text_len);
        /* BUG: td->text_len is attacker-controlled and not checked
         * against 64. sanitize_text only checks for null terminator,
         * not that text_len <= 64. */
        return 0;
    }

    case DATA_SUBTYPE_STRUCT: {
        /* VULNERABILITY: No size validation for StructuredData.
         * Payload could be smaller than sizeof(StructuredData),
         * causing out-of-bounds read when accessing field_offsets. */
        StructuredData *sd = (StructuredData *)(payload + sizeof(DataPayload));

        /* BUG: field_count is attacker-controlled, not checked against 16 */
        for (uint32_t i = 0; i < sd->field_count; i++) {
            uint32_t off = sd->field_offsets[i];
            if (off < 256) {
                /* Write marker at each field offset */
                sd->field_data[off] = 0xFF;
            }
        }
        return 0;
    }

    case DATA_SUBTYPE_BINARY:
        /* Simple passthrough, no vulnerability */
        return 0;

    default:
        return -1;
    }
}

/*
 * Top-level IPC message dispatcher.
 * Validates header and total length, then routes to handler.
 */
void ipc_dispatch_message(const uint8_t *msg, int msg_len) {
    if (msg_len < (int)sizeof(IpcHeader))
        return;

    IpcHeader *hdr = (IpcHeader *)msg;

    /* Validate total length matches */
    if (hdr->msg_len != (uint32_t)msg_len)
        return;

    /* Validate minimum size per type */
    if (hdr->msg_type == MSG_TYPE_AUTH && msg_len < (int)(sizeof(IpcHeader) + sizeof(AuthPayload)))
        return;
    if (hdr->msg_type == MSG_TYPE_DATA && msg_len < (int)(sizeof(IpcHeader) + sizeof(DataPayload)))
        return;

    const uint8_t *payload = msg + sizeof(IpcHeader);
    int payload_len = msg_len - sizeof(IpcHeader);

    switch (hdr->msg_type) {
    case MSG_TYPE_AUTH:
        handle_auth(payload, payload_len);
        break;
    case MSG_TYPE_DATA:
        handle_data(payload, payload_len);
        break;
    default:
        break;
    }
}

int main(void) {
    /* Craft a DATA message with STRUCT subtype, field_count=20 (>16) */
    uint8_t msg[512];
    IpcHeader *hdr = (IpcHeader *)msg;
    hdr->msg_type = MSG_TYPE_DATA;

    DataPayload *dp = (DataPayload *)(msg + sizeof(IpcHeader));
    dp->data_subtype = DATA_SUBTYPE_STRUCT;
    dp->data_len = 400;

    StructuredData *sd = (StructuredData *)(msg + sizeof(IpcHeader) + sizeof(DataPayload));
    sd->field_count = 20; /* exceeds array size of 16 */
    for (int i = 0; i < 20; i++)
        sd->field_offsets[i] = i * 10;

    int total = sizeof(IpcHeader) + sizeof(DataPayload) + sizeof(StructuredData);
    hdr->msg_len = total;

    ipc_dispatch_message(msg, total);
    return 0;
}
