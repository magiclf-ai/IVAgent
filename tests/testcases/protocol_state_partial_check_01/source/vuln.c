/*
 * Protocol State Machine Partial Validation Vulnerability
 *
 * A network protocol handler uses a state machine: INIT → AUTH → DATA.
 * The AUTH state validates credentials and sets "authenticated" flag.
 * The DATA state validates message format but assumes all security
 * checks were done in AUTH. However, a crafted sequence can transition
 * from INIT directly to DATA by exploiting a fallthrough in the
 * state transition logic, bypassing authentication entirely.
 * Additionally, the DATA state's format parser has a length bug.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define STATE_INIT  0
#define STATE_AUTH  1
#define STATE_DATA  2
#define STATE_ERROR 3

#define CMD_HELLO    0x01
#define CMD_AUTH     0x02
#define CMD_DATA     0x03
#define CMD_RESET    0x04

#define MAX_FIELDS   8

typedef struct {
    uint8_t  cmd;
    uint16_t length;
    uint8_t  payload[];
} ProtocolMsg;

typedef struct {
    int      state;
    int      authenticated;
    char     username[32];
    uint8_t  session_key[16];
    /* Data processing buffer */
    uint8_t  data_buf[256];
    int      data_buf_used;
} SessionContext;

/*
 * Validate authentication credentials.
 * Returns 0 on success, -1 on failure.
 */
static int validate_credentials(const uint8_t *payload, int len,
                                SessionContext *ctx) {
    if (len < 48) /* 32 username + 16 key */
        return -1;

    memcpy(ctx->username, payload, 32);
    /* Ensure null termination */
    ctx->username[31] = '\0';

    memcpy(ctx->session_key, payload + 32, 16);

    /* Simplified credential check */
    if (ctx->session_key[0] == 0x00)
        return -1; /* reject null key */

    ctx->authenticated = 1;
    return 0;
}

/*
 * Parse structured data fields from payload.
 * Expects: [num_fields:1][field_len:2][field_data:field_len]...
 *
 * Validates total consumed bytes against payload length,
 * but has a signed/unsigned comparison bug on field_len.
 */
static int parse_data_fields(const uint8_t *payload, int len,
                             SessionContext *ctx) {
    if (len < 1)
        return -1;

    uint8_t num_fields = payload[0];
    if (num_fields > MAX_FIELDS)
        return -1; /* count check is correct */

    int offset = 1;
    for (int i = 0; i < num_fields; i++) {
        if (offset + 2 > len)
            return -1;

        /* BUG: field_len is uint16_t but compared as signed int.
         * A value like 0xFFFF becomes 65535, which passes the
         * "offset + field_len <= len" check if len is also large
         * due to integer promotion. But the real bug is below. */
        uint16_t field_len = *(uint16_t *)(payload + offset);
        offset += 2;

        if (offset + field_len > len)
            return -1;

        /* Accumulate into session data buffer.
         * BUG: data_buf_used is not checked against sizeof(data_buf).
         * Multiple fields can collectively overflow the 256-byte buffer
         * even though each individual field_len passes the payload check. */
        memcpy(ctx->data_buf + ctx->data_buf_used,
               payload + offset, field_len);
        ctx->data_buf_used += field_len;

        offset += field_len;
    }
    return 0;
}

/*
 * Process a protocol message within the state machine.
 */
void process_protocol_msg(const uint8_t *msg_data, int msg_len,
                          SessionContext *ctx) {
    if (msg_len < 3)
        return;

    ProtocolMsg *msg = (ProtocolMsg *)msg_data;
    if (msg->length + 3 > msg_len)
        return;

    switch (ctx->state) {
    case STATE_INIT:
        if (msg->cmd == CMD_HELLO) {
            ctx->state = STATE_AUTH;
        } else if (msg->cmd == CMD_RESET) {
            /* Reset is allowed in any state */
            ctx->state = STATE_INIT;
            ctx->authenticated = 0;
        } else if (msg->cmd == CMD_DATA) {
            /* BUG: INIT state should reject DATA commands,
             * but falls through to DATA state processing.
             * This bypasses authentication entirely. */
            ctx->state = STATE_DATA;
            /* Fall through to process data immediately */
            parse_data_fields(msg->payload, msg->length, ctx);
        }
        break;

    case STATE_AUTH:
        if (msg->cmd == CMD_AUTH) {
            if (validate_credentials(msg->payload, msg->length, ctx) == 0) {
                ctx->state = STATE_DATA;
            } else {
                ctx->state = STATE_ERROR;
            }
        }
        break;

    case STATE_DATA:
        if (msg->cmd == CMD_DATA) {
            /* Assumes authentication was done in AUTH state */
            if (!ctx->authenticated) {
                /* This check exists but was bypassed via INIT→DATA */
                /* BUG: this check is dead code when coming from INIT
                 * because state was set to DATA before reaching here.
                 * Actually, the INIT case processes data inline and
                 * never reaches this branch. */
            }
            parse_data_fields(msg->payload, msg->length, ctx);
        }
        break;

    case STATE_ERROR:
        /* Only reset allowed */
        if (msg->cmd == CMD_RESET) {
            ctx->state = STATE_INIT;
            ctx->authenticated = 0;
            ctx->data_buf_used = 0;
        }
        break;
    }
}

int main(void) {
    SessionContext ctx;
    memset(&ctx, 0, sizeof(ctx));

    /* Send DATA command directly in INIT state (bypass auth) */
    /* with 8 fields of 40 bytes each = 320 bytes > 256 buf */
    uint8_t msg[512];
    msg[0] = CMD_DATA;

    int payload_offset = 3;
    int pos = payload_offset;
    msg[pos++] = 8; /* num_fields = 8 */

    for (int i = 0; i < 8; i++) {
        *(uint16_t *)(msg + pos) = 40;
        pos += 2;
        memset(msg + pos, 'A' + i, 40);
        pos += 40;
    }

    *(uint16_t *)(msg + 1) = pos - payload_offset;
    process_protocol_msg(msg, pos, &ctx);
    return 0;
}
