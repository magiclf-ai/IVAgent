# Test Case: protocol_state_partial_check_01

## Metadata
- **Engine**: source
- **Skill**: eval_source_scan
- **Entry Functions**: process_protocol_msg
- **Timeout**: 300 seconds
- **Tags**: state_machine, auth_bypass, buffer_overflow, partial_validation, cross_function, protocol

## Description

This test case models a network protocol state machine with states INIT → AUTH → DATA. The AUTH state validates credentials and sets an `authenticated` flag. The DATA state processes structured data fields. However, the INIT state handler has a fallthrough bug: when it receives a CMD_DATA command, it transitions directly to DATA state and processes the data inline, bypassing authentication entirely. Additionally, `parse_data_fields` validates each field against the payload boundary but never checks the cumulative size against the session's 256-byte `data_buf`, allowing multiple fields to collectively overflow it.

Key complexity:
- Two independent vulnerabilities: auth bypass (state machine) + buffer overflow (accumulation)
- The auth bypass is a logic bug in state transitions, not a memory corruption
- The buffer overflow requires understanding that individual field checks pass but cumulative writes overflow
- `validate_credentials` is correctly implemented but never called on the bypass path
- The `authenticated` check in DATA state is dead code on the bypass path
- 3-function chain: `process_protocol_msg` → state dispatch → `parse_data_fields`

## Source Code

See `source/vuln.c`

## Expected Vulnerabilities

### Vulnerability 1: Authentication Bypass via State Machine Fallthrough

The INIT state processes CMD_DATA directly, transitioning to DATA state and calling `parse_data_fields` without going through AUTH.

- **Location**: `case STATE_INIT:` → `else if (msg->cmd == CMD_DATA)` in `process_protocol_msg`
- **Root Cause**: The INIT state handler should reject CMD_DATA, but instead transitions to DATA and processes the payload inline, bypassing the AUTH state entirely
- **Data Flow**: Attacker sends CMD_DATA in INIT state → state set to DATA → `parse_data_fields` called directly → authentication never checked
- **Severity**: HIGH
- **Attack Scenario**: An unauthenticated attacker sends a DATA command immediately after connection, bypassing the HELLO → AUTH sequence. This grants access to data processing functionality without credentials.

### Vulnerability 2: Stack Buffer Overflow via Cumulative Field Writes in parse_data_fields

Multiple data fields collectively overflow the 256-byte `data_buf` even though each individual field passes the payload boundary check.

- **Location**: `memcpy(ctx->data_buf + ctx->data_buf_used, payload + offset, field_len)` in `parse_data_fields`
- **Root Cause**: Each `field_len` is validated against the remaining payload length, but `data_buf_used` is never checked against `sizeof(data_buf)` (256). Eight fields of 40 bytes each = 320 bytes, overflowing the buffer.
- **Data Flow**: `process_protocol_msg` → `parse_data_fields(payload, len, ctx)` → loop accumulates field data into `ctx->data_buf` → cumulative size exceeds 256 → stack/heap overflow
- **Severity**: CRITICAL
- **Attack Scenario**: Attacker sends a DATA message with 8 fields of 40 bytes each. Each field individually fits within the payload, but the total (320 bytes) overflows the 256-byte data_buf, corrupting adjacent session context fields or stack data.

The evaluator should reward reports that identify both the logic bug (auth bypass) and the memory corruption (cumulative overflow) as independent vulnerabilities that can be chained.
